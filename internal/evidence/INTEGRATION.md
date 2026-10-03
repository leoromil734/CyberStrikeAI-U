# 原件与离线发现模块接线

本目录和 `../recon` 不依赖 MCP 或数据库。数据库实现这些目录声明的接口，避免数据库与 MCP 的循环依赖。本模块不调用网络、不运行扫描器或 POC、不写项目事实、不创建正式漏洞。

## 初始化与调用顺序

1. 在数据库 `initTables()` 中调用 `db.initResultArtifactsTables()`；测试或外部启动器可调用公开的 `db.InitResultArtifactsTables()`。
2. 先由现有执行服务保存执行归属，并从可信运行上下文取得 owner、project、conversation、scope、assessment。scope/assessment 是不可复用的范围版本与评估标识，不得仅用 hostname 代替。
3. 工具退出且文件写入结束后，调用 `recon.Processor.Observe`。它首先保存轻量执行 metadata，随后登记并流式校验原件，再离线解析。原始输入需作为独立 `input` 原件提供；数据库不保存参数正文、预览或完整输出。
4. 原件路径清单是非可信输入。管理根目录必须来自服务配置或执行器预先分配的目录，绝不能用工具结果中的 `work_dir`、路径提示或 manifest 字段直接构造信任根。所有根必须同时绑定执行 ID、owner、project 和 conversation。

```go
// db 实现 recon.Store。以下标识应从已经授权的执行上下文提取。
access := evidence.Access{
    ProjectID: projectID, ConversationID: conversationID, Owner: ownerUserID,
}
ctx := evidence.WithAccess(ctx, access)
execution := evidence.Execution{
    ID: executionID, Access: access, ScopeID: scopeVersion,
    AssessmentID: assessmentID, Tool: "httpx", Status: "completed",
    Completion: evidence.Complete, StartedAt: startedAt, FinishedAt: finishedAt,
    OutputBytes: actualOutputBytes, Capped: resultWasCapped, TimedOut: timedOut,
}

// allocatedRunDir 来自执行器分配，不从 tool stdout 取值。
registry, err := evidence.NewRegistry(db, []evidence.ManagedRoot{{
    Path: allocatedRunDir, Access: access, ExecutionID: executionID,
    Files: []string{"input.json", "httpx.jsonl"},
}}, evidence.DefaultMaxArtifactBytes)
if err != nil { return err }
defer registry.Close()
processor := &recon.Processor{
    Store: db, Artifacts: registry,
    // Scope 为主程序的授权策略。无策略、无范围/评估标识时全部候选。
    Scope: authorizedScopeResolver,
}
report, err := processor.Observe(ctx, recon.Event{
    Execution: execution, CappedResult: cappedResultText, ExpiresAt: sourceExpiresAt,
    Artifacts: []evidence.Candidate{
        {Path: inputPath, Kind: "input", Format: "json", Completion: evidence.Complete},
        {Path: outputPath, Kind: "output", Format: "jsonl", Completion: evidence.Complete},
    },
})
if err != nil { return err }
// report.Records 是有界结构化记录。主程序调用资产模块导入，
// 必须继续保留 CandidateOnly、ScopeState、scope/assessment 和来源位置。
// report.Inserted 是本次真正新增数量；来源自称计数/预览计数不能替代它。
// report.Inventory 是本评估、同执行归属的真实去重库存计数。
// report.Sources 是本次来源状态，ArtifactErrors/RecordsTruncated 也必须处理。
```

对于 `tooloutput` 溢出文件，可使用 `evidence.ReductionRoot(base, execution)`，它复用 `tooloutput.SessionRoot`，且只允许本执行的精确文件名。该根目录必须已经存在。会话 workspace 应使用执行专用子目录或显式 `Files` 清单。`/var/lib/jsapiscan/runs` 必须绑定执行器预先分配的具体 job 目录，不能信任整个共享父目录。注册器持有 `os.Root` 目录句柄，需要在使用后关闭；需要后续读取时，可以使用相同可信配置重新建立注册器。

## 查询与最小证据

- `db.ResultExecution(ctx, executionID)` / `ResultArtifacts(ctx, executionID, limit, offset)`：轻量元数据。
- `db.ReconInventory(ctx, executionID, kind, limit, offset)`：以执行的 project、scope、assessment、owner、conversation 为隔离边界的库存。`ReconInventoryCounts` 返回真实库存计数。
- `db.ReconSources(ctx, executionID, limit, offset, now)`：该隔离边界内所有执行的来源，包含完整性、解析状态、过期状态和历史新增量。
- `db.ReconSourceRecords(ctx, sourceID, limit, offset)`：具体来源的原件位置，而不是只取库存第一次发现的位置。
- `registry.ReadRegion(ctx, executionID, evidence.Region{ArtifactID: id, Offset: offset, Length: limit})`：仅按登记 ID 和字节位置读取，每次复核完整 hash，单次最大 64 KiB。
- `registry.Assemble(ctx, executionID, inputRegion, outputRegion)`：原始输入与实际输出的最小有界文本，始终标记 `verification=unverified`。默认遮蔽常见认证字段；遮蔽不保证识别所有秘密，调用方不得记录证据正文到日志。

全量内容只保留在原件文件。业务层应使用上述有界读取，不要绕过注册器按工具报告的绝对路径使用普通文件读取。正式 finding 仍需现有独立验证门槛。

## 格式、幂等与限制

支持的核心格式：FOFA 声明 fields 的 JSON（fields 必须先于 results/data）和 CSV；subfinder text/JSONL；OneForAll CSV/JSONL；dnsx text/JSONL；httpx text/JSONL；naabu host:port text/JSONL；nmap XML；gau text/JSONL；katana text/JSONL；JSAPIscan URL/Method CSV 或结构化 JSONL；nuclei JSONL。nuclei 仅生成 candidate。人类日志、HTML、JSAPIscan manifest/preview 和未知格式明确标为 unsupported；不会从日志中猜 URL，或自动跟随 manifest 的文件路径。

默认原件登记上限 1 GiB，解析上限 64 MiB、单行/单记录 1 MiB、每个原件最多 10,000 个结构化记录，单事件最多 256 个原件，report 最多 1,000 个记录。全部限制可造成 partial；完整原件 hash 仍以流式方式计算。CSV/FOFA/XML 的一个结构化行/host 可能由标准解码器临时分配至解析字节上限，但不会落库为正文。

幂等键包含执行 ID、原件 hash、解析器版本、声明格式、工具、project/scope/assessment 和执行归属。跨执行的相同发现去重，但各来源仍保留实际新增数量和原件位置。来源首次登记后不可通过同一执行/同一 hash 再次宣称完整；超时始终是 partial。库存是历史发现集合，过期来源不会自动删库存；资产模块和后续扫描授权仍必须检查当前范围与来源新鲜度。

本模块采用严格 owner+conversation+project 绑定，无隐式全项目读取或管理员绕过。共享项目授权或 system 执行的身份映射应由主程序在可信上下文中处理，不能把 untrusted 输入直接传入 `WithAccess`。

通用 `exec`/命令执行工具须保留原始 `Execution.Tool`，并由执行服务根据真实 dispatch 设置 `Execution.ParserTool`（如 `httpx` 或 `subfinder`）。此身份不从日志/preview 猜测；数据库允许由空值补充一次，之后不可换解析器身份。未明确标识的通用执行结果标为 unsupported。
