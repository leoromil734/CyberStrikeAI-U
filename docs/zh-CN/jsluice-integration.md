# jsluice 本地静态分析与机读原件契约

## 当前默认

`tools/jsluice.yaml` 启用，命令为 `/usr/local/bin/csai-jsluice`，对应 `scripts/recon/jsluice_runner.py`。系统需另外安装 BishopFox 原始 `jsluice` 并放入受控 PATH；本次代码改动不代表完成部署或运行时重载。

`tools/jsapiscan.yaml` 保留、默认停用；只有显式启用才恢复在线兼容调用，不自动回退。旧原件仍可离线读入。

流程：katana/gau 等发现范围内 JS URL → 按授权下载保存源码 → `jsluice(mode=urls, file=本地文件, source_url=真实来源URL)` → 对同批全部源码实际 grep/rg 复核 → 独立基线及风险验证。jsluice 封装不联网、不执行 JS；source_url 仅是元数据，不能用首页地址代替 JS 来源。

## 核实的上游 CLI

已查阅 BishopFox/jsluice 的 `cmd/jsluice/main.go`、`urls.go`、`secrets.go`：

- URL 模式使用 `jsluice urls --include-source -- <本地快照文件>`。
- 秘密模式使用 `jsluice secrets -- <本地快照文件>`。
- 输出原生一行一条 JSON；`-j` 是 raw-input，`-p` 是秘密模式 patterns 文件，均不是 JSON/pretty 输出开关。
- 上游本身可以接收 HTTP URL；本项目封装故意拒绝 URL 文件参数，不向上游传 source_url，也不开放任意 additional_args。
- 上游部分错误只写 stderr 而退出码为0，因此任何非空 stderr 均将本轮标为 partial，供人工检查。

## 托管布局与证据

服务端注入 `CSAI_EXECUTION_ID`（规范 UUID）和 `CSAI_ARTIFACT_DIR`（当前 executions/<id> 目录）。运行器独占创建：

`$CSAI_ARTIFACT_DIR/jsluice/execution-<id>/`

其中保留：

- `source.js`：实际分析的本地文件快照。
- `raw.jsonl`：上游完整原始输出，可能含秘密，只能按私有证据权限读取。
- `stderr.log`：独立诊断原件。
- `urls.jsonl` 或 `secrets.jsonl`：离线导出，不作为网络响应证据。
- `manifest.json`：schema=`csai.jsluice.v1`、tool、execution_id、mode、source_js/source_sha256、各固定文件 SHA-256/字节数、完整性与阻断原因。

归一化每行保留 source_js、source_sha256、source_file、raw_line 和 candidate_only/verification；URL 还保留 method、url/relativeURL、参数名及 EXPR 占位。相对 URL 不自动按 JS 目录解析，避免捏造运行时 baseURL。库存 RawURL/RawPath/Method 保存原始路径与方法；来源 URL/hash 可由该记录引用的机读原件行读取，不新增数据库列。

秘密导出只保留种类和来源；秘密值/context 留在 raw.jsonl。解析器只生成 tentative 候选，不生成正式漏洞，也不会从静态 URL 字符串生成“已观察”主机/服务资产。即便授权范围匹配，静态候选仍保持 candidate_only。

单文件≤32MiB；输出监测上限64MiB；导出每行≤1MiB、最多100000条；默认分析120秒（1–600秒）。达到限制、超时、缺依赖、无清单、非法 JSON、stderr 错误或 hash 变化均不能宣称完成。`complete` 仅表示有界分析/导出完成，`coverage_complete` 始终 false，不表示运行时攻击面完整。

后端根据受信 reduction 根及 project/conversation/execution 绑定推导目录，不读 stdout 的任意 manifest/work_dir 路径；注册与读取继续复核 owner/scope/assessment、hash、symlink/hardlink 和固定文件名。再次注册同路径必须匹配已登记 hash。缺少 source.js 的有效清单项或无法核实其真实原件时，不导入归一化候选；行内声称的来源 hash 不能替代源码原件。

## 旧 jsapiscan 兼容

优先读取 `$CSAI_ARTIFACT_DIR/jsapiscan/execution-<id>/manifest.json` 与 `work/**/*.csv`。没有 workspace 执行目录时才回退 `/var/lib/jsapiscan/runs/execution-<id>/`。这是修正“运行器在 workspace 写原件、应用只读系统目录”造成的缺原件/partial，不放宽任意路径读取。

清单只能下调完整性，CSV 才形成库存；stdout 预览不形成库存。CSV遍历错误、symlink、超过200文件边界会留下 partial。历史执行不会因修改代码自动重新处理，需要由服务端按原执行绑定安排离线重导入。

## Nmap / Nuclei 协调契约

应用现在优先识别当前 `CSAI_ARTIFACT_DIR` 中的固定独立机读原件：

- Nmap：`nmap.xml`，上游参数 `-oX <绝对托管目录>/nmap.xml`，格式 `xml`。
- Nuclei：`nuclei.jsonl`，上游参数 `-jsonl-export <绝对托管目录>/nuclei.jsonl`，格式 `jsonl`。

执行器/安装工作流必须实际展开由服务注入的目录，不能把 `$CSAI_ARTIFACT_DIR` 当成不展开的字面参数。文件出现后应用只解析该原件，stdout/stderr 合并文本保留为日志，不当成机读源。不存在固定文件时保留原有显式登记入口：自定义文件必须位于同执行托管根，并用 `register_result_artifact` 登记相对路径和真实格式；不根据 stdout 给出的路径读取。

显式用户输出选择优先：`xml_output=""`、`json_output=false` 或用户自己的 `-oX/-oA/-oN/-json-export/-jsonl-export` 不能被默认覆盖。独立机读副本的自动创建须由执行层仅在没有显式输出选择时完成；该执行层协调不在本次结果解析修改范围内。

stdout 兼容：实际参数明确 `xml_output="-"` 或 `-oX -` 才声明 XML；Nuclei 实际 json_output/jsonl=true 或原生 `-jsonl/-j` 才声明 JSONL。文件导出参数不是 stdout 格式。混合 stdout 输出（例如 `-oN -`）、重复输出选择不声明 XML。没有记录实际输出参数的历史调用不按当前 YAML 默认猜格式，保留 partial/unsupported。当前执行器合并 stdout/stderr，因此仅修改默认 stdout 参数仍可能混入诊断；独立原件是优先方案。

Nmap XML 解析还要求单一 nmaprun 根节点与完整闭合，拒绝根外非空日志、重复根、嵌套 host 等异常结构。尾部损坏时可以保留此前有效记录，但来源只能标为 partial，不能宣称完整。

## 离线回归

- `python -m unittest scripts.recon.test_jsluice_runner -v`：mock 上游子进程且禁止 socket，不运行扫描器。
- `go test ./internal/recon ./internal/projectprompt ./internal/agents ./internal/skillpackage`。
- `go test internal/app/jsluice_result_format.go internal/app/jsluice_result_format_test.go`：纯格式判定测试，不引入 app 包的数据库/C2 依赖。
- 集成环境运行 `go test ./internal/app -run 'Test(JSLuice|LegacyJSWorkspace|JSMissingWorkspace|IndependentMachineOriginal|MachineResultFormat|JSManifest)'` 以及 `go test ./internal/security -run TestJSLuiceBundledAdapterOfflineContract`。

Windows 本地 go-sqlite3/GCC 对象解析问题可能阻断集成测试；关闭 CGO 也无法构建使用 sqlite3 扩展类型的数据库包。需要父流程在隔离环境验证集成，不把编译失败报告成测试通过。
