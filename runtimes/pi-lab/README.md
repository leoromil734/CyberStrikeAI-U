# PI Node 运行时：正式平台模式与兼容探测模式

本目录提供隔离的 PI SDK 运行时。`mode:"platform"` 通过 Go 平台提供的角色、技能索引和工具桥参与正式工作流；省略 `mode` 或使用 `mode:"probe"` 保留原有独立探测行为。Node 只负责模型会话、真实并发分工和事件转换，平台绑定、工具权限、工作目录边界、生命周期及漏洞证据门禁由 Go 调用方负责。本目录没有服务、部署配置或真实目标探测脚本。代码为本项目独立实现；没有复制其他项目的 AGPL 实现。

## 安装与离线检查

需要 **Node.js >= 22.19.0**（建议 Node 24 LTS），与锁定的 SDK 和 HTTP 客户端版本要求一致。

在本目录执行：

```sh
npm ci --ignore-scripts --no-fund --no-audit
npm run check
npm test
```

无需全局安装。`--ignore-scripts` 已在测试环境验证可用，本运行时不使用剪贴板或图片处理功能。

从仓库根目录执行 `node runtimes/pi-lab/runner.mjs --check`，成功时仅输出一行：

```json
{"ready":true,"runtime":"pi-coding-agent","version":"1.0.4"}
```

`--check` 不读取 stdin，不创建会话文件，不请求模型或任何网络地址。失败返回非零退出码和一行 `ready:false` JSON。SDK 精确锁定 MIT 许可的 `@earendil-works/pi-coding-agent@1.0.4`，同 scope 的 PI 子包（含 MCP、codemode、telemetry 及 chord）同样精确锁定 1.0.4；全部传递依赖和完整性校验在 `package-lock.json`。旧 scope SDK 已移除。MCP/codemode 作为上游传递依赖安装，不代表在本运行时启用其发现或工具能力。

## 与 Go 调用方的协议

调用方为每次运行创建全新、独立的工作目录，将其作为子进程 `cwd`，并用绝对路径启动 `node <仓库>/runtimes/pi-lab/runner.mjs`。仅传一个 UTF-8 JSON 行，然后关闭 stdin（EOF）。模型 key、平台工具桥 token、角色/技能/工具说明和其他平台上下文只经 stdin 进入内存，不通过环境变量、命令行或文件传递。

### 兼容模式：`probe`（也是省略 mode 时的行为）

```json
{"run_id":"example-run","prompt":"观察 https://example.com/，区分事实和假设。","scope":["https://example.com"],"limits":{"max_parallel":2,"max_agents":6,"timeout_seconds":900,"max_requests":80},"model":{"provider":"openai","base_url":"https://model-provider.invalid/v1","api_key":"仅为占位符","id":"明确选择的模型ID","context_window":128000,"max_tokens":4096}}
```

此示例只说明协议；测试不会访问其中任何外部地址。`model.provider` 支持 `openai` 和 `claude`：

- `openai` 映射到 PI 的 `openai-completions`，调用兼容的 Chat Completions API。`base_url` 通常以 `/v1` 结尾，SDK 追加 `/chat/completions`。
- `claude` 映射到 PI 的 `anthropic` 提供方及 `anthropic-messages`。`base_url` 是 Anthropic SDK 基础地址，通常为 `https://api.anthropic.com`，SDK 追加 `/v1/messages?beta=true`。不要重复添加 `/v1`。
- 模型和非空 key 始终来自 stdin；不回退到环境变量或主机凭据。key 使用 `await ModelRuntime.setRuntimeApiKey`，不会被当作配置命令执行，即使以 `!` 开头。
- 模型端点属于调用方明确配置的服务，不是目标 HTTP scope。允许显式配置本机模型网关；SDK 请求限制在这个精确 origin，拒绝跳转，TLS 验证开启。模型配置必须由可信调用方提供。

输入上限 1 MiB，读取输入最多等候 30 秒；只接受单行 JSON。两个模式共用 `model` 和 NDJSON 输出协议。兼容模式省略 limits 字段时采用示例默认值；`max_parallel` 范围 1–8，`max_agents` 为 0–32（只计 child，协调器不占额度），`timeout_seconds` 为 1–3600，`max_requests` 为 0–1000。`context_window` 为 1024–2000000，`max_tokens` 为 1–32768 且不大于 context window。

### 正式模式：`platform`

在相同顶层输入上指定 `mode:"platform"`，`scope` 改为 **1–32 项明确授权范围字符串**（每项最多 4096 字符），可包含主机、IP、CIDR、带路径 URL 和排除说明。正式模式不构造 `ScopePolicy`，不以公网/精确 origin/原始 URL 白名单代替授权策略；它将完整授权边界写入所有会话提示词，实际工具和目录权限继承 Go 平台执行层。

正式模式 `limits`：`max_parallel` 默认 2，范围 1–8；`max_agents` 默认 6，范围 1–32；`timeout_seconds` 默认 900，范围 60–21600；`max_turns` 默认 **120**，范围 1–500；`max_tool_calls` 默认 **600**，范围 1–2000。轮次和工具预算由所有会话共享，工具调用包括分工与笔记工具。达到轮次/工具预算时，即使模型给出结束文本，也返回 `partial`；超过预算的工具不再执行。`max_requests` 仅用于 probe，不影响平台工具。

额外 `platform` 字段示意（实际发送时序列化为同一个 stdin JSON 行）：

```json
{
  "role_name": "渗透测试",
  "instructions": "由后端渲染的现有角色指令和共享执行契约",
  "worker_instructions": "由后端提供的工作会话交接要求",
  "project_id": "project-example",
  "conversation_id": "conversation-example",
  "workspace": "/backend/workspaces/project-example",
  "skills": [{"name":"pentest-agent-os","description":"共享执行与证据契约"}],
  "tools": [{"name":"load_skill","description":"通过平台逐步加载技能","input_schema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}}],
  "bridge": {"url":"http://127.0.0.1:49152/tools/call","token":"backend-generated-per-run-random-token"}
}
```

- `instructions` 只注入协调器；工作会话使用 Go 提供的完整 `worker_instructions`（`ComposeSystemPrompt(SubAgent)`、角色与范围），不会再叠加完整协调器指令。仅当 `worker_instructions` 为空时，为兼容旧调用方回退到 `instructions` 一次。运行时仍为两者追加工具桥、技能索引、预算和授权边界等共享约束。两者均限制 128000 字符。`workspace` 是后端工具的上下文标识，**不会成为 Node 的 cwd 或赋予 Node 文件权限**。project/conversation ID 必须为字符串，允许调用方显式传空值。
- 技能索引最多 256 项，仅提供名称与描述，不自动读取主机技能文件。所有会话先用平台 `load_skill` 加载 `pentest-agent-os`，再按角色路由用 `load_skill` / `read_skill_file` 渐进加载。平台未提供必要工具时应明确报告限制。
- `tools` 为 1–256 项平台 allowlist。每项以 PI `customTools` 注册，直接使用原始 object JSON Schema；已核实 PI 1.0.4 使用 `typebox/compile` 接受普通 JSON Schema，并测试嵌套约束、枚举、required、类型转换及本地 `$ref`。每项 schema 最多 65536 字符，不加载远程引用；编译失败直接结束为 partial，不回退到宽松参数。
- 工具名必须匹配 `[a-zA-Z0-9_-]{1,64}` 且唯一。`delegate_agents`、`record_surface`、`record_finding`、`inspect_http`、`codemode`、`tool_search` 和 `mcp__*` 为保留名称，不得覆盖。本机插件/MCP 自动发现仍关闭；正式模式不注册原生 `inspect_http`，也不开启任何 PI 内置 OS 工具。后端明确提供的 `exec`、`read_file`、`write_file` 等全部走工具桥。
- 协调器通过 `delegate_agents` 创建真实并发 PI 工作会话，传递具体目标、范围、证据要求及交付物，等待实际结果后汇总；后续交接可引用先前结果及平台保存的文件。工作会话没有 `delegate_agents`，只能执行交接目标。

### 本机工具桥

桥地址严格匹配 `http://127.0.0.1:<1–65535 的显式端口>/tools/call`，不接受 localhost、其他 IP/IPv6、缩写/整数/十六进制地址、userinfo、路径变体、查询、片段或重定向。调用方应使用随机临时端口和每次运行的随机凭据。请求只使用该 token，不使用用户会话 token：

```text
POST /tools/call
Authorization: Bearer <platform.bridge.token>
Content-Type: application/json
```

请求 JSON：`{"name":"exec","arguments":{"command":"..."},"agent_id":"worker-1"}`。成功 HTTP 响应约定：`{"content":[{"type":"text","text":"工具结果"}],"is_error":false,"execution_id":"可选的后端执行记录ID"}`。HTTP 级错误约定：`{"error":"错误说明"}`。`is_error:true` 正确映射到 PI 的 `isError:true`，保留模型可读错误但不把它标成成功。正式模式将普通工具参数错误（含 SDK 调用前校验）和成功 HTTP 响应中的平台执行错误作为警告，不永久污染运行状态：模型纠正参数或重新执行后，可正常得到运行时 `completed`。失败仍保留在 `tool_end.is_error:true`、`kind:"tool",status:"failed"` 图节点及最终报告的工具警告中；SDK 参数校验阶段尚未触达桥的失败也有图节点，`execution_id` 为空。运行时不会因此宣称错误已恢复。`is_error:false` 的正常异步 `running/pending` 返回仍不置 partial，运行时不解析工具文本判断任务最终完成。**Go 服务端既有覆盖、执行与证据门禁必须独立判定最终完整交付，不可省略，不能仅凭运行时 completed、退出码 0 或模型报告认定正式任务完成。** 即使 `record_vulnerability` 被平台门禁拒绝后对话正常结束，也只是运行时完成，绝不等于漏洞登记成功。预算耗尽、取消、模型故障、子会话失败、上下文压缩失败，以及桥连接、协议、认证及其他非 2xx HTTP 故障仍永久导致 partial；HTTP 故障由桥传输层分类，不从工具文本推断。probe 保持任何工具错误导致 partial 的原保守行为。错误响应不自动重试，避免重复执行。

工具桥使用独立 Undici `request` 和专用 dispatcher，既不受模型 fetch origin 限制误拦截，也不使用环境代理；拒绝全部 HTTP 跳转，不转发凭据。请求 JSON 最多 1 MiB，响应最多 8 MiB，响应头最多 16 KiB，连接最多等待 5 秒，其余读取受总运行预算及取消信号控制。桥请求并发不超过 `max_parallel`；取消会关闭活动请求并清除等待队列。

工具结果只作为 PI 的模型输入返回，不额外复制进事件。`tool_start/tool_end` 只写有界状态摘要；每个已返回的平台工具产生 `kind:"tool"` 的 `node` 与执行者 `edge`，其 `detail` 是短 JSON 字符串 `{"name":"exec","execution_id":"...","is_error":false}`，可供后端关联已有执行记录；未新增事件类型或顶层 metadata 字段。

`record_surface` 只写资产笔记；正式模式 `record_finding` 只写 `kind:"note",status:"hypothesis"` 的图节点，不发 `finding` 事件、不登记漏洞。正式 `record_vulnerability` 若由后端提供，就原样走平台工具桥并服从既有验证门禁。会话 `completed` 仅表示运行预算内正常结束，后端仍须独立检查授权和漏洞证据门禁。

桥地址/token 永不进入模型提示或工具定义；模型 key、桥 token、模型基础地址及桥地址的已知直接/URL 编码/Base64 形式会在输出脱敏，在正式模式的提示词、工具说明、schema 字符串和工具结果中也脱敏。完整平台对象、设置、会话、凭据不写本机磁盘；证据文件只能交由后端 workspace 工具落盘。

### 两种模式共用的输出

stdout 只含 `{type,agent_id,data}` 的 NDJSON，不含 console 日志、思考过程、原始模型错误或私密配置。事件类型与数据字段：

- `agent_start`: `{id,role,task,parent_id}`；第一个执行会话 ID 为 `coordinator`，子会话为 `worker-N`。
- `agent_end`: `{status,summary}`，status 可为 `completed`、`partial`、`failed`。
- `message`: `{text}`，仅已结束的文本消息，不输出逐 token 或思考内容。
- `tool_start` / `tool_end`: `{name,summary,is_error}`。
- `node`: `{id,kind,label,detail,status,url,parent_id}`，detail 为字符串。
- `edge`: `{id,source,target,label}`。
- `finding`: `{id,title,severity,status,url,evidence,remediation}`，severity 为 `info|low|medium|high|critical`，status **只允许 hypothesis / observed**。
- `report`: `{text}`，正常时为真实协调器最终文本；失败时明确声明没有有效最终报告，保留部分结果和限制说明。报告最多 24000 字符（包括截断标记）；所有序列化事件行在 UTF-8 下严格小于 96 KiB，必要时进一步缩短文本以适配 Go 读取上限。
- `error`: `{message}`，只输出经过控制的公共错误信息。
- `complete`: `{status:"completed"|"partial"}`，最后一个事件且只发一次。

退出码：完整完成为 0；模型失败、空最终响应、预算限制、取消或不完整结果为 1；部分无效输入为 2。调用方应同时检查最后的 `complete` 和退出码。`partial` 并不代表发现漏洞，也不代表所有任务成功。完全失败仍按约定发 `complete:partial`，配合 `error`、`agent_end:failed` 和非零退出码；没有扩展不存在的 `complete:failed` 枚举。

## 实际 SDK 接口与隔离

实现依据已安装 1.0.4 的声明文件和实现，并以真实 SDK 连接本机模拟模型验证：

- `createAgentSession({ modelRuntime, model, tools: string[], customTools, ... })`。新版使用 `modelRuntime`，不再向它传旧的 `authStorage/modelRegistry` 参数；`tools` 仍为名称数组。
- `ModelRuntime.create({ credentials: new InMemoryCredentialStore(), modelsPath: null, refreshOnCreate: false, allowModelNetwork: false })` 显式隔离凭据和模型目录。`modelsPath` 若省略会读取用户配置，所以必须传 `null`；对应模型缓存也在内存中。
- 使用 `registerNativeProvider(createProvider(...))` 为显式模型绑定 OpenAI Completions / Anthropic Messages 适配器，避免新版 OpenAI 默认转向 Responses；认证只使用 stdin key，无 OAuth、配置命令插值或环境凭据回退。`setRuntimeApiKey/removeRuntimeApiKey` 是异步接口，均等待完成。
- `SettingsManager.inMemory(...)`、`SessionManager.inMemory(cwd)` 保持设置和会话无文件持久化。
- 自行提供全内存 `ResourceLoader`（包括新版两个 prompt source 方法）和 `createExtensionRuntime()` 的空扩展集合。**不实例化 `DefaultResourceLoader`**，避免包、插件、MCP、技能及上下文文件发现；MCP 注册表始终为空。
- `noTools:'builtin'` 加显式 allowlist 和 `excludeTools:['mcp__*','codemode','tool_search']`；新版普通白名单可能保留延迟 MCP 工具，故额外检查 `getActiveToolNames()`、`getCallableToolNames()`、`getAllTools()` 三者均只有自定义工具。没有 PI 内置 bash/read/edit/write/ls/find/grep 或外部扩展入口；平台明确提供的同名工具也仅能经桥执行。
- 使用 `session.subscribe` 转换结束消息、工具生命周期事件；调用 `session.prompt(...,{expandPromptTemplates:false})`。
- SDK 的 `prompt()` 在模型返回错误时可能正常 resolve，因此必须检查最终 assistant 的 `stopReason`，而不是把 Promise resolve 当作成功。
- 包装每个会话公开的 `modelRuntime.streamSimple` 执行共享轮次计数、输出 token 上限及取消信号，再调用原始 SDK 方法。旧 `session.agent.streamFn` 已不再是有效拦截点，兼容模式真实 20 轮循环测试验证不会发出第 21 次网络请求；正式模式改为 stdin 指定的共享预算，真实测试已完成 22 次模型调用及 273 次本机桥工具调用。禁用 SDK 普通错误自动重试、提供方重试、安装遥测及技能命令；显式 `cacheWarming:'off'` 防止后台缓存预热请求。
- 正式模式通过受支持的 `SettingsManager.inMemory({compaction:{enabled:true,reserveTokens,keepRecentTokens}})` 开启 SDK 自动压缩；预留 token 为 `min(16384, floor(context_window/4))`，近期保留 token 为 `min(20000, floor(context_window/4))`。SDK 在工具循环的后续模型请求前检查阈值，并支持上下文溢出后的压缩恢复。摘要生成同样经过 `modelRuntime.streamSimple`，计入同一个共享 `max_turns` 预算、服从总取消和原模型输出上限，并保留 SDK 更小的摘要输出额度。摘要认证仍使用内存中 stdin key、同一受限模型 origin；会话及摘要不落盘，不启用插件或主机凭据。压缩失败/取消由运行时转成受控的 partial 原因，不输出 SDK 原始错误。压缩无法保证超大单条结果或过小模型窗口一定可用，后端仍宜保存大证据到 workspace 并返回摘要/引用。probe 保持自动压缩关闭。
- 所有会话使用 `session.abort()` / `session.dispose()` 清理。SIGINT、SIGTERM 和总超时同时取消模型流、所有子会话、排队任务和 HTTP 请求。Windows 的外部强制终止可能不给 JavaScript 信号处理器执行机会，Go 仍需处理进程异常退出。

运行时不写工作文件、凭据或会话日志，也不读取现有项目/用户的 PI auth、settings、skills、extensions、AGENTS 文件。V8 字符串无法保证物理内存清零；退出前释放引用，不能声称密码学级内存擦除。输出做已知 key、其 URL 编码/Base64 和私密模型基础地址的脱敏；不保证识别恶意任意变换过的秘密。

## 兼容 probe 模式的自定义工具与边界

本节只适用于省略 mode 或 `mode:"probe"`；其中的公网、原始 URL、GET/HEAD、响应哈希和固定 20 轮/256 工具约束不进入正式模式的提示或目标访问逻辑。

只有协调器可以通过实际 PI `delegate_agents({tasks:[{name,task}]})` 创建子会话。跨批次累计 child 数量并在 await 前预留额度，最多同时执行 `max_parallel` 个 worker；worker 只获得下面三个工具，不能递归派发。协调器等待实际子会话摘要后再调用模型汇总，也可直接单会话完成。未预置任何假发现或假执行结果。

- `inspect_http({url,method:'GET'|'HEAD'})`：精确 origin scope；此外只允许原始 scope 或原始用户 prompt 中明确出现的完整 URL。仅授权 origin 并不授权自动枚举新路径。模型生成的任务、HTTP 响应链接、重定向都不能扩大授权。
- `record_surface({label,url,detail,parent_id?})`：仅记录 scope 内资产，不发送请求；未观察到的 URL 为 hypothesis，parent 必须已存在。
- `record_finding({title,url,severity,status,evidence,remediation})`：禁止 confirmed；observed 必须有同 URL 的真实 HTTP 观察，并附上实际证据。模型文字不是独立漏洞验证器。

HTTP 防护：

- 仅 http/https，禁止 userinfo、反斜线和含空白的 URL；区分协议、主机、端口，不自动授权子域名。
- 阻断 loopback、link-local、私网、CGNAT、云元数据及其他保留地址；IPv6 只允许非保留全球单播范围，包括对 IPv4 映射和过渡地址的防绕过处理。当前版本不开放内网选项。
- 在连接器 DNS lookup 中验证全部解析结果，并把同一批已验证地址交给 socket，避免校验后重新解析造成的 DNS rebinding。遇到公私地址混合解析也拒绝。
- 不使用环境代理，TLS `rejectUnauthorized:true`，无关闭验证选项。所有 HTTP 跳转直接停止，包括同 origin；绝不跟随跨 origin 跳转。
- 全局 HTTP 并发不超过 `max_parallel`。共享 `max_requests` 只计算实际目标 HTTP 尝试（包括网络失败），模型请求另由共享 **20 轮**上限控制。
- 单次 HTTP 请求含读取过程最多 15 秒，连接最多 5 秒，响应头最多 16 KiB，生产传输层限制响应体 64 KiB，读取层也限制 64 KiB。超限可能被传输层直接拒绝；保留前缀时明确标记 truncated/hash_covers，结果为 partial。
- 只返回允许的响应头、状态、已读字节数和 SHA-256，不输出原始 body、Cookie 或 Authorization。压缩响应不自动解压，hash 覆盖收到的原始字节或明确标示的前缀。HTTP 状态与响应头只是事实，**不是漏洞确认**。

共享 20 轮模型调用（协调器与所有子会话合计）、最多 256 次自定义工具调用、总运行超时。达到请求/轮次/响应读取上限时报告 partial；child 额度不足时未派发部分明确报告 skipped。最终文本最多 24000 字符，会话摘要与字段也有限长。

这是应用级能力限制，**不是真正的 OS sandbox**。用户输入、供应链依赖和模型端点仍需可信；生产需要更强隔离时，应由调用方另行设置进程权限、网络出口和容器策略。本实现不修改现有运行服务或部署。

## 离线测试

`npm test` 使用 Node 原生 `node --test`，保留原有 44 个 probe/隔离回归测试并新增正式模式测试，不访问真实 API 或真实目标：

- 真实 SDK 自动压缩测试验证长工具循环触发摘要、随后模型收到摘要并继续执行、摘要请求占用共享轮次预算、压缩错误不泄露原始提供方详情、压缩中取消关闭连接且没有迟到事件、无磁盘写入及 probe 保持关闭。参数纠正后成功和普通后端执行错误可正常结束为运行时 completed，但保留失败事件、图节点及报告警告，最终必须经过 Go 交付门禁；正常异步等待不置 partial。真实 SDK 回归还验证桥 HTTP/认证/连接/协议错误即使随后恢复也仍为 partial，及 worker 参数纠正不污染协调器、worker 模型会话失败仍使整次运行 partial。
- 正式模式校验内网主机/IP/CIDR/路径/排除说明、协调器与 worker 完整指令互不重复、技能索引进入所有会话、worker 交接契约、命名/schema 约束及 NDJSON 字节上限。
- 真实 PI SDK 连接本机模拟模型和独立工具桥，验证授权 Bearer 请求、并发工具执行、通过平台 workspace 工具保存与共享交接结果、脱敏、执行记录图节点和无原始大结果事件；验证超过旧 20/256 上限仍可正常完成，以及达到新共享轮次/工具预算后必为 partial。
- 本机工具桥验证认证失败、301/302/307/308 拒绝跳转、任意主机/URL 变体拒绝、响应大小约束、应用错误映射、活动请求/读取/等待队列取消，以及真实 SDK 排队工作会话不再启动。正式模式命令行测试使用假主机配置与磁盘快照确认平台上下文和凭据不落盘、全局插件/MCP/凭据发现仍关闭。

- 注入受控 session/transport，验证 URL 白名单、路径授权、跨域跳转阻断、DNS 地址检查、预算原子性、HTTP 并发、超时、取消、无递归派发、发现证据状态和 NDJSON 协议。
- 本机真实 HTTP 连接覆盖 HEAD、带正文重定向、不消费正文时的清理、重复关闭、读取超时和响应大小限制；真实 PI SDK 同时验证这些请求能够返回 `tool_end`、报告及最终完成事件。测试通过程序参数将授权来源映射到本机夹具，不开放 stdin 的范围绕过入口。
- 本机临时 HTTP 服务模拟 OpenAI SSE 与 Anthropic SSE，**真实调用 PI SDK** 验证协调器派发、worker 工具调用、汇总、20 轮限制、401 不重试、空结果/失败判断及模型重定向拒绝。
- 用临时假主机配置（含不可解析的 models/MCP 配置、显式启用内置 MCP 的 settings）和会主动报错的假扩展验证隔离；快照比对磁盘文件，验证 key 不落盘。额外验证工具三重白名单、空 MCP 注册表、缓存预热关闭、初始化无 fetch 请求和依赖锁无旧 SDK。所有测试数据在本目录 `.test-tmp` 创建并清理。
- 子进程测试 SIGINT/SIGTERM 处理器；在 Windows 通过 IPC 触发相同 Node signal event，避免 `child.kill('SIGTERM')` 直接强杀导致处理器无法执行。测试会确认 SDK 请求连接被取消及最后输出 partial。

注入点仅是 JavaScript 测试函数参数。stdin 协议没有替换 transport、加载扩展或关闭 TLS 的入口；probe 也没有放开内网的旁路选项。platform 的内网、路径、执行和文件能力来自后端明确授权及其既有工具权限，而非 probe 限制的绕过。
