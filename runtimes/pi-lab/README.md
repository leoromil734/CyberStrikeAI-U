# 独立 PI Lab Node 运行时

这是可选的 PI SDK 试验运行时，与 Go/Eino 的现有任务、工具、配置、技能及会话持久化完全分离。本目录没有服务、部署配置或真实目标探测脚本。代码为本项目独立实现；没有复制其他项目的 AGPL 实现。

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

调用方为每次运行创建全新、独立的工作目录，将其作为子进程 `cwd`，并用绝对路径启动 `node <仓库>/runtimes/pi-lab/runner.mjs`。仅传一个 UTF-8 JSON 行，然后关闭 stdin（EOF）。不通过环境变量、命令行或文件传 API key。

```json
{"run_id":"example-run","prompt":"观察 https://example.com/，区分事实和假设。","scope":["https://example.com"],"limits":{"max_parallel":2,"max_agents":6,"timeout_seconds":900,"max_requests":80},"model":{"provider":"openai","base_url":"https://model-provider.invalid/v1","api_key":"仅为占位符","id":"明确选择的模型ID","context_window":128000,"max_tokens":4096}}
```

此示例只说明协议；测试不会访问其中任何外部地址。`model.provider` 支持 `openai` 和 `claude`：

- `openai` 映射到 PI 的 `openai-completions`，调用兼容的 Chat Completions API。`base_url` 通常以 `/v1` 结尾，SDK 追加 `/chat/completions`。
- `claude` 映射到 PI 的 `anthropic` 提供方及 `anthropic-messages`。`base_url` 是 Anthropic SDK 基础地址，通常为 `https://api.anthropic.com`，SDK 追加 `/v1/messages?beta=true`。不要重复添加 `/v1`。
- 模型和非空 key 始终来自 stdin；不回退到环境变量或主机凭据。key 使用 `await ModelRuntime.setRuntimeApiKey`，不会被当作配置命令执行，即使以 `!` 开头。
- 模型端点属于调用方明确配置的服务，不是目标 HTTP scope。允许显式配置本机模型网关；SDK 请求限制在这个精确 origin，拒绝跳转，TLS 验证开启。模型配置必须由可信调用方提供。

输入上限 1 MiB，读取输入最多等候 30 秒；只接受单行 JSON。省略 limits 字段时采用示例默认值。`max_parallel` 范围 1–8，`max_agents` 为 0–32（只计 child，协调器不占额度），`timeout_seconds` 为 1–3600，`max_requests` 为 0–1000。`context_window` 为 1024–2000000，`max_tokens` 为 1–32768 且不大于 context window。

stdout 只含 `{type,agent_id,data}` 的 NDJSON，不含 console 日志、思考过程、原始模型错误或私密配置。事件类型与数据字段：

- `agent_start`: `{id,role,task,parent_id}`；第一个执行会话 ID 为 `coordinator`，子会话为 `worker-N`。
- `agent_end`: `{status,summary}`，status 可为 `completed`、`partial`、`failed`。
- `message`: `{text}`，仅已结束的文本消息，不输出逐 token 或思考内容。
- `tool_start` / `tool_end`: `{name,summary,is_error}`。
- `node`: `{id,kind,label,detail,status,url,parent_id}`，detail 为字符串。
- `edge`: `{id,source,target,label}`。
- `finding`: `{id,title,severity,status,url,evidence,remediation}`，severity 为 `info|low|medium|high|critical`，status **只允许 hypothesis / observed**。
- `report`: `{text}`，正常时为真实协调器最终文本；失败时明确声明没有有效最终报告，保留部分结果和限制说明。
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
- `noTools:'builtin'` 加显式 allowlist 和 `excludeTools:['mcp__*','codemode','tool_search']`；新版普通白名单可能保留延迟 MCP 工具，故额外检查 `getActiveToolNames()`、`getCallableToolNames()`、`getAllTools()` 三者均只有自定义工具。没有 bash/read/edit/write/ls/find/grep 或外部扩展入口。
- 使用 `session.subscribe` 转换结束消息、工具生命周期事件；调用 `session.prompt(...,{expandPromptTemplates:false})`。
- SDK 的 `prompt()` 在模型返回错误时可能正常 resolve，因此必须检查最终 assistant 的 `stopReason`，而不是把 Promise resolve 当作成功。
- 包装每个会话公开的 `modelRuntime.streamSimple` 执行共享轮次计数、输出 token 上限及取消信号，再调用原始 SDK 方法。旧 `session.agent.streamFn` 已不再是有效拦截点，真实 20 轮循环测试验证不会发出第 21 次网络请求。禁用 SDK 自动重试、提供方重试、自动上下文压缩、安装遥测及技能命令；显式 `cacheWarming:'off'` 防止后台缓存预热请求。
- 所有会话使用 `session.abort()` / `session.dispose()` 清理。SIGINT、SIGTERM 和总超时同时取消模型流、所有子会话、排队任务和 HTTP 请求。Windows 的外部强制终止可能不给 JavaScript 信号处理器执行机会，Go 仍需处理进程异常退出。

运行时不写工作文件、凭据或会话日志，也不读取现有项目/用户的 PI auth、settings、skills、extensions、AGENTS 文件。V8 字符串无法保证物理内存清零；退出前释放引用，不能声称密码学级内存擦除。输出做已知 key、其 URL 编码/Base64 和私密模型基础地址的脱敏；不保证识别恶意任意变换过的秘密。

## 自定义工具与边界

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

`npm test` 使用 Node 原生 `node --test`，不访问真实 API 或真实目标：

- 注入受控 session/transport，验证 URL 白名单、路径授权、跨域跳转阻断、DNS 地址检查、预算原子性、HTTP 并发、超时、取消、无递归派发、发现证据状态和 NDJSON 协议。
- 本机临时 HTTP 服务模拟 OpenAI SSE 与 Anthropic SSE，**真实调用 PI SDK** 验证协调器派发、worker 工具调用、汇总、20 轮限制、401 不重试、空结果/失败判断及模型重定向拒绝。
- 用临时假主机配置（含不可解析的 models/MCP 配置、显式启用内置 MCP 的 settings）和会主动报错的假扩展验证隔离；快照比对磁盘文件，验证 key 不落盘。额外验证工具三重白名单、空 MCP 注册表、缓存预热关闭、初始化无 fetch 请求和依赖锁无旧 SDK。所有测试数据在本目录 `.test-tmp` 创建并清理。
- 子进程测试 SIGINT/SIGTERM 处理器；在 Windows 通过 IPC 触发相同 Node signal event，避免 `child.kill('SIGTERM')` 直接强杀导致处理器无法执行。测试会确认 SDK 请求连接被取消及最后输出 partial。

注入点仅是 JavaScript 测试函数参数，stdin 协议没有替换 transport、开放内网、加载扩展或关闭 TLS 的配置入口。
