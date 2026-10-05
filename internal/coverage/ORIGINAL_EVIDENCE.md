# 本地原件覆盖证据接入契约

本模块只读取已有本地原件，绝不执行 POC、Shell、Python 或 HTTP 请求。

## 必须接入的初始化

服务创建 resultPipeline 后，调用 `agentfinalizer.ConfigureCoverageOriginals(db, p.root)`。必须传入结果流水线实际使用的、来自服务配置的 spool 根目录。不得从事实字段、stdout、工具返回路径推导根目录。关闭数据库或测试清理时可传空字符串移除配置。

本次没有修改 app/result_pipeline.go 或 handler；这个初始化调用需要主流程接入。未配置时不会猜路径，也不会把 generic exec completed 行提升为 HTTP 证据。

## 读取和绑定

`database.CoverageOriginalBinding(project, conversation, assessment)` 从当前 conversations.owner_user_id、project_id 和 projects.scope_json 解析绑定；scope 哈希算法与结果流水线一致。缺少 owner、项目重绑定失败关闭。

`database.AssessmentHTTPExecutions(ctx, binding)` 只枚举同 owner/project/conversation/assessment/scope 的 completed、complete、非 timeout/capped 执行。候选执行不是证据；读不到、超限、解析失败均不能增加已验证执行数。

`coverage.VerifyHTTPOriginal(ctx, registry, binding, executionID, inputID, outputID)` 需要同一执行的独立 input 和 output/stdout 原件、完整状态、非零起止时间、输出字节数一致。通过 Registry 的安全目录、无链接、文件身份、大小、SHA-256 和读后不变检查，再复查元数据。返回不可由外部字段直接构造的 `HTTPObservation`。该对象只证明请求响应观测，不证明漏洞、安全性或任意风险测试结论。

终态检查会重新读取原件，不缓存旧的已验证结果。每次最多 2000 个候选执行、1000 个原件/执行（达到页边界即失败关闭），单原件 16MiB，总候选输入输出 128MiB。超限保留未完成状态和库存。

## 支持的原件格式

- 原生 `http-framework-test`：完整原始参数 JSON，以及唯一 Prepared Request / Response #1 / Meta #1 结构；明确 Method、URL、请求 Headers/Body、HTTP 状态行、至少一个响应头和头部终止空行。URL、method、可选 Host 和 wire request-target 精确校验。拒绝重定向、重复请求、下载代替输出、附加选项或 response_filter 等歧义。不会信任通用执行器自己声称的 ParserTool。
- `exec` / `execute` / `curl` 的 command：仅单次直接 `curl`、`/usr/bin/curl` 或 `/bin/curl` 调用，首选项必须是 `-q` 或 `--disable`（排除默认 curlrc 注入）。必须有 `-i` / `--include` 或 `-I` / `--head`，原始 stdout 含真实响应头。只接受受限明确选项及一个 URL；拒绝 Shell/Python 包装、echo、管道/重定向/命令替换、配置文件、--write-out、-L、多 URL、Host 覆盖、@文件输入。未使用 --path-as-is 的点段路径拒绝。CONNECT 代理握手不能冒充目标响应。
- read_file、事实写入、Python/Shell 脚本、模型自报状态、jsluice/jsapiscan 文本里出现的 HTTP 字样均不能获得 HTTPObservation。

## 事实如何引用

端点事实需要原始 `endpoint_url` 和明确的大写 `method`，以及 `execution_id` 或 `source_id` / evidence 中完整 execution:ID、source:ID 引用。所有 query 值、顺序、路径大小写、转义、协议和端口均保留在 HTTP 精确比较中；只归一化主机大小写、默认端口及空根路径。

合成来源 ID 为 `http-<output artifact ID>`；同一已验证输出的现有 recon_source ID 可以通过数据库全绑定和哈希关联作为别名。`source_id` 与 `execution_id` 同时给出必须均匹配。源事实若为 HTTP 工具，target 必须是精确 URL，并填写 method。

HTTP 原件仅支持 endpoint `risk-mapped` 配合 `covered` 的 `http-baseline` / `http-response` 单元；其他风险类别、negated 或 endpoint verified 不会因此通过。不得把已有业务/授权/注入风险单元替换成基线单元来完成评估。风险单元继承所引用端点的 URL/方法；若自己声明不同 URL/方法，则拒绝。

真实 HTTP 请求不自动生成事实、删除风险单元或降低总数。单次执行无论多个来源别名都只计一个 EvidenceExecutions。

## 库存与尚未支持事项

分组继续保留所有原件；新增 owner/scope 分区隔离，相同 URL/方法但不同 owner 或 scope 不会合并、不会相互处置。旧/不同分区保留为未解决项，不从分母移除。MappedGroups 是分组处置计数，绝不表示组内所有普通 query 参数值都已逐个测试。

jsluice 和历史 jsapiscan 可以计独立静态发现/分析来源，但不能单独支持 HTTP 风险。JS expanded 暂未新增自动放行：安全实现还需要将 source.js 的哈希绑定到同分区实际获取的 JS 原件，并校验完整解析 manifest、raw/export 数量与哈希；source_url 自报归属或静态 URL 命中不够。当前完整 jsluice 静态解析仍不能凭引用 alone 消除 JS 独立库存缺口。

本次未增加批量处置引用；也未支持任意风险的专门断言验证器。现有原始库存、未测范围和待分类范围全部保留。capped 为 true（包括某些仅预览缩减的完整 spill）、不支持的历史输出和大于读取上限的原件会保持保守未关联，不能据此声称全面完成。
