# PI 实验室：独立底层 Agent 试验

## 定位

在 CyberStrikeAI 内新增 `PI 实验室` 页面（`#pi-lab`），真正使用 `@earendil-works/pi-coding-agent` 的 Agent 会话执行推理和工具循环，不是 iframe、参考项目代理，也不是给现有 Eino Agent 换名字。

这是一版有意缩小工具权限的引擎试验，可比较模型在任务拆分、子 Agent 协作、HTTP 观察和报告归纳上的效果。它不是参考项目的完整渗透能力移植；不能用本版低影响 HTTP 工具的结果代表完整漏洞扫描覆盖率。

参考 `others/StrikeAgent_AtkBrain-Flash` 的架构思路，独立实现编排、事件和展示。参考项目采用 AGPL-3.0，当前项目采用 Apache-2.0，因此没有复制其源代码、提示词、页面或资源。PI SDK 为 MIT 许可依赖；具体依赖版本由独立 `package-lock.json` 锁定。

## 本次与原系统的边界

- 保持原 Eino 单/多 Agent、生产任务队列、MCP 工具、数据库结构、项目事实和漏洞入库流程不变。
- `/api/pi-lab/*` 是新增路由，使用原登录验证和 `agent:execute` 权限，但试验列表、详情、事件、取消只能访问本人记录，管理员也不自动跨属主读取。
- 模型只读复用所选 AI 通道。在提交时获取加锁快照，后续修改系统模型设置不会改变已运行的试验。
- API Key 只通过子进程 stdin 传递，不放到命令行、浏览器、会话文件或试验记录中；不继承服务进程的 API Key、`NODE_OPTIONS`、用户 PI 配置、扩展、技能和凭据。
- 每个试验一个 Node 子进程与独立工作目录。默认全局最多同时运行 **1 个试验**，内部默认并发 2 个子 Agent、最多 6 个子 Agent、900 秒、80 次 HTTP 请求。
- 取消只作用于该 PI 子进程；应用正常关闭会取消 PI 试验；异常重启后的运行中记录标记为 `interrupted`，不会自动重复请求目标。
- 默认关闭，页面仍可显示原因和查看历史。没有通过本次变更部署、重启或调用现有项目服务，也没有自动执行任何真实目标测试。

目录隔离不是操作系统级沙箱。模型和 HTTP 请求仍占用宿主资源；正式扩大工具集前，应增加容器/低权限执行身份和更完善的审批策略。

## 现有功能

1. 创建独立试验，填写标题、授权范围、任务要求、模型、并发数、总子 Agent 数和时限。
2. PI 协调 Agent 可以调用 `delegate_agents`，有界并行运行多个独立 PI 工作会话，然后读取摘要并汇总报告。由真实模型决定是否派发，界面不会伪造子 Agent。
3. 查看任务状态、父子 Agent 状态、路线图、脆弱面候选、观察证据、报告和增量事件时间线。
4. 手动取消、重新打开已保存试验、导出当前记录 JSON。
5. 明确区分 `completed`、`partial`、`failed`、`cancelled`、`interrupted`。缺少终止事件或报告、进程异常退出、无有效结果均不视为成功。

### 内置工具与证据含义

- `inspect_http`：只允许精确授权来源内、且已在原始任务文本中明确给出的完整 URL（来源根 URL 也可）的 `GET` / `HEAD`，限制请求数、并发、超时和响应读取大小；所有跳转都停止，启用 TLS 验证和 DNS/IP 检查。返回白名单响应头、状态、读取字节数和 SHA-256，不返回原始响应正文。
- `record_surface`：记录测试入口、观察内容和图节点。
- `record_finding`：记录 `hypothesis`（待验证假设）或 `observed`（已观察现象），不允许标为已确认漏洞；观察与漏洞证明是不同概念。
- `delegate_agents`：仅协调 Agent 可用，子 Agent 不可递归派发。

没有开启 PI 默认的 `bash/read/edit/write`，没有接入现有 Shell、扫描器、外部 MCP、C2、漏洞自动确认或自动提交。没有额外注入参考项目的方法论、技能包或自动利用能力。

授权范围填写完整 **origin**，例如 `https://example.com` 或 `https://lab.example.com:8443`。HTTP 与 HTTPS、不同端口、不同子域名分别授权；不接受路径、通配符和 URL 内的凭据。要检查具体路径，应将完整 URL 写在测试需求中，例如 `请观察 https://example.com/login`；模型不能通过生成任务文本或响应里的链接自行扩大 URL 清单。首版只开放公网目标，阻断私网、本机回环、链路本地、云元数据及其他保留地址，暂不适用于内网靶场。

本版有意不自动爬取页面、不向模型返回响应正文，也不提交表单。它可以验证 PI 的原生工具循环和协作流程，但还不能与现有系统的全工具渗透效果作等价比较。

## 以后启用（等当前任务结束后，按计划操作）

本次仅改本地源码并执行隔离测试。运行中的旧进程不会自动拥有新 API；不要为了看到入口而立即中断已有任务。

准备运行时需要 Node.js **22.19+**（建议 24 LTS）。当前独立锁定参考项目所用的 `@earendil-works/pi-coding-agent@1.0.4`；参考项目自身是未固定版本的 CLI 安装，本模块使用同源 SDK，不依赖其 CLI RPC 私有封装。在未来实际运行后端的主机上，于项目根目录执行：

```sh
npm --prefix runtimes/pi-lab ci --ignore-scripts --no-fund --no-audit
node runtimes/pi-lab/runner.mjs --check
```

`--check` 仅验证模块加载和接口，不调用模型，不访问目标。成功返回 `ready: true` 和实际 SDK 版本。

在下一次计划启动新版后端时，为该进程提供环境变量：

```sh
CYBERSTRIKE_PI_ENABLED=true
```

可选环境变量：

- `CYBERSTRIKE_PI_NODE`：Node 可执行文件路径，默认 `node`。
- `CYBERSTRIKE_PI_RUNNER`：runner 的绝对路径，默认由启动工作目录解析 `runtimes/pi-lab/runner.mjs`。
- `CYBERSTRIKE_PI_DATA_DIR`：独立数据目录，默认 `data/pi-lab`。建议使用服务账号专有目录；同一目录仅供一个后端进程使用。

不需要修改 `config.yaml`、全局 PI 配置或现有任务的模型通道。部署源码/二进制之外，还应保留 `runtimes/pi-lab` 的源码、依赖，以及新增静态资源；运行时不会自动执行 `npm install`。

首次试验建议使用自建测试站点，选择支持工具调用和流式输出的模型，明确勾选授权确认，并设置较小的并发和时限。OpenAI 兼容与 Claude 通道可用；空 base URL 使用对应官方默认地址。PI 的单次模型输出预算上限为 32768 tokens，不修改原通道配置。模型供应商仍可能收费。

## 独立数据和接口

默认记录位置：

```text
data/pi-lab/runs/<uuid>/run.json
                         events.ndjson
                         workspace/
```

`run.json` 保存属主、状态和展示投影，`events.ndjson` 保存带单调游标的事件；HTTP 返回值不含内部属主字段或运行凭据。内容来自目标和模型，可能包含业务敏感信息，应按证据文件保管。默认最多保留 1000 个试验，列表显示最近 100 个本人试验；达到上限时明确拒绝新建，由管理员在停止使用后离线归档，不自动删除证据。

每个试验上限为 2000 条事件、8 MiB 事件日志、2 MiB 状态快照、256 个节点、512 条边、128 条发现。达到存储/事件预算时停止运行并标明失败，保留已接收部分；这是可视化和存储保护，不是漏洞覆盖度判断。

接口：

- `GET /api/pi-lab/status`：默认开关、运行时就绪情况、工具和预算；不探测模型连通性。
- `GET /api/pi-lab/runs`：本人试验索引。
- `POST /api/pi-lab/runs`：授权确认、校验、创建并异步执行，返回 202。
- `GET /api/pi-lab/runs/:id`：详情和完整展示状态。
- `GET /api/pi-lab/runs/:id/events?after=0`：每页最多 100 条事件，返回 `cursor`、`has_more`。
- `POST /api/pi-lab/runs/:id/cancel`：幂等取消本人试验。

## 本地验证

```sh
go test ./internal/pilab
node --test web/static/js/pi-lab.test.cjs
npm --prefix runtimes/pi-lab test
node runtimes/pi-lab/runner.mjs --check
go test ./internal/handler ./internal/security ./internal/app -run 'TestPILab|TestEveryProtectedRouteHasCatalogPermission' -count=1
```

`internal/pilab` 包不依赖主数据库。安装可选 Node 依赖后，其真实 SDK 集成测试使用本机临时模拟模型服务，验证 Go → Node → 实际 PI SDK → 子 Agent → 图节点 → 报告 → Go 存储整条流程，不使用真实 API Key，也不请求测试目标。未安装运行时依赖时，该项明确跳过，其余纯 Go 测试仍可运行。

主项目 SQLite 测试需要可用 CGO 编译器。本机默认 GCC 16 输出与 Go CGO 不兼容时，可仅在测试进程中临时使用 Zig cc；不要修改持久 Go 环境，也不需要修改生产服务。

2026-10-08 本地验证记录：PI 1.0.4 自检和运行时 35 项离线测试通过；真实 OpenAI/Anthropic SDK 使用本机模拟接口验证，不使用真实模型；Go 独立模块及跨进程派发集成通过；HTTP/角色权限回归和 `go build ./...` 通过（SQLite 部分使用仅测试进程的 Zig cc）；纯 PI 模块并发竞争检测通过（本机 GCC）。前端全量离线测试通过，并使用临时本机静态夹具检查了浅色/深色布局、路线节点点击和事件展示，预览进程已关闭。未部署到项目服务器，未运行真实目标评估；实际渗透效果尚未验证。
