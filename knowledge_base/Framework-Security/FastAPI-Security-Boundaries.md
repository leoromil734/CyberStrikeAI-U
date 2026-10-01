# FastAPI 安全边界：依赖、挂载应用与异步操作

## 1. 触发与范围

适用于 FastAPI/Starlette 的认证依赖、router/mount、HTTP/WS/SSE/后台作业权限候选。
核心区分令牌提取、身份验证、scope 与对象/动作授权，不用框架名或函数名替代实际控制。
SRC 先通过 `skills/src-hunting/SKILL.md` 定界，再按本场景切换框架技能，不常驻叠载。
继承用户环境、对象、动作与通道排除项；子应用/外部任务地址被发现不代表可测试。
仅用授权 A/B 身份和少量合成对象，不批量下载作业结果、文件或用户数据。
创建作业、发事件、上传、状态变更与代理头实验都按许可，禁止生产阻塞/资源耗尽验证。

## 2. 真实版本与部署

FastAPI、Starlette、Pydantic、ASGI server、认证/JWT 库分别记录真实部署版本。
锁文件/本地源码与部署构建应对齐，Starlette 不能从 FastAPI 品牌自动推断版本。
确认 Pydantic v1/v2、validators、union、extra 与 strict 设置，类型转换以实际运行行为为准。
列出 Uvicorn/Gunicorn、front proxy、TrustedHost/ProxyHeaders/session 与挂载顺序。
API 文档、源码依赖和线上实际路径三者可能不同；文档 securitySchemes 不证明验签。
请求 parser、form/multipart 限制和主机 URL 处理按实际分支与上游文档核对。
不复制来源中的新 CVE、默认转换或特定补丁断言；适用性无法确认时标 unverified。
对于托管平台无法取得内部版本的部分，保留可观察行为与版本缺口，不虚构版本。

## 3. 基线与对象操作矩阵

选 A 所有的非公开合成对象/任务，内容带唯一无敏感标记，保存合法成功请求。
保存 B/未认证拒绝和无效 ID 负对照，明确租户、owner、角色和业务允许动作。
矩阵按 identity × object × tenant × read/write/result/subscribe × route/channel 记录。
固定部署、对象、方法、正文和解析类型，每次仅改变身份、对象或入口一项。
状态码、最终 URL、Content-Type、必要字段与真实状态变化一起保存；200/422 不独立证明权限。
需排除凭据过期、router 前缀、代理重写、环境差异和测试对象不存在造成的假差分。
缺账号 B/角色只影响对应跨身份单元；用户排除项、未测通道和预算单独记账。

## 4. 依赖生命周期与认证

沿 app/router/route 的依赖图追踪输入提取、token decode、验签、用户加载、scope 与对象检查。
`OAuth2PasswordBearer` 返回 token 字符串，不直接证明其签名、issuer/audience 或业务身份有效。
`HTTPBearer` 提取 bearer 结构也不等价认证；“头存在”与“用户可信”分开记录。
`Security` 可传递 scope 需求，但是否检查由依赖实现决定；`Depends` 可实现完整鉴权。
因此缺 `Security` 或改用 `Depends` 不能直接报 scope 绕过，要读真实校验并动态比较。
对签名、算法、issuer、audience、expiry 和撤销/用户状态按业务要求检查，使用授权测试凭据。
token、session cookie、代理注入身份分别核对，不能用其中安全一路推定其他路径安全。
tenant header/路径与 userId 请求字段必须绑定可信 identity/member relation，不可信地照抄会产生候选。
对象加载与权限依赖可能使用不同参数/规范化结果，需记录最终服务消费的 ID 与身份。
依赖缓存是具体请求内行为之一，不能从名称推定跨用户缓存泄漏；共享可变状态需实际反例。

## 5. Router、mount 与替代入口

`include_in_schema=False` 隐藏文档，不限制调用；仅在允许流量/源码已有线索时验证线上入口。
APIRouter 前缀、version path、普通 route、mounted 子应用分别核对有效依赖和 middleware。
父应用 middleware 可能包裹 mount，但父 router 的依赖不自动成为子应用的 route 依赖。
不能笼统宣称“挂载绕过全局 middleware”；必须证明真实 stack、缺控制与目标效果。
同业务 admin/static/metrics mount 需明确公开意图，health/doc 可见本身不是漏洞。
HTTP/GraphQL/WS 不同入口对同对象应按具体业务规则比较，不要求它们响应完全相同。
缺入口动态可达性时，静态缺依赖仅 tentative，不能把源码链直接写 confirmed。

## 6. 输入与返回数据

对目标支持的 JSON/form/multipart 单独比较，不要求每一路都接受所有内容类型。
extra、union、Annotated 与自定义 validator 以最终模型值/服务消费结果为准。
无害字符串/布尔/嵌套字段单变量可检查转换，不能假设所有模型都把空值或字符串统一转换。
接受额外字段只有被用来改变 owner/tenant/role 或其他安全相关效果才可能形成漏洞。
返回 ORM 实体/字典与 response_model 的具体路径需要观察；模型声明不代替最终字段最小化。
文件名/下载 ID/导出参数要绑定对象归属，不请求真实文件或探测未授权目录。
解析失败、500、schema 暴露或不同 422 消息均非新增权限，保存为线索而非漏洞。
表单大小、spool 阈值、线程/事件循环阻塞只检查配置与实现，不在在线目标做压力实验。

## 7. WebSocket、流式与后台任务

WS 分开校验握手身份、Origin、join/subscription、每消息对象操作及身份过期行为。
握手成功不证明可执行敏感动作，HTTP 403 也不能反证 WS 消费路径。
SSE/StreamingResponse 的单个对象、租户与后续事件绑定必须持续保持，仅读取少量合成事件。
后台任务分别检查创建、参数存储、执行上下文、取消/状态与结果读取，job ID 不是授权凭据。
使用经许可的可回滚测试任务，确认 B 不能读取 A 的合成结果；不触发生产导出/通知。
执行时是否重新校验 membership/revocation 取决于明确业务规则，避免擅自将所有异步时差报错。
proxy 头影响 request.url/身份/IP 的候选需证明头真实进入及最终业务效果，错误 URL 拼接不是充分证据。
cookie CSRF/Origin 需授权浏览器实验与真实状态变化；curl 不证明浏览器附带 cookie 的语义。

## 8. 误报、反证与可测反例

反例一：`Depends` 内完整验签、scope 和对象授权，B 实际被拒绝，缺 `Security` 不是问题。
反例二：隐藏路由仍受同一 service 控制；公开 OpenAPI 无非公开能力，不独立成漏洞。
反例三：mount 被父 middleware 包裹且有自身对象校验，子应用存在不等于鉴权绕过。
反例四：extra 字段接受但不进入权限/业务写入，实际状态未变，不能报新增权限。
反证必须说明控制位置、时序和覆盖路径，安全 sibling 或某内容类型拒绝不覆盖其他路径。
静态链、配置弱项、token 提取、版本命中仅 tentative；实际目标新增权限闭环才 confirmed。

## 9. blocked、停止与证据

缺版本、第二身份、合成对象、stream 客户端或任务许可时标对应 blocked，不宣布整体安全。
预算耗尽、配额/负载异常、真实数据出现、外部通知或清理不可靠时停止相应操作。
请求记录包括可信 principal、依赖链、最终对象 ID、基线、差分、业务效果和未覆盖/排除项。
`http-framework-test` 用于已授权 HTTP 对照；已安装可信客户端按许可用于 WS，不能自动安装或跑陌生项目。
用实际可用事实工具保存 tentative/negated/blocked 与 Do-Not-Repeat；漏洞记录仅用于动态闭环。
遵循 `skills/pentest-verification/SKILL.md`，真实请求/输出必须能说明攻击者起始权限和新增能力。

## 10. 修复与验收

分清 token 提取、身份验证、scope 与对象权限依赖，在最终操作绑定可信用户和 tenant。
为 mount/WS/任务设置等价业务规则，后台保存可信上下文，结果读取重新核对调用者。
限制输入/输出字段、明确代理信任与 cookie CSRF；配置改动本身不证明目标恢复安全。
验收原反例、已支持内容类型/替代通道和合法 A 流程，未执行修复复测标“未验收”。

## 11. 来源与改编

原路径 `others/strix/strix/skills/frameworks/fastapi.md`，Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`。
[固定版本原文](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/frameworks/fastapi.md)；原作 [Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。
本篇中文重写，修正 Depends/Security 和 mount 的泛化，新增异步对象边界、动态门禁与合成数据；不沿用新 CVE 断言或在线阻塞探测。
官方核对：[安全依赖](https://fastapi.tiangolo.com/tutorial/security/first-steps/)、[scopes](https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/)、[Sub-applications](https://fastapi.tiangolo.com/advanced/sub-applications/)、[Middleware](https://www.starlette.io/middleware/)、[Pydantic migration](https://docs.pydantic.dev/latest/migration/)。
入口 `skills/framework-security-testing/SKILL.md`；短流程 `skills/framework-security-testing/references/fastapi-boundaries.md`。可直接读取，不依赖知识服务。
