# FastAPI 边界：精简检查流程

## 触发与前提

命中 FastAPI/Starlette 的 Depends/Security、挂载应用、HTTP/WS/流式/后台作业时读取。核对部署 FastAPI、Starlette、Pydantic 主版本、ASGI server、proxy 与路由挂载；源码锁文件不直接代表部署，解析器/默认转换按真实版本。继承用户排除项、对象和动作预算。

## 执行顺序

1. 从允许的流量/OpenAPI/源码映射 router、route、mount 和作业结果入口；`include_in_schema=False` 是文档控制，不是权限。父应用 middleware 与 mount 独立依赖分别核对，不假定挂载必然绕过中间件。
2. 建立 A 成功、B/未认证拒绝、无效对象负对照。记录依赖具体做令牌提取、签名/issuer/audience/expiry 验证、scope 或对象校验中的哪一步。
3. `OAuth2PasswordBearer`/`HTTPBearer` 提取凭据不等于认证；`Security` 提供 scope 信息也不自动替业务执行授权，`Depends` 可实现完整鉴权，不因名称判断缺陷。
4. 保持输入与对象固定，用缺凭据、无效凭据及授权测试身份比较最终业务效果；tenant header 和 owner 字段必须绑定可信身份。
5. 对 JSON/form/multipart、Pydantic union/extra/validator 只测已支持路径和无害单变量；字段接受/422 差异须追到服务消费和新增权限，不能假定字符串转 bool 的统一结果。
6. 比较 WS 每消息、SSE/Streaming 每资源、后台 job 创建/状态/结果的对象权限与身份生命周期；已允许合成任务不应凭可猜 job ID 向 B 开放。
7. proxy/header 信任候选须证明头实际到达、消费方式及业务差异；禁止大表单、磁盘阈值或阻塞事件循环测试。

## 反证、停止与修复

- 可测反例：使用 `Depends` 但完整验签和对象校验；隐藏路由照常拒绝 B；挂载子应用在父 middleware 内且还有独立鉴权；额外字段被忽略或仅进入非权限元数据。
- 文档可见、缺 `Security`、缺 Host/CORS 配置和静态依赖链均不能直接 confirmed。cookie CSRF 需浏览器实际状态变化，curl 不足以代替。
- 缺账号、作业可回滚条件、部署版本或流式客户端，阻断对应单元；预算到达、异常资源消耗、真实消息/非测试数据出现停止并保存未覆盖项。
- 修复应分清提取/认证/授权依赖，在最终操作绑定对象和 tenant，明确 mount/通道策略，输出使用受限模型；作业必须可信地保存并使用身份/租户上下文。
- 验收原反例、支持的内容类型/通道和合法 A 操作；按 `skills/pentest-verification/SKILL.md` 动态证明新增权限后才记录。

## 补充资料与来源

完整正文：根路径 `knowledge_base/Framework-Security/FastAPI-Security-Boundaries.md`，可直接读取。
原路径 `others/strix/strix/skills/frameworks/fastapi.md`，改编自 [Strix 007ed1a](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/frameworks/fastapi.md)，[Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。中文重写，修正 Depends/Security 与 mount 的无条件断言，不复制新 CVE/版本断言或阻塞探测。
官方核对：[安全依赖](https://fastapi.tiangolo.com/tutorial/security/first-steps/)、[OAuth2 scopes](https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/)、[Sub-applications](https://fastapi.tiangolo.com/advanced/sub-applications/)、[Middleware](https://www.starlette.io/middleware/)、[Pydantic migration](https://docs.pydantic.dev/latest/migration/)。
