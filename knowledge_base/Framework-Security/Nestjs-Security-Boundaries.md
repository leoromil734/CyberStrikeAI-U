# NestJS 安全边界：守卫、验证与多通道业务权限

## 1. 触发场景与范围

适用于已确认 NestJS 的 Guard/Reflector/Pipe、REST/GraphQL/WS/RPC 等价业务操作候选。
核心增量是装饰器与上下文组合后的有效策略、最终输入消费和跨 transport 的权限一致性。
SRC 起点先由 `skills/src-hunting/SKILL.md` 定界，再按具体场景切换框架技能，不常驻叠载。
继承用户全部排除项，地址可见、broker 开放、Swagger 列出方法均不自动产生测试授权。
使用授权 A/B 身份、合成对象和测试房间，限制请求数；禁止批量抓取、发真实消息和触发生产队列。
写入敏感字段、订阅、RPC/事件发送需单独许可；服务端名称含 internal 不证明其安全或授权。

## 2. 真实版本与配置

对齐部署 NestJS、Express/Fastify adapter、GraphQL/WS/microservice 包与实际构建。
记录 class-validator、class-transformer、其他 schema 库和全局注册方式，锁文件与线上必须对齐。
Express 的 query parser 与 Fastify 的 schema/validator 均按部署配置验证，不假定嵌套输入解析。
若使用 Standard Schema 等新接口，先核对已安装版本支持以及实际 Pipe/serializer 注册。
区分 app 全局 Guard/Pipe、controller、method、gateway 与 hybrid application 的继承设置。
WebSocket 记录实际 subprotocol、握手认证和消息格式；版本文档描述不代替实际流量。
无法获取真实版本/有效配置时标 unverified；不复制来源中的新特性或迁移结论为事实。
Swagger DTO 和 securityScheme 是文档证据，不能证明请求一定执行对应控制。

## 3. 基线和权限矩阵

用 A 的私有合成对象成功请求描述业务规则，明确 tenant、owner、角色和允许动作。
建立 B/未认证拒绝基线和无效对象负对照；固定请求方法、对象、正文与部署。
矩阵按 identity × tenant × object × action × HTTP/resolver/WS/RPC 分开记录。
认证成功、可建立连接、可调用公开 health 与可执行敏感动作是不同单元。
一次只改变身份、对象或 transport；跨通道形状差异必须映射到同一业务参数。
记录响应字段、目标侧状态变化或合成事件，不把返回 true、200 或 ACK 直接当新增权限。
缺角色/第二身份只阻断对应单元，保留用户排除项与未测通道。

## 4. 有效 Guard 和 metadata

沿全局→controller→method 的实际执行链列出 Guard、读取的 metadata 与默认分支。
核对 decorator 设置的 key 与 Reflector 读取 key 是否相同，override/merge 是否符合业务预期。
`@Public()`、权限组合 decorator 和版本化 route 可能改变策略，但必须检查最终有效 metadata。
方法没有局部 `@UseGuards` 可能仍受全局/类级 Guard 或 service 校验，不能据缺失直接报错。
`@Roles()` 只是 metadata，需控制消费；Passport strategy 的认证 principal 不自动带对象权限。
Guard 使用 ExecutionContext 时分别确定 HTTP/WS/RPC principal 的来源和对象参数位置。
未知 context 默认 allow 是候选；只有真实可达且产生未授权效果才形成漏洞。
Guard 检查 query id 而 service 使用 body/path id 时，记录转换前后值与实际消费，单变量验证。
tenant、role、userId 需从可信认证/成员关系得到，不能只复制客户端字段。
service 作为最终统一对象/动作授权层可能是有效反证，应核对其时序和所有已测调用路径。

## 5. Pipe、DTO 与输入生命周期

记录 middleware、Guard、interceptor、Pipe 与 service 各阶段看到的输入形状。
测试 extra 字段只在合成对象加入无害标记，观察它是否被剥离、是否被更早组件使用。
`whitelist` 静默删除而非拒绝不自动成漏洞；被删除字段未影响业务就是重要负对照。
嵌套对象/数组要查实际实例化、子字段约束与 each 校验，不能只根据 `@ValidateNested` 名称判断。
interface/type 在运行时可缺元数据；是否产生风险仍取决于最终字段消费与授权。
transform、implicit conversion 和条件/分组校验按真实选项观察；不假定所有字符串都转为布尔值。
`@IsArray` 与元素约束是不同事实，必要时一项元素做无害类型变化，不用巨型数组。
schema decorator 只有配合实际执行的验证组件才生效，serializer 也要观察最终响应。
缺 ParseInt/UUID Pipe、额外字段接受或 DTO 声明不独立证明注入/越权，通用候选另交对应技能。

## 6. 多通道和异步对象操作

HTTP 全局注册不自动保证 WS/RPC 继承；以实际 app/gateway/hybrid 初始化与目标行为确认。
WebSocket 分别查 connection、join、subscribe、publish 和每消息对象校验，握手仅是第一步。
连接时用户身份可能过期或撤销，是否重验按业务规则；仅记录已允许的合成事件。
RPC/EventPattern 若网络可达，仍需 transport 和动作授权；禁止自行向生产 broker 注入消息。
GraphQL resolver、字段级数据与 subscription 各有入口，查询保护不反证变更/订阅保护。
共享 service 的正确校验能收敛通道差异，但必须取得真实路径和拒绝输出。
缓存/请求上下文泄漏用 A/B 合成标记低频对照；singleton provider 本身不是泄漏证据。
`@Global()` 允许注入 provider 属于模块设计，不是外部 principal 获得调用权限。
后台任务需要可信保存身份/tenant，创建和结果读取均限定对象；触发外部副作用前停止。

## 7. 输出与缓存

`@Exclude` 或 DTO 声明不能保证所有响应走 ClassSerializerInterceptor/对应 serializer。
比较实际 plain object/entity、嵌套关系与普通/管理员 serialization groups 的允许字段。
只读取少量测试标记；密码字段名、内部 ID 或元数据是否敏感需业务规则支撑。
CacheInterceptor/custom cache 要核对身份/tenant key 与失效，公开响应共享不自动有风险。
相同响应长度、ETag 或缺 `Vary` 不能独立证明跨用户，需要 B 得到 A 私有标记。

## 8. 误报与可测反例

反例一：method 没局部 Guard，但全局 Guard 与 service 都拒绝 B 的 foreign ID。
反例二：多余字段被剥离且更早组件未使用，业务状态也不变，不能报 mass assignment。
反例三：WS 成功连接，但 join/publish 都校验 tenant；HTTP 与 WS 权限不同尚未产生越权。
反例四：模块 provider 可注入，但无攻击者入口，模块可见性不是新增权限。
有效反证须具备具体控制位置、消费前时序、覆盖路径和实际拒绝；安全 sibling 不能反证全部。
静态 metadata 差异、宽配置、错误/ACK 和文档安全标记仅支持 tentative 或限定 negated。
confirmed 需目标侧动态证明独立边界与新增权限，遵循 `skills/pentest-verification/SKILL.md`。

## 9. blocked、停止、修复与验收

缺真实版本、transport 身份、已知测试对象、消息许可或可用可信客户端时标对应 blocked。
达到预算、出现配额/负载异常、非测试数据、真实通知或无法回滚时停止对应操作。
使用已注册 `http-framework-test` 比较 HTTP；`exec` 仅用于批准的可信已安装客户端，不自动装依赖。
保存实际请求/输出、上下文提取、消费字段、差分、反证、清理与 Do-Not-Repeat。
修复应明确各 context 的可信 principal，未知 context 默认拒绝，最终 service 绑定对象/tenant/action。
核对 decorator key/合成规则并统一验证、序列化、缓存隔离；模块 scoping 修改不是授权替代品。
验收原最小反例、同业务兄弟入口/通道及 A/B 合法流程，未执行复测标“未验收”。
事实状态按工具实际启用情况保存，仅动态闭环条目使用 `record_vulnerability`。

## 10. 来源与改编

原路径 `others/strix/strix/skills/frameworks/nestjs.md`，来自 Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`。
[固定版本原文](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/frameworks/nestjs.md)；原作 [Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。
本篇中文重写，增加宿主动态门禁、对象/动作/通道对照，修正局部 Guard、类型转换与模块可见性泛化。
官方核对：[Guards](https://docs.nestjs.com/guards)、[Execution context](https://docs.nestjs.com/fundamentals/execution-context)、[Validation](https://docs.nestjs.com/techniques/validation)、[Hybrid application](https://docs.nestjs.com/faq/hybrid-application)、[WS guards](https://docs.nestjs.com/websockets/guards)。
入口 `skills/framework-security-testing/SKILL.md`；短流程 `skills/framework-security-testing/references/nestjs-boundaries.md`。无需知识服务。
