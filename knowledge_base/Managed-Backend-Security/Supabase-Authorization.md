# Supabase 授权边界：项目凭据、数据库与多入口差分

## 1. 触发与范围

适用于已授权 Supabase 项目的 RLS/RPC、REST/GraphQL、Storage、Realtime 和 Edge Functions 候选。
核心增量是区分项目 key、可信用户与实际执行角色，并按对象/操作/入口定位最终授权引擎。
SRC 先由 `skills/src-hunting/SKILL.md` 定界，再切换托管后端技能，不常驻叠载。
用户排除的 project、环境、表、bucket、账号和动作继续排除；公开第三方 ref 不产生授权。
只用 A/B 授权测试身份、已知合成 row/object/channel 与少量标记字段，不批量抽取真实记录。
写入、签名、角色变化、订阅/发布与 key 撤销/rotation 需单独许可；不自动安装 SDK 或部署策略。

## 2. 真实版本与部署依据

对齐 project ref、自定义域、实际请求、环境、数据库 schema 和 SDK/Functions 部署版本。
可取得时记录 Postgres/PostgREST/pg_graphql/Realtime/Auth 版本；托管内部未知部分标 unverified。
本地 migrations/RLS/Functions 源码需关联线上发布，不从仓库文件存在推断实际保护生效。
记录暴露 schema、表/视图、RPC grants、bucket public/private 与实际支持的 key 格式。
API key/签名 key 的 migration、verify_jwt 和 JWKS cache 行为按项目配置、当前文档与目标证据核对。
不复制来源中新的平台版本/弃用/默认行为断言，旧 key 与新 key 并存需独立验证。
文档中的接口路径仅作线索，实际调用使用已观察授权流量，不探测其他项目或源站。

## 3. 凭据与用户身份

legacy `anon`/`service_role` JWT key 与 `sb_publishable_`/`sb_secret_` opaque key 分类方式不同。
opaque key 不能通过 JWT decode 确认角色；类型需结合项目设置和官方说明，敏感值脱敏。
publishable/anon 项目凭据设计上可以公开，出现于客户端 bundle 不自动是漏洞。
`apikey` 标识应用/项目组件，用户 JWT 通常通过 Authorization 表达用户身份，两者分开记录。
项目 key 通过某平台检查不证明已登录，合法用户 JWT 也不自动证明对象/tenant 允许。
实际 client session/Authorization 可改变执行用户上下文，不能仅凭初始化 service key 推断执行角色。
secret/service_role 候选在许可内只验证最小额外能力，不能批量读敏感表或将密钥全文写报告。
服务权限泄漏要区分未认证攻击者获得了什么与合法服务身份本来允许什么，证明独立边界。
新 key 建立不证明旧 key 撤销，撤销与客户端限制的实际效果需按服务分别复测。

## 4. 基线和授权矩阵

为 A 创建/选择已允许的私有合成 row、对象与 channel，带唯一无敏感标记。
保存 A 成功、B/无用户 JWT 拒绝、无效对象负对照，注明 tenant 和各动作的业务规则。
矩阵按 object × SELECT/INSERT/UPDATE/DELETE/list/sign/subscribe × principal × tenant × entrypoint。
入口分别列 REST、GraphQL、RPC、Storage、Postgres Changes、broadcast/presence、Functions。
固定 project key、对象、请求形状和部署，单次只换用户、对象、入口之一。
记录状态、Content-Type、必要标记、真实状态回查与目标执行上下文，不只记录 200/空列表。
不使用 select=*、全表 count、通配过滤和递归分页来绘制真实数据集，限制已知测试对象。
缺第二身份只阻断相关单元；缺管理员身份不允许自行提权补齐。

## 5. RLS 与对象/操作权限

核对表级 RLS、生效角色、SQL grants、列权限、schema exposure 与相关视图/函数路径。
RLS 开启不保证每个操作安全；RLS 关闭也须业务预期和线上新增能力证据，不能直接报配置漏洞。
SELECT/UPDATE/DELETE 的 USING 与 INSERT/UPDATE 的 WITH CHECK 分别对应旧行/新行条件。
更新 owner/tenant 要核对新旧对象都满足约束，不能仅验证更新前行属于当前用户。
auth.uid()/JWT claims 与客户端 ownerId/tenantId 分清来源，成员关系还需可信证明。
视图执行安全属性、表 owner、BYPASSRLS、FORCE ROW LEVEL SECURITY 和有效角色需实际分析。
列权限/字段更新是独立约束；读取安全不能反证 owner/role 字段写入安全。
关系嵌入/GraphQL nested node 比较已知对象同一身份，不做深度大查询或真实关系导出。
空列表、缺 table 权限、无效 filter 或不存在对象可能都返回无数据，需有所有者成功基线。

## 6. RPC 与高权限代理

`SECURITY DEFINER` 以函数 owner 执行，但是否绕过 RLS 取决于 owner 权限、表 ownership/FORCE RLS 等。
不能无条件宣称 DEFINER 绕过；核对 EXECUTE grants、函数 owner、search_path 与实际调用角色。
函数内部 caller/tenant/object 检查可以形成有效反证，业务参数中的 userId 不能取代可信 caller。
search_path 是否可被不可信对象影响是候选，静态弱项必须有真实可达性与新增权限。
以相同合成 foreign ID 对 A/B、无用户 JWT 比较最小 RPC 请求，不调用批量导出/admin 生产函数。
Edge Functions 的平台 verify_jwt 和 handler 身份/对象授权是不同控制，逐项记录。
verify_jwt=false 可由严格 webhook/secret 验证补足；配置关闭不自动意味着公开敏感操作。
高权限 client 在 handler 内应先验证用户并绑定对象/tenant，公开 key 通过平台不等价用户身份。
签名、issuer/audience/expiry 与 JWKS cache 的验证按实际 SDK/custom validator 路径核对。
不自行 rotation 或制造签名 key 状态，受控验收缺条件时标 blocked。

## 7. Storage 与签名能力

分别检查已知测试路径的 read/list/upload/update/delete/sign，不以读取权限推定写权限。
public bucket 预期公开内容不是漏洞，公开敏感合成对象需有业务保密依据。
Storage policy 路径、bucket_id、owner/tenant 与实际对象消费需一致，编码差分仅用许可对象。
签名 URL 本来是持有者能力；B 持有有效 URL 后下载不自动是越权。
应证明 B 能未授权签发 A 私有对象、超出承诺作用域/期限或凭据被非预期泄漏。
已有可转发 URL、到期正常拒绝和签发端有效校验是重要反证，不能强行要求账户绑定。
写入许可时用唯一合成对象，回查存在/内容，再仅清理本次创建的对象；无法清理即停止。

## 8. Realtime 与跨入口差分

Postgres Changes 与 broadcast/presence 使用不同上下文/策略，不能由一个通道安全推定另一个。
连接成功、channel 名可猜或 ACK 不证明越权订阅；需 B 收到 A 的私有合成事件。
测试房间绑定 user/tenant/membership，发布与订阅分别记录，结束及时退出连接。
REST 拒绝而 GraphQL/RPC/Functions 返回同一私有标记，才支持实际跨入口授权差异。
缓存/旧 subscription/session 状态可能污染比较，先对齐会话与部署再做单变量对照。
不能以时间/长度/count 差异推定大量真实对象，存在性候选也需受控业务规则与稳定反例。

## 9. 误报、blocked 与停止条件

反例一：只有 public key，能读预期公开内容而不能读 A 私有测试行，不构成权限增量。
反例二：DEFINER RPC 显式校验 caller/tenant，B 被拒绝，函数属性本身不是漏洞。
反例三：verify_jwt=false，但可信 webhook 验证在高权限操作前生效且无 bypass。
反例四：签名 URL 依预期可转发，但签发受权限限制、路径不可替换且到期拒绝。
静态链、配置弱项、key 字符串、introspection 和单次 403 均不能直接 confirmed。
有效反证须说明具体控制、时序、覆盖入口/操作与目标拒绝，安全 sibling 不外推。
缺第二身份、live policy/版本、合成对象、写入/签名/事件许可时标对应 blocked。
预算耗尽、配额/负载异常、未知项目、真实数据/外部消息或无法清理时停止对应路径。
保存原始最小请求/输出、起始权限、新增能力、反证、清理、排除项与 Do-Not-Repeat。
按 `skills/pentest-verification/SKILL.md` 完成动态闭环才 confirmed，事实与漏洞工具按实际注册使用。

## 10. 修复与验收

收紧 SQL grants/列权限和逐操作 RLS，绑定可信 user/tenant，限制 RPC owner/EXECUTE/search_path。
Functions 使用最小权限，Storage/Realtime 独立授权，密钥轮换/撤销覆盖实际仍接受的旧凭据。
缓存/JWKS/既有 URL/历史对象状态要按明确产品承诺单独验收，不推定全部即时失效。
重放原最小反例、同业务替代入口和合法 owner 流程，未执行复测标“未验收”。

## 11. 来源与改编

原路径 `others/strix/strix/skills/technologies/supabase.md`，Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`。
[固定版本原文](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/technologies/supabase.md)；原作 [Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。
本篇中文重写，修正 DEFINER/RLS 与签名 URL 泛化，加入真实版本、受控数据、用户排除项与动态新增权限门禁。
官方核对：[API keys](https://supabase.com/docs/guides/api/api-keys)、[RLS](https://supabase.com/docs/guides/database/postgres/row-level-security)、[Functions auth](https://supabase.com/docs/guides/functions/auth)、[Storage](https://supabase.com/docs/guides/storage/security/access-control)、[Realtime](https://supabase.com/docs/guides/realtime/authorization)、[Postgres RLS](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)。
入口 `skills/managed-backend-security/SKILL.md`；短流程 `skills/managed-backend-security/references/supabase-authorization.md`。无需知识服务，可直接读取。
