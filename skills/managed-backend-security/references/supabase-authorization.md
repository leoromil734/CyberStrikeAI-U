# Supabase 授权：精简检查流程

## 触发与前提

命中 Supabase 项目、Storage/RPC/Realtime/Functions 时读取。将 project ref、自定义域、环境、实际请求、SDK/PostgREST/数据库与部署策略对齐；托管平台内部版本无法获知时标 unverified。继承用户排除项，只使用已授权项目、A/B 账号与已知合成 row/object/channel，禁止全表/通配列表/递归分页。

## 执行顺序

1. 分清 legacy anon/service_role JWT key 与 publishable/secret key，再分清用户 JWT；`apikey` 标识项目/组件，不直接建立用户所有权，公开 publishable/anon key 不是漏洞。
2. 建立“对象 × SELECT/INSERT/UPDATE/DELETE/签名/订阅 × 身份 × tenant × REST/GraphQL/RPC/Storage/Realtime/Functions”矩阵，只测真实存在且允许的入口。
3. 用 A 拥有的标记对象成功、B/无用户 JWT 拒绝、无效对象负对照；固定 project key、对象、请求，仅换一个变量。检查最终执行角色与用户上下文，不能仅凭初始化 key 判断。
4. 核对 RLS 表/视图/关系与各操作的 USING/WITH CHECK、列权限及 owner/tenant 更新前后约束。RLS 开启或关闭均需业务意图与线上效果支撑。
5. RPC 核对 EXECUTE grants、函数 owner、SECURITY INVOKER/DEFINER、search_path、RLS/FORCE RLS 与实际调用角色；DEFINER 不是无条件绕过。以同一合成 foreign ID 对照业务校验。
6. Functions 分清平台 verify_jwt 与 handler 的认证/对象权限；关闭平台检查但正确验 webhook/用户身份可安全。高权限 client 必须绑定实际请求身份，公开 key 通过平台不等于登录。
7. Storage 分开读取/列举/上传/更新/删除/签名；签名 URL 是持有者能力，预期转发本身非越权。Realtime 区分 Postgres Changes 与 broadcast/presence，测试房间订阅只发送合成事件。
8. 每次允许写入须回查与清理，异步事件须停止订阅；读取只取少量标记字段，不通过 count/通配过滤绘制真实数据集。

## 反证、停止与修复

- 可测反例：仅 public key 获取公开内容；DEFINER 函数有严格 caller/tenant 校验且拒绝 B；verify_jwt=false 但 handler 验证可信 webhook；签名 URL 到期拒绝且签发受权限限制。
- 空列表、403、RLS 配置、key 字符串、introspection 与静态高权限 client 均不充分；有效 secret 的泄漏只在许可内验证最小额外能力，不批量读敏感表。
- 缺第二身份、规则/版本、已知对象、签发或写入许可标对应 blocked；未知项目、真实数据、配额告警、外部消息或预算耗尽立即停止相关路径。
- 修复限制 SQL grants、逐操作 RLS/列与 tenant，函数固定安全 search_path 并显式授权，Functions 使用最小权限，Storage/Realtime 独立校验；key 撤销及缓存失效按实际服务复测。
- 仅目标侧动态新增权限通过 `skills/pentest-verification/SKILL.md` 后 confirmed；保留排除项、基线、输出与清理，未复测不宣称修复有效。

## 补充资料与来源

完整正文：根路径 `knowledge_base/Managed-Backend-Security/Supabase-Authorization.md`，直接文件读取。
原路径 `others/strix/strix/skills/technologies/supabase.md`，改编自 [Strix 007ed1a](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/technologies/supabase.md)，[Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。中文重写，修正 DEFINER/RLS 泛化、取消批量提取与无条件版本断言。
官方核对：[API keys](https://supabase.com/docs/guides/api/api-keys)、[RLS](https://supabase.com/docs/guides/database/postgres/row-level-security)、[Functions auth](https://supabase.com/docs/guides/functions/auth)、[Storage access](https://supabase.com/docs/guides/storage/security/access-control)、[Realtime authorization](https://supabase.com/docs/guides/realtime/authorization)、[PostgreSQL RLS](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)。
