# IdP：管理面与目录配置权限证据

## 适用条件
- 已确认 Keycloak realm/client、Auth0 M2M grant、Authentik provider/flow或Okta/Ping管理资源。
- 或存在SCIM tenant/base path与提供的token/配置材料；公开discovery不足以触发全面测试。
- SRC先使用 `src-hunting`，本篇补产品管理资源，不重复OAuth/OIDC通用协议清单。
- 端口、非404、issuer字符串均需与实际产品/对象核对；缺身份只做获准静态审阅。

## 身份 → 对象 → 允许操作
- IdP是身份提供方；记录issuer、tenant/realm/environment、token audience与主体。
- 身份分end-user、service account、M2M client、directory provisioner与tenant admin。
- 对象分client/provider/application、user/group、mapper/claim、flow和SCIM资源。
- 允许操作分list/read、配置修改、secret read、目录provision、角色赋予与token issuance。
- scope/JWT role是声明；真正管理API返回与目标执行才证明effective权限。
- 管理员正常资源管理、provisioner正常目录写入、失陷token既有权限不独立计洞。
- tenant Admin仍应被限制于本tenant；跨tenant/平台管理需单独对照，不因Admin一概排除。

## 基线与未授权对照
1. 准备A/B受控tenant或同tenant两角色，配各自测试user/client/group。
2. A读A测试对象建立允许基线；A读B或低角色读高角色对象建立拒绝基线。
3. 固定endpoint、audience、realm与操作，只切身份或资源ID一项。
4. 记录对象归属和预期业务职责；公开目录按政策可能是合法共享，不猜应私密。
5. 分页仅一个测试对象/少量结果，避免全租户导出或批量user枚举。
6. JWT解码结果不能代替签名/issuer/audience验证或服务端接受结果。
7. 无第二主体、无测试资源、无管理读权则tentative/blocked，指出缺口。

## Keycloak 产品细化
- 分清realm role与 `realm-management` client role，service account不自动等于realm admin。
- `manage-users`/`manage-clients`等要结合fine-grained admin permission、版本和资源scope。
- 低角色可看到client列表与可读client secret分开核对，不全realm export取证。
- 用受控client/user的只读管理请求核effective权，管理角色名本身不是提权证明。
- mapper关联输入属性谁可改、输出claim谁消费、下游授权如何使用。
- `fullScopeAllowed`或group claim可见仅是候选，不能只凭JWT声明确认下游权限。
- user-attribute mapper若取可自改字段，需证明它被受信任consumer当授权信息使用。
- token exchange条件随版本/配置不同，不把返回victim sub直接等同真实会话接管。
- 禁真实user impersonation、管理员组改写、exportSecrets、长期token或offline持久化测试。

## Auth0、Authentik、Okta 与 Ping
- Auth0 M2M核Management API audience与client grant scopes，不以拿到access token判管理权。
- `read:clients`与 `read:client_keys`分开；只请求测试client必要字段，不列全tenant秘密。
- connection/action/rule配置中secret只做脱敏属性和权限映射，不导出可用值。
- Authentik将provider object permission与flow policy binding关联，公开API文档不是未授权。
- enrollment/recovery flow按政策可能允许匿名，需实际越过目标身份/tenant边界才确认。
- Okta token scope与用户admin角色/资源集共同核对，SSWS token不一概当全tenant控制。
- PingOne按environment与worker-app role核对，PingFederate运行面与admin API分开。
- client_id/issuer公开、允许callback或合法offline_access本身不是独立漏洞。
- 不因缺nonce、动态client注册或版本匹配自动HIGH/critical；继续遵守项目quality与排除。

## SCIM 产品细化
- SCIM是目录provision协议，先用允许的ServiceProviderConfig/schema确定实际支持功能。
- base path可能在URL中承载tenant，也可能靠token绑定；记录实际tenant约束。
- 对Users/Groups区分id、externalId、userName、member引用与对象owner。
- token职责可能就是同步全批准目录，能正常list/read/write不等于越权。
- filter返回多条数据可能符合表达式；OR合法语法不因扩大结果自动判注入。
- 分页count是返回预算，不是权限控制；跨tenant候选需B测试对象证据。
- group成员变化可能映射下游角色；静态group名“admin”不等于下游实际授权。
- default readonly不创建用户、不PATCH真实组、不停用/删账号，不触发真实provision。
- 另行批准写测试只用隔离测试目录/无特权组，独立回读和审计确认效果与恢复。

## 签发、读取与副作用
- token endpoint/登录会签发新credential，不自动包含在readonly管理元数据授权中。
- 不用真实用户冒充/换票证明权限，不生成长期credential和新管理员。
- GET可能查询/导出secret，操作是否无写副作用与数据是否获准读取分别判断。
- scope名称可见不代表secret可读，API可达也不代表该identity被授权。
- 请求cookies/token不得跨issuer、tenant域或redirect带到不获准目标。

## 目标侧证据与持久效果
- 保留脱敏管理请求、响应对象ID/owner、实际scope/角色来源与基线差分。
- 目标审计关联actor、tenant、资源、操作、时间和request ID，避免仅JWT截图。
- mapper/group候选需下游受控服务的授权对照；无法访问则明确“下游权限未验证”。
- 另有批准的写测试用独立会话回读，必要时核对异步同步结果与目标审计。
- 写返回200/202不保证保存或下游生效；记录最终状态及恢复结果。
- 未做写/签发/持久化明确未验证，不把可读目录写成账号接管。

## 可核验反例
- Keycloak service account按批准role只管理测试client，B client拒绝：正常分权。
- tenant Admin管理本tenant全部用户而其他tenant拒绝：正常tenant授权。
- Auth0 M2M可读client元信息而keys拒绝：不是client secret泄露。
- Authentik匿名公开flow只创建无特权自有账号：按政策可能合法。
- SCIM provisioner读批准目录并同步无特权组：本职能力，不独立提权。
- SCIM标准filter返回匹配的多个user且仍在tenant范围：正常查询，不是注入。
- token有group claim但下游拒绝高权限操作：声明不等于额外authority。

## 缺口、记录与敏感值
- 缺预期职责、第二主体、下游权限或目标审计时逐项列出，不固定判严重度。
- 401/403、invalid audience、wrong realm、timeout与空对象分别记录，不合并为安全。
- 起始状态含凭据来源/类型、正常角色、已失陷能力与测试授权限制。
- 记录issuer/tenant/object、允许操作、基线/未授权对照、target审计与新增能力。
- 记录采样数、反证、未做持久化/下游验证；一个成功读不代表域完成。
- user信息、client secret、recovery token、SCIM bearer脱敏，只留必要类型与受控标记。

## 工具边界
- 当前已注册 `http-framework-test`可做有限HTTP对照，核参数/依赖，关闭请求概览。
- 默认不follow_redirects；响应过滤/截断不是脱敏，不把真实secret留stdout。
- `exec`不代表IdP原生CLI已安装；缺能力blocked，禁止运行时安装和自动全租户导出。
- 不搬演示凭据免责、固定severity、持久化/DoS和无限扫描规则。

## 来源、改编与许可
- 改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。
- 作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
- 源：`others/Dark-Moon/conf/agents/sso-idp.md`，https://github.com/ASCIT31/Dark-Moon 。
- 快照 `cb0d9b8`（`cb0d9b83e745034c8bcff90daee9668b834d1508`），原GPLv3；本文GPL-3.0-only。
- 用户2026-10-01自述作者授权自有内容改编；第三方原许可保留，根LICENSE不变。
- 改编将全tenant导出/管理员组写入换成产品职责矩阵、最小读对照与下游待证条件。
- 官方：https://www.keycloak.org/docs/latest/server_admin/ ；https://auth0.com/docs/secure/tokens/access-tokens/management-api-access-tokens 。
- 官方：https://docs.goauthentik.io/ ；https://developer.okta.com/docs/guides/implement-oauth-for-okta/ 。
- 官方：https://apidocs.pingidentity.com/ ；https://www.rfc-editor.org/rfc/rfc7644 。
