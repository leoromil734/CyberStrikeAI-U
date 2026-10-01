# IdP 管理与 SCIM 资源工作流

仅在确切 Keycloak realm/client、Auth0 M2M grant、Authentik provider/flow、Okta/Ping管理资源或SCIM tenant/token出现时触发。公开discovery、端口和非404只提供线索；SRC先使用 `src-hunting`。

1. 将issuer/tenant/realm、audience、token主体、管理scope/角色、目标资源与职责关联；解码JWT只是假设，服务端验证结果才是权限证据。
2. Keycloak区分realm role、realm-management client role、service account和fine-grained admin permission；查看一个受控client/user/mapper，不将manage-users等角色名视为漏洞。
3. Auth0核对M2M的Management API audience与grant；Authentik核对provider、flow policy binding和object permission；Okta/Ping区分token scope、主体role与环境限制。
4. SCIM以ServiceProviderConfig/schema确认实际支持能力，对照tenant路径、Users/Groups归属和scope；filter返回多条正常结果不自动当注入。
5. 两个受控身份/对象先允许基线再仅换tenant/object；默认只读和分页采样。写入仅另行批准测试资源，目标侧回读与审计验证持久效果；不改管理员组、不冒充真实用户、不创建长期token。
6. 正常租户Admin管理、已授权SCIM provisioning、公开client_id、合法offline_access和多scope声明均不是独立漏洞。缺下游权限/持久化证据时说明缺口，不机械判critical。

工具：仓库启用定义 `http-framework-test`，调用前核对当前会话注册及参数/依赖、禁止带token跨域跳转、关闭请求概览并脱敏。`exec`不代表IdP专用CLI可用，禁运行时安装、全租户导出、批量reset和真实账户修改。

记录：issuer/tenant、主体/凭据类型、实际角色与资源、允许操作、身份/对象对照、请求与审计、新增权限、反证、采样量、未做写入/签发/下游验证。

完整知识：[IdP-Management-Authority](../../../knowledge_base/Authentication-Bypass/IdP-Management-Authority.md)。
改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
来源：`others/Dark-Moon/conf/agents/sso-idp.md`，提交 `cb0d9b8`，原GPLv3；本文GPL-3.0-only。用户2026-10-01自述作者授权自有内容改编；第三方许可保留，不改根LICENSE。
官方参考：https://www.keycloak.org/docs/latest/server_admin/ ；https://auth0.com/docs/secure/tokens/access-tokens/management-api-access-tokens ；https://www.rfc-editor.org/rfc/rfc7644 。
