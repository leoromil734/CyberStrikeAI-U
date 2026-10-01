# Vault 路径能力工作流

仅在明确 Vault 地址、namespace/mount 与提供的 token、AppRole 对或 Kubernetes SA 绑定材料时触发；8200 端口、健康响应不够。SRC 先遵守 `src-hunting`，这里只加载本专题。

1. 确认授权路径、版本、KV 引擎版本与 token 使用次数；`lookup-self` 也可能消耗有限 token。将 entity、policy、namespace、mount 和对象路径对应到预期职责。
2. 只读检查允许查看的 policy/role 绑定，使用 `sys/capabilities-self` 查询有限测试路径；该 POST 是能力查询，不等于授予权限。无法读 policy 不代表 policy 不存在。
3. KV v2 区分 `metadata/<path>` 的 LIST/版本元数据与 `data/<path>` 的实际数据；建立本身份获准测试路径与另一个受控身份路径的对照，仅改变一项。
4. 如明确允许 secret 读取，读单个无业务秘密的测试标记；关联 request_id、路径、版本及脱敏审计，确认新增权限而非仅得到 200。受限于 readonly 时不登录签发新 token、不申请动态凭据/证书。
5. Transit decrypt、PKI role、数据库动态角色只做配置与能力映射；实际签发、解密需单独授权。正常读取自己授权秘密、有效 root token 正常管理功能不是独立漏洞。
6. 缺第二身份/测试路径/审计记 tentative 或 blocked；403 是该路径条件负结果，不代表所有路径安全。禁止解封、续租持久化、子令牌、递归秘密导出与使用秘密横向连接。

工具：核对当前 `http-framework-test`；默认关闭重定向和请求概览。`exec` 仅在已注册、平台兼容且已具备解析器时处理获准本地产物，禁止安装 Vault CLI。过滤/截断不是脱敏。

记录：起始权限、namespace/mount/KV版本、身份A/B、允许/拒绝路径、capabilities、实际操作、目标侧证据引用、新增能力、反证、采样量、未验证签发/持久化和敏感值处理。

完整知识：[Vault-Path-Authority](../../../knowledge_base/Infra-Control-Plane/Vault-Path-Authority.md)。
改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
来源：`others/Dark-Moon/conf/agents/hashicorp-vault.md`，提交 `cb0d9b8`（完整哈希见主入口），原 GPLv3；本文 GPL-3.0-only。用户 2026-10-01 自述作者并授权自有内容改编；第三方许可不变，不调整根 LICENSE。
官方参考：https://developer.hashicorp.com/vault/docs/concepts/policies ；https://developer.hashicorp.com/vault/api-docs/system/capabilities-self 。
