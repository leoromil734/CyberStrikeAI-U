# Vault：路径与新增权限证据

## 适用条件
- 已确认 Vault 产品、地址、版本及授权 namespace/mount，而非仅看 8200 端口或健康响应。
- 存在提供的 token、AppRole 材料、Kubernetes 服务账户绑定或获准离线配置。
- SRC/赏金先使用 `src-hunting`；本篇仅补充产品对象，不覆盖其低价值排除及报告规则。
- 目标是证明身份获得正常职责之外的路径能力，而不是统计读取了多少秘密。

## 身份 → 对象 → 允许操作
- 身份记录 token 类型、entity、policy、namespace、认证 mount 和凭据来源；原值不进报告。
- token 的 `ttl`、`num_uses`、renewable、orphan 是上下文，不自动构成漏洞。
- 对象记录完整 mount 与逻辑路径；同名路径在不同 namespace 中不是同一个对象。
- KV v1 的值路径与 KV v2 的 `data/<path>`、`metadata/<path>` 分开映射。
- KV v2 metadata 可列名称/版本，不意味着 data 可读；LIST 返回名称也不等于值泄露。
- policy 的 read/list/create/update/delete/sudo 分别对应操作；不能把通配符一概判危。
- AppRole 将 role_id/secret_id 条件与最终 policy 关联；拿到 role_id 不代表可以登录。
- Kubernetes auth 将 SA 名、namespace、JWT audience/issuer 与 Vault role 绑定关联。
- Transit 将 key、encrypt/decrypt/rewrap 权限分开；能 encrypt 不等于能 decrypt。
- PKI 将 role、允许域、签发用途与身份职责关联；数据库引擎将 role 与数据库授权关联。

## 基线与未授权对照
1. 先定义两个受控身份 A/B 与两个无业务秘密的测试路径，不猜生产秘密名称。
2. 用 A 对 A 路径建立允许基线；用 B 或匿名对相同路径建立预期拒绝基线。
3. 固定对象切身份，或固定身份切对象；每次只改变一个变量。
4. 请求中固定 namespace、mount、版本与其他头，防止实际上请求了另一租户。
5. `auth/token/lookup-self` 仅在权限与 token 次数允许时使用；有限 token 可能被请求消耗。
6. `sys/capabilities-self` 用有限路径查询能力；该 POST 不创建权限，但仍会消耗请求预算。
7. 能力结果是授权计算证据，不代替真实数据读取、签发或持久效果。
8. 无 policy 查看权时保留缺口，不能写成“未配置 policy”。
9. KV 读取仅在授权允许时验证一个受控标记，并记录实际返回版本。
10. 相同 token 正常读取获准 secret 是合法基线，不能独立计洞。

## 产品专项核对
- AppRole：比较角色绑定条件、secret_id 使用约束和最终 policy，不枚举所有 role。
- SA 绑定：通配配置是候选；验证是否真允许非预期 SA，需明确测试身份与登录授权。
- 认证登录会产生 token；只有 readonly 授权时只检查配置，不自动执行 AppRole/SA 登录。
- KV v2：分别核对 list metadata、read data 和指定版本，避免用旧版本内容冒充最新值。
- Transit：先读允许的 key 配置；解密只用自建测试密文并另行获准，不解密业务数据。
- PKI：查看 role 限制与 capability；正常获准域签发不是冒充证据。
- 数据库动态凭据：`creds/<role>` 的 GET 可能创建数据库用户与 lease，并非无副作用读取。
- 证书/动态凭据签发、token 创建/renew 属于额外操作，本篇默认不执行。
- 能访问 Vault 后端不代表获准访问秘密指向的云、数据库或其他主机。

## 目标侧证据与持久效果
- 保留脱敏请求、状态、结构化错误及 Vault `request_id`，避免只引用响应长度。
- 对照目标审计中的认证主体、namespace、路径、操作、时间与 request_id。
- 审计内容可能 HMAC 化；不能因缺少明文值就认定未访问。
- 读取证明包括测试标记、版本和对象归属，不需要保留真实口令值。
- capability 计算与实际返回不一致时检查显式 deny、引擎行为、版本与缓存差异。
- 未授权写入仅另有批准、仅自建测试路径；回读与审计同时核对，并验证恢复。
- readonly 阶段明确“写入/签发/持久化未验证”，不能据此报告持久控制。
- 禁止解封、递归导出秘密、长期子 token、续租持久化或借 secret 横向连接。

## 可核验反例
- A policy 明确允许 `secret/data/team-a/*`，A 读取 team-a 测试值：正常权限。
- A 对 team-b 返回403而对 team-a成功：仅支持该路径条件下边界有效。
- A 能 LIST metadata 但 data 拒绝：名称可见与秘密读取不是同一能力。
- root token 可管理所有 mount：证明 root 权限，不证明额外漏洞。
- 同一AppRole按预期签发受限token，敏感路径拒绝：不能只凭登录成功计洞。
- PKI只签发批准域且非批准域被拒绝：正常签发基线，不是任意身份冒充。
- 历史配置含宽绑定但当前审计/配置已限制：历史候选，不可冒充实时确认。

## 缺口、反证与记录
- 缺第二身份、无测试路径、禁止登录/读取值：标 blocked 或 tentative，说明具体限制。
- 超时、429、代理错误与403分别记录；两次超时不证明不可利用。
- 否定结果限定到身份、路径、操作、版本和时间，不能覆盖整个 Vault。
- 起始状态：凭据类型、来源、正常职责、已失陷权限与使用约束。
- 对象：namespace、mount、KV版本、路径/版本和 owner/业务归属。
- 对照：允许请求、预期拒绝请求、实际返回、控制变量、目标侧证据引用。
- 结论：被跨越边界、额外能力、反例排除、采样量与未验证步骤。
- 敏感值仅保留类型/必要属性与受控标记；token、secret_id、私钥不进入普通日志。

## 工具边界
- 仓库有启用的 `http-framework-test` 定义；当前会话注册与 Python 依赖仍需核对。
- 请求头使用 X-Vault-Token/namespace 时关闭请求概览，禁带凭据自动跨域重定向。
- 响应过滤/截断仅减少输出，不是脱敏；先规划敏感字段和受限证据存储。
- `exec` 仅用已具备、允许的本地解析能力；不假设安装 Vault CLI，禁止运行时安装。
- 缺协议/安全凭据传递能力即 blocked，不通过来源命令绕过限制。

## 来源、改编与许可
- 改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。
- 作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
- 源：`others/Dark-Moon/conf/agents/hashicorp-vault.md`，https://github.com/ASCIT31/Dark-Moon 。
- 快照：`cb0d9b8`（`cb0d9b83e745034c8bcff90daee9668b834d1508`），原许可 GPLv3；本文 GPL-3.0-only。
- 用户于2026-10-01自述为作者并授权自有内容改编；第三方素材原许可继续保留，不修改根LICENSE。
- 改编：将全树secret确认和持久化规则改为路径授权对照、采样与独立边界证据；不复用固定severity。
- 官方：https://developer.hashicorp.com/vault/docs/concepts/policies 。
- 官方：https://developer.hashicorp.com/vault/api-docs/system/capabilities-self 。
- 官方：https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2 ；https://developer.hashicorp.com/vault/docs/auth/kubernetes 。
