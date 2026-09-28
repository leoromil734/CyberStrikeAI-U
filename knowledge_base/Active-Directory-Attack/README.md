# Active Directory 攻击总览

> AD 攻击按**当前持有物**分为三个阶段：无凭据 → 有普通凭据 → 有特权凭据。每阶段的目标都是"获得下一个凭据或会话"，而不是一次性拿到域控。

## 阶段零：先理解 Kerberos

不熟悉 Kerberos（AS-REQ/AS-REP/TGS/TGT、SPN、PAC、委派）就无法判断哪些攻击可行。要点：

- **TGT**：`krbtgt` 密钥签名，用于申请 TGS。
- **TGS**：用服务账号密钥加密 → 可离线破解（Kerberoast）。
- **Pre-auth**：关闭时任何人可为该用户拿 AS-REP（ASREPRoast）。
- 客户端通常用 **FQDN** 才会走 Kerberos，用 IP 会退化为 NTLM —— 这决定了你能测哪条路。

## 阶段一：无凭据 / 无会话

1. **网络与端口**：`nmap`/`masscan` 找 DC（88/389/445/636/3268/5985）、Web、打印机、VPN、共享。
2. **用户名枚举**：
   - Kerberos 预认证探测（无效用户返回 `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN`）：`kerbrute userenum`、`nmap krb5-enum-users`。
   - MS-NRPC（Netlogon）无认证调用 `DsrGetDcNameEx2` 判断用户/计算机是否存在（NauthNRPC）。
   - OWA/Exchange 枚举（MailSniper）。
   - OSINT：公开文档、社交、企业命名规则（`Name.Surname` 等），`username-anarchy` 生成候选。
3. **空会话 / Guest**：`enum4linux`、`smbmap`、`smbclient -U '%' -L`（现代 Windows 多已禁用，但仍值得一试）。
4. **匿名 LDAP**：`nmap --script ldap*`，`ldapsearch -x` 拉 `sAMAccountName`、`description`（有时直接写着口令）。
5. **投毒与中继**：LLMNR/NBT-NS/mDNS/WPAD 投毒（Responder）+ NTLM 中继（见 `NTLM-Relay-and-Coercion.md`）。
6. **AS-REPRoast**：对已知用户名请求 AS-REP 并离线破解（`GetNPUsers.py`）。
7. **口令喷洒**：遵守锁定策略，每轮尝试次数低于阈值（见 `../Credential-Attack/README.md`）。
8. **可预测的预建计算机账号**：`userAccountControl` 含 `PASSWD_NOTREQD`（4128）的机器账号，初始口令常为小写主机名（前 14 字符）。成功后注意 gMSA 的 `msDS-GroupMSAMembership` 可读性。
9. **遗留 Netlogon 通道允许列表**：Zerologon 修补后仍被 GPO/注册表 `VulnerableChannelAllowList` 显式放行的账号（SDDL），可被 MS-NRPC 攻击重置口令（Onelogon 类）。
10. **打印机/共享泄漏**：Web 管理页 HTML 中内嵌明文口令；打印队列里有入职文档（含每人初始口令）。

## 阶段二：有普通域凭据

1. **认证枚举**：PowerView、BloodHound（`SharpHound`/`bloodhound-python`）、ADRecon、PingCastle、`adPEAS`。
2. **凭据收集**：
   - 共享目录搜索（`smbmap -R`、`manspider`、`netexec smb -M spider_plus`）。
   - `description`/`userPassword`/`unixUserPassword` 字段。
   - GPP `cpassword`（`SYSVOL` 中的 `Groups.xml`，AES 密钥公开）。
   - `LAPS` 密码（若可读 `ms-Mcs-AdmPwd`）。
3. **Kerberoast**：请求 SPN 服务的 TGS 离线破解（`GetUserSPNs.py`）。
4. **委派滥用**：非约束/约束/基于资源的约束委派（RBCD）。
5. **ADCS**：模板滥用（ESC 系列，见 `ADCS-Abuse.md`）。
6. **本地提权**：进入任一成员服务器后提权到本地管理员 → dump LSASS/SAM → 找域内复用口令。
7. **中继**：域内凭据下的中继路径更多（`--delegate-access`、LDAP 中继等）。
8. **ACL 滥用**：`GenericAll`、`GenericWrite`、`WriteDacl`、`WriteOwner`、`ForceChangePassword`、`AddMember`、`AddSelf`、`AllExtendedRights`。

## 阶段三：有特权凭据

- **DCSync**（`DRSGetNCChanges`）→ 导出域内哈希（含历史哈希）。
- **Golden/Silver Ticket**（`krbtgt` / 服务账号密钥）。
- **Skeleton Key**、**DSRM**、**AdminSDHolder**、**SID History 注入**。
- **ADCS CA 私钥窃取** → 伪造任意证书（Golden Certificate）。
- **信任关系滥用**：跨域/跨林 SID 过滤、`sidHistory`、信任密钥。
- **持久化**：黄金票据、DCSync 权限（复制权限）、影子凭据、ADCS 模板、计划任务/GPO 落地。

## 判定纪律

1. 每次提权/横向都要有**前后两条命令的完整输出**（身份证明 + 新权限证明）。
2. 不做破坏性动作（不改域内数据、不锁账号、不删对象），除非客户明确要求并书面同意。
3. 记录"凭据链"：初始访问点 → 每次获得的凭据/票据 → 最终权限。
4. 域控上**只读**验证即可证明影响（例如导出用户列表或读取一个属性），不要执行 DCSync 全量导出除非授权。

## 常见误报

- 抓到的哈希是已禁用/已改密账号的旧值。
- Kerberoast 成功但口令强到不可破解 → 影响降级为"不必要 SPN + 弱加密类型"。
- ACL 可写但没有可用路径（目标对象无价值/无登录权限）。
- BloodHound 路径理论可达但需先拿到中间节点（未验证）。

## 修复要点

- 减少特权：Tier 模型、PAW/跳板机、LAPS、gMSA 替代服务账号口令。
- 禁用 NTLM/LLMNR/NBT-NS（可行时），强制 SMB/LDAP 签名与通道绑定。
- Kerberos：禁用 RC4（`msDS-SupportedEncryptionTypes`），清理不必要 SPN。
- ADCS：移除 `EnrolleeSuppliesSubject`、禁用 Web 注册、启用强映射与审计。
- 监控：4662（复制权限）、4769（弱加密 TGS）、4720/4738（账号修改）、5827-5831（Netlogon）。

## 参考

- HackTricks：Active Directory Methodology；adsecurity.org；SpecterOps BloodHound 文档
- Skills：`active-directory-attack`、`post-exploitation`、`credential-stuffing`
