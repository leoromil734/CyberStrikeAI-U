# AD 横向移动与 ACL 滥用

> 横向移动的判据是"**以新身份在新主机上取得会话/权限**"。工具选择取决于目标是否禁用 NTLM、是否有签名、以及你有哈希还是票据。

## 一、认证材料的三种用法

| 材料 | 用法 | 工具 |
|---|---|---|
| 明文口令 | 直接登录/远程执行 | `netexec`、`psexec`、`wmiexec`、`smbexec`、`evil-winrm` |
| NT 哈希 | Pass-the-Hash | `netexec -H`、`psexec.py -hashes`、`mimikatz sekurlsa::pth` |
| 票据（TGT/TGS） | Pass-the-Ticket / Overpass-the-Hash | `Rubeus ptt`、`export KRB5CCNAME=...ccache`、`-k` |
| 证书 | PKINIT | `certipy auth`、`Rubeus asktgt /certificate:` |

NTLM 被禁用时走 Kerberos：确保使用 **FQDN**、`/etc/hosts` 与 DNS 正确、时钟同步（5 分钟内）。

## 二、远程执行通道

| 通道 | 特征（取证与 OPSEC） | 备注 |
|---|---|---|
| SMB（PsExec 类） | 创建服务 + 命名管道，易留痕 | 需要 445 与管理共享 |
| WMI | 无文件落地，进程父级为 WmiPrvSE | 需要 135/445 |
| WinRM/PSRemoting | 5985/5986，日志清楚 | 需要管理员组成员 |
| DCOM | 135 + 动态端口 | 多种对象（`MMC20.Application` 等） |
| RDP | 交互式，可挂载驱动器 | 需 3389 与登录权限 |
| 计划任务 | 需 SMB + RPC | `schtasks /s` |
| 服务/驱动 | 高权限 | 谨慎 |

## 三、ACL 滥用（无凭证横向的关键）

检查对象 ACL/属性可写性：

```text
GenericAll / GenericWrite / WriteDacl / WriteOwner / WriteProperty
ForceChangePassword / AllExtendedRights / AddMember / AddSelf
User-Force-Change-Password / msDS-AllowedToActOnBehalfOfOtherIdentity(可写)
```

对应操作：

- `GenericAll` on User → 直接重置口令或设 SPN 后 Kerberoast。
- `GenericAll` on Group → 加自己入组（如 Domain Admins、Backup Operators）。
- `GenericAll` on Computer → RBCD。
- `WriteDacl` → 给自己加 `DCSync`（`Replicating Directory Changes`）→ 复制凭据。
- `WriteOwner` → 先改属主再加 ACL。
- `ForceChangePassword` → 需注意会打断业务（**授权后**再做，或只证明可写）。
- `AddSelf` on Group → 自加入。
- **影子凭据（Shadow Credentials）**：对目标对象有 `GenericWrite` 时写入 `msDS-KeyCredentialLink`，用 PKINIT 以目标身份取证（`pywhisker`、`Whisker`、`Certipy shadow`）。
- **GPO 滥用**：对 OU 有 `GenericWrite`/GPO 可写 → 改 GPO 下发计划任务/脚本（影响面大，需授权）。

## 四、BloodHound 路径分析

```bash
bloodhound-python -u <user> -p <pass> -d <domain> -ns <dc> -c All
# 或 Windows: SharpHound.exe -c All --zipfilename out.zip
```

高效查询：`Shortest Paths from Owned Principals`、`Shortest Path to Domain Admins`、`Kerberoastable Users`、`AS-REP Roastable`、`Users with Foreign Domain Group Membership`、`Principals with DCSync Rights`。

注意：BloodHound 的边是"理论可达"。每条边落地前都要确认**实际条件**（目标是否可达、是否被补丁影响、是否禁用 NTLM）。

## 五、信任关系与跨域

- `nltest /domain_trusts`、`Get-DomainTrust`、`Get-ForestTrust`。
- **SID History 注入**（需要 `SeEnableDelegationPrivilege` 或被信任域的林内特权）。
- 跨域 Kerberos：`getST.py -spn` + 信任票据（`inter-realm TGT`）。
- 森林信任密钥导出 → 伪造信任票据。

## 六、验证（最小证据）

1. 材料来源：凭据/哈希/票据是如何获得的（前一步的完整链）。
2. 目标会话：`whoami` / `klist` / `netexec -x whoami` 在**目标主机**上的输出。
3. 不做持久化（不建后门账号、不改 GPO、不删数据），除非授权明确。
4. 记录每跳使用的通道与端口，便于客户封堵。

## 七、常见误报

- 哈希可 PtH 但目标为该账号的旧密码（认证失败）。
- 有 `GenericAll` 但目标对象已被禁用/服务未运行。
- 能枚举但无法登录（登录权限受限：`SeDenyInteractiveLogon`、受保护用户组）。
- WMI/WinRM 命令返回成功但实际未执行（防火墙阻断）。

## 八、修复

- 消除大范围 ACL 滥用：定期用 BloodHound/`aclscan` 审计，收紧 `GenericAll/WriteDacl`。
- 特权分层（Tier0/1/2）：域管账号只能在域控与 PAW 登录。
- 禁用/限制 NTLM；强制签名；限制 `MachineAccountQuota`。
- 对 `msDS-KeyCredentialLink`、`msDS-AllowedToActOnBehalfOfOtherIdentity`、`sidHistory` 写操作告警。
- 保护 GPO（谁可改谁就是管理员级别）。
- 监控：4624/4648（显式凭据登录）、5140（共享访问）、5857/5861（WMI）、4768/4769。

## 九、参考

- HackTricks：ACL Abuse、Lateral Movement；SpecterOps：Shadow Credentials、Certified Pre-Owned
- 工具：netexec、Impacket、Rubeus、BloodHound、pywhisker、Certipy
- Skill：`active-directory-attack`、`pentest-blackboard`
