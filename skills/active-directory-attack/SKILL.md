---
name: active-directory-attack
description: >-
  内网域 / Active Directory / BloodHound / Kerberoast / ADCS / NTLM Relay /
  DCSync / 横向域管 / IAM / PAM / responder / impacket / netexec / enum4linux /
  smbmap / rpcclient。用户说「打域」「AD」「域渗透」「Kerberos」「证书服务」
  「NTLM」「DCSync」「BloodHound」时加载。
allowed-tools: bloodhound impacket netexec responder enum4linux-ng smbmap rpcclient nmap hydra hashcat john exec metasploit record_vulnerability list_vulnerabilities upsert_project_fact
metadata:
  tags: [渗透测试, penetration-testing, 红队, ad]
  source_augment: Hi-FullHouse/CyberSecurity-Skills
---

## 内网域攻击

### CSS IAM / AD 手册（按需 `references/csskills-iam/`）

优先：`AD域安全与攻击路径分析-ADSecurityAttackPathAnalysis.md`、`PAM特权账号管理-PrivilegedAccessManagement.md`。

### 系统工具补全（场景 → MCP）

| 场景 | 优先工具 | 备选 | 备注 |
| --- | --- | --- | --- |
| 攻击路径图 | `bloodhound` | — | SharpHound 收集后分析 |
| Kerberos/票据/同步 | `impacket` | `netexec` | AS-REP/Kerberoast/DCSync 等 |
| 喷洒/SMB/WinRM | `netexec` | `hydra`、`smbmap` | 授权与锁账户 |
| LLMNR/NBT 投毒 | `responder` | — | 仅授权内网 |
| 主机/服务枚举 | `enum4linux-ng` / `rpcclient` | `nmap` | 域成员与共享 |
| Hash 破解 | `hashcat` / `john` | — | 离线 |
| 利用框架 | `metasploit` | `exec` | 域 CVE 验证 |
| 落库 | `record_vulnerability` | `upsert_project_fact` | 路径证据+边界 |

```
=== 内网域(2023+真实主战场) ===
侦察: BloodHound(SharpHound收集→攻击路径) | Kerberos: GetNPUsers(AS-REP)/GetUserSPNs(Kerberoast)
🚨ADCS(Certipy一把梭): certipy find -vulnerable | ESC1指定SAN申域管证书 | ESC8 relay到CA拿DC证书
🚨NTLM Relay(比PtH重要,PtH常被EDR拦): ntlmrelayx -t ldap--escalate-user / -t http CA --adcs(ESC8) / RBCD
🚨强制认证Coerce: PetitPotam(MS-EFSRPC)/coercer全协议喷/printerbug → 喂给relay
🚨DACL滥用: WriteDACL→给自己加DCSync | 影子凭据certipy shadow(GenericWrite即可,不改密码不留痕)
DCSync: secretsdump -just-dc → krbtgt hash→Golden Ticket
🚨一击致命域CVE(先测,命中直接域管): Zerologon(CVE-2020-1472,置空DC机器账户密码→DCSync) | NoPac(CVE-2021-42278/42287,机器账户改名申DC TGT) | PrintNightmare(CVE-2021-34527,后台打印RCE/加载恶意驱动) | EternalBlue(MS17-010,老SMBv1直RCE)
🚨IPv6/mitm6(默认双栈内网必打): mitm6劫持DHCPv6+DNS→WPAD→ntlmrelayx到LDAP/ADCS(比LLMNR更隐蔽,现代内网首选)
LLMNR/NBT-NS投毒: responder抓NetNTLMv2→hashcat破/relay
Linux内网: Redis未授权(CONFIG SET dir写SSH key) | NFS showmount | Docker 2375
```