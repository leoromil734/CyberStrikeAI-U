# 口令攻击（Password Attacks）

> 覆盖三类：**在线爆破/喷洒**、**凭据填充**、**离线破解**。在线手法必须先确认锁定策略，避免造成业务中断。

## 一、先摸清策略（必做）

```bash
# AD 默认域策略
netexec smb <dc> --pass-pol            # 锁定阈值、观察窗口、最小长度、复杂度
# 或 LDAP 读取 defaultDomainPolicy
```

关键参数：

- **锁定阈值**（如 5 次）与**观察窗口**（如 30 分钟）：决定每轮可尝试次数。
- 是否对特定账号豁免（服务账号常不锁定）。
- 是否启用精细口令策略（PSO，按组不同）。

## 二、密码喷洒（Password Spraying）

原则：**固定一个弱口令，横向试多个账号**（而非固定账号试多个口令）。

```bash
# 每轮 1 个口令，轮间隔 > 观察窗口
netexec smb <dc> -u users.txt -p 'Summer2026!' --continue-on-success
netexec smb <dc> -u users.txt -p 'Company@123' --continue-on-success
# 常见来源：公司名+年份、季节+年份、Welcome@123、<Company>123!
```

变体：

- **OWA/Exchange**（`MailSniper Invoke-PasswordSprayOWA`）、**SSO 门户**、**VPN**、**邮箱客户端（IMAP）**。
- **用户名变体**：大小写、`.`/`_` 分隔、`+tag`（部分系统忽略）、空格与 Unicode 归一化 → 与限流绕过叠加（见 `../API-GraphQL/Rate-Limit-Bypass.md`）。
- **口令变体**：首字母大写、末尾 `!`/`1`/`2026`、`Password1` → 用规则生成候选（Hashcat `-r`）。

## 三、凭据填充（Credential Stuffing）

- 用第三方泄漏的 `user:pass` 组合批量尝试（**必须授权且需评估法律风险**）。
- 成功率提升技巧：跨站点口令复用、大小写/后缀变换、同域不同系统。
- 防护识别：设备指纹、速率限制、异常地理、`Referer`/JS 校验、CAPTCHA。
- 合规提示：不得使用来源不明的个人数据；仅在客户明确书面同意下进行。

## 四、离线破解

```bash
hashcat -m 1000 ntlm.txt wordlist.txt -r rules/best64.rule        # NT
hashcat -m 5600 netntlmv2.txt wordlist.txt                        # NetNTLMv2
hashcat -m 13100 tgs.txt wordlist.txt                             # Kerberoast RC4
hashcat -m 22000 wifi.hc22000 wordlist.txt                        # WPA
```

要点：

- **规则与掩码**比纯字典有效：`?u?l?l?l?l?d?d?s`（公司口令模式）、`-r best64.rule`。
- **Hash shucking**：用已有 NT 哈希作为候选校验 RC4 票据/NetNTLM/DCC（模式 35300/35400/27100/31600），快两个数量级；AES 无效。
- 分布式：多 GPU / `--session` 断点续跑；先跑高频候选再上大字典。
- 时间预算：先跑"公司模式 + 常见词典"，把长尾留给客户决策。

## 五、验证（最小证据）

1. 成功凭据：给出被命中的账号（脱敏）与验证动作（`whoami`/读取自身信息）。
2. 统计：尝试次数、轮次间隔、成功数、是否触发锁定（若触发需立即停止并报告）。
3. 密码政策证据：`--pass-pol` 输出，说明为何该攻击在策略下可行。
4. 不导出业务数据。

## 六、常见误报

- 命中但账号被禁用（`ACCOUNT_DISABLED`）。
- 口令正确但需要 MFA（在线成功率 ≠ 可访问）。
- 目标返回成功但实际是"口令过期需修改"（`STATUS_PASSWORD_MUST_CHANGE`），这本身也是重要发现。
- 被锁定导致的连锁失败（把"账号已锁"误认为"口令错误"）。

## 七、修复

- 锁定策略 + 渐进延迟；禁止对同一账号无限尝试。
- 禁用"口令永不过期"；使用长口令（>14 位）+ 黑名单（拒绝常见弱口令与公司名变体）。
- **抗钓鱼 MFA**（passkey）与条件访问，使"拿到口令"不再等于"拿到访问"。
- 检测：同一来源多账号失败（喷洒）、跨地理成功登录、`STATUS_PASSWORD_MUST_CHANGE` 异常集中。
- 对服务账号使用 gMSA/短期凭据，避免长期弱口令。

## 八、参考

- HackTricks：Password Spraying；MITRE ATT&CK：T1110（Brute Force）/T1078
- Hashcat 模式与规则文档；`netexec`、`MailSniper`
- Skill：`credential-stuffing`
