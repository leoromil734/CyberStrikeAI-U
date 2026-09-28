# 邮件安全（Email Security）

> 邮件既是**攻击入口**（钓鱼/伪造），也是**数据出口**（外发泄漏）。评估时两部分都要看：能不能伪造目标域发信、能不能从内部外发数据。

## 一、发件人认证三件套

| 机制 | 检查命令 / 位置 | 常见缺陷 |
|---|---|---|
| **SPF** | `dig TXT <domain>` | 缺失、`~all`/`?all`（软失败）、`include` 过多或有失效委托、超 10 次 DNS 查询限制 |
| **DKIM** | `dig TXT <selector>._domainkey.<domain>` | 选择器未轮换、密钥长度不足 1024、`l=`（长度截断）允许追加内容、选择器可被第三方滥用 |
| **DMARC** | `dig TXT _dmarc.<domain>` | 缺失、`p=none`（只监控）、`p=quarantine` 而非 `reject`、无 `sp=`/`adkim`/`aspf` 严格模式、无 `pct=100` |
| 附加 | `BIMI`、`MTA-STS`、`TLS-RPT`、`DANE` | 缺失导致降级与中间人 |

评估结论示例：

```text
SPF:  v=spf1 include:_spf.google.com ~all        → 软失败，可尝试伪造
DMARC: p=none; rua=...                            → 不阻断，仅报告
结论：可直接伪造该域外发邮件（收件方仅标注/放行）
```

**注意**：DMARC 通过 ≠ 不可伪造。`p=none`、子域策略缺失（`sp`）、以及"合法第三方代发"都是常见绕过面。

## 二、伪造与绕过手法（授权范围内验证）

1. **直接伪造**：`MAIL FROM`/`From` 头使用目标域（当 SPF 不严格或 DMARC 为 none）。
2. **显示名欺骗**：`From: "IT Support" <attacker@evil.com>`（显示名与地址分离，用户难以识别）。
3. **相似域**：同形字/新 TLD/短横线变体（见 `../Initial-Access/README.md`）。
4. **子域伪造**：主域 `p=reject` 但子域无 DMARC 记录 → 用子域发信（`sp=none` 或未继承）。
5. **DKIM `l=` 截断**：签名只覆盖前 N 字节 → 在后面追加恶意内容仍通过 DKIM。
6. **第三方代发滥用**：邮件营销/SaaS 平台（`include` 中的域）若可注册/被接管 → 从合法 SPF 域发信。
7. **Reply-To / Return-Path 混淆**：回复地址指向攻击者。
8. **MTA-STS 缺失 + TLS 降级**：可对邮件传输做中间人（需网络位置）。

工具：

```bash
spoofcheck <domain>              # 检查 SPF/DMARC 是否可伪造
dig +short TXT <domain>
dig +short TXT _dmarc.<domain>
swaks --to victim@target --from ceo@target --server target-mx   # 测试投递
```

## 三、SMTP 层测试

- **开放中继**：`swaks --server <mx> --to external@example.com --from me@example.com` 若被接受即中继（高危）。
- **用户枚举**：`VRFY`/`EXPN`/`RCPT TO` 响应差异（见 `Recon-OSINT` 的用户名枚举）。
- **注入**：在邮件主题/地址中注入 CRLF（`%0d%0a`）篡改头或拼接 SMTP 命令。
- **邮件网关绕过**：附件类型伪装（HTML/ISO/HTA/加密压缩包带口令）、宏文档、超链接重定向、二维码；这不是"漏洞"，但要作为**有效性结论**记录（客户关心投递率）。

## 四、内部侧：邮件作为出口

- Exchange/Graph 权限滥用：`Mail.Read`、`Mail.Send`、应用权限过大（见 `../API-GraphQL/README.md`、`../Initial-Access/Device-Code-Phishing.md`）。
- 转发规则（Transport/Hidden Inbox Rule）常用于长期窃取邮件。
- SMTP 凭据在应用配置/脚本中明文（可把内部主机变成发信中继）。
- 邮件归档/日志导出接口未授权访问。

## 五、验证（最小证据）

1. 认证记录与 DNS 查询输出（SPF/DKIM/DMARC 原文）。
2. 投递证据：收到邮件的原始头（`Authentication-Results`：`spf=pass/fail`、`dmarc=pass/none`）与显示效果。
3. 中继：SMTP 会话日志（含服务器响应码）。
4. 不向真实员工发送超出授权范围的内容；测试邮件使用客户指定邮箱。

## 六、常见误报

- 显示名欺骗成功但被垃圾箱收走（送达 ≠ 通用）。
- 目标域有 DMARC `p=reject` 但测试时使用了已被列入白名单的 IP（如客户自己的出口）。
- 子域记录实际继承主域策略（取决于实现）。
- 邮件被网关隔离（在隔离区而非收件箱）。

## 七、修复

- DMARC：`p=reject` + `sp=reject` + `adkim=s` + `aspf=s` + `pct=100`；覆盖所有子域（`*.domain`）。
- SPF：精确列出授权发送源，`-all`；控制 `include` 数量。
- DKIM：2048 位密钥、定期轮换、避免 `l=`。
- 部署 **MTA-STS + TLS-RPT**；有条件上 **DANE**。
- 接收侧：对内部域名做防护（内部邮件伪造检测）、显示名与外部发件人标记、附件类型策略。
- 监控：DMARC 聚合报告异常、异常外发（大量收件人、异常地理）、隐藏收件箱规则创建（Exchange 事件）。

## 八、参考

- OWASP WSTG-CONF/邮件相关；RFC 7489（DMARC）、RFC 7208（SPF）、RFC 6376（DKIM）
- HackTricks：Pentesting SMTP；`spoofcheck`、`swaks`
- MITRE ATT&CK：T1566（Phishing）、T1114（Email Collection）
