# 边界设备与网络基础设施攻击（Edge / Appliance）

> VPN 网关、防火墙、堡垒机、负载均衡、邮件网关、虚拟化平台（ESXi/vCenter）位于**信任边界之外**：攻破它们通常意味着进入内网或拿到大量凭据。2023-2026 年，这类设备是勒索团伙最常用的初始访问来源。

## 一、为什么优先看边界设备

- 暴露在公网（被动扫描即可发现：Shodan/Censys/FOFA 的产品指纹）。
- 更新滞后（设备生命周期长、维护窗口少）。
- 一旦被控制：可读写凭据（VPN 会话、AD 认证）、可绕过 MFA（VPN 层）、可直接进内网。
- 常被用于**持久化**（设备层难以检视的定时任务/脚本）。

## 二、常见产品族（按攻击面归类）

| 类别 | 代表 | 关注点 |
|---|---|---|
| SSL VPN / ZTNA | Fortinet FortiGate/FortiClient EMS、Ivanti Connect Secure/Policy Secure、Pulse Secure、Cisco ASA/AnyConnect、Citrix NetScaler/ADC、SonicWall、Palo Alto GlobalProtect | 认证绕过、预认证 RCE、会话令牌泄漏、MFA 绕过 |
| 防火墙/网关 | 同上 + WatchGuard、Sophos、Check Point | 管理接口暴露、配置导出、默认凭据 |
| 远程管理 | ScreenConnect/ConnectWise、Kaseya、Zoho ManageEngine、SolarWinds | 供应链/已部署的 RMM 被滥用 |
| 邮件网关 | Exchange（OWA/ECP/Autodiscover）、Zimbra、MDaemon | ProxyLogon/ProxyShell 类、SSRF、EWS 滥用 |
| 虚拟化 | VMware vCenter/ESXi（vSphere、vRealize）、Proxmox、Xen | 认证绕过、`vim://`/`vsan` 漏洞、hypervisor 逃逸 |
| 网络设备 | Cisco IOS、Juniper、华为/华三 | 默认/弱 SNMP、未授权配置导出 |
| 堡垒机 | JumpServer、齐治、Teleport、CyberArk | 默认凭据、会话录制绕过、API 越权 |
| 备份/存储 | Veeam、NetBackup、NAS（群晖/QNAP） | 凭据库读取、RCE |

> 具体 CVE 编号请以厂商公告与 CISA KEV 目录为准（下表只给形态）。

## 三、攻击形态（保持通用，避免"报 CVE"）

1. **预认证漏洞**：
   - 认证绕过：伪造特定 HTTP 头/路径/JWT/会话 Cookie（例如仅校验签名不校验内容、或可预测的令牌）。
   - 命令/SQL/模板注入发生在登录前页面（登录页参数、`/dana-na/`、`/+CSCOE+/` 类静态路径处理）。
2. **会话令牌泄漏**：设备把会话信息写入可从外部读取的路径（内存残留/日志/错误页），导致可批量窃取他人会话（CitrixBleed 类）。
3. **配置与凭据导出**：管理接口（或漏洞）允许下载设备配置，其中含 VPN 用户凭据哈希、LDAP bind 口令、预共享密钥。
4. **MFA 绕过**：部分设备在特定认证顺序/头部组合下跳过二次验证。
5. **RMM 滥用**：已部署的远程管理工具被攻击者使用（合法进程、合法域名，极难检测）。
6. **设备层植入**：登录脚本、定时任务、perl 脚本（Ivanti 类"零日+隐身"）；重启后可能消失（内存型），需要取证时优先抓内存。
7. **管理面暴露**：管理端口直接暴露公网 + 默认凭据/弱口令。

## 四、测试方法

1. **指纹与版本**：响应头、登录页特征、静态资源哈希、TLS 证书、favicon hash；与厂商公告版本比对（不依赖单一指纹）。
2. **攻击面枚举**：`/robots.txt`、`/dana-na/`、`/remote/`、`/admin/`、`/api/`、`/cgi-bin/`、`/my.policy`、`/+CSCOE+/`；用 `nuclei -t` 的对应模板做线索。
3. **只读验证优先**：能读配置页/版本信息/会话列表就足够证明影响，不要触发 RCE。
4. **认证类测试**：默认凭据（授权范围内低频）、MFA 绕过组合（改 `X-Forwarded-For`、请求顺序、并发）、令牌可预测性。
5. **虚拟化平台**：`/ui/`、`/sdk/`、`vim` 接口、`/rest/` API；注意 vCenter SSO 与 AD 的集成路径。
6. **取证准备**：边缘设备一旦中招，攻击者常清日志；测试前与客户约定取证与快照策略。

## 五、验证（最小证据）

1. 完整请求与响应（含版本信息、认证状态变化）。
2. 影响证据：可读的配置片段（凭据掩码）、获得的会话、到达内网服务的响应。
3. 不做破坏性操作（不重启设备、不导出全部配置、不改管理配置）。
4. 记录设备型号/固件版本/补丁级别（这是修复的关键输入）。

## 六、常见误报

- 版本"看起来旧"但已打补丁（厂商常反向移植）。
- 登录页存在漏洞特征字符串但利用条件不满足（需内部角色/特定模块启用）。
- 会话泄漏路径可读但内容已加密/已过期。
- 默认凭据提示但账号被强制首次改密。

## 七、修复

- **资产与补丁**：边界设备纳入资产库与补丁流程，关注 CISA KEV 与厂商紧急公告；高危漏洞 24-72 小时内处理。
- **不要暴露管理面**：管理接口只允许 VPN/跳板访问；禁止公网暴露 `mgmt`/`admin`/`8443` 等。
- **强认证**：管理面强制 MFA + FIDO2；VPN 用户启用**证书 + 设备合规**（不只用口令+MFA）。
- **会话安全**：缩短会话寿命、禁用不安全的重用、限制并发会话。
- **日志与检测**：设备日志集中外发（本地日志易被清除）；监控异常管理操作、异常登录地理、已知植入路径的文件创建。
- **架构**：VPN 内部再做微分段，防止"设备被攻破 = 内网全通"；对边界设备专用网段。
- **RMM 治理**：清点并限制 RMM 工具，禁止未经批准的远程管理软件。

## 八、参考

- CISA KEV 目录与已知被利用漏洞公告
- 各厂商安全公告（Fortinet PSIRT、Ivanti、Citrix、VMware、Palo Alto）
- MITRE ATT&CK：T1190（Exploit Public-Facing Application）、T1133（External Remote Services）
- Skill：`web-attack-methods`、`attack-surface-recon`
