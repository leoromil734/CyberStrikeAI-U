# 设备码钓鱼（Device Code Phishing）

> 利用 OAuth 2.0 **设备授权流程**（RFC 8628）：攻击者让受害者在**真实的 IdP 页面**输入一个短码完成授权。全程没有伪造登录页，因而不触发许多反钓鱼控制。

## 一、为什么危险

- 全过程发生在**真实 IdP 域**（如 `microsoft.com/devicelogin`）→ 用户与安全工具都难以怀疑。
- 受害者输入验证码并批准 → 攻击者获得**可刷新的令牌**（`access_token` + `refresh_token`）。
- 若客户端是"公共客户端"（如 Azure CLI 的 client id），则令牌无需客户端密钥即可使用。
- 对启用了 MFA 的账号同样有效（MFA 由用户自己在真实页面完成）。
- 2024-2025 年已被多个威胁组织（如 Storm-2372 类）规模化使用。

## 二、攻击流程（概念）

```text
1. 攻击者调用设备码端点（用某公共 client_id）：
   POST /oauth2/v2.0/devicecode   →  得到 user_code + device_code
2. 把 user_code 通过邮件/IM/Teams 发给受害者，
   并给出"照此操作"的引导（后缀/URL + 验证码）。URL 指向真实 IdP 的
   /devicelogin 页面（不伪造任何页面）。
3. 受害者输入验证码并登录批准。
4. 攻击者轮询 /oauth2/v2.0/token 拿到 access_token/refresh_token。
5. 用令牌访问邮件/文件/Graph；因是"合法设备流"，常没有新设备告警。
```

对应 Azure AD 常见端点（示意，具体以目标 IdP 文档为准）：

```http
POST https://login.microsoftonline.com/common/oauth2/v2.0/devicecode
Content-Type: application/x-www-form-urlencoded

client_id=<public-client-id>&scope=https://graph.microsoft.com/.default

POST https://login.microsoftonline.com/common/oauth2/v2.0/token
grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=<...>&client_id=<...>
```

## 三、诱饵设计（社工侧）

- **"Teams/邮件迁移通知"**：让用户在多设备间同步（看似合理）。
- **加入会议/共享文档**：要求先"连接设备"。
- **IT 支持/合规审计**：要求核验设备身份。
- 关键点：把 `user_code` 与**真实 URL** 一起给出，并让用户在"等待批准"的感觉中完成操作。

## 四、检测与判定要点

- 受害者侧几乎无可见异常；日志证据在 IdP：
  - 认证日志中的 `deviceCodeFlow` / 设备码登录事件。
  - **发起 IP** 与**完成认证 IP/设备**不一致（攻击者轮询 IP ≠ 用户 IP）。
  - 短时间内新出现的应用访问（`Mail.Read`、`Files.ReadWrite.All` 等）。
  - 令牌获取的 `UserAgent` 为脚本/CLI 特征（非浏览器）。
- 攻击者侧可用脚本轮询；令牌有效期内可长期访问（刷新令牌）。

## 五、验证（最小证据）

1. 完整的端点调用与响应（devicecode → 用户批准 → token）。
2. 令牌**有效性证明**：以该令牌调用只读接口（如读取用户基本信息或一个无害对象），**不读取真实业务数据**。
3. 说明绕过了哪些控制（MFA？条件访问？设备合规？）。
4. 若条件访问阻断，记录阻断条件（这是重要的阴性结论）。

## 六、常见误报

- 用户输入了错误验证码（流程未完成）。
- 令牌获取成功但 API 调用被条件访问拒绝。
- 设备码流程在企业租户被**完全禁用**（策略层面拦截）。
- 令牌只能访问极低权限范围（影响降级）。

## 七、修复（客户侧）

- 在租户中**禁用设备码流程**（或在条件访问中阻止设备码认证）。
- 条件访问要求**受管设备/合规设备**；拒绝未注册设备的令牌。
- 限制可用客户端应用（只允许受信 client_id）；启用应用同意管控。
- 短令牌寿命 + 持续访问评估；对异常令牌使用做告警（尤其是非浏览器 UA 的服务调用）。
- 监控：设备码登录事件、认证发起与完成 IP 不一致、异常 Graph 调用（`Mail.Read` 邮件批量读取）。
- 培训：**"任何要求你输入验证码去'授权设备'的请求都应当作钓鱼"**。

## 八、参考

- RFC 8628（OAuth 2.0 Device Authorization Grant）
- Microsoft：设备码钓鱼缓解与检测指引（2024-2025）
- MITRE ATT&CK：T1528（Steal Application Access Token）
