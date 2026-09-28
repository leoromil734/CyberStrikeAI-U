# OAuth 2.0 / OIDC 攻击与绕过

> OAuth 的绕过几乎都落在**三个变量的解析差异**上：`redirect_uri` 校验、`state`/PKCE 绑定、以及"谁来消费授权码"。2025 年的研究把 PKCE 与 BFF 一并纳入攻击面。

## 一、redirect_uri 绕过

| 手法 | 示例 | 前提 |
|---|---|---|
| 宽松匹配 | `https://app.com.evil.com`、`https://app.com.evil.com/` | 前缀/后缀匹配 |
| 路径追加 | `https://app.com/callback/../../evil` | 未做规范化 |
| 参数追加 | `https://app.com/callback?next=https://evil.com` | 二次跳转未校验 |
| userinfo | `https://app.com@evil.com/cb` | 解析器差异 |
| IPv6 多 `@` | `https://[::1]@evil.com` | 回环白名单校验被绕过（Google Cloud 账号接管，2025） |
| 回环端口 | `http://localhost:PORT/cb`（移动端常见） | 任意本地端口被允许 → 本地恶意进程接收码 |
| 开放重定向链 | 白名单域上的开放重定向 → 跳到 evil | 白名单域存在 OR |
| fragment/`#` | `https://app.com/cb#https://evil.com` | 前端把 fragment 当跳转目标 |
| Scheme 混淆 | `javascript:`、`data:` 出现在回调处理 | 前端直接跳转 |
| 大小写/尾点 | `Https://APP.com.` | 弱校验 |

## 二、授权码相关

- **授权码注入（Authorization Code Injection）**：用自己的账号拿到 code，再把 code 注入受害者浏览器会话，使受害者会话绑定到攻击者身份（或反之，取决于服务端绑定逻辑）。
- 2025 研究（"Attacks via a New OAuth flow, Authorization Code Injection"）指出：**即使启用 PKCE 与 BFF**，只要能同源执行脚本并中断/切换响应模式，仍可能在带外提前获取预认证 Cookie 后完成注入。
- **OAuth 流程新变体**：`response_mode` 切换、`window.open` 中断、`form_post` 自动提交被 `sandbox`/导航阻止策略影响的行为，都可能留下可读的 code。
- **PKCE 降级**：服务端对部分客户端不强制 PKCE；`code_challenge_method=plain`；`code_verifier` 可预测。

## 三、state / CSRF 与账号绑定

- `state` 未校验或可预测 → 登录 CSRF：把受害者登录到攻击者账号，后续受害者操作落在攻击者账号（或诱导上传敏感数据）。
- 绑定逻辑：`/oauth/bind` 直接把新身份附加到当前登录用户，无确认步骤 → 账号劫持。

## 四、令牌与端点

- `implicit` 流程可用、`token` 泄漏在 Referer/history。
- 隐式 flow 或 `response_type=token id_token` 在 SPA 中可被 XSS 直接取走。
- Token 端点未校验 `client_secret`（public client 场景被误当 confidential）。
- 刷新令牌轮换失效：旧 refresh token 长期有效。
- `id_token`：未校验 `iss`/`aud`/`nonce`（见 `../JWT/JWT-Attack-Matrix.md`）。
- 多租户：`tenant`/`realm` 参数可控，跨租户拿令牌。

## 五、会话与 BFF

- BFF 模式：Cookie 与 code 同时存在时的绑定校验、`SameSite` 与 POST 回调的兼容性取舍常引入 CSRF。
- 登出与撤销：`/oauth/revoke` 只删本地会话，上游 token 仍有效。

## 六、验证（最小证据）

1. 两个账号（攻击者 + 受害者）或 匿名 + 受害者 的凭证。
2. 完整可复现的跳转序列（含每个 302 的 `Location`）。
3. 成功判据：以受害者身份获得会话/数据，或把受害者会话绑定到攻击者身份。
4. 若仅"redirect_uri 校验不严"但无法落地（如需要用户点击且无 OR 链），结论写"潜在开放重定向/中低危"。

## 常见误报

- 放宽 `redirect_uri` 但回调仅接受同源且不接受 `//`/`@` 变体。
- 会话 cookie `SameSite=Lax` + `state` 校验存在 → 登录 CSRF 不成立。
- 用本地搭建的测试 IdP 复现，生产配置不同。

## 修复

- `redirect_uri` **精确字符串匹配**（预注册），禁止通配与前缀匹配。
- 强制 PKCE（S256），服务端校验 `code_verifier`。
- 强制 `state` 且与浏览器会话绑定；回调必须校验 `nonce`。
- 授权码一次性、绑定 `client_id` + `redirect_uri` + PKCE，且有短 TTL。
- 回环地址白名单仅允许**已注册端口**或改用自定义 URI scheme + 应用签名校验。
- 对 `response_mode`/`prompt`/`login_hint` 等参数做白名单。

## 参考

- PortSwigger：OAuth 2.0 认证漏洞系列、Splitting the Email Atom（2025）
- Medium/Anador：Authorization Code Injection 与 PKCE/BFF 边界（2025）
- Google Cloud Account Takeover via URL Parsing Confusion（2025）
- OWASP：OAuth 2.0 Security Best Current Practice
