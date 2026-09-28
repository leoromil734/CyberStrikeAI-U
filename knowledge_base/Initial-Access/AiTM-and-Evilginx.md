# AiTM 反向代理钓鱼与 Evilginx

> AiTM（Adversary-in-the-Middle）= 反向代理真实登录页面，**转发凭据并窃取会话令牌**。它可以绕过绝大多数 MFA，因为 MFA 是在真实 IdP 页面上完成的。

## 一、原理

```text
受害者 → [攻击者代理 phishing.example] → 真实 IdP (login.microsoftonline.com)
                 ↑ 记录账号/口令/OTP          ↑ 返回会话 Cookie
```

- 页面 HTML/CSS/JS 全部由真实站点提供（视觉零差异）。
- 凭据与 OTP 被记录；**认证成功后**的 `Set-Cookie` 被保存 → 攻击者用该 Cookie 直接访问，无需 MFA。
- 因此防护重点变成"**令牌能否在别处使用**"。

## 二、工具与流程

- `evilginx2`（phishlet 适配不同 IdP）、`muraena`、`CredSniper`、`Modlishka`。
- 需要：域名 + 有效证书（Let's Encrypt）+ VPS；在 IdP 允许的域名/重定向上做匹配（子域伪装、路径伪装）。
- 典型流程：

```bash
# 概念性流程（需在授权范围内、自建环境）
evilginx2 -p ./phishlets
config domain <your-domain>; config ip <vps-ip>
phishlets hostname <phishlet> <sub.your-domain>
phishlets enable <phishlet>
lures create <phishlet>; lures get-url 0
```

## 三、限制与对抗（判定要点）

| 防护 | 对 AiTM 的影响 |
|---|---|
| **FIDO2/Passkey** | origin 绑定 → 在伪造域上无法完成，**阻断 AiTM** |
| 证书绑定 / token binding | 令牌绑定 TLS 通道，代理无法使用 |
| **Token Protection / 设备绑定令牌** | 令牌只能在受管设备使用 |
| 条件访问（合规设备、可信位置） | 新设备/新地理登录被拦或要求额外验证 |
| 短令牌寿命 + 持续访问评估 | 窗口很短 |
| 密码管理器域名绑定 | 不会在相似域自动填充 |
| 邮件网关/浏览器反钓鱼 | 拦截新注册域、阻断已知钓鱼特征 |

**验证时必须确认**：拿到的 Cookie 能否在不使用 MFA 的前提下访问受保护资源；若服务端做了令牌绑定/设备校验，则应记录"令牌不可复用"，这是重要的阴性结论。

## 四、变体

- **VNC 型 AiTM（EvilnVNC）**：把受害者引入一台浏览器开着真实站点的 VNC 会话 → 完整观察与窃取，对指纹类检测有一定规避。
- **反向代理 + 会话固定**：代理同时控制两种会话，能做更复杂的劫持。
- **OAuth 应用同意钓鱼（Illicit Consent Grant）**：不用偷 Cookie，直接让用户授权恶意应用获得 Graph/Mail 权限（对启用了 MFA 的账号同样有效）。检测点：企业应用同意记录、`adminconsent` 事件。

## 五、验证（最小证据）

1. 代理链路证据：访问日志显示同时向代理与真实 IdP 的请求（含用户名与时间）。
2. 凭据证据：捕获的用户名、口令（掩码）与 OTP（若使用）。
3. 会话证据：使用捕获 Cookie 访问受保护接口的响应（含身份信息），并说明是否经过 MFA。
4. 反证记录：若被条件访问/令牌保护阻断，记录阻断点与策略。

## 六、常见误报

- 只捕获到凭据，未获得可用会话（MFA 未通过）。
- Cookie 属于测试账号自身。
- 捕获的 Cookie 因 `SameSite`/设备绑定不可用。
- 页面重定向链断裂（用户看到错误页，未提交）。

## 七、修复（客户侧）

- 推广 **FIDO2/passkey** 作为首选因素；这是唯一在架构上阻止 AiTM 的方案。
- 启用令牌保护/设备绑定（如 Token Protection、条件访问"要求受管设备"）。
- 缩短令牌寿命并启用持续访问评估；支持一键吊销用户全部会话。
- 监控：不可能旅行、新设备+新地理、同一账号短时间多处登录、`UserAgent` 异常（代理特征）。
- 邮件与浏览器层拦截新注册域与已知 phishlet 特征。

## 八、参考

- HackTricks：Phishing MFA（Via Proxy MitM / Via VNC）
- Microsoft：AiTM 钓鱼与令牌窃取缓解（含 Token Protection）
- 工具：evilginx2、muraena、EvilnVNC
