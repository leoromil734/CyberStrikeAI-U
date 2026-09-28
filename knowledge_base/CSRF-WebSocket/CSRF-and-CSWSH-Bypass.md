# CSRF 与跨站 WebSocket 劫持（CSWSH）

> CSRF 的现代防御是 `SameSite` + CSRF token + Origin 校验。绕过 = 找到这三者未覆盖的请求形态。**纪律**：必须证明"跨站请求完成了敏感动作"，单纯"没有 token"不算证据。

## 一、SameSite 绕过

| `SameSite` | 绕过条件 |
|---|---|
| 未设置 | 现代浏览器默认 `Lax`；但**老浏览器**（<2020）视为 None |
| `Lax` | 顶层 **GET 导航**会带 Cookie → 找 GET 型状态变更接口；`Lax+POST` 宽限期（2 分钟内的 POST）在部分浏览器存在 |
| `None` | 必须 `Secure`，正常可跨站，直接 CSRF |
| `Strict` | 通过同站子域跳转（同站定义是 eTLD+1，跨子域仍算同站） |

其他要点：

- **同站子域**可绕过：`evil.target.com`（子域被控）→ 请求 `api.target.com` 携带 Cookie。
- 端口与协议：`http://` 到 `https://` 的 Cookie 规则差异。
- 变更 `Origin`/`Referer` 校验：仅校验是否**存在**（可用 `<meta name="referrer" content="no-referrer">` 去掉）、仅校验前缀（`target.com.evil.com`）、`null` origin（`sandbox` iframe、`data:` 文档）常被放行。
- 从 `https` 页面攻击 `http` 端点仍可带非 `Secure` Cookie。

## 二、请求形态绕过

| 目标防御 | 绕过 |
|---|---|
| 只查 `Content-Type: application/json` | 用 `text/plain` 发送 JSON 文本（后端宽松解析）；或用 `fetch` + `no-cors` 发送 `application/x-www-form-urlencoded`（当后端接受）；或表单 `enctype="text/plain"` 构造 JSON 语法 |
| 要求自定义头（`X-Requested-With`） | 除 CORS 预检外的头无法跨站添加 → 转向 **CSWSH** 或找到不做预检的端点 |
| 依赖 `Referer` 含域名 | `no-referrer`、`rel="noreferrer"`、从 HTTPS 到 HTTP 时 Referer 被裁剪 |
| 依赖 token 在 Header | 找 token 在 Cookie 中的路径、或 token 可预测 |
| 只保护 POST | 检查 PUT/PATCH/DELETE/`_method=POST`（方法覆写） |
| 多步流程 | 逐步跨站触发（每步都是简单请求） |

## 三、JSON CSRF 手法

```html
<form action="https://api.target/add" method="POST" enctype="text/plain">
  <input name='{"a":"b","role":"admin","x":"' value='"}'>
</form>
```

- 生成 body：`{"a":"b","role":"admin","x":"="}`。当后端用宽松 JSON 解析（或去尾部 `=`）即成功。
- 变体：`Content-Type: application/json` 通过 `fetch` 在**同源**脚本中设置后重定向（部分场景）；或利用 `navigator.sendBeacon`。
- 结合**同站子域**：把恶意页面托管在子域上，即可自由设置头与 `Content-Type` → 完全绕过头相关防御。

## 四、CSWSH（跨站 WebSocket 劫持）

WebSocket 握手**不适用 CORS**：浏览器发送 `Origin`，但服务端若不校验，跨站页面即可完成握手并读写消息。

```js
const ws = new WebSocket("wss://target.example/graphql-ws");
// 浏览器自动带上 Cookie（同站/None+Secure 场景）
```

关键点（2025 研究）：

- WebSocket 可访问的 **GraphQL 端点** 可绕过"需要预检的 CSRF 防护"：查询/变更全部走 WS 消息，不受 CORS 限制。
- **Private Network Access（PNA）不适用于 WebSocket** → 跨源 WebSocket 仍可连到内网 IP 服务（localhost、192.168.x.x），可做内网探测/交互。
- 需要拿到响应时，用 WS 的返回消息（不像 CSRF 那样"盲打"，CSWSH 往往是**可读的**）。

检测步骤：

1. 找到 WS 端点（`/ws`、`/socket.io`、`/graphql-ws`、`/cable`）。
2. 手动握手确认服务端是否校验 `Origin`（用错误 Origin 发送握手，看是否 101）。
3. 从**另一个域**的页面发起连接，验证能否读写。
4. 若可读 → 升级为数据窃取；若可写 → 升级为状态变更。

## 五、验证（最小证据）

1. 受害者视角的请求与结果（跨站页面 + 服务端状态变化）。
2. 说明 Cookie 是否实际携带（`SameSite` 实测，必要时用浏览器开发者工具）。
3. CSWSH 需给出 101 握手 + 消息交互证据（含错误 Origin 测试）。
4. 若只是"缺少 CSRF token"，记为配置缺陷并说明可达性。

## 六、常见误报

- 页面 no-cors 请求发出但服务端因校验拒绝（无状态变化）。
- 只在禁用 SameSite 的测试浏览器中复现。
- WS 握手 101 但后续因认证失败立即关闭 → 无实际影响。
- 应用有 Origin 校验但测试时用了错误 Host 导致 101（误判）。

## 七、修复

- 敏感状态变更只用 POST/PUT/DELETE + **CSRF token（与用户会话绑定，一次性）**。
- 校验 `Origin`（严格匹配，允许值时不用前缀匹配），并拒绝缺失 Origin 的写请求。
- Cookie 用 `SameSite=Lax/Strict` + `Secure` + `HttpOnly`；跨站场景用 `__Host-` 前缀。
- WebSocket：握手时校验 `Origin` 与会话绑定令牌（不能用 Cookie 隐式认证），消息级也要鉴权。
- 禁用方法覆写（`_method`）或对其也做 token 校验。

## 参考

- PortSwigger：CSRF、WebSocket 安全
- IncludeSecurity：Cross-Site WebSocket Hijacking Exploitation in 2025
- OWASP：CSRF Prevention Cheat Sheet
