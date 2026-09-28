# 客户端路径穿越（CSPT）与 Host 头攻击

## 一、客户端路径穿越（Client-Side Path Traversal）

前端把用户输入拼进 API 路径时，`../` 会让浏览器请求**另一个端点**。

```js
fetch(`/api/v1/users/${userId}/profile`)   // userId = "../../admin/users"
→ GET /api/v1/admin/users/profile
```

要点：

- 不在浏览器 URL 栏显示（因为 `fetch` 的 URL 是脚本构造的），因此不触发常规的"路径规范化可见性"。
- 常用于让"受信任的响应"落到攻击者可控的位置，从而伪造 API 响应、触发 DOM XSS、绕过 CSRF token 绑定。
- 编码变体：`%2e%2e%2f`、`..%2f`、`%2e%2e/`、反斜杠（浏览器在部分 API 中把 `\` 当 `/`）、双重编码。
- 与服务端路由结合：前端 `fetch` 用 `encodeURIComponent` 缺失时最常见。

### 利用链（典型）

1. CSPT 让 API 请求打到**用户可控内容**的端点（如 `/api/upload/<我的文件>` 或一个 JSON 回显接口）。
2. 该响应被前端当作"可信 API 响应"解析 → 伪造字段（如 `email`、`role`、`url`）。
3. 若响应内容进入 DOM sink → DOM XSS；若影响 OAuth 跳转 → 账号接管。

### 验证

1. 给出前端代码中被拼接的位置（源码或构建产物）。
2. 触发请求显示实际路径跨越（用 Burp/代理记录真实请求）。
3. 影响证据：伪造响应被消费、XSS 执行、或敏感字段被替换。

### 修复

- 前端对路径参数使用 `encodeURIComponent`；后端对路径做严格白名单。
- 后端路由不接受被前端"拼接"覆盖的语义端点（避免"前缀 + 用户输入"的结构）。
- 对返回给前端的"可信响应"加上绑定校验（nonce/签名）。

## 二、Host 头攻击

服务端用 `Host` 生成绝对 URL、发邮件链接、做缓存键或路由时，如果 `Host` 来自客户端且未校验：

| 后果 | 说明 |
|---|---|
| 密码重置链接投毒 | 重置邮件中的域被改为攻击者域 → 令牌窃取 |
| 缓存投毒 | `Host` 进入缓存键/未键输入（见 `Cache-Poisoning-Deception.md`） |
| 路由绕过 | vhost 级 ACL 被伪造的 Host 绕过 |
| SSRF/内部访问 | 内部服务用 Host 拼接下游 URL |
| XSS | Host 反射进页面（含 `javascript:` 与 `"` 等） |
| Web cache deception + Host | 组合得到跨用户读取 |

### 绕过校验的 Host 变体

```text
Host: evil.com
Host: target.com.evil.com
Host: target.com:evil.com
Host: evil.com#target.com
Host: target.com@evil.com
Host: target.com%00.evil.com
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-Host: evil.com
Host: TARGET.com.        （尾点）
Host: target.com:PORT    （端口混淆）
```

绝对 URL 形式：请求行直接写 `GET https://evil.com/ HTTP/1.1`，部分服务器用该 URL 的 host。

### 验证（最小证据）

1. 受影响功能（重置邮件、跳转、缓存）中的**输出**包含攻击者域。
2. 端到端证明：收到含攻击者域的邮件链接 / 缓存返回被污染内容 / 访问到内部 vhost 内容。
3. 仅"Host 未被校验"但无法体现到任何输出 → 结论降级。

### 修复

- 配置层固定 ServerName 与默认 vhost，拒绝未知 Host（`return 444`）。
- 应用层维护 Host 白名单（含端口），生成绝对 URL 时只使用白名单值。
- 反向代理剥离客户端提供的 `X-Forwarded-Host`/`X-Original-URL`，由代理层写入可信值。
- 严格规范化 Host（小写、去尾点、拒绝 userinfo/端口混入）。

## 参考

- PortSwigger：Host header attacks、Client-side path traversal（Renwa 2025 汇总）
- YesWeHack：syntax confusion（2025）
