# 缓存投毒与缓存欺骗

> 两者都利用"缓存键 ≠ 语义输入"这一事实。**投毒**是让缓存保存攻击者构造的响应给其他人；**欺骗**是让受害者的私有响应被缓存下来给攻击者读。

## 一、缓存键 vs 语义输入

缓存键通常只含：`scheme + host + path (+ query 视配置)`。

但响应可能取决于：

- `Host`、`X-Forwarded-Host`、`X-Forwarded-Scheme`、`X-Forwarded-Port`
- `X-Original-URL`、`X-Rewrite-URL`
- `Cookie`、`Authorization`（若未标记 `private`）
- `Accept-Language`、`User-Agent`（移动版/桌面版分流）
- 请求方法、`Content-Type`
- 路径规范化（`/a/../b` 与实际命中不同）

**Unkeyed input** 就是投毒入口。

## 二、缓存投毒流程

1. 找到 Unkeyed 输入（常见：`X-Forwarded-Host`、`X-Host`、`X-Forwarded-Scheme`、`X-Original-URL`）。
2. 构造响应差异（例如让页面里的资源 URL 指向攻击者域 → 后续 XSS；或直接注入 `<script>`）。
3. 触发缓存（观察 `X-Cache: hit`、`cf-cache-status: hit`、`Age`）。
4. 请求干净 URL，确认返回被污染的响应。

```http
GET /en/page?cb=1 HTTP/1.1
Host: target.example
X-Forwarded-Host: evil.example
```

缓存成功后：

```http
GET /en/page HTTP/1.1
Host: target.example
→ 200，内容中的链接指向 evil.example（持久化 XSS）
```

## 三、缓存欺骗流程

1. 目标把 `/<敏感路径>/<伪造静态后缀>` 视为可缓存。
2. 诱导已登录受害者访问该 URL（图片、`<script>`、预取）。
3. 攻击者请求同一 URL，从缓存中读取受害者私有数据。

```text
/account/profile        → 私有，no-store（正常）
/account/profile/x.css  → 框架忽略尾部，返回 profile 内容，但缓存器认作 .css 可缓存
```

变体：`;.css`、`.css` 后加 `/`、`%2F`、`?` 后路径、`/..;/`、编码后的 `.css`。

## 四、2025 相关新手法

- **重定向缓存的隐蔽通道**：`CL.0` 去同步污染 3xx 的 `Location`，把 C2 地址写进缓存（malicious.group 2025）。
- **框架内部头被滥用**：伪造框架内部头与数据请求机制链式组合，把 SSR JSON 强制缓存为 HTML（Next.js 系列，zhero-web-sec 2025），导致缓存投毒 DoS 与存储型 XSS。
- **竞态 + 键碰撞**：让多个失败请求碰撞到同一错误缓存键，泄漏瞬时变体（"Eclipse on Next.js" 2025）。
- **客户端路径穿越（CSPT）** 与缓存结合可伪造 API 响应（见 `Client-Side-Path-Traversal.md`）。

## 五、验证（最小证据）

1. 请求序列：投毒请求（附缓存状态头）+ 干净请求（返回被污染内容）。
2. 证明影响他人：用不同 IP/Cookie 的第二次请求仍拿到污染内容。
3. 缓存欺骗：受害者视角的响应含其私有数据，且攻击者无凭证可读到。
4. 记录缓存层（CDN/Varnish/nginx/framework cache）与 TTL。

## 六、常见误报

- 响应被缓存但内容是公开的（无影响）。
- `X-Cache: HIT` 但 URL 含 cache-buster，实际是本次请求命中。
- 本地浏览器缓存（非共享缓存）导致的假象。
- 只有自己账号可见的内容（不是跨用户）。

## 七、修复

- 缓存键包含所有影响输出的输入；把所有未列入键的输入视为不可信并禁止其影响响应。
- `Set-Cookie`/`Authorization` 响应标 `Cache-Control: private, no-store`。
- 静态资源前缀与动态路由严格区分，禁止"路径后缀即静态"的推断。
- 反向代理层拒绝 `X-Forwarded-*`/`X-Original-URL` 等来自客户端的伪造。
- 归一化路径后**再**做缓存判定，避免 `/a/../b` 歧义。

## 参考

- PortSwigger：Web Cache Poisoning / Cache Deception
- zhero-web-sec：Next.js cache and chains（2025）
- malicious.group：Smuggling with CL.0 for C2（2025）
