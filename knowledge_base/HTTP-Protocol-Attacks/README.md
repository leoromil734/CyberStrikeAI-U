# HTTP 协议层攻击总览

> 这一类的共同点：**攻击发生在 HTTP 语义层，而不是应用参数层**。因此常常绕过 WAF、绕过应用逻辑，甚至跨越租户。

## 分类

| 类别 | 本质 | 文档 |
|---|---|---|
| 请求走私 / 去同步 | 前后端对请求边界理解不同 | `Request-Smuggling.md` |
| 缓存投毒 / 缓存欺骗 | 缓存键与源站语义不一致 | `Cache-Poisoning-Deception.md` |
| HTTP/2、HTTP/3 专项 | 多路复用与降级引入的语义差 | `HTTP2-HTTP3-Attacks.md` |
| 客户端路径穿越（CSPT） | 前端拼接 URL 与后端路由不一致 | `Client-Side-Path-Traversal.md` |
| Host 头攻击 | 服务端用 Host 生成 URL/路由 | `Host-Header-Attacks.md` |
| CRLF / 响应拆分 | 换行注入到 Header | 见 `WAF-Bypass/Encoding-and-Obfuscation.md` |

## 共同的判定纪律

1. **不要求 WAF 放行**：走私/投毒常对 WAF 透明，判定依据是**别人的请求受影响**。
2. **先探测差异，再构造利用**：用半隐藏头（`Host` / `Xost`、前导空格）探测 前端-后端 解析分歧（V-H / H-V）。
3. **区分"我自己的响应异常"与"影响他人"**：只有后者才是高危。
4. **复现窗口**：这类漏洞对连接池、时序敏感，必须记录完整的请求序列与重放步骤。
5. 生产环境慎用 DoS 类副作用；优先用"读取到他人数据"作为证据。

## 通用探测清单

- 同一请求里同时给 `Content-Length` 与 `Transfer-Encoding`（含混淆写法）。
- 给请求加上 `Expect: 100-continue`。
- 在 Header 名前加空格/制表符，制造"隐藏"头。
- 用 `HEAD`、`GET`、`POST` 交叉组合触发早响应（early-response gadget）。
- 对静态资源路径发送带 body 的 GET（CL.0 场景）。
- 观察 `Lenght`/拼写错误头的处理差异。
- 对比带/不带缓存键（cache-buster）的行为差异 —— 差异本身就是线索。

## 验证（最小证据）

1. 请求序列原文（含逐步的响应状态码）。
2. 可观测影响：他人会话的响应片段、缓存内容被替换、到达内部路径。
3. 抗辩证据：换连接/换时间仍可复现（或说明依赖条件）。
4. 明确写出前置条件（前端/后端软件栈、是否共享连接池）。

## 常见误报

- 前后端差异存在但**不共享连接池**（无跨用户影响）→ 结论降级为"解析不一致"。
- 只有 400/500 而无跨用户影响的"mystery 400"。
- 缓存返回陈旧内容（正常的 TTL 行为）被当作投毒。
- CDN 的边缘拦截导致观察不到后端行为。

## 修复

- 全链路使用 HTTP/2+（上游连接亦如此），避免 H1 上游。
- 前端与后端使用同一 HTTP 解析实现；拒绝歧义请求（同时含 CL/TE、非法头名、超长 chunk 扩展）。
- 缓存键包含所有影响语义的输入（Host、Cookie、认证头、方法、路径规范化形式）。
- 禁用 `X-Forwarded-*` 的隐式信任；对 Host 做白名单。
- CRLF：所有 Header 输出做字符过滤。

## 参考

- PortSwigger：HTTP/1.1 must die（2025）、HTTP Desync Attacks、Web Cache Deception
- w4ke：Funky chunks（2025）
- Assured：The Single-Packet Shovel（2025）
- YesWeHack：HTTP request smuggling 终极指南
