# 浏览器侧绕过总览

> "浏览器侧"= 攻击效果发生在受害者浏览器中，且绕过的是**浏览器的安全机制**（CSP、SOP、SameSite、权限提示、缓存）。这类漏洞常被当作"只是 XSS 的辅助"，实际上 2025 年的研究把它做成了独立攻击面。

## 分类

| 目标机制 | 绕过思路 | 文档 |
|---|---|---|
| CSP | nonce 复用、script gadget、响应拆分、可信第三方 | `CSP-Bypass.md` |
| HTML 净化器 | mXSS、命名空间混淆、DOM clobbering、原型污染 | `Sanitizer-and-mXSS-Bypass.md` |
| SOP | XS-Leaks（侧信道）、CORB/COEP 边界 | 本篇"侧信道" |
| SameSite / CSRF | CSWSH、JSON CSRF、导航型请求 | `../CSRF-WebSocket/CSRF-and-CSWSH-Bypass.md` |
| 权限（相机/位置） | 点击劫持 + 权限提示交互 | 本篇"权限滥用" |
| 缓存 | bfcache/disk cache 复用已泄漏的 nonce | `CSP-Bypass.md` |

## 一、侧信道（XS-Leaks 家族）

即"没有注入也能读信息"。常用信号：

- **ETag 长度泄漏**：跨站读取响应头长度差异（部分浏览器仍可），配合 431/导航失败检测（2025 "Cross-Site ETag Length Leak"）。
- **连接池与主机排序**：用连接耗尽 + 确定性排序推断跨站请求的最终目标域（2025 "XSS-Leak: Leaking Cross-Origin Redirects"）。
- **frame counting / onload 差异**：基于 `window.length`、错误页与成功页差异。
- **CSS 选择器 oracle**：`:valid`、`@container`、字体连字宽度（Fontleak 2025），可无网络请求地逐字符读取。
- **导航阻塞与 history 泄漏**：检测"跳转是否被拦截"（2025 "Stopping Redirects"）。

判定纪律：侧信道结论必须给出**统计显著性**（多次采样、基线对比、误报率），单次差异不算。

## 二、SOP 相关的常见组合拳

- 用 `about:blank` / `window.open` + `document.domain` 遗留在子域间穿越。
- `postMessage` 未校验 `origin` → 跨站消息驱动 DOM sink。
- `window.name` 跨域持久化作为数据通道。
- JSONP/`<script src>` 加载跨域数据（若端点可被当作脚本）。

## 三、权限滥用（Permission Jacking）

- DOM-based **扩展点击劫持**：把密码管理器自动填充 UI 隐藏/移位，用户一次误点即把凭据填入攻击者字段（2025）。
- Safari TCC 提示可被覆盖点击（相机/麦克风/位置）（2025）。
- 通过被嵌入的第三方小组件（客服/反馈 widget）继承已委派权限，实现规模化滥用。
- 防御视角：权限提示必须与真实用户意图绑定（不能用 CSS 控制位置）。

## 四、客户端路径穿越与 SPA 路由

见 `../HTTP-Protocol-Attacks/Client-Side-Path-Traversal.md`：前端拼接 URL 的规范化差异可伪造 API 响应，进而影响 DOM 与 OAuth 流程。

## 五、浏览器缓存

- **bfcache → disk cache 回退**：让页面复用已泄漏的 CSP nonce 重新缓存可注入内容（Jorian Woltjer 2025 "Nonce CSP bypass using Disk Cache"）。
- `cache-control`/`Vary` 配置不当导致的跨用户内容复用（与 `../HTTP-Protocol-Attacks/Cache-Poisoning-Deception.md` 联用）。

## 六、验证（最小证据）

1. 明确绕过的是哪个机制（用对照实验：禁用该机制后行为是否变化）。
2. 真实浏览器环境复现（无头浏览器 + 明确步骤脚本），不用 curl 断言"浏览器行为"。
3. 侧信道需给出统计与阈值。
4. 权限/点击劫持类需给出用户交互序列（谁在什么位置点了什么）。

## 七、常见误报

- 用 `curl`/Python 得到的差异被当作"浏览器 SOP 绕过"。
- CSP 报错存在但 payload 实际未执行（只看到 console 报错）。
- 侧信道单次命中（噪声）。
- 点击劫持理论可行但页面有 `X-Frame-Options`/`frame-ancestors` 阻断。

## 八、修复（横向）

- CSP 使用 nonce + `strict-dynamic`，并消除 script gadget（不要用 `querySelector` 取可控元素的 value/src）。
- 净化器升级并做多层防护（服务端净化 + 客户端 Trusted Types）。
- 敏感响应加 `Cache-Control: private, no-store`；禁用对敏感数据的跨域可观测性（`Cross-Origin-Resource-Policy`、`SameSite=Strict`）。
- 权限提示不可被 CSS 遮蔽（平台层修复），敏感操作二次确认。
- 所有 `postMessage` 严格校验 `origin` + `source`。

## 参考

- PortSwigger：Hunting nonce-based CSP bypasses（2021）、Permission Hijacking at Scale（2025）、Nonce CSP bypass using Disk Cache（2025）、Fontleak（2025）
- marektoth：DOM-based Extension Clickjacking（2025）
