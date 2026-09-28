# 净化器与 mXSS 绕过

> 净化器（DOMPurify、sanitize-html、Bleach 等）的目标是"输出安全 HTML"。绕过它有三条路：**解析差异（mXSS）**、**上下文错配**、**非 HTML 向量**。

## 一、mXSS（mutation XSS）

原理：净化器用一套解析结果判断安全，浏览器**重新解析**后结构变化，恶意标签"复活"。

经典序列（HTML 命名空间切换 + 重解析）：

```html
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
```

```html
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```

```html
<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">
```

排查思路：在 `<math>`/`<svg>`（外来命名空间）内部创建 HTML/表格，让 `</p>`、`<style>`、`<template>`、`<noscript>` 促成破坏性重解析。

## 二、命名空间与属性混淆

- `<svg><script>` vs `<script>` 的行为差异（SVG 脚本元素、`href` 在 SVG 中可执行）。
- 属性名含空格/引号：`onerror` + `%0a`、`onerror="..."` 被拆成多个属性。
- 属性值中的 `&#x0A;`、`&#x09;` 使"事件处理器"在浏览器中被容错解析。
- `srcdoc`、`data:`、`blob:`、`<object data>`、`<embed>` 常被净化器漏掉（不在允许列表但被当"无害"）。
- `<iframe>`/`<frame>` 的 `sandbox` 缺失时的组合。

## 三、属性白名单绕过

净化器常允许 `class`/`id`/`style`：

- `style` 中的 `url(javascript:...)`（现代浏览器已忽略 `javascript:` 于 CSS，但 `background:url(http://attacker)` 可用于数据外带）。
- `id`/`class` 用于 **DOM clobbering**：`<img id="config" name="config">` 覆盖引用。
- `href`/`xlink:href` 的白名单检查若只查开头 `http`，可用 `//evil`、`https:evil`（浏览器容错为 `https://evil`）。

## 四、DOM Clobbering + 原型污染

- clobbering：用 `id`/`name` 在 `window`/`document` 上创建/覆盖属性，使库读到攻击者对象而非预期变量。
- 与"节点移除 gadget"组合可在运行时替换转义函数（见 `CSP-Bypass.md` 的 Under the Beamer）。
- 原型污染：`constructor.prototype`、`__proto__`、`prototype[<key>]` 通过 URL 解析/表单解析污染全局；配合客户端模板渲染成 XSS。
- 寻找点：`JSON.parse` + `merge`/`extend`/`defaultsDeep`/`set`（lodash、jQuery、qs、`url-parse`）。

## 五、非 HTML 向量

- Markdown 渲染：链接语法 → `javascript:`；图片语法 → `data:`；自动链接把纯文本变成链接（2025 Gemini 案例：Markdown/HTML 链接化 + 跨产品导出层把"经净化的链接"翻转为图片，绕过 URL 重写）。
- SVG 上传后在同源直接渲染（见 `../File-Upload/README.md`）。
- PDF/Office 预览器把注释内容当 HTML。
- 邮件客户端：`<style>` 中的属性和 `@import`。

## 六、验证（最小证据）

1. 给出净化器版本与被允许的 HTML（可用公开 bypass 语料对版本回归）。
2. 在**真实浏览器**中执行证据；mXSS 必须用 DOM 解析后的结构（`innerHTML` 后读取 `outerHTML`）证明结构变化。
3. 若为 clobbering：给出被覆盖的变量与受影响代码路径。
4. 若为原型污染：给出污染入口（URL/JSON）与最终 sink 的完整链。

## 七、常见误报

- 净化器输出的 HTML 里含 `<img>`，但 `onerror` 已被移除且无其他执行路径。
- payload 只在 `innerHTML` 赋值时"看起来危险"，但未插入文档树（未执行）。
- 只影响 Safari 旧版/特定浏览器 → 需注明适用范围。

## 八、修复

- 升级净化器（DOMPurify 需保持最新，并**在插入前**做净化，插入后不要再操作 HTML）。
- 采用 Trusted Types（`require-trusted-types-for 'script'`），从根上限制 `innerHTML`。
- 严格 CSP；避免 `unsafe-inline`。
- 处理外来命名空间：拒绝 `math`/`svg` 子树或使用成熟净化器而非自研正则。
- 服务端与客户端双重净化；对 Markdown 输出做 URL scheme 白名单。

## 参考

- PortSwigger：mXSS 研究、DOM clobbering、Under the Beamer（2025）
- DOMPurify 安全公告与 bypass 语料
- Aikido：Prompt-injection inside GitHub Actions（2025，链接化/内容层绕过相关链）
