# 编码与混淆绕过

> 当一个 payload 被拦，最先怀疑的应是"编码层"。本篇按**解码发生的位置**组织，因为绕过的本质是让检测器与执行器看到的字节不同。

## 解码层模型

```text
客户端编码 → 传输(URL/HTTP) → CDN/WAF 解码 → 应用框架解码 → 业务/DB 驱动解码 → 执行
                  ↑ 检查点通常在这里          ↑ 真正的执行语义在这里
```

绕过 = 在检查点之后还有一次解码。

## 一、多次编码

- 双重 URL 编码：`%2527` → 解一次得 `%27` → 再解得 `'`。
- 混合编码：`%25%32%37`、HEX 与 URL 混用。
- 表单与 URL 双解析：`application/x-www-form-urlencoded` 中 `+` 与 `%20` 差异。
- Base64 嵌套：JSON 字段内 Base64，后端再解码。

## 二、Unicode 归一化（2025 重点）

- **Best-fit / 虚拟混淆字符**：`＜`(U+FF1C)、`＇`(U+FF07)、`∕`(U+2215)、`：`(U+FF1A) 在 NFKC 后被映射为 ASCII。
- **截断与溢出**：某些归一化实现在长输入或孤立代理对（surrogate）时截断尾部，导致校验与执行看到不同字符串。
- **UTF-7/UTF-16 混用**：`+ADw-` 之类在特定解码器下变成 `<`。
- 关键：**先确认目标在哪一层做归一化**（框架路由？参数解析？DB 驱动？），再决定用哪种映射。PortSwigger《Lost in Translation》给出可复用方法论。

## 三、字符集与宽字节

- GBK 宽字节：`%df%27`、`%bf%27`、`%81%27` —— 转义符与前一字节组成合法多字节。
- charsets 混淆：`Content-Type: application/json; charset=ibm037`、`charset=utf-7`。
- 空字节：`%00`、`\x00`、`%2500` —— 截断基于 C 字符串的校验。
- 换行族：`%0a`、`%0d`、`%0d%0a`、`%e5%98%8a%e5%98%8d`（UTF-8 编码的 CRLF，用于响应拆分）。

## 四、语法层混淆（不改变语义）

- 注释：`/**/`、`--`、`#`、`/*!...*/`、XML `<!-- -->`。
- 空白：Tab、VT(`%0b`)、FF、NUL、Unicode 空白（U+00A0、U+2000 系列）。
- 大小写与命名空间前缀：`ScRiPt`、`<svg:script>`。
- 等价结构：`onerror` ↔ `onload` ↔ `onbegin`；`innerHTML` ↔ `insertAdjacentHTML`。
- 隐式转换 gadget：`toString`/`valueOf` 触发无括号函数调用，绕过形如 `\w+\(` 的规则。

## 五、传输层混淆

- `Transfer-Encoding: chunked` 分块，让关键字跨 chunk 边界。
- `Content-Encoding: gzip/deflate` 后 WAF 不解压（或只解压一层）。
- HTTP/2 伪头与 `:path` 特殊字符；H2→H1 降级时的长度重解释。

## 验证方法

1. 写一个"最小可判"payload（能产生唯一可观测效果，如 SQL 报错字符串、`document.title` 变更）。
2. 对同一 payload 生成编码变体表，逐条发送并记录状态码 + 响应差异 + 延迟。
3. 至少保留两条证据：被拦版本 + 通过版本，且**执行效果**可见。
4. 记录目标是"无归一化""单次归一化"还是"多次"，写成结论，方便复用。

## 常见误报

- 编码后返回 200，但业务层把 payload 当作普通字符串存储（未执行）。
- 归一化只发生在客户端 JS（浏览器），服务端并未执行。
- 用孤儿字节（非法 UTF-8）触发的 500 被误判为"绕过成功"。

## 修复

- 在**最靠近执行点**的位置做校验，且校验前完成全部解码与归一化（先归一化再白名单）。
- 禁用不必要的字符集与 `charset` 覆盖；拒绝非法编码序列。
- 统一编码链路：CDN、框架、DB 驱动使用同一规范（UTF-8 + 明确归一化形式）。

## 参考

- PortSwigger：Lost in Translation: Exploiting Unicode Normalization（2025）
- Trail of Bits：Unexpected security footguns in Go's parsers（2025）
- OWASP CRS 规则说明、PayloadsAllTheThings
