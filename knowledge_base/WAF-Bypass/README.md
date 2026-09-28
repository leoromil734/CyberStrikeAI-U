# WAF / 过滤器绕过总览

> 把"被 WAF 拦了"变成"证据链里的一个变量"。WAF 只是中间件，**绕过成功的判据是业务层真实产生了恶意效果**，而不是响应从 403 变成 200。

## 判定纪律

1. 先建立**被拦基线**：记录原始 payload 的状态码、响应体标记（如 `Attention Required`、`Request blocked`、`cf-ray`）、延迟。
2. 每次只改一个维度（编码 / 位置 / 协议 / 时序），记录成对结果。
3. 绕过成功必须落到可验证的业务效果：SQL 报错差异、执行回显、带外回调、数据越权。
4. 无法确认是哪种拦截（WAF、应用层、CDN、限流）时，记 `inconclusive`，不要记"绕过成功"。

## 六个绕过维度

| 维度 | 常用手法 | 关联文档 |
|---|---|---|
| 语法 | 注释、空白、大小写、等价函数、关键字拆分 | `SQLi-WAF-Bypass.md`、`XSS-Bypass-Techniques.md` |
| 编码 | 多重 URL 编码、Unicode 归一化、宽字节、Base64/分块传输 | `Encoding-and-Obfuscation.md` |
| 位置 | Header、Cookie、JSON 深层、multipart 文件名、路径段、碎片参数（HPP） | 各注入文档 |
| 协议 | chunked 分块、HTTP/1.1 拆包、H2 降级、请求走私 | `HTTP-Protocol-Attacks/Request-Smuggling.md` |
| 解析差异 | WAF 解析器与后端解析器对同一输入理解不同 | `Parser-Confusion-Bypass.md` |
| 时序/资源 | 慢速发送、分片延迟触发检测超时、单包竞态 | `Race-Condition/README.md` |

## 常见 WAF 特性与可利用点

- **正则规则**：对长度、深度、嵌套层数有上限。超长噪声填充、深层 JSON 嵌套可让检测失效。
- **缓冲区**：chunked 或超大 body 只检查前 N KB，payload 放到 N KB 之后。
- **解码次数**：只解一次编码，后端解两次 → 双重编码。
- **参数合并**：WAF 取首个同名参数，后端取最后一个 → HPP。
- **JSON 解析**：WAF 用宽松解析器（重复键、注释），后端用严格解析器（或反之）。
- **字符集**：`Content-Type: text/plain; charset=ibm037` 之类的字符集混淆。
- **HTTP/2 → HTTP/1.1 降级**：降级过程引入新的长度语义（详见 `HTTP-Protocol-Attacks/HTTP2-HTTP3-Attacks.md`）。
- **来源信任**：`X-Forwarded-For`/内网 IP 被信任后跳过检测。

## 反指纹与速率

- 命中拦截后立即降速，避免 IP 封禁污染后续测试结论。
- 单变量重放，不要把"换了 UA + 换了 payload + 换 IP"混在一起。
- 记录时间戳，区分真绕过与限流冷却后的恢复。

## 验证（最小证据）

1. 原始 payload → 被拦（状态码/标记）。
2. 变体 payload → 通过**且**触发业务层可观测效果。
3. 说明通过原因（哪一个维度变化导致），否则无法复用。
4. 无法落地业务效果时，结论写"WAF 可被部分绕过（未证实影响）"。

## 常见误报

- 403 → 200 但返回的是通用错误页或空壳页面。
- 应用本身返回 200 而 WAF 只记录不拦截。
- 把 CDN 的 JS Challenge 页面当成"绕过失败"（那是需要浏览器流程，见 `CDN-TLS-Fingerprint/README.md`）。
- 目标变更（灰度、缓存）导致前后不一致。

## 修复（防御视角）

- 规则不在客户端做唯一防线，关键校验放在业务层（参数化、编码、白名单）。
- 统一解析器与后端一致（同一 HTTP 库、同一 JSON 解析器），消除解析差异。
- 拦截日志与业务日志关联，避免"被绕过却无感知"。
- 定期用已知绕过语料回归测试规则集（如 CRS 的 paranoia level 提升）。

## 工具

`wafw00f`（指纹）、`nuclei`（线索）、`ffuf`（变体批量对比，注意速率）、`execute-python-script`（自定义编码/分块请求）。

## 参考

- OWASP CRS、PortSwigger WAF bypass 系列
- PayloadsAllTheThings：WAF Bypass
