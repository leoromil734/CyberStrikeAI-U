# 解析器差异与语法混淆（Parser Confusion）

> 2025 年最"可复用"的一类手法：**同一个字节串被两个组件理解成不同东西**。它是 SSRF 白名单绕过、鉴权绕过、请求走私、缓存投毒的共同根因。

## 为什么有效

链路中至少有两次解析：

```text
原始字节 →[校验器/网关]→ 中间表示 →[业务/DB/模板/其他服务]→ 实际效果
```

只要两侧对同一输入的解释不同，攻击者就能让"被校验的那个"和"被执行的那个"不一致。

## 一、URL / Host 解析差异

- userinfo：`https://trusted.com@evil.com`（多 `@` 时最后一个 `@` 才是分隔符，但很多校验器取第一个）。
- IPv6 多 `@`：`https://[::1]@evil.com`、`https://evil.com@[::1]` —— 曾在 Google Cloud OAuth 回环白名单绕过中用于窃取授权码。
- 反斜杠：`https://trusted.com\@evil.com`（WHATWG 视 `\` 为 `/`）。
- 端口解析：`https://trusted.com:80@evil.com:443`、前导零端口。
- 大小写与尾点：`TRUSTED.com.`、`trusted.com%2e`。
- 路径规范化：`/admin/../public`、`//admin`、`/%2e%2e/admin`、分号参数 `/admin;x=y`。

## 二、JSON / XML 解析差异

- **重复键**：`{"role":"user","role":"admin"}` —— 有的取首个，有的取末个，有的同时保留。
- **大小写不敏感匹配**：Go 的 `encoding/json` 会把 `Role`/`ROLE` 匹配到 `role` 字段（Trail of Bits 2025），配合重复键可造成鉴权分歧。
- **类型混淆**：`{"role":["admin"]}`、`{"role":{"$ne":null}}`（Prisma 类型混淆 → 操作符注入）。
- **XML**：前导/尾随垃圾容忍、属性命名空间被忽略（`xmlGetProp` 忽略 namespace）、`ID` 与 `samlp:ID` 同名冲突（见 `Authentication-Bypass/SAML-XSW-Bypass.md`）。
- **属性顺序**：`<x ID="1" ns:ID="2">` 与 `<x ns:ID="2" ID="1">` 在不同解析器返回不同值。

## 三、multipart / 表单解析差异

- `Content-Disposition` 参数解析：引号、转义、重复 `filename`、`filename*`（RFC 5987）优先级不同。
- boundary 边界歧义，使同一个 body 被切成不同部分。
- `name` 与 `name[]`，以及同名多次（HPP）：WAF 取首个、后端取末个。

## 四、邮件与字符串语义（访问控制绕过）

- 邮箱原子分割（`Splitting the Email Atom`，PortSwigger 2025）：`victim@company.com` 与 `victim@company.com@evil.com`、Unicode 变体、注释 `user(comment)@company.com` 在不同解析器下等价/不等价，从而绕过"域名后缀即权限"的校验。
- 因而**不要用邮件域名后缀做访问控制**。

## 五、HTTP 层

- `Content-Length` vs `Transfer-Encoding` 的优先级差异（CL.TE/TE.CL/TE.TE/CL.0/TE.0）见 `HTTP-Protocol-Attacks/Request-Smuggling.md`。
- chunk 扩展与行终止符歧义（`EXT.TERM`、溢出行）。
- H2→H1 降级引入第四种长度语义（H2 length）。

## 六、Go 解析器专项（2025）

Trail of Bits 总结的组合拳：

1. JSON 键大小写不敏感 + 重复键后者覆盖
2. XML 容忍前后垃圾
3. 跨格式 polyglot：同一份输入既是合法 JSON 又是合法 XML 的片段

→ 同一请求经过不同微服务（一个用 JSON 解析，一个用 XML 解析）时，权限判定不同。

## 检测方法

1. 找出链路中所有解析点（网关、WAF、业务框架、序列化库、DB 驱动、下游服务）。
2. 对每个解析点构造**最小分歧输入**：写一个同时满足两种解释的 payload，观察行为差异。
3. 用"半隐藏头"探测法（HTTP Request Smuggler v3 的思路）：`Host` + 形近头（`Xost`）或前导空格，比对响应差异，判断 V-H / H-V 结构。
4. 记录分歧方向（可见-隐藏 / 隐藏-可见），因为利用方式不同。

## 验证（最小证据）

1. 同一字节串，两个解析点产生不同业务结果（如鉴权通过 vs 拒绝）。
2. 可复现的请求原文与两次响应。
3. 影响结论：绕过的是哪一层校验。

## 常见误报

- 差异存在但不在安全边界上（两个解析点都不参与权限判断）。
- 差异只导致 500，无权限差异。
- 前端 JS 解析差异（与后端无关）。

## 修复

- 全链路**同一解析器/同一库版本**；网关与后端使用相同 HTTP/JSON/XML 实现。
- 拒绝歧义输入：重复键、同名属性、超长/异常编码直接 400。
- 校验使用"规范化后的中间表示"，且该表示就是后续处理所用的表示（避免二次解析）。
- 不要在权限判断中依赖字符串后缀、邮箱域名、Host 名等易混淆语义。

## 参考

- PortSwigger：HTTP/1.1 must die（2025）、Splitting the Email Atom（2025）、The Fragile Lock（2025）、Parser Differentials 演讲（2025）
- Trail of Bits：Unexpected security footguns in Go's parsers（2025）
- YesWeHack：The minefield between syntaxes（2025）
