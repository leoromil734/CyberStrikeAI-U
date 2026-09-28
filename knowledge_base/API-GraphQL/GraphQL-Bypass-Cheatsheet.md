# GraphQL 绕过速查

> GraphQL 把"多个 REST 端点"合并为"一个端点 + 查询语言"，于是**授权、限流、缓存**这三层的传统假设全部失效。

## 一、侦察

```graphql
{ __schema { types { name fields { name } } } }
{ __type(name:"User"){ fields { name type { name } } } }
```

- 关闭 introspection 时：
  - **字段建议（field suggestions）**：故意写错字段名，错误信息会提示 `Did you mean "email"?` → 可逐层枚举 schema（常见于 Apollo/graphql-js）。
  - 拼写变体探测、`__typename` 探测、错误信息差异（`Cannot query field` vs `null`）。
  - 用 REST/前端 JS 中的查询片段（`gql` 模板、`*.graphql` 文件、sourcemap）还原 schema。
- 端点变体：`/graphql`、`/graphql/`、`/graphiql`、`/v1/graphql`、`/api/gql`；GET 与 POST 均试。

## 二、授权绕过

- 同一端点，不同字段的**字段级授权**差异：`me { email }` 被限制，但 `user(id:1) { email }` 未限制。
- `node(id: "...")`：全局 ID + `edges/node` 关系遍历，跨用户拿对象。
- 批量请求（batching）绕过限流：一个请求里 N 个操作。
- 别名（aliases）绕过限流：一个请求里同一字段 N 个别名。
- `@include`/`@skip`、`fragment` 展开造成字段校验遗漏。
- 变更（mutation）的参数校验常弱于查询。

## 三、DoS 与资源耗尽

- 别名爆破（alias overloading）、深层嵌套（`user{friends{friends{...}}}`）。
- 循环引用（`comment{author{comments{author{...}}}}`）。
- 片段递归炸弹、`@defer`/`@stream` 滥用、`n+1` 查询放大。
- 需要在**授权范围内**谨慎验证（不要打挂生产）。

## 四、注入与提交面

- 参数进入 SQL/NoSQL/命令/模板 → 复用 `../SQL Injection/`、`../NoSQL-Injection/README.md`、`../SSTI/README.md` 的手法。
- 变量类型混淆：把 `String` 传数组/对象（`{"id":["1","2"]}`）、`{"id":{"$ne":null}}`。
- 文件上传 mutation（GraphQL multipart 规范）→ 走 `../File-Upload/README.md`。
- SSRF：`importFromUrl`、`fetchRemoteSchema`、webhook 参数。

## 五、传输与缓存

- **GET 查询被 CDN 缓存** → 可能缓存了带认证信息的响应（配合缓存键看 `Authorization` 是否在键内）→ `../HTTP-Protocol-Attacks/Cache-Poisoning-Deception.md`。
- **WebSocket（graphql-ws）**：不受 CORS 预检约束 → 跨站可读写（CSWSH）→ `../CSRF-WebSocket/CSRF-and-CSWSH-Bypass.md`。
- **batched HTTP**：`[{...},{...}]` 数组请求，限流器常只算 1 次。
- APQ（Automatic Persisted Queries）：`sha256Hash` 可被枚举/绕过校验。

## 六、验证（最小证据）

1. 完整查询与响应（含错误信息）。
2. 授权绕过：两个身份对照 + 拿到的他人字段值。
3. 限流绕过：给出"REST 端点会被 429、GraphQL 别名 N 次不触发"的对照证据。
4. DoS 类：只做小规模证明（如单请求耗时随嵌套层数指数增长），并说明影响。

## 七、常见误报

- 关闭 introspection 后把"字段建议错误"当成"schema 泄漏"（需展示实际获取到的敏感字段）。
- 别名批量被服务端按子操作计数（限流有效）。
- 缓存返回的是无凭证响应。

## 八、修复

- 生产关闭 introspection 与 GraphiQL；关闭字段建议（或改造错误信息）。
- **字段级**授权（resolver 内校验，而不是只校验端点），禁用万能 `node(id:)` 或对其做所有权校验。
- 查询复杂度/深度分析（cost analysis、`max depth`、`max aliases`）、禁用递归片段。
- 按**子操作**计数限流；对 batched 请求按数组长度计费。
- 对 WebSocket 做 Origin + 会话校验；GET 查询加入缓存键或禁缓存。
- 变量做严格类型与白名单校验。

## 参考

- OWASP GraphQL Cheat Sheet、PayloadsAllTheThings GraphQL
- PortSwigger：GraphQL API vulnerabilities
- IncludeSecurity：Cross-Site WebSocket Hijacking Exploitation in 2025
