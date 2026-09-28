# 批量赋值与属性级授权（Mass Assignment / Property Authz）

> OWASP API3:2023。核心问题：**请求体里多写了字段，服务端照单全收**；或**响应里多回了字段，调用者本无权看**。

## 一、批量赋值（写侧）

| 手法 | 示例 |
|---|---|
| 直接加字段 | `{"email":"a@b.c","role":"admin"}` |
| 嵌套对象 | `{"user":{"role":"admin"}}`、`{"profile":{"verified":true}}` |
| 数组/多值 | `{"roles":["user","admin"]}` |
| 重复键 | `{"role":"user","role":"admin"}`（取决于解析器取首/末） |
| 大小写变体 | `{"Role":"admin"}`、`{"ROLE":"admin"}`（Go/部分框架大小写不敏感匹配） |
| 类型混淆 | `{"role":{"$ne":null}}`、`{"id":["1","2"]}`、`{"age":"abc"}` |
| 内部字段名猜测 | `is_admin`、`is_staff`、`verified`、`balance`、`credits`、`tenant_id`、`owner_id`、`status`、`approved` |
| 下划线/别名 | `_role`、`role_id`、`permissions`、`acl` |
| 时间与归属 | `created_at`、`updated_at`、`owner`、`created_by` |

探测方法：

1. 先读自己账号的 **GET 响应**，把返回字段全部作为候选（响应字段名 = 内部字段名）。
2. 逐个在 PATCH/PUT/POST 中带上并观察是否持久化（再 GET 验证）。
3. 关注只有管理员能改的字段（价格、状态、额度）。
4. 框架线索：Rails `strong_parameters` 缺失、Laravel `$fillable` 过宽、Spring `@ModelAttribute`、Node `Object.assign(model, req.body)`、Go 的 `json` 大小写不敏感。

## 二、属性级授权（读侧）

- `GET /me` 与 `GET /users/{id}` 字段不同（后者返回 `password_hash`、`internal_note`、`ssn`）。
- `?fields=`、`?include=`、`?expand=` 参数允许请求敏感字段。
- GraphQL：同一对象不同 resolver 的字段级授权不一致（见 `GraphQL-Bypass-Cheatsheet.md`）。
- 列表接口返回全量对象（含内部字段），单对象接口做了裁剪。
- 导出/报表接口（CSV/PDF）跳过 DTO 裁剪。

## 三、验证（最小证据）

1. **写侧**：给出请求 + 之后 GET 的响应证明字段已持久化；如影响权限，给出越权生效的证据。
2. **读侧**：给出低权身份读到高权字段的响应（敏感值掩码）。
3. 说明绕过的校验层（DTO？策略？仅前端隐藏字段？）。
4. 记录字段的实际效果（例如改 `role` 后能访问管理员接口）。

## 四、常见误报

- 字段被服务端忽略（返回成功但 GET 后未变化）。
- 该字段本来就允许用户自改（如昵称）。
- 只在自建环境生效。
- 响应中包含字段但值为 `null`（未实现）。

## 五、修复

- 输入使用**显式 DTO / 白名单绑定**，禁止直接把请求体映射到模型。
- 输出使用 DTO/序列化视图，按角色裁剪字段。
- 对"角色/状态/额度/归属"类字段做服务端授权检查（不接受客户端赋值）。
- 严格 JSON 解析：拒绝重复键、大小写变体、对象出现在标量字段。
- 对所有写接口统一策略（避免某些接口漏掉）。

## 参考

- OWASP API3:2023 Broken Object Property Level Authorization
- PortSwigger：Mass assignment vulnerabilities
- Elttam：ORM Leaking More Than You Joined For（2025）
