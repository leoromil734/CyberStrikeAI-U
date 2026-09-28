# API 与 GraphQL 攻击面总览

> API 的绕过集中在四处：**对象级授权（BOLA）**、**属性级授权/批量赋值**、**限流与业务流**、**查询语言特性（GraphQL/OData）**。上游 `API-Security-Top10/README.md` 提供 OWASP 检查表；本篇补充可执行的绕过手法。

## 一、入口与清单发现

- OpenAPI/Swagger：`/swagger.json`、`/openapi.json`、`/v2/api-docs`、`/api-docs`、`/.well-known/openapi.json`
- GraphQL：`/graphql`、`/api/graphql`、`/graphql/console`、`/v1/graphql`、`/query`
- gRPC-gateway：`/v1/*` 与 protobuf 反射（`grpcurl -plaintext host:port list`）
- 移动/前端产物：`katana`、`gau`、JS sourcemap、`api-schema-analyzer`
- 影子版本：`/v1` vs `/v2`，`/internal/*`、`/admin/*`、`/debug/*`

## 二、对象级授权（BOLA/IDOR）绕过

- 直接换 ID：数字自增、UUID v1（时间可预测）、base64（`gid://`、`node id`）。
- 换**父对象**：`/users/A/orders/B` 中 A 与 B 属于不同用户。
- 换**字段**：`?fields=email,phone` 或 GraphQL 中请求本不该返回的字段。
- 换**方法/路径**：`GET /doc/1` 403，`PATCH /doc/1` 200。
- 批量接口与导出接口（`/export`、`/search`、`/list`）常缺少逐对象校验。
- GraphQL `node(id:)` 全局 ID、`edges→node` 关系遍历。
- 通过**中介对象**授权：A 可读的共享文档中引用了 B 的资源。
- 见 `../IDOR-BOLA/README.md`。

## 三、属性级授权与批量赋值

- 请求体多加字段：`role`、`isAdmin`、`verified`、`balance`、`owner_id`、`tenant_id`。
- 嵌套对象与数组：`{"user":{"role":"admin"}}`、`{"roles":["admin"]}`。
- 重复键与大小写：`{"role":"user","Role":"admin"}`。
- 类型混淆：`{"role":{"$ne":null}}`（ORM 操作符注入）、`{"id":["1","2"]}`。
- 响应侧泄漏：接口返回了不该给该角色的字段（`password_hash`、`internal_note`、`ssn`）。

## 四、限流与业务流

- 限流绕过手法见 `Rate-Limit-Bypass.md`。
- 业务流：跳过付款、重复领取、状态机跳跃（见 `../Race-Condition/README.md`）。

## 五、GraphQL 专项

见 `GraphQL-Bypass-Cheatsheet.md`。

## 六、验证（最小证据）

1. 两个身份（或匿名 + 认证）与同一端点的对照。
2. 受保护数据片段或成功的高权限动作。
3. 请求/响应原文（含被绕过的具体校验点）。
4. 如果是"能读到别人的数据"，需确保不是缓存或公共数据。

## 七、常见误报

- 公开数据（可按 ID 获取的资源本质是公开的）。
- 前端隐藏按钮但后端正确校验。
- 测试环境与生产不一致。
- 只"能枚举"但每次都被 403。

## 八、修复

- 每个对象访问都做**服务端**所有权校验（不可只依赖前端或网关）。
- 请求体字段白名单（禁止批量赋值），并对可写字段做角色校验。
- 响应字段按角色裁剪（DTO 层）。
- 批量/导出接口单独审计。
- 统一鉴权与限流于网关 + 服务双层，消除"边缘拦、源站放"。

## 参考

- OWASP API Security Top 10 2023、WSTG API Testing
- GraphQL 相关见 `GraphQL-Bypass-Cheatsheet.md`
