# 契约到操作库存与合法基线

## 触发

获准读取 OpenAPI/Swagger、Postman collection、GraphQL schema 或 proto 时读取。

## 最小流程

1. 固定文档格式/版本/哈希/来源和目标构建；文档 servers/$ref/回调不自动授予目标权限。
2. 按实际格式读取 method/path/operationId、参数位置、body、required 和认证继承。
3. 追踪 $ref/allOf/oneOf/anyOf/nullable，限制循环/深度，未解引用标 unresolved。
4. OpenAPI 全局/operation security override 与 AND/OR 组合按版本核查；Postman folder/request auth 与变量作用域单独解析。
5. 禁止自动执行 Postman scripts、远程引用和未解变量请求。
6. 建立操作 × 身份 × 对象/字段 × 风险，区分 documented/observed/baselined/risk-mapped。
7. 合法请求和自有对象先成功，再只改一项身份/对象/动作/字段，回查副作用。
8. unresolved/未基线/缺第二身份记对应缺口；未部署操作不能标已测试。

## 工具边界与反例

api-schema-analyzer 是 spectral lint，不是请求执行/$ref 完整展开/覆盖完成器。
lint 通过、introspection 开放、文档列 security 都不证明运行时安全或漏洞。
http-framework-test/httpx 用于批准目标基线；不能盲发全部操作和 destructive mutation。
缺协议客户端、身份/对象或范围前提记 blocked，不自动安装工具。

## 交付与修复

保留文档定位、继承结论、请求/响应、执行 ID、归属与目标状态。
confirmed 仍需新增权限和完整 POC/validation；修复真实服务边界而非只修改契约。

## 来源与补充

Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`，`skills/api-security-testing/SKILL.md`、`strix/utils/api_spec.py`，Apache-2.0；中文重组，根 LICENSE。
其代码将操作语义留给模型，本文不声称已移植解析执行引擎。
完整原理：`knowledge_base/API-GraphQL/Contract-Driven-API-Testing.md`。
