# API 契约驱动库存与逐操作验证

## 适用与触发

已有 OpenAPI/Swagger、Postman collection、GraphQL schema 或 gRPC proto 时使用。
契约用于减少猜测、建立操作库存和合法基线，不证明服务实现符合契约。
api-schema-analyzer 实际为 spectral lint；不是请求执行、引用展开或覆盖完成器。

## 前提与范围

固定文档格式/版本、文件哈希、来源、环境变量和目标构建。
规范中的 servers、链接、回调和 Postman 变量不自动授予测试权限。
外部 $ref 拉取、远程 collection 读取和脚本执行须另获批准。
Postman pre-request/test scripts 及扩展字段作为不可信数据，不自动执行。
秘密引用脱敏；不把 token 写入提交、日志或公开报告。

## 展开与继承

1. 区分 OpenAPI 3.x、Swagger 2.0、Postman、GraphQL 与 proto 语义。
2. 读取 operation 的方法、路径、operationId、参数位置和 requestBody。
3. 追踪本地 $ref、allOf、oneOf/anyOf、required、nullable 与 discriminator。
4. 设置深度/节点预算，发现循环、缺失引用和冲突记录 unresolved，不能跳过后称完整。
5. 根据实际规范版本处理继承：全局 security 与 operation override、参数覆盖和 servers 优先级。
6. OpenAPI security requirement 列表通常为替代条件，单个对象内多 scheme 为组合条件；按版本核查。
7. Postman 逐层读取 folder/request 的 auth、变量作用域和禁用项；未解变量不发请求。
8. GraphQL 字段/参数和 gRPC service/method 用各自客户端/传输，不能直接套 HTTP 路径。

## 逐操作库存

每项保存源定位、实际 base URL、方法/路径、认证要求、字段、对象归属和副作用。
区分 documented、observed、baselined、risk-mapped；存在于规范不代表可达。
将 JS/抓包发现与契约对照，识别未记录、旧版或未部署入口。
覆盖单位是操作 × 身份 × 对象/字段 × 相关风险，不是“lint 已通过”。
低价值、破坏性或范围排除记录理由，与已验证安全分开。

## 合法基线与差分

- 构造符合 schema 的正常请求，使用授权身份和自有对象。
- 固定 Content-Type、传输、版本及认证，先确认实际业务成功。
- 一次只变身份、对象、动作或字段，区分 BOLA/BFLA/字段授权。
- 请求体满足结构不代表满足业务约束，金额/状态/租户需对照。
- 对副作用接口回查目标状态，不能以 200/500 独立判断。
- 不盲目执行全部操作、批量 mutations 或支付/通知/删除接口。

## 原始证据

保留规范源定位、解析/继承结论、变量解析、请求/响应及执行 ID。
记录认证主体和对象原始归属，不伪造缺少的第二身份。
未解析/未基线单元写缺口，不能因 scanner 或 lint 输出为空标安全。
confirmed 仍需实际目标侧新增能力、稳定复现和完整 POC/validation。

## 反证与工具边界

schema 宣称需要认证不证明运行时验证了 token。
规范未声明认证不证明敏感操作匿名可达。
公开 introspection、API 文档和缺描述字段不是独立高危漏洞。
Spectral lint 可发现规范规则问题，不代表 $ref/allOf 已被本系统完整展开。
协议客户端不可用、受控身份不足或对象不可建时记 blocked 对应单元。
不能把 sg-code-search 或 supply-chain-collect 当本地解析工具。

## 停止、清理与修复

未解目标变量、授权不清、脚本副作用或外部引用越范围时停止。
临时对象只在批准范围内清理并保存验收，缺口继续处理其他 ready 单元。
修复在真实服务的主体、对象、字段边界实施；同步契约但不只修文档。
复测包含合法业务、未授权操作和共享 helper 的兄弟入口。

## 来源与改编

- Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`，`skills/api-security-testing/SKILL.md`、`strix/utils/api_spec.py`，Apache-2.0。
- 中文重组，未引入 Strix CLI/自动安装；其 api_spec.py 把操作语义留给模型，并非确定性展开引擎。
- 来源：https://github.com/usestrix/strix ；许可见根 `LICENSE`。
- 官方参考：https://spec.openapis.org/oas/latest.html 、https://schema.postman.com/ 、https://graphql.org/learn/ 。latest 链接仅作入口，评估需固定实际版本。
