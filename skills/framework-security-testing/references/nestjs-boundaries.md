# NestJS 边界：精简检查流程

## 触发与前提

命中 Guard/Reflector、Pipe/DTO、HTTP/GraphQL/WS/RPC 复用业务时读取。核对部署 Nest、Express/Fastify 适配器、验证/转换库、各 transport 与全局注册方式；不按源码名假定 schema 或转换生效。继承用户排除项，只使用授权身份、合成对象和允许通道，broker 地址不自动授权。

## 执行顺序

1. 画出已部署操作的全局→controller→method 守卫及权限 metadata，核对 Reflector 的 key、override/merge、`@Public()` 分支及未知 context 的返回值。
2. 用 A 所有对象成功基线、B/未认证拒绝和无效对象负对照固定业务规则；同一操作按 HTTP、resolver、WS 消息或 RPC 分别记账。
3. 逐路径识别守卫究竟取得哪个 principal、对象 ID 和 tenant；Passport 成功或 `@Roles` 声明不等于对象授权。仅缺 `@UseGuards` 不证明漏洞，可能有全局/服务层控制。
4. 检查 Pipe/DTO 实际消费形状：额外字段、嵌套对象、数组元素、transform、条件校验各用一项无害变化；对照进入服务的最终字段和受控效果，不能凭隐式类型转换假设。
5. 比较 HTTP/WS/RPC 的注册继承、每消息/操作权限和反序列化；WS 连接成功不代表可订阅/发布。只订阅测试房间和合成事件。
6. 检查返回字段及缓存 key 的用户/租户绑定；`@Exclude` 需要实际序列化路径，`@Global` provider 可注入本身不是远程越权。
7. 已允许的敏感字段写入只作用合成对象，回查新增能力并清理；若写入会触发真实消息或工作队列，停止该单元。

## 反证、停止与修复

- 可测反例：method 无局部 Guard 但全局 Guard 和服务层对象校验拒绝 B；多余字段被剥离且未被更早组件使用；HTTP/WS 同一对象操作均拒绝跨租户。
- DTO 声明、Swagger 安全标记、错误差异、可注入 provider、宽松模块作用域均非独立漏洞证据。
- 缺可用 WS/RPC 身份或工具、transport 未授权、请求无法到达守卫、部署版本未知，标相应 blocked；预算耗尽、真实副作用或非测试数据出现停止。
- 修复应在每个 transport 明确提取可信身份，绑定对象/动作；未知 context 默认拒绝，核对 metadata 合成语义，统一验证/序列化，缓存隔离身份。
- 验收原最小反例、兄弟入口及合法对象流程。按 `skills/pentest-verification/SKILL.md`，只有动态证明新增权限才 confirmed；保留排除项和有限范围反证。

## 补充资料与来源

完整正文：根路径 `knowledge_base/Framework-Security/Nestjs-Security-Boundaries.md`，无需知识服务。
原路径 `others/strix/strix/skills/frameworks/nestjs.md`，改编自 [Strix 007ed1a](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/frameworks/nestjs.md)，[Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。中文重写，修正装饰器/模块可见性/类型转换即漏洞的泛化，增加动态与范围门禁。
官方核对：[Guards](https://docs.nestjs.com/guards)、[Execution context](https://docs.nestjs.com/fundamentals/execution-context)、[Validation](https://docs.nestjs.com/techniques/validation)、[Hybrid application](https://docs.nestjs.com/faq/hybrid-application)、[WebSocket guards](https://docs.nestjs.com/websockets/guards)。
