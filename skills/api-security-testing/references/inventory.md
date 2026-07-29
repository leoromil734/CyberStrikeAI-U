# API 库存与攻击面

## 发现来源

按证据强度合并：公开 OpenAPI/Swagger、GraphQL introspection、前端/移动端调用、历史 URL、网关配置、运行时流量和源码路由。每个 endpoint 记录来源与最后确认时间。

## 端点字段

| 字段 | 内容 |
|---|---|
| base/version | 主机、前缀、版本、环境 |
| method/path | HTTP/RPC 方法和规范化路径 |
| content type | JSON、multipart、GraphQL、protobuf 等 |
| auth | token/session/key、scope、角色 |
| object | 对象类型、ID 来源、归属主体 |
| fields | 输入字段、响应敏感字段、服务器生成字段 |
| side effect | 只读、写入、异步任务、第三方回调 |
| evidence | schema、流量、源码或响应 |

## 影子与旧版本

比较 v1/v2、移动端旧基址、测试环境和管理 API，但只有可证明属于范围的资产才主动验证。旧版在线本身不是漏洞；需证明其缺失当前安全控制或暴露敏感能力。

## GraphQL

记录 query/mutation、对象 ID、resolver 鉴权位置、批量/alias 行为和字段敏感度。introspection 开放通常只是信息项；真正风险来自低权可访问敏感字段、对象或 mutation。

## 交付

输出去重后的 endpoint 表、身份需求、对象边界、优先级和信息缺口。库存 fact 可为 tentative；不要在库存阶段记录未验证漏洞。