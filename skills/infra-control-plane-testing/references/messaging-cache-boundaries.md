# 消息与缓存命名空间工作流

仅在 Redis ACL、RabbitMQ vhost、Kafka topic/group、NATS account/subject、MQTT topic 或 ZooKeeper znode 的确切产品与对象证据出现时触发；端口和非404不是产品确认。SRC 先加载 `src-hunting`。

1. 建立身份/命名空间/操作矩阵：管理 API 可见性与数据读、写、订阅、消费、配置权限分开；记录版本和动态角色继承。
2. Redis 对照用户、命令 ACL、key pattern；只读小批 SCAN 是库存采样，不是完整 keyspace。RabbitMQ 对照 user tag 与 vhost 的 configure/write/read，管理角色不等价于全部队列读权。
3. Kafka 对照 topic Read/Describe 与 consumer group 权限；NATS 对照 account 和 subject import/export；MQTT 对照证书/用户名映射及单一 topic 的订阅 ACL；ZooKeeper 对照单个 znode 的 ACL 与数据权限。
4. 使用两身份和受控测试标记，先允许基线再跨 namespace 单变量读取。队列 get/requeue、consumer poll、订阅持久会话可能改变顺序、redelivery、offset；metadata-only 授权不含消息消费。
5. 获取目标审计、ACL版本、受控标记和实际协议结果；只持有管理员凭据读取授权消息不是独立漏洞。元数据泄露按项目低价值排除，不机械确认高危。
6. 无安全测试队列/受控 consumer group/已具备协议客户端则 blocked，保留 metadata-only 结论。禁止清空队列、提交生产offset、通配订阅、Redis CONFIG/MODULE/复制植入和全量秘密导出。

工具：可用管理 API 通过已注册 `http-framework-test`；原生客户端不因源文档命令存在而视为可用。`exec` 只在受控环境已有依赖且操作获准时使用，禁止运行时安装。限量、低速、脱敏，禁输出凭据。

记录：身份、认证映射、namespace/资源、预期 ACL、基线与对照、payload标记、审计引用、消费副作用、回读/恢复证据、反证、blocked条件；未做写入明确持久化未验证。

完整知识：[Messaging-Namespace-Isolation](../../../knowledge_base/Infra-Control-Plane/Messaging-Namespace-Isolation.md)。
改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
来源：`others/Dark-Moon/conf/agents/messaging-cache.md`，提交 `cb0d9b8`，原 GPLv3；本文 GPL-3.0-only。用户 2026-10-01 自述作者授权自有内容改编，第三方原许可保留，根 LICENSE 不变。
官方参考：https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/ ；https://www.rabbitmq.com/docs/access-control ；https://docs.nats.io/running-a-nats-service/configuration/securing_nats/authorization 。
