# 消息与缓存：命名空间隔离证据

## 适用条件
- 具体 Redis/RabbitMQ/Kafka/NATS/MQTT/ZooKeeper 产品、版本、凭据或配置产物已确认。
- 存在可指认 key pattern、vhost、topic/group、account/subject 或 znode 对象。
- 端口和非404只是线索，不自动派发；SRC先使用 `src-hunting`，按需加载本篇。
- 区分管理面库存可见与数据面操作，证明正常授权之外的读/写能力。

## 身份 → 对象 → 允许操作
- 记录用户名/证书主体、ACL role、租户/namespace、认证入口与动态继承。
- Redis：用户 → 命令类别与 key pattern → GET/HGET等类型匹配读取；channel pattern另记。
- RabbitMQ：用户 → vhost/exchange/queue → configure/write/read；management tag不是数据ACL替代。
- Kafka：principal → topic/consumer group → Describe/Read/Write及Group操作，分开核对。
- NATS：user → account、publish/subscribe subject、import/export与JetStream资源权限。
- MQTT：client证书/用户名 → topic filter与发布/订阅ACL；client_id不一定是身份。
- ZooKeeper：auth identity → 具体znode ACL → read/write/create/delete/admin；父ACL不自动继承。
- 对每种资源指定合法owner、允许操作、拒绝对象和认证机制；不以“连上”代替权限。

## 安全基线与对照
1. 准备受控身份A/B、各自测试namespace和非敏感标记；禁止向生产队列混入测试消息。
2. A读取A标记为允许基线，A访问B标记为拒绝基线，固定客户端其他参数。
3. 固定identity只换资源，或固定资源只换identity；避免同时改协议/认证/操作。
4. 先核对元数据与ACL；获得消费授权与安全测试对象后才进行消息读取。
5. 响应200/连接成功不足以确认消息内容可读；证明payload标记与资源归属。
6. 空topic/queue不能证明ACL有效；实际没有测试数据时明确缺口。
7. 仅有readonly管理授权时可查看允许的元数据，不自动许可消费/订阅。

## Redis 产品细化
- ACL WHOAMI/GETUSER信息仅在实际权限允许时查看；无法执行不代表未启用ACL。
- 分开命令permission与key pattern，验证GET允许不等于任意键/任意命令允许。
- 用TYPE匹配读取，限一个测试key；SCAN限定次数和游标预算，不认全量覆盖。
- SCAN可能重复/遗漏并发变化的key；库存计数写采样与时间窗口。
- pub/sub权限与普通key ACL区别，使用获准测试channel，不监听业务通配channel。
- 不做KEYS全库、Lua逃逸、MODULE LOAD、CONFIG改写、RDB/cron或复制链。
- 能读取自己业务缓存/session是正常权限；额外秘密或跨租户内容需实际边界证据。

## RabbitMQ 与 Kafka 产品细化
- RabbitMQ核对每个vhost权限regex，列表能看到queue不等于能consume。
- 管理API的queue get通常POST；requeue仍可能改变redelivery标记、顺序和消费竞争。
- `ack_requeue_true`不能标成完全无副作用；没有消费授权则停止在metadata。
- Kafka的Describe成功不等于Read成功，topic权限与group权限分别保留证据。
- 受控consumer group也可能新建服务端状态；获准后才创建，不借用生产group。
- 禁止commit生产offset；poll仍可能触发rebalance/审计/流量，不宣称天然无副作用。
- 生产topic只允许明确批准的最少样本；默认用隔离测试topic与固定分区标记。

## NATS、MQTT 与 ZooKeeper 产品细化
- NATS跨account可见subject可能来自批准的export/import，不自动判隔离失效。
- Core NATS订阅与JetStream持久consumer不同；后者可改变ack/delivery状态。
- MQTT通配订阅只静态审阅ACL，不以 `#`/`+`采集业务消息。
- retained消息、persistent session与QoS ack可能产生状态；使用临时受控测试会话需授权。
- ZooKeeper只检查具体znode路径与ACL；不递归导出树，不写真实协调节点。
- TLS证书、SASL、代理映射与anonymous连接分别建基线，防止实际被映射成同一主体。

## 目标侧证据与持久效果
- 保留脱敏认证结果、资源标识、协议返回、测试payload及关联时间。
- 目标审计记录principal、namespace、操作与拒绝/允许；不要只引用管理截图。
- 如另行批准写测试，只写自建测试对象，回读与审计验证新增效果及恢复。
- 涉及消费记录consumer/group、offset或ackmode、消息数量与已知副作用。
- 缺目标审计不自动否定，但需实际对象归属与请求链；不伪造持久效果。
- 未做写入/配置验证时标“持久化未验证”；禁队列purge、拓扑改写和broker植入。

## 可核验反例
- Redis用户只可读 `team-a:*` 且 `team-b:*`拒绝：正常隔离基线。
- RabbitMQ用户的management tag允许看统计，但vhost B消费拒绝：非跨namespace读取。
- Kafka能Describe topic但Read被拒：元数据访问不等于消息泄露。
- NATS按批准import获得共享subject：合法共享；检查仅限定批准subject。
- MQTT测试topic允许而业务topic拒绝：条件负结果，不覆盖通配规则全空间。
- ZooKeeper管理员正常修改自己获准znode：既有权限，不是独立提权。
- 默认账户有效但无业务数据/管理新增权限：不能固定判critical。

## 缺口、记录与敏感值
- 无测试payload/第二主体/消费授权/安全客户端：blocked，保留metadata-only结论。
- timeout/空数据/协议版本错不视为拒绝；负结果限定身份、资源、操作与时间。
- 记录起始权限、资源owner、ACL来源、允许基线与未授权对照、证据引用。
- 记录额外能力、恢复结果、采样预算和未覆盖协议/namespace；一例不代表测试完成。
- payload、cookie、密码、证书私钥脱敏；只留测试标记和业务类型，不导出秘密库。
- 沿用项目低价值排除：普通版本/拓扑元数据不机械升为漏洞。

## 工具边界
- 可用管理HTTP接口通过当前已注册 `http-framework-test`做限量验证，禁打印认证头。
- 原生redis/kafka/nats/mqtt客户端仅在已有依赖、实际注册工具允许且授权时使用。
- `exec`定义存在不等于原生客户端或Linux环境存在；缺能力用HTTP替代或blocked。
- 禁运行时安装、自动广扫和来源脚本；响应截断不是脱敏。

## 来源、改编与许可
- 改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。
- 作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
- 源：`others/Dark-Moon/conf/agents/messaging-cache.md`，https://github.com/ASCIT31/Dark-Moon 。
- 快照 `cb0d9b8`（`cb0d9b83e745034c8bcff90daee9668b834d1508`），原GPLv3；本文GPL-3.0-only。
- 用户2026-10-01自述作者并授权自有内容改编；第三方原许可保留，根LICENSE不变。
- 改编去除复制/RDB/module持久化和固定severity，修正requeue无副作用假设。
- 官方：https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/ ；https://www.rabbitmq.com/docs/access-control 。
- 官方：https://kafka.apache.org/documentation/#security_authz ；https://docs.nats.io/running-a-nats-service/configuration/securing_nats/authorization 。
- 官方：https://www.oasis-open.org/standard/mqtt/ ；https://zookeeper.apache.org/doc/current/zookeeperProgrammers.html 。
