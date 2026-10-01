# 幂等、支付回调与持久化效果

## 触发与边界

已确认 Idempotency-Key/requestId 或支付/权益 Webhook 时读取，只选当前分支。
仅授权 TEST/沙箱、自有订单/账号、最小可恢复额度；不处理真实客户资金和无法回滚履约。

## 幂等分支

1. 保存初始账本/订单，same key + same body 串行两次建立效果一次基线。
2. 单独对照不同正文、主体/租户、操作、到期和失败重试的契约语义。
3. 仅获准后做有界少量并发，限制速率/请求数，不做洪泛。
4. 读回账本/余额/权益，两个 200 或不同 transaction ID 不能证明双重效果。
5. cross-user 同键须证明他人缓存数据或越界动作，不能仅因接受相同字符串计洞。

## Webhook 分支

1. 固定提供商/SDK/算法、商户/环境和签名材料；保存 raw body 字节。
2. 正常有效事件基线，再逐一对照无/错签名、错密钥/环境、正文语义、时间窗和重放。
3. 验证实际处理的正文、订单归属、金额、币种、事件类型及可信状态绑定。
4. 后续正常认证读回订单/账本，200 可表示丢弃，500 也可能已提交。
5. TEST ping 不等于支付事件；不同校验失败表现按根因去重，不固定等级。

## 证据与终态

保存每次原始请求/响应、唯一无敏感 nonce、执行/时间、目标身份和最终状态。
异步等待一次正常窗口且最多 5 分钟，缺状态证据转 blocked，继续独立 ready。
数据库约束使效果一次、合法缓存返回是反例；模型判断和状态码不替代新增能力。
现有没动钱和审核、只害自己等排除保持；confirmed 须完整 POC/validation。

## 清理与修复

异常金额/履约/恢复失败即停止并保存状态；清理仅自有测试对象并验收。
键绑定主体/操作/请求，原子去重并覆盖下游消费者；签名覆盖确切字节和环境、可信绑定订单状态。

## 来源与补充

NeuroSploit `5d4e7e0347219ceae22735ec6af3d8cdd0561ded`，`agents_md/vulns/idempotency_key_abuse.md`、`payment_webhook_forgery.md`，MIT；Copyright (c) 2026 Joas A Santos & Red Team Leaders。
中文改编，完整许可见 NeuroSploit 独立许可文本；原理见 `knowledge_base/API-GraphQL/Idempotency-Key-State-Evidence.md` 与 `knowledge_base/API-GraphQL/Payment-Webhook-State-Evidence.md`。
