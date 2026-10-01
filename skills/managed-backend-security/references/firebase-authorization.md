# Firebase 授权：精简检查流程

## 触发与前提

命中 Firebase config、Firestore、Realtime Database、Storage 或 Functions 时读取。核对实际 project/database/bucket、区域 URL、SDK/Functions 代际与生效 Rules；公开 config/API key 非用户认证。继承用户排除项，准备未认证、匿名登录、A/B 身份与少量已知合成路径；不请求数据库根或全 bucket。

## 执行顺序

1. 对齐本地规则与部署项目；缺 firebase.json 规则段或规则文件仅是版本/生效证据缺口，不能直接报漏洞。
2. 建立对象 × get/list/create/update/delete/签名/订阅 × 身份/tenant × SDK/REST/Functions 矩阵；未认证与匿名登录分别记账。Admin SDK 后端通常走服务权限，不以客户端 Rules 替代业务校验。
3. 用 A 的非公开合成文档/对象成功、B/未认证拒绝、无效路径负对照；每次只改变身份/路径/入口一项，不用真实业务记录猜 ID。
4. Firestore 区分 get/list，Rules 不是结果过滤器；比较允许查询约束和单文档权限。create/update 分别核对新旧 owner/tenant、字段差分及可信角色来源。
5. Realtime Database 检查高层 read/write 许可向下级传播、更新与校验；只测测试子树，父级许可不能假定被子级 deny 撤销。
6. Storage 必须分别测 Firebase Rules 入口与 GCS IAM/ACL 入口，同一已知测试对象固定身份对照；一侧 403 不证明另一侧安全。查所有匹配 Rules 的 OR 语义，ACL 是否生效取决于实际 bucket 配置。
7. Functions onCall/onRequest 按部署 SDK 验身份，严格绑定 Firebase ID token 的 project audience/issuer；Google 登录 ID token、自定义 token 与 session cookie 不混用。App Check 是应用证明，不是用户/对象授权。
8. 函数签名/角色触发器只在许可合成对象测试，回查并清理；签名 URL/下载 token 本来就是持有者能力，必须证明越权签发或超出承诺范围，不能以跨账号重放独立报错。

## 反证、停止与修复

- 可测反例：公开 config 仅访问公共内容；GCS 拒绝且 Firebase Rules 同样拒绝测试对象；宽 match 不匹配目标路径；Admin SDK 之前已有真实 tenant 校验；匿名身份仅能操作自身测试空间。
- Rules 缺文件、过时测试时间门、App Check 关闭、token 可见和静态宽规则均非充分证据；空查询与索引报错不能证明权限安全。
- 缺第二身份、已知对象、live Rules 证据、函数/写许可时阻断对应单元；预算、配额、未知资源归属、真实通知或非测试数据出现停止，保存排除项。
- 修复覆盖各匹配 Rules/操作/字段；收紧父层许可，独立移除有效的 GCS 共享权限或 ACL；高权限 Functions 做对象/tenant 检查并限制签发，缓存与旧 URL 撤销需单独复测。
- 按 `skills/pentest-verification/SKILL.md` 以实际目标新增权限确认，验收原反例、替代授权入口及合法 owner 操作。

## 补充资料与来源

完整正文：根路径 `knowledge_base/Managed-Backend-Security/Firebase-Authorization.md`，无需知识服务。
原路径 `others/strix/strix/skills/technologies/firebase.md`，改编自 [Strix 007ed1a](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/technologies/firebase.md)，[Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。中文重写，修正 Firebase token 泛化与“缺 IaC 即漏洞”，加入双入口、合成数据与动态门禁。
官方核对：[Firestore Rules](https://firebase.google.com/docs/firestore/security/rules-conditions)、[Realtime Rules](https://firebase.google.com/docs/database/security/core-syntax)、[Storage Rules](https://firebase.google.com/docs/storage/security/core-syntax)、[ID token 验证](https://firebase.google.com/docs/auth/admin/verify-id-tokens)、[Callable Functions](https://firebase.google.com/docs/functions/callable)、[GCS access control](https://cloud.google.com/storage/docs/access-control)。
