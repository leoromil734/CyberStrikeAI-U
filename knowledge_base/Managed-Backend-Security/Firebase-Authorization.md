# Firebase 授权边界：Rules、Storage 双入口与高权限函数

## 1. 触发与授权范围

适用于已授权 Firebase 的 Firestore/Realtime Database/Storage Rules、GCS IAM/ACL 与 Functions 候选。
核心增量是多授权引擎、未认证/匿名登录差异、对象读写与高权限后端的实际业务约束。
SRC 先通过 `skills/src-hunting/SKILL.md` 定义范围，再切换托管后端场景，不常驻叠载。
继承用户全部排除项，公开 config 的 projectId/bucket/API key 或第三方 SDK 地址不产生测试授权。
只使用 A/B 合法测试身份、已知合成 document/node/object 与少量标记字段，不提取真实业务数据。
禁止数据库根读取、全 bucket 列表、collection 扫描、递归分页或根据真实用户信息猜文档路径。
写入、签名、角色触发器、订阅与服务权限操作需单独许可；不部署规则、启动陌生项目或安装 SDK。

## 2. 真实部署与版本

对齐客户端配置、实际 project/database/bucket、区域 URL、Hosting rewrite 和部署环境。
记录 SDK、Functions 代际/API、Admin SDK 版本、规则版本与实际部署依据，不仅看仓库名称。
bucket 不仅有一个命名约定，使用实际 config/流量，不猜测其他项目的 appspot/firebasestorage 路径。
firebase.json/.firebaserc/规则文件/CI 配置需关联线上项目与部署，文件存在不证明 live Rules 相同。
缺规则声明/规则文件仅代表生效策略证据缺口，不能直接作为独立漏洞。
托管平台内部版本未知时标 unverified，Rules/SDK 行为按当前官方文档与受控目标证据核对。
来源中的 key/token、App Check 或通用 API 行为不可无条件沿用，支持/默认/覆盖服务需实际确认。

## 3. 凭据、身份与权限引擎

Firebase config/API key 通常标识项目与公开客户端，不是数据库对象授权，也不是用户密码。
未认证与 Anonymous Auth 不同：后者有合法 uid，auth!=null 不等于普通有权业务用户。
Firebase ID token、Google sign-in ID token、custom token 与 session cookie 是不同凭据类型。
Firebase ID token 的 aud 应对应 project，iss 对应 `https://securetoken.google.com/<project>`，并校验签名/expiry 等。
不能把 accounts.google.com issuer、appId audience 或自定义 token 直接当 Firebase 用户 ID token 接受。
具体 token 撤销/disabled user/custom claims 生效按 SDK 和业务规则核对，不靠 decode 判断真实性。
App Check 提供应用证明，不替代 user/tenant/object 权限；有 App Check 也不意味着用户可读所有数据。
Admin SDK/服务账户的 Firestore 等后端访问通常走服务权限而非客户端 Rules，函数必须做业务授权。
有效服务凭据只在授权内最小验证额外能力，禁止下载真实记录、复制密钥全文或扩大项目。

## 4. 基线和矩阵

选 A 所有的私有合成 document/node/object，明确 owner/tenant、公开意图和允许动作。
保存 A 成功、B/未认证拒绝、无效路径负对照；匿名登录单独建立身份基线。
矩阵按 object × get/list/create/update/delete/sign/subscribe × principal × tenant × entrypoint。
入口分别列客户端 SDK/REST、Firestore、Realtime DB、Firebase Storage、GCS 与 Functions。
固定部署、对象、请求形状，每次只换身份、路径或入口一个变量。
记录状态、必要标记、真实状态回查/合成事件，不把 200、空列表、index error 或 token 存在当权限证据。
无 owner 成功基线时，403/404/空数据无法区分对象不存在、索引要求与授权控制。
缺第二身份/角色只阻断相关单元，排除项与请求/时间预算在矩阵中保留。

## 5. Firestore 对象、查询与字段

Rules 不是结果过滤器：查询必须满足规则对可能结果集合的要求，查询失败不等于个别对象无权。
get/list 分开验证；受限 list 与具体 document 的授权语义可以不同，不强行要求响应一致。
只对已知测试对象/受限测试查询比较 SDK/REST，不使用全 collection/collectionGroup 枚举。
collectionGroup 候选需明确实际部署 rules match 与查询作用域，不能由 API 可用推定 bypass。
create 用 request.resource 的新数据，update 同时校验 resource 旧值与 request.resource 新值。
owner/tenant 不仅要满足当前身份，还需防止更新时转移归属、跨 tenant 关联或新增权限字段。
字段集合/affectedKeys 等白名单按规则版本核对，允许普通字段不应顺便开放 role/admin/member 数据。
custom claims 必须来自可信 Auth 管理路径；把用户可写 document 的 role 当可信身份是候选。
多个匹配 allow 的组合要整体审查；最具体-looking deny 不自动覆盖更宽 allow。
实际业务可能预期共享公共集合，auth!=null 的规则必须结合私有对象意图与动态效果判断。

## 6. Realtime Database 层级授权

read/write 的高层许可可能向下传播，下层 deny 不一定撤销父层 allow，核对实际匹配规则。
`.validate` 与 `.write` 的用途不同，新旧数据/删除行为按官方语义和部署规则分析。
只测已知合成子树，逐动作核对 auth.uid、owner/tenant、角色和字段，不请求 `.json` 数据库根。
高层 auth!=null、过期测试时间门或角色节点可写仅是候选，需实际新增能力与业务边界。
浅层/深层响应、缺 filter 或空路径可能不同，固定对象和请求形状排除假差分。
订阅只允许测试节点和少量合成事件，及时关闭，不监听生产根或真实用户通知。

## 7. Storage 双入口与 IAM/ACL

Firebase Storage 规则入口常见为 `firebasestorage.googleapis.com/v0/b/<bucket>/o`，以实际流量为准。
GCS `storage.googleapis.com` 对象/JSON API 入口走其 IAM/有效 ACL 等语义，不能拿某一侧 403 证明两侧安全。
同一已知测试对象在两入口分别保留 owner/非owner/未认证对照；list/read/write/delete 单独记账。
若两入口认证机制不同，要注明传入的真实 principal，不把一侧无效凭据与另一侧有效凭据混比。
Storage Rules 所有匹配 allow 通常按 OR 组合，宽递归 match 可能重新开放具体路径。
GCS bucket IAM、allUsers/allAuthenticatedUsers、历史对象 ACL 与 Uniform Bucket-Level Access 单独核对。
ACL 是否有效取决于 bucket 实际配置；开启统一访问后不能仍把旧 ACL 字符串直接当生效共享。
仅在允许合成对象核对公开/私有，不主动扫描历史 prefix 或下载真实公开文件来证明影响。
收紧 Rules 不自动撤销 GCS 共享或旧 cache；规则改动、IAM/ACL、缓存与既有 URL 验收分别记录。

## 8. 签名 URL、下载 token 与 Functions

签名 URL/下载 token 是持有者能力，预期共享/转发本身不是越权；账户切换能下载不充分。
重点证明未授权签发、路径/范围替换、超过明确期限或非预期泄漏；到期与撤销按机制分别核对。
onCall 的认证上下文取决于 Functions 代际/SDK，提供身份信息不自动执行对象权限。
onRequest 必须按真实实现验证身份，不能信客户端 uid/orgId 或仅 decode JWT。
Admin SDK 前需校验 caller、membership、对象与动作，客户端 Rules 安全不能替代高权限函数授权。
创建/更新文档触发角色授予、签名或消息的路径只在许可合成对象测试，不诱发生产角色或通知。
App Check 的缺失/关闭不是直接越权，需证明应用证明与业务权限哪一个独立边界被违反。
后台执行时权限/成员变化是否重验按业务承诺，返回 job/下载能力也要限制可信用户与 tenant。

## 9. 误报、反证、blocked 与停止

反例一：公开 config/key 只能读取公共内容，无法取得 A 的私有合成标记，不构成权限增量。
反例二：宽 Rules match 不匹配目标路径，或约束正确且目标拒绝 B，配置文字不是动态漏洞。
反例三：GCS 拒绝不能单独反证 Firebase Rules；双入口都拒绝才限定反证该对象/动作。
反例四：Admin SDK 前已有真实 membership/object 校验，匿名身份只操作自身空间，未越界。
反例五：签名 URL 按承诺可转发、签发受控且不能替换路径，不将重放单独记录漏洞。
缺 IaC、过时测试门、App Check 关闭、静态链、索引报错和版本命中仅为 tentative/证据缺口。
有效反证需具体控制、时序、所有已测匹配路径与实际拒绝，安全 sibling 不能外推全项目。
缺账号、规则部署证据、已知测试对象、写/签名/函数许可时标对应 blocked。
预算、配额/负载异常、未知项目/对象归属、真实数据/外部通知或清理不可靠时停止。
保存最小请求/输出、凭据类型、授权引擎、起始权限、新增能力、反证、清理和 Do-Not-Repeat。
按 `skills/pentest-verification/SKILL.md` 仅以目标侧动态独立边界闭环确认，不批量提取。

## 10. 修复与验收

修复所有匹配 Rules、对象/动作与字段约束，收紧父层许可，绑定可信 user/tenant/member。
独立移除实际生效的 GCS IAM/ACL 共享，高权限 Functions 最小权限并严格授权/签发。
规则修复不推定旧 URL/token/cache 失效，按明确机制和承诺复测并记录限制。
原反例、替代授权入口和合法 owner 流程都需实际验收，未执行复测标“未验收”。

## 11. 来源、许可与改编

原路径 `others/strix/strix/skills/technologies/firebase.md`，Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`。
[固定版本原文](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/technologies/firebase.md)；原作 [Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。
本篇中文重写，修正 Firebase token 泛化与“缺 IaC 即漏洞”，保留双入口/规则组合并加入动态新增权限、合成数据与停止约束。
官方核对：[Firestore Rules](https://firebase.google.com/docs/firestore/security/rules-conditions)、[Realtime Rules](https://firebase.google.com/docs/database/security/core-syntax)、[Storage Rules](https://firebase.google.com/docs/storage/security/core-syntax)、[ID token](https://firebase.google.com/docs/auth/admin/verify-id-tokens)、[Callable](https://firebase.google.com/docs/functions/callable)、[GCS access control](https://cloud.google.com/storage/docs/access-control)。
入口 `skills/managed-backend-security/SKILL.md`；短流程 `skills/managed-backend-security/references/firebase-authorization.md`。直接读文件，不依赖知识服务。
