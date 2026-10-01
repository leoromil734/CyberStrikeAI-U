# 初始信息收集：FOFA 必调规则

## 适用与顺序

线上目标的初始信息收集，Quick/Standard/Deep、SRC 锁面/自由跳均必须先实际调用 `fofa_search`。先定界目标与查询条件，再执行 FOFA，之后做子域、DNS、HTTP、端口及 JS/API 补充。FOFA 是必经来源，不是与 Shodan/ZoomEye/Quake 四选一。

只写查询语句、读取历史 FOFA 截图、调用 httpx/subfinder 或其他测绘引擎，均不能冒充本次 FOFA 调用。上游交接已有本轮同目标、同范围的真实调用证据时复用，不让每个子任务重复查询；新增范围或新一轮初始收集重新执行。

纯离线源码/制品审阅、普通问答及已完成侦察后的专项验证，不重新开启空间搜索。用户明确禁止外部测绘时保留该限制，不为满足流程泄露私有目标或扩范围。

## 按范围构造查询

- 根域：围绕当前授权根域使用 `domain="example.com"`，不自动查询集团所有业务。
- 固定 URL/锁面：仅查询指定 host/IP；FOFA 返回的近似 host、关联 IP、同证书或同品牌结果不自动纳入主动测试。
- IP/CIDR：使用当前批准的 `ip` 范围，不扩到所在 ASN 或更大网段。
- 固定资产清单：按当前批准项分批，记录覆盖范围，禁止换成无关集团/产品全网搜索。
- SRC 自由跳：只查询当前一个种子；搜→去重去废去非存活→归属核查→处理剩余活面→再换种子，不把全队列一次搜完。
- 标题、favicon、证书或产品语法仅辅助当前范围；单独 `app/title/icon_hash` 全网查询不能替代目标定界。

## 参数与工具真实性

使用当前注册工具的 schema：`query` 为原始查询文本，工具内部编码 qbase64；不要把 Base64 当 query。
首轮小页、`page=1`、`full=false`；`fields` 使用逗号分隔字符串，如 `host,ip,port,title,server`。
页数、条数、重试和费用服从当前任务预算与账户配额；首轮零结果不需要无限翻页。
凭据由配置 `fofa.api_key` 或 `FOFA_API_KEY` 注入，不作为调用参数，不打印/复制 email、API key。
仓库工具默认禁用；现有配置加载逻辑会在存在非空配置值/环境 key 时启用定义。定义启用不保证 key有效、配额充足或请求成功；本规则不自动设置凭据或开通账号。

## 本轮证据与事实

绑定全面评估轮次时写 `recon/source/{assessment_id}/fofa_search/{target_id}`；其他侦察按既有 `recon/source/fofa_search/{target_id}` 保存。不伪造 assessment_id。

正文保存：tool、target、实际 query/范围、采集时间、status、raw、unique、incremental、error、alt_tried、evidence。
raw 用本次实际返回 results 的数量，不把远端 total 当已获取量；去重和范围过滤计数单独保存，满足 incremental ≤ unique ≤ raw。
evidence 引用本次工具执行与原始返回；模型宣称“已查FOFA”不代替原件。
FOFA 是历史测绘，结果不等于当前存活/当前版本；后续再做范围内 DNS/HTTP 基线。

## 失败与收尾

- 调用成功且零结果：covered，raw/unique/incremental=0，保存真实成功回包，不标全目标安全。
- 工具未注册、缺 key、无配额、429/权限/网络错误：blocked，记录真实原因与已尝试替代来源。
- 工具可用时必须尝试真实调用；未注册不能臆造调用。其他来源可补资产缺口，但 FOFA 仍保持 blocked，不能改 covered 或用 not-applicable 跳过。
- 正在运行/等待回包记 gap/进度，尚未调用也记 gap，不能写完成。
- 重试遵循工具与任务预算；持续限流不空刷，继续范围内独立可执行单元并披露 FOFA 限制。
- 全面覆盖检查要求本轮 FOFA 来源记录，成功或有证据阻断均保留实际性质；blocked 不等于成功调用/完整覆盖。

本文是运行流程约定，不自动触发查询、不安装工具、不改凭据、不测试外部目标。
