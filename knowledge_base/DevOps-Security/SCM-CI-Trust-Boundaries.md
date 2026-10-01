# SCM/CI：代码来源与流水线信任证据

## 适用条件
- 已授权 GitHub/GitLab仓库、Jenkins job或已提供workflow/token/runner配置产物。
- 公开仓库可对已提供代码做静态审阅；不据此推定组织API、生产job和写权限均获准。
- SRC先使用 `src-hunting`；本篇细化信任矩阵，不重复历史secret与表达式注入的通用清单。
- token种类、代码commit、目标project/job可指认才加载，不因平台URL猜测全面测试。

## 身份 → 对象 → 允许操作
- 记录actor、token主体/类型、org/project/repo、ref、job、environment和runner对象。
- GitHub classic PAT、fine-grained PAT、installation token、GITHUB_TOKEN权限来源不同。
- scope响应头不完整覆盖各token类型；缺头不能证明无权限或固定权限。
- GitLab区分user/PAT、project/group access token、deploy token、CI_JOB_TOKEN。
- Jenkins区分用户API token、folder/job授权、controller/node身份与credential scope。
- 允许操作分别记录读代码、提交、改workflow、启动job、审批、读secret、部署和发布。
- “可运行job”和“可读取它内部credential”不是同一个授权，也不是天然独立漏洞。
- 即使凭据已泄露，其正常权限只属于起始状态；另一个boundary需新增能力证明。

## 代码与秘密信任图
1. 标注不可信输入与commit来源：fork/PR/MR、branch、tag、artifact和调用workflow。
2. 标注实际checkout/ref及后续build/test/install命令消费的代码，不只看事件名称。
3. 标注gate检查的是actor、仓库、ref还是代码hash，审批前后是否换了commit。
4. 标注job权限、secret来源、environment保护、runner租户与发布目标。
5. 标注artifact生成者、下载条件、签名/digest与消费者，防止把可信名字当可信内容。
6. OIDC额外标注issuer、audience、subject、ref/environment与下游role trust。
7. 缺任一跳证据明确候选；静态危险模式不代替实际获得secret/部署能力。

## GitHub 产品细化
- `pull_request_target`运行上下文和checkout实际ref分别核对，不默认所有此类任务有漏洞。
- `workflow_run`核对上游workflow、conclusion、仓库/branch、下载artifact来源及执行方式。
- `actions/checkout`默认值、显式ref和调用层参数要解析，区分base代码与PR head代码。
- GITHUB_TOKEN以workflow/job permissions及组织限制为准，不凭事件名猜写权限。
- environment保护核对审批人、branch/tag约束、自审批与实际待审批commit。
- secrets API列表通常只给名称/时间；看到名称不是读到值。
- OIDC需下游信任策略和可获授角色证据，能签发JWT不等于获得云权限。
- fork隔离、显式可信ref、最小job权限与审批均是可能成立的反证。

## GitLab 产品细化
- protected变量按实际ref/项目/版本与MR上下文判断，不只看变量名称或masked标签。
- masked限制日志显示，不保证脚本读不到值，也不等于已证明外传。
- fork/MR pipeline核对运行项目、权限、secret注入条件及批准人。
- CI_JOB_TOKEN核对来源project、目标allowlist、主体权限与可用API操作集合。
- 项目A允许project B合法拉制品是基线；不批准project读取B私有制品才是对照。
- runner protected/tag/共享范围与执行代码来源关联，不以self-hosted名称直接计洞。
- deploy token只证明获准registry/repo权限，不把正常pull当组织接管。

## Jenkins 产品细化
- job所在folder与继承策略核对，区分Read、Build、Configure和管理员权限。
- credential ID可见不等于明文secret可读；credentials所在scope与job执行身份分别记录。
- 若Configure本来允许执行可信脚本，管理员正常脚本执行不是新RCE。
- 低权限是否可控制受信任pipeline代码、共享库版本或参数才是独立边界问题。
- controller与agent/node隔离、workspace共享、artifact owner与日志权限分别核对。
- 禁触发真实生产job、下载业务credential或在node植入长期任务。

## 基线与未授权对照
- 默认静态配置和获准API元数据；先定义owner与低权限actor预期能力。
- 用A/B受控账号对同一测试repo/job建立允许与拒绝基线，只切主体或对象。
- 写/运行验证需额外批准的隔离测试job，只使用无效secret标记，不绑定生产部署。
- 验证代码ref、runner身份与protected条件确实与候选一致，不“简化”成另一个配置。
- 实际run保留commit/hash、run ID、actor、gate/审批结果和目标审计。
- 仅发现拼接/宽trust无法安全动态复验时tentative；无可用测试job则blocked。

## 目标侧证据与持久效果
- 脱敏workflow片段、token权限响应和job日志关联同一commit与时间。
- 证明无效标记跨到不获准主体即可，不泄露真实secret或发送到外部接收端。
- 下游权限若未获准验证，结论限制到静态trust或job上下文，不声称云接管。
- 测试写入需独立回读、run记录与审计证明保存/执行；确认恢复和无残留状态。
- readonly授权下不提交workflow、不审批、不新建credential/token，持久化明确未验证。
- 不改真实branch保护、runner配置和webhook，不借测试部署现网。

## 可核验反例
- Maintainer按职责启动本项目pipeline，未得到额外对象：正常功能。
- `pull_request_target`只checkout批准base且不执行PR代码：事件名不成立漏洞。
- `workflow_run`校验artifact digest/来源且不执行不可信内容：相关候选可否定。
- secret仅有名称列表、值不可读取：不是secret泄露证据。
- OIDC subject限制到批准environment且审批有效：不是任意actor取得云角色。
- CI_JOB_TOKEN跨project按批准allowlist且仅获准制品可读：合法共享。
- Jenkins管理员用合法credential执行本职job：不能重复计作独立RCE。

## 缺口与记录
- 记录起始权限、actor/token、对象/owner、代码来源、允许操作与gate条件。
- 记录单变量基线/对照、commit/ref、run与审计证据、新增权限和反例排除。
- 缺审批/runner/下游策略资料时分项记缺口；401或 /user失败不证明所有API都无权限。
- API列表分页/采样范围需说明；一次发现不代表CI域覆盖完成。
- 历史/演示secret也不能免责；但有效性未知只记候选，不把字面量当confirmed。
- 令牌、部署key、webhook URL等脱敏；不把正常失陷权限重复记洞，保持项目quality。

## 工具边界
- 已注册 `http-framework-test`可做有限metadata对照，禁凭据跨域redirect/请求概览输出。
- `checkov`/`trivy`仅已有依赖且关闭默认联网/下载时分析提供的本地产物，结果为候选。
- `exec`不代表gh/glab/Jenkins客户端可用，不运行来源命令或自动clone全历史。
- 缺能力blocked，禁运行时安装、秘密外传、长期访问植入、DoS和现网发布。

## 来源、改编与许可
- 改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。
- 作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
- 源：`others/Dark-Moon/conf/agents/{github,gitlab,jenkins}.md`，https://github.com/ASCIT31/Dark-Moon 。
- 快照 `cb0d9b8`（`cb0d9b83e745034c8bcff90daee9668b834d1508`），原GPLv3；本文GPL-3.0-only。
- 用户2026-10-01自述作者并授权自有内容改编；第三方原许可保留，根LICENSE不变。
- 改编将secret外传/接管方案替换为信任图、隔离标记与起始权限对照，不搬固定severity。
- 官方：https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions 。
- 官方：https://docs.gitlab.com/ci/jobs/ci_job_token/ ；https://docs.gitlab.com/ci/variables/ 。
- 官方：https://www.jenkins.io/doc/book/security/ ；https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect 。
