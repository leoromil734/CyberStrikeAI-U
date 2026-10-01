# IaC：source、state、plan 与部署证据

## 适用条件
- 已提供 Terraform/Terragrunt source、tfvars、tfstate、plan或确切授权backend/workspace。
- 文件来源和格式可核验；名称像tfstate、bucket域名或非404不能确认内容暴露。
- SRC先使用 `src-hunting`，本篇补产物关联方法，不替代已有云配置审计。
- 默认本地静态/只读分析，不执行terraform初始化、计划、刷新或部署。

## 身份 → 对象 → 允许操作
- 身份分repo reader、CI builder、workspace owner、backend reader及云部署主体。
- 对象分source commit、module/provider version、workspace、state key/version与plan run。
- backend bucket/container/key/prefix与workspace映射明确，不把同名文件当同环境。
- 允许操作分source read、state read、plan view、backend write/lock及部署操作。
- 有效owner读取state是正常能力；非owner读取批准范围外的敏感产物才是对照。
- sensitive输出标记减少UI显示，不保证raw state/plan不含明文；存储本身不是漏洞。
- tfstate是某个时点的快照，不能不经核对就当实时云资源/有效secret事实。

## 产物预检与关联
1. 每份产物记录来源、获取授权、文件哈希、时间、commit/run、格式与版本。
2. raw state记录lineage、serial、terraform_version；这些字段不是防伪签名。
3. plan JSON记录format_version、terraform_version、prior_state、planned_values与resource_changes。
4. source记录module source/ref、provider lock、变量来源与backend配置，不执行module获取。
5. Terragrunt记录include/依赖、remote_state与生成配置，避免误用父目录workspace。
6. HCL可能含环境依赖/run_cmd/hooks；只读解析，不执行Terragrunt求值。
7. 二进制plan只有在已有兼容解析能力且获准时转换；缺能力记blocked，不联网装版本。
8. 接收state/plan后先限制敏感输出，禁止整份打印到普通日志。

## 资源地址 → 属性路径
- raw state关联 `resources[]` 的module/type/name与instances索引/instance_key。
- 保留完整地址，如 `module.app.aws_db_instance.main["prod"]`，不要只记资源类型。
- 按实例定位具体attribute路径与值类型，避免grep匹配到示例或未使用字段。
- plan/show JSON与raw state结构不同，不能复用同一解析路径假装完整扫描。
- 关联before/after、actions、after_unknown与sensitive标记，unknown不是安全或空值。
- deposed/历史实例、destroy action和data resource分别记录，不当当前运行对象。
- provider schema差异与缺失字段记解析缺口，不推断所有秘密均已覆盖。

## source/state/plan/deployment 交叉核对
- source说明意图；plan说明某次拟执行变化；state说明上次记录；实时API说明观察时状态。
- 比较是否同commit、workspace、backend、resource ID和run，先排除环境错配。
- 静态通配policy/公网CIDR是候选，需实际业务授权、deploy状态与可达性证据再确认影响。
- plan有修复不代表已apply；state有旧值不代表现网仍使用；源代码已删也不清除旧产物。
- drift只能在授权只读实时资料与可比时点下描述；不运行refresh来“补证据”。
- 无实时访问时结论写“静态配置/历史快照风险”，不声称现网已被控制。
- demo/test标签不免责，需判断是否被真实业务信任；也不把随机占位字面量当有效secret。

## backend 读权对照
1. 使用已知授权对象key和两个受控身份，禁止列举整个bucket/container或猜测他人workspace。
2. owner身份读取测试state建立合法基线，低权限/匿名读取同一对象建立拒绝对照。
3. 只变主体，固定URL、object version与region；分别记录网关/CDN/object storage响应。
4. 返回200须核验state结构、对象来源与敏感测试标记；HTML错误页/catch-all不是state。
5. pre-signed/hosted-state-download URL携带授权，不把无header请求当真正匿名公开读取。
6. redirect到新域需先核范围/凭据传播；对象version不同不得直接比较。
7. 元数据请求不能证明body读权，实际读取需授权与敏感值处理方案。
8. 不做state upload、lock/unlock、backend迁移、apply/destroy/import或state修改。

## 秘密与新增能力
- 标注秘密类型、资源地址/属性路径、使用环境与来源，不输出实际值。
- 有权state reader正常看到部署需要的secret，不重复计作独立权限漏洞。
- 不获准主体得到测试secret标记或受保护配置，才能证明读取边界跨越。
- 历史secret可能已轮换，不能用字符串存在推断当前有效，也不尝试登录外部目标。
- 默认不利用secret做云/数据库横向测试；若无有效性验证，影响范围明确待证。
- 配置severity与扫描标签不等于项目quality；记录额外权限及反证而非固定critical。

## 目标侧证据与持久效果
- backend读取证据保留请求身份、key/version、状态与对象存储访问审计request ID。
- 结合workspace/run日志和资源ID说明哪份产物属于哪次部署，不能混用不同环境。
- 已提供离线产物只能证明其内容，不能单独证明当前低权限可从backend读取。
- 本篇默认不执行写入，明确“部署/持久化/当前凭据有效性未验证”。
- 获取的签名链接、连接串、私钥和state原文件放受限证据位置，正文仅必要脱敏字段。

## 可核验反例
- private backend只允许批准CI/owner，匿名和非owner拒绝：正常访问控制。
- 敏感值标记为sensitive但raw state含值：设计事实；需不获准读权才是越界。
- 显示public CIDR的是已销毁旧实例，当前API证实不存在：不能确认现网公网暴露。
- plan包含宽权限拟变更但未执行：候选变更风险，不是部署确认。
- hosted下载URL含有效签名，普通无签名URL拒绝：授权链接，不是公开bucket。
- 旧serial与当前workspace不匹配：历史/环境错配证据，应限定结论。
- scanner匹配示例模块且未被引用：不等价于实际资源配置漏洞。

## 缺口与记录
- 缺来源/commit、workspace/lineage映射、backend身份或实时对照时逐项标明。
- 缺二进制plan解析能力blocked；静态资料无法复验读取边界则tentative。
- 记录身份→产物→允许操作、资源地址/属性路径、基线与未授权对照。
- 记录审计/对象version、时间窗口、额外能力、反例排除、采样与解析覆盖范围。
- 403、404、授权过期、timeout与格式不兼容分别记录，不把两次timeout判安全。

## 工具边界
- 仓库启用定义有 `checkov`、`terrascan`、`trivy`，会话注册/依赖需核对。
- 仅提供的本地产物、已有离线规则/数据库；关闭默认下载、遥测和联网模块获取。
- 包装器参数按当前schema核对，不假设支持terraform show或任意原生子命令。
- `http-framework-test`可限量验证获准HTTP backend；关闭请求概览，审查redirect。
- `exec`仅受控已有解析器，不安装Terraform/Terragrunt/provider，不运行来源命令。

## 来源、改编与许可
- 改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。
- 作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
- 源：`others/Dark-Moon/conf/agents/terraform.md`，https://github.com/ASCIT31/Dark-Moon 。
- 快照 `cb0d9b8`（`cb0d9b83e745034c8bcff90daee9668b834d1508`），原GPLv3；本文GPL-3.0-only。
- 用户2026-10-01自述作者并授权自有内容改编；第三方原许可保留，根LICENSE不变。
- 改编去除literal/public-state自动确认，补产物时序、环境对应、readonly与反证。
- 官方：https://developer.hashicorp.com/terraform/language/state/sensitive-data ；https://developer.hashicorp.com/terraform/internals/json-format 。
- 官方：https://developer.hashicorp.com/terraform/language/backend ；https://terragrunt.gruntwork.io/docs/reference/hcl/blocks/ 。
