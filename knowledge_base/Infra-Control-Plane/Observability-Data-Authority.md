# 可观测性平台：数据授权证据

## 适用条件
- 已确认 Grafana org/data source、Prometheus数据集、Splunk index或Kibana space/ES对象。
- 存在提供的身份、数据源配置、查询样本或受控测试数据；端口与metrics响应不够。
- SRC先加载 `src-hunting`，沿用低价值排除，按需读本篇，不把拓扑库存当漏洞清单。
- 目标是前端身份借后台数据主体获得未被批准的数据，而非平台正常代用凭据。

## 身份 → 对象 → 允许操作
- 记录前端用户/服务账户、组织/tenant/space、实际角色和资源授权来源。
- 再记录数据源UID/index、连接后台身份、允许表/索引/字段与行过滤规则。
- Grafana Viewer/Editor/Admin是上下文；权限随版本、版本类型、RBAC和插件而异。
- dashboard可读、data source可查询、data source可管理分别映射，不能互相替代。
- `secureJsonFields`指示秘密已配置；不等于API返回密码，也不等于数据必然安全。
- Prometheus自身与反向代理/网关的认证分别核对；不能默认每个部署具备逐租户隔离。
- Splunk分role、index允许集、默认搜索集与search filter，记录token/user主体。
- Kibana分space功能权限与Elasticsearch index、DLS/FLS授权；space不是数据隔离的唯一层。

## 基线与未授权对照
1. 用A/B测试用户和两个无业务秘密的数据集建立允许与拒绝基线。
2. 保持相同短查询，仅切用户或数据源/index一项；避免同时换SQL与对象。
3. 明确政策允许的数据范围；Viewer读取公开dashboard使用的数据可能本来允许。
4. 记录query、数据源UID、org/space、backend identity、返回行数与字段。
5. 使用目标标记证明读到B数据；`current_user`仅证实后台主体，不能证明数据越权。
6. 查询限制时间窗、最大样本/行数和开销；不执行全表导出或高基数昂贵聚合。
7. 缺安全测试数据或数据授权政策时是候选，不猜“用户应该不能看到”。

## Grafana 数据源与代理
- 按实际版本核对 `/api/datasources`、UID/id接口、proxy与 `/api/ds/query`的支持情况。
- 首先检查是否可看到元信息，再分别检查允许的查询面，不从列表200跳到越权结论。
- proxy可能按插件规则向后台转发并使用存储凭据；这是正常机制，需证明额外目标/数据权限。
- 只请求授权测试数据源和获准路径，不以发现internal URL为由访问其他主机。
- rawSql支持不等于SQL注入；正常查询权只要仍在批准数据范围内就是基线。
- 数据库只读角色、行过滤、数据源权限分别记录，缺任一层资料说明缺口。
- datasource edit需要单独写授权，本篇不创建内部目标数据源来证明SSRF。
- 不mint API key/service account token，不改告警/contact point，不向真实频道发送通知。

## Prometheus 与 Alertmanager
- `targets`、`status/config`、query API只对授权部署限量检查，拓扑仅作为事实线索。
- 脱敏配置中的 `<secret>`、token_file路径不是明文秘密泄露。
- `up`或exporter版本信息通常是可见性检查，遵循项目低价值排除。
- 若声明多租户隔离，用已知tenant标记对照认证与query headers，而非猜label名称。
- `web.enable-admin-api`/lifecycle标志只显示潜在操作面，不能代替实际未授权破坏证据。
- 禁delete series、reload、silence真实告警或改监控配置；不执行DoS验证。
- Alertmanager只看获准配置/状态，避免导出业务webhook和私密通知内容。

## Splunk、Kibana 与日志数据
- Splunk固定index/time range/短搜索，用受控字段对照低权限与owner身份。
- 仅列index名称未获得敏感正文不自动计洞，搜索job创建也需考虑目标负载。
- Kibana固定space与查询，核对ES返回是否落实DLS/FLS，不以UI隐藏确认服务端拒绝。
- 跨space共享对象可能按政策许可；跨index可见性需结合实际角色限制。
- 日志内token/个人信息只保留脱敏必要字段，禁止整包下载。
- 不停采集、不改saved search/告警、不伪造日志、不以插件安装证明代码执行。

## 目标侧证据与持久效果
- 保留脱敏完整请求及相关响应字段、测试行标记、时间范围和最大结果限制。
- 用query/job ID、用户主体和时间与目标查询审计关联；记录后台身份与返回数据集。
- 浏览器菜单/截图只作辅助，不代替请求执行和对象归属。
- 平台会话缓存或org切换易污染对照，使用独立会话且记录实际组织头/space。
- 若另行批准测试对象写入，回读与审计确认保存效果和恢复；默认readonly不执行。
- 未验证写入/持久化/下游访问时明确声明，不把能查询写成后台接管。

## 可核验反例
- Grafana Viewer按政策查询共享Prometheus数据，Admin才可编辑data source：正常分权。
- datasource密码不返回，但允许查询授权表：不是凭据泄露或独立越权。
- proxy对批准API有效、越界路径拒绝：正常代理，不能凭server-side转发判SSRF。
- 公共snapshot经owner批准发布，匿名读到发布内容：正常共享基线。
- Splunk低权限只能读批准index，B敏感index拒绝：条件边界有效。
- Kibana换space仍因ES权限不能读B索引：UI对象范围与后端数据范围分层生效。
- Prometheus只有普通版本/拓扑，缺敏感数据/新增权限：按现有低价值政策处理。

## 缺口与记录
- 缺数据policy、第二身份、受控数据或query审计时写明，不自动标confirmed。
- 401/403、空结果、query语法错、timeout、缓存命中分别记录；空结果不是授权拒绝。
- 记录起始权限、前端/后台主体、数据源/index、预期允许操作和资源owner。
- 记录单变量基线/对照、实际数据字段、目标侧证据、额外能力和反例排除。
- 记录采样上限、未验证操作/持久效果与未覆盖数据集；一条问题不代表域完成。

## 工具边界
- `http-framework-test`当前注册与依赖需核对，关闭show_command并禁带凭据跨域redirect。
- `httpx`仅低速探活/指纹线索，不从title/非404唯一确认产品。
- `exec`不等于已具备平台CLI；禁运行时安装、全量导出和来源命令自动执行。
- 响应过滤/截断不是脱敏，生产秘密不通过stdout预览或原始证据公开。

## 来源、改编与许可
- 改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。
- 作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
- 源：`others/Dark-Moon/conf/agents/observability.md`，https://github.com/ASCIT31/Dark-Moon 。
- 快照 `cb0d9b8`（`cb0d9b83e745034c8bcff90daee9668b834d1508`），原GPLv3；本文GPL-3.0-only。
- 用户2026-10-01自述作者授权自有内容改编；第三方原许可保留，根LICENSE不变。
- 改编去除代理/SQL自动确认和持久化规则，补前后端主体、数据集对照与readonly限制。
- 官方：https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/ ；https://grafana.com/docs/grafana/latest/developers/http_api/data_source/ 。
- 官方：https://prometheus.io/docs/operating/security/ ；https://help.splunk.com/ 。
- 官方：https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/kibana-privileges 。
