# 可观测性数据授权工作流

仅在 Grafana 数据源/组织/服务账户、Prometheus 查询数据集、Splunk index 或 Kibana space/ES数据权限明确时触发。开放metrics、端口或错误页不自动 dispatch；SRC 先使用 `src-hunting`。

1. 写出前端主体 → 平台组织/space → 数据源 → 后台凭据主体 → 允许数据集；分开 dashboard 可见性、查询权与管理权。
2. Grafana 先对照角色、数据源权限及组织；数据源 secureJsonFields 仅说明已配置秘密，不是明文泄露。proxy 与 ds/query 路径按实际版本核对。
3. 用受控测试数据集和最小只读查询对照两个角色，固定查询只切身份或对象；后台使用服务凭据是正常设计，只有读取政策禁止的数据才构成额外能力。
4. Prometheus targets/config 只验证范围内有限字段；Splunk 对照 role 的 index/search filter；Kibana 对照 space 与 Elasticsearch index/DLS/FLS。导航隐藏不等于服务端拒绝。
5. 关联请求、实际返回行/字段与目标查询审计；配置返回内部地址仅记线索，不以此访问外部/内网其他目标。readonly 不允许改数据源、告警、插件、账户或停监控。
6. 公共snapshot、批准的共享dashboard、Viewer获准查询、普通版本/拓扑信息为可核验反例；沿用项目低价值排除，不认定 datasource 代理必然SSRF或SQL查询必然注入。

工具：核对 `http-framework-test` 当前注册和依赖，禁带凭据自动跟随重定向，关闭请求概览；`httpx` 仅低速指纹线索。禁止运行时安装、全量日志导出、高开销查询与真实告警触发。

记录：用户与后台主体、org/space、ds UID/index、预期数据集、单变量对照、返回字段/条数、审计引用、新增数据权限、反证、采样界限与缺口；写入/持久化未测试须明示。

完整知识：[Observability-Data-Authority](../../../knowledge_base/Infra-Control-Plane/Observability-Data-Authority.md)。
改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
来源：`others/Dark-Moon/conf/agents/observability.md`，提交 `cb0d9b8`，原 GPLv3；本文 GPL-3.0-only。用户 2026-10-01 自述作者并授权自有内容改编；第三方原许可继续保留，不改根 LICENSE。
官方参考：https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/ ；https://prometheus.io/docs/operating/security/ ；https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/kibana-privileges 。
