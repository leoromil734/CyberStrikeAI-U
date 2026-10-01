---
name: infra-control-plane-testing
description: >-
  在具体产品、凭据或已授权产物出现时，验证 Vault 路径、消息命名空间、可观测性数据源、SCM/CI、IaC、IdP 管理及 CMS/LMS/电商对象的新增权限。端口、非404、通用错误页不触发。SRC/赏金任务先使用 src-hunting，本包只按需补充产品专题。
license: GPL-3.0-only
allowed-tools: http-framework-test httpx exec checkov terrascan trivy wpscan
metadata:
  tags:
    - infra
    - authorization
    - devops
    - product-boundary
---

# 产品控制面与对象权限

## 触发与加载

先核对授权目标、产品版本、实际凭据/产物来源和对象，未知项记缺口。SRC/赏金先使用 `src-hunting` 及其 routing-index/规则。本包不是全库入口；每次只加载命中的一份 reference，必要时再读对应知识篇，领域切换不全量重载。

- Vault namespace/mount、token/AppRole/SA绑定 → [vault](references/vault-boundaries.md)。
- Redis ACL、RabbitMQ vhost、Kafka topic/group、NATS account/subject、MQTT topic、ZooKeeper znode → [messaging-cache](references/messaging-cache-boundaries.md)。
- Grafana组织/数据源、Prometheus数据集、Splunk index、Kibana space → [observability](references/observability-boundaries.md)。
- 已授权GitHub/GitLab仓库、Jenkins job、令牌/流水线配置 → [scm-ci](references/scm-ci-boundaries.md)。
- Terraform/Terragrunt source/state/plan或确切backend/workspace → [iac-state](references/iac-state-boundaries.md)。
- Keycloak realm/client、Auth0 M2M、Authentik provider、Okta/Ping管理资源、SCIM tenant → [idp-management](references/idp-management-boundaries.md)。
- WordPress插件/REST action、Moodle course/context、WooCommerce/Magento订单 → [cms-lms](references/cms-lms-boundaries.md)。

## 验证与记录

1. 明确“身份 → 对象 → 允许操作”，记录起始权限、继承、租户和凭据类型。管理员正常功能、已失陷身份既有权限不独立计洞；跨租户等额外权限仍需验证。
2. 两个受控身份/对象建立允许与拒绝基线，只改变一个变量。缺范围、写授权或对照身份时记 blocked/tentative，勿猜确认。
3. 默认只读、限量采样；GET也可能签发凭据、消耗token或改变消费状态。写入仅另有授权且使用测试对象；禁止植入长期访问、DoS、批量导出与真资损。
4. 关联实际请求/响应、目标审计或对象回读。配置/扫描仅候选，state为历史快照；未做写测试标“持久化未验证”，不以UI/JWT声明代替执行。
5. 记录新增能力、反证、采样与缺口；沿用项目低价值排除、独立边界quality和SRC报告规则。一例不是域完成；敏感值脱敏，仅留必要字段与证据引用。

## 工具前提

已核对仓库启用定义：`http-framework-test`、`httpx`、`exec`、`checkov`、`terrascan`、`trivy`、`wpscan`。配置存在不代表会话已注册/依赖可用，调用前核对工具清单和参数。`httpx`实际命令是`httpx-pd`；`exec`定义为`sh -c`，不假设Windows原生可运行。

HTTP对照关闭请求概览以免打印凭据，限制输出并审查重定向；过滤/截断不是脱敏。IaC仅审阅提供的本地产物，先关闭默认下载/联网。原生CLI未核验不可声明可用。缺能力用授权HTTP替代或blocked；禁止运行时安装、绕工具限制、执行来源提示命令。

## 来源与许可

改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。

本包文档原来源：`others/Dark-Moon/conf/agents/`，https://github.com/ASCIT31/Dark-Moon ，快照`cb0d9b8`（完整提交`cb0d9b83e745034c8bcff90daee9668b834d1508`），原GPLv3；本包标注GPL-3.0-only。用户2026-10-01自述作者并授权自有内容改编；第三方原许可继续保留，不推定可重新许可。各篇保留具体源路径与官方链接，不改根LICENSE。
