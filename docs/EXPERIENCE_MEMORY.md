# 跨任务经验记忆

## 已实现的三阶段能力

1. **工具修复经验**：同一用户、同一会话、同一工具定义和平台上，在十分钟内按顺序出现的参数失败与结构变化后的完成调用，会生成私有候选。保留参数类型、字段和安全旗标；目标、凭据和任意命令原文不进入自动提炼正文。模型还可主动提出更完整的修复方法。
2. **漏洞验证方法**：模型或用户提交参数化方法、准确验证版本、前提、验证判据、失败说明和完整文本附件，并绑定真实执行证据。搜索仅返回已审核且条件匹配的内容，未知版本或前提不满足时不召回。
3. **工作流与技能沉淀**：工作流和失败反例采用相同审核、版本和反馈机制；当前版本在至少两个独立会话中获得审核员确认的成功结果后，可以下载版本化技能 ZIP。不会自动写入或覆盖全局 `skills/`。

这是外部经验记忆，不会训练或修改模型权重。自动提炼目前为确定性的参数结构归纳；漏洞与复杂工作流由 Agent 的 `propose_experience` 主动提炼，不会后台读取所有对话并无条件生成方法。

## 配置

在配置文件中添加（省略时也默认启用）：

```yaml
experience:
  disabled: false
  auto_learn_disabled: false
```

这些开关在应用启动时生效，修改后需要重启后端。`auto_learn_disabled: true` 只关闭自动工具学习，保留提案、检索、审核和导出；`disabled: true` 关闭整个运行时经验服务。数据库表仍保持兼容，已有经验不会被删除。

经验数据存放在会话数据库中，兼容 SQLite 和 PostgreSQL，不依赖知识库是否启用。检索使用权限过滤、条件匹配及本地关键词排序，不请求第三方嵌入或搜索服务。

## Web 使用方式

在侧栏「知识 → 经验记忆」中：

- 查看自动生成的候选，按状态、类型、项目和关键词过滤。
- 「查看与审核」展示内容、适用条件和当前可访问的证据。
- 修改 JSON 后保存会创建新内容版本，并重置为私有候选，旧版本保留。
- 审核时填写真实依据；确认实际输出和基线后才标记“条件内已验证”。正常退出或 HTTP 200 不能单独证明方法有效。
- 共享时明确选择原项目或跨项目，使用 `{{target}}`、`{{credential}}` 等占位符。
- 可以确认本次复用结果；成功/真实失败须提供执行记录、实际环境和审核依据。
- 满足两个独立会话成功的要求后，可以导出 ZIP。解压后为标准 `SKILL.md` 与 `references/` 文本附件，由管理员通过已有技能管理流程安装。

首版编辑和反馈界面采用结构化 JSON，避免隐藏或自动推断关键适用条件。

## 权限边界

- `experience:read`：访问自己的记录、已授权项目内已验证方法，以及已验证的共享方法。
- `experience:write`：提交候选、修改自己有权维护的内容、记录观察。
- `experience:review`：审核经验和确认复用结果。不能因此自动获得跨项目共享权限。
- `experience:share`：发布脱敏方法。需要全局权限范围。
- `experience:export`：下载通过审核且满足独立复用要求的技能包。

管理员默认拥有全部权限；普通操作员可读、可提案，不获得审核、共享或导出权限。只读用户不能提交。

**共享方法不会共享原始证据。** 原始执行快照单独保存，读取时仍检查 `monitor:read`、源所有者及当前项目/会话授权。跨项目读者不会收到不可访问的执行 ID、来源项目或审核人备注。历史内容版本只对所有者或全局读者开放，避免重新暴露共享前删除的私有内容。

共享校验会拦截明显的地址、字面目标 URL 和凭据；公开参考链接必须不含用户信息和查询参数。启发式检查无法识别所有客户敏感信息，审核员仍须检查正文、参数、附件及来源。

## Agent 工具

- `search_experience`：按产品与准确版本、工具名、定义哈希、平台、已确认事实和关键词检索。
- `get_experience`：按需读取已审核方法及文本附件；拒绝向 Agent 加载候选或已废弃内容。
- `propose_experience`：提交候选，不能指定所有者、验证状态或共享范围。
- `observe_experience`：只记录 `inconclusive` 或 `environment_mismatch`，不能自行增加成功/失败统计。

单代理、Deep、Supervisor、Plan-Execute 和专家角色共享使用规则；有权限且角色工具列表包含搜索与详情工具时，会在新任务开始时给出少量匹配当前工具定义的经验索引。显式角色工具白名单不会被绕过。

识别新框架时，Agent 应提供 `product`、准确 `version` 和前提 `facts` 进行检索；版本未知先继续识别。不命中时继续查询参考知识或外部资料，不将“无经验”解释为“无漏洞”。

## 数据与生命周期

- `experience_entries`：当前内容、确认状态、共享范围和所有者。
- `experience_revisions`：不可变内容版本与内容哈希。
- `experience_evidence`：内容版本与原始执行的关联。
- `experience_execution_archives`：私有原始证据快照与完整性哈希，不随监控记录清理消失。
- `experience_reviews`：审核决定与依据。
- `experience_outcomes`：按内容版本和实际执行去重的观察、成功和失败。
- `experience_execution_metadata`：执行开始时固定的工具定义与平台。
- `experience_learning_events`：持久化学习事件及处理状态。

执行记录与学习事件在同一事务提交。消费者每三秒处理一个有界批次；生成候选及完成事件也在同一事务中提交，支持重启重放和重复处理。处理失败最多重试五次后标记 `failed`，不无限重试。

参数解析发生在 MCP 执行服务之前的失败，也会由编排中间件记录；外部 MCP 工具使用带服务名的完整名称及定义哈希。没有已注册定义的原生文件系统工具不会被猜测为已识别工具，仍可由 Agent 主动提案。

`candidate → verified → needs_review / deprecated` 为发布生命周期。当前内容版本出现三个不同执行的审核确认真实失败后转为待复核；权限、取消、网络和超时不计为方法失败。内容修改后必须重新审核。

准确版本为已验证版本白名单，不自动推断版本范围；必要和排除条件均需要足够的当前事实。工具定义哈希不是二进制版本检测器：升级本机工具程序但定义不变时，仍需要人工复核，或给经验增加明确的工具版本前提。

## HTTP API

- `GET /api/experiences`：分页列表；`status`、`kind`、`query`、`project_id`、`limit`、`offset`。
- `POST /api/experiences`：提交 `content`、`evidence` 与可选 `origin_project_id`。
- `GET /api/experiences/:id`：当前版本及可访问证据索引。
- `PUT /api/experiences/:id`：提交当前 `revision` 与新的完整提案，创建下一版本。
- `GET /api/experiences/:id/revisions`：受限版本历史。
- `GET /api/experiences/:id/evidence/:executionId`：单独鉴权的私有证据快照。
- `POST /api/experiences/:id/review`：`revision`、`status`、`scope`、`note`；审核权限和共享权限分别检查。
- `POST /api/experiences/:id/outcomes`：不确定或环境不匹配观察。
- `POST /api/experiences/:id/confirmed-outcomes`：审核员确认结果，须提供真实执行、环境和依据。
- `GET /api/experiences/:id/skill`：下载审核后的版本化 ZIP。
- `GET /api/experiences/learning-events`：全局审核员查看队列状态。

陈旧版本的修改、审核和结果提交返回 `409`；原始执行不属于当前项目、外部证据不可访问、匿名或越权请求均拒绝。

## 测试与运维注意

新增测试覆盖：适用条件、未知版本、脱敏、发布权限、角色范围、事务回滚、重放幂等、定义变更、跨任务误关联、证据归档与完整性、候选拒绝加载、结果造假及独立复用导出门槛。

```bash
go test ./internal/experience/... ./internal/database ./internal/handler ./internal/security ./internal/app ./internal/agent ./internal/multiagent ./internal/projectprompt
node --test web/static/js/experience.test.cjs
```

运行数据库测试需要可用的 CGO C 编译器。SQLite/PostgreSQL 主库备份须包含经验表；经验会长期保存私有证据，部署者应按项目数据政策管理备份、保留与删除，不将主库或证据快照当作公开知识包。

本次实现不会自动部署服务器或重启线上后端。
