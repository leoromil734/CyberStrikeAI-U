# 测试覆盖与任务效率优化

本轮改动针对技能执行一致性、负结果范围、跨会话恢复和覆盖完成检查；不扩大授权范围，不恢复用户排除的低价值测试。

## 运行时变化

- `internal/coverage` 是不依赖数据库的结构化检查器：检查 manifest、六阶段、来源计数、脚本队列、端点与风险单元引用、终态和证据字段。
- `agentfinalizer` 在本轮写入评估 manifest 时自动检查；API 可显式设置 `finalization.requireCoverageEvidence=true`，在缺少清单时也阻断。不会根据“deep”编排名或自然语言猜测测试意图。
- 清单按 assessment_id 隔离，并限制为当前会话；旧轮次与其他会话的记录不能满足当前要求。普通后续问答不被历史清单自动拦截。
- 检查失败提供 coverage_incomplete 缺口，Eino 流式路径最多自动续跑两段，输入为有长度/数量上限的宿主缺口清单，保留范围和排除项。
- 端点 body 提供 endpoint_url、method、assessment_id 时，事实工具按完整 origin 与大小写保真路径生成稳定 key；随后引用实际返回的 fact_key。未提供新字段的旧事实不自动迁移。
- 事实工具部分更新保留省略字段；明确 false/空关联仍可清空。旧数据库 API 的全量更新行为继续兼容。
- 软恢复从数据库原始 user 消息重建约束快照，保持用户消息优先级，不重放历史系统指令或工具伪造的约束。
- 事实索引优先保留活动阶段、待处理资源、端点与风险单元，显式置顶仍优先。
- 知识检索展示保留最终精排次序，不再用原向量分数改回排序。

## 使用方式

1. 将全面评估会话绑定到项目。
2. 启动时读取 `skills/pentest-blackboard/references/coverage-contract.md`，建立 schema_version:2 的 manifest。
3. 阶段、来源、资源、端点和风险单元都带当前 assessment_id；同步实际库存计数。
4. 根据真实入口选适用单元，不机械生成身份×全部风险的组合。
5. 终态和证据闭合后交付；缺身份、工具或可达性时如实记录 blocked，策略排除记有具体理由的 N/A。

专项短验证、普通问答及旧自由格式事实保持兼容。未绑定项目的任务仍应交付待落库清单；没有持久账本时不能宣称运行时已核验完整覆盖。

## 技能变化

- 补回路由索引引导、压缩入口正文，统一回连工具名称与角色中的 jsluice 能力。
- 允许授权范围内低成本准备两个受控身份；有次数和时间预算，挑战/费用/人工前提即阻断，不磨注册。
- 基础负探针只否定当前假设；同皮仅复用前端发现，后端安全结论需要部署自身证据。
- 系统繁忙、维护和超时不代表认证安全；等待身份、回调或异步结果不阻塞独立 ready 单元。
- 新入口、身份或部署版本重新映射；连续失败的禁止重复范围限定为入口+身份+方法+参数组合。
- 源码阶段明确衔接既有白盒运行时对齐流程；保持一种子闭环与原低价值过滤。

## 回归验证

```powershell
go test -count=1 ./internal/coverage ./internal/projectprompt ./internal/skillpackage ./internal/agents ./internal/vulnquality
go test -count=1 ./internal/database ./internal/agentfinalizer ./internal/handler ./internal/multiagent ./internal/project ./internal/knowledge ./internal/app
```

Windows 的 w64devkit GCC BigObj 输出与当前 cgo 不兼容时，需要使用兼容的 C 编译器；本轮采用临时 Zig cc 验证，不改持久 Go 配置或 go.mod。
新增测试覆盖：事实部分更新、清单终态/缺口/库存一致性、会话隔离、端点碰撞、约束恢复、防止工具伪造恢复信号、上下文优先级、知识展示排序和技能/工具一致性。

## 当前边界

覆盖检查验证结构与状态闭合，不替代动态证据人工/模型复核，也不自动证明范围中的未知入口已全部发现。
本轮未实现完整浏览器身份托管、全参数自动变异器或端到端靶场发现率基准。优化的实际召回与成本收益，仍需固定模型、范围、目标版本和预算的重复评测；已确认发现按根因去重，排除项不计入召回分母。
