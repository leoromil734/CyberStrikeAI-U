# 报告提交、阶段交付与运行终态

## 三种不同状态

- **候选输出**：模型的普通正文、流式文本或过程记录，即使标题写着“正式最终报告”，也不是已交付结论。
- **完整交付**：通过执行证据、覆盖及其他现有检查，`finalizable=true`、`finalized=true`。Deep/Supervisor 的报告候选还须由当前主代理成功执行 `exit` 提交。
- **阶段报告**：本次运行已停止，但完整评估检查未通过。由服务端依据数据库中的会话记录生成，状态仍为 `blocked`、`failed`、`timeout` 或 `cancelled`，不把覆盖不足改判成成功。

## exit 的含义

Deep 使用 Eino v0.8.13 的原生 `ExitTool` 和 `ReturnDirectly` 注册提交工具；Supervisor 使用框架原生 `Exit`。完整报告正文放入 `exit.final_result`，不要先作为普通正文输出后继续补写。

`RunResult.ReportSubmitted` 只由当前执行段主代理路径上的成功 exit 结果设置。历史 exit、子角色 exit、失败工具结果、未执行的工具参数都不算本次提交。当前成功提交的报告优先于更长的普通草稿；其原始全文保存在 `SubmittedReport`，不参与工具输出截断或正文去重。Plan-execute 保持其原有生命周期。

exit 结束模型运行，不代表评估完整。提交后的覆盖检查若失败，停止本次运行并保留缺口，不能自动再启动覆盖补写。对于已形成完整报告结构的普通候选，也不重新进入覆盖补写循环；它仍不是成功交付。没有提交报告的短过程输出仍受既有续跑、绝对时限、事实写入和独立证据进展预算约束。

## 阶段报告接口

SSE 和 JSON 显式携带以下字段：

- `deliveryAvailable: true`
- `deliveryKind: "partial_report"`
- `runTerminated: true`
- `deliveryText`：服务端生成的阶段报告 Markdown。

这些字段不替代 `status`，也不提升 `finalizable`、`finalized` 或 `evidenceVerified`。仍有工具执行、待人工审批或数据库状态无法核实时，不提供阶段报告合约。

报告包含会话所属项目、真实停止状态、累计完成态工具记录、可核实的独立候选库存概况、仅该会话/项目的已登记发现、范围限制及后续建议。工具调用数不是验证次数；处置关联数不是安全端点数；无已登记漏洞不等于目标安全。未经完整检查的模型安全评价不复制到阶段报告主正文。

原候选保存在 `finalization_check.finalText`，完整诊断保存在 `missingChecks`，原过程记录及证据不删除。主消息保存与前端交付相同的阶段报告。历史回放及懒加载只能补状态标签，不得用旧草稿覆盖已保存正文。

## 离线回归

- `internal/multiagent/eino_report_submission_test.go` 使用真实 Eino Deep/Supervisor 运行器和模拟模型，验证主路径提交、子任务隔离、历史边界及提交优先级。
- `internal/agentfinalizer/partial_delivery_test.go` 验证阶段报告不提升成功状态、待工具/审批时拒绝交付、发现按会话隔离和未知数量不被写成零。
- `internal/handler/partial_report_delivery_test.go` 验证报告后不再自动补写、数据库/SSE/批量任务一致。
- `web/static/js/report-delivery.test.cjs` 使用内存 DOM/SSE 夹具，验证严格交付合约、历史回放及晚到事件不覆盖报告；不调用模型或扫描目标。
