# n8n 与插件工作流定义的只读数据流审计

## 适用与授权边界
- 适用于获授权 n8n 导出 JSON、插件 manifest、工具定义、工作流配置和关联源码。
- 审计对象是文件中的节点、连接与能力声明，不是自动启动线上工作流。
- 导出可含敏感参数和执行样本，先确定允许读取、存储和发送到模型的范围。
- `tentative` 为影响未证实候选，`confirmed` 为已证明指定缺陷，`blocked` 为权限/依赖缺口。
- 静态硬编码秘密可证明文件暴露事实；秘密活性、权限和利用影响必须分开说明。
- 不导入/激活流程，不发送线上 webhook，不执行 Code 节点或插件安装脚本。

## 版本、模型与身份基线
- 固定定义文件哈希、导出时间、来源、工作流 ID、修订号与是否活动的已有材料。
- 记录 n8n 实际版本、节点 type/typeVersion、社区节点包与插件版本。
- 编辑器导出、部署中的版本、测试分支与运行实例可能不同，不能相互替代。
- 模型记录 provider、model ID、固定版本/可变别名、adapter 与系统提示来源。
- 记录工具 schema、资源来源、检索库修订及模型输出处理组件版本。
- 记录操作者、工作空间、租户、触发身份及每个 credential 引用的所有者。
- Credential 引用 ID 是关联标识，不是秘密内容，也不证明该凭据当前存在或可用。
- 服务账号权限、token audience/scope/expiry 和下游目标是有效能力的重要约束。
- 无凭据元数据或部署配置时保留未知，不自动查询凭据服务或解密导出。

## 节点与连接的原理
- 建立节点 ID、name、type、参数、credential refs、禁用状态与输入/输出清单。
- 连接按来源端口、目的端口、输出分支及条件记录，不能只画节点相邻关系。
- n8n 常规数据流、AI 模型/工具连接与记忆/检索连接含义不同，需分别解释。
- IF/Switch、Merge、Loop、Wait、错误处理和子工作流可能改变身份、顺序与可达性。
- 禁用节点、孤立节点、pinData 与运行时输入分别标注，测试样本不等于当前运行数据。
- 子工作流引用未提供时，该段记 `blocked`，不要假设继承原触发者权限。
- 表达式 `={{…}}` 是求值线索，需追踪输入来源及实际参数语义，不能当成已执行注入。
- 节点 name 可变，报告优先使用稳定 ID、参数路径与定义文件哈希。

## 信任源、秘密引用与 sink
- Source 包括 webhook body、查询参数、外部 HTTP、数据库记录、文件、检索文档与模型输出。
- 标注哪些字段能被低权主体影响，哪些来自受控配置；外部数据不自动成为指令。
- 中间变换记录模板拼接、字段重命名、编码、默认值、过滤和丢失的身份上下文。
- Sink 包括 Code、命令、HTTP 请求、SQL、文件、邮件/消息、发布、支付与部署节点。
- 对 URL/路径/收件人/对象 ID 等能力参数，追踪规范化、schema 与目标授权。
- Code 节点文本可见不等于所有模块可用；task runner、沙箱与部署限制影响实际能力。
- `require`、`eval` 或命令样式字符串是审计候选，不运行它来判可达性。
- 硬编码 token 与 credential ref 分开记录；引用的存在不能被描述为凭据明文泄露。
- 秘密送往模型需核对输入字段、provider/接收方与数据政策，不把模型调用当本地处理。
- 从导出移除秘密不撤销已泄露秘密，轮换需要所有者批准。

## AI 与插件组件差异
- 普通 HTTP/DB 工作流不等于 AI Agent；分别标注确定性节点与模型决策节点。
- 模型可选工具不等于可调用工具，运行时策略、schema、凭据和目标权限需单独核对。
- 插件 manifest 声明网络或文件权限不证明进程实际获得权限。
- Instruction-only skill 可以影响行为，但不能据名称推断任意系统执行。
- 检索文本进入 prompt 与模型输出进入 sink 是两条不同的数据流。
- 模型把不可信字段转为动作参数时，应在 sink 端重新验证身份、目标与动作。
- 人工审批节点需核对批准主体、参数绑定及重试后是否重新校验，不只看节点存在。
- Provider fallback 会改变数据接收方与模型行为；未知 fallback 记录为缺口。
- 不引入 PAIR/TAP 自动越狱、批量载荷、无界重试或自动扩大工具范围。

## 只读执行流程
1. 固定文件与权限，先脱敏执行样本、秘密和个人数据，保留字段位置及摘要。
2. 解析定义为节点/端口/分支清单，标出禁用、缺失与未知组件。
3. 对每个外部 source 标注可控字段、用户/租户、输入 schema 与身份传递。
4. 沿连接追踪到 prompt、工具参数及 sink，引用每次变换和校验。
5. 核对 credential 所有权、有效作用域与目标环境的已有材料。
6. 对重要路径记录审批、失败、取消、重试、子流程与并行分支的处理。
7. 建立正负静态夹具，分别观察合法路径、断连、参数化与无权主体的策略材料。
8. 输出定义事实、候选路径、缺失证据及独立动态验证需求；不触发线上流程。

## 基线、证据与反证
- 基线是同一修订的获批正常流程定义及预期身份/目标，不用另一个工作流替代。
- 单变量夹具可改变一个连接、输入字段或审批条件，不执行原 Code/插件代码。
- 对照应包含输入 schema 拒绝、SQL 参数化、目标 allowlist、credential 隔离等阻断材料。
- 证据包含文件哈希、节点 ID/name/typeVersion、参数 JSON 路径与连接端口。
- 路径证据写为 source→变换/guard→sink，指出每一步身份与数据控制变化。
- 静态可证明的是定义存在和特定校验缺口，不把可疑路径描述为真实执行结果。
- 越权确认需要另获授权的运行记录、真实目标副作用/私有数据回查及拒绝对照。
- 模型响应声称“已发送”或截图显示流程完成都不能替代目标审计。
- 未连接或禁用节点、不可用凭据、沙箱禁止 API、下游授权拒绝是重要反证。
- 公开 webhook 若只处理公开合成数据且无敏感能力，不能自动确认高危。
- 扫描到 credential ref、假 token、pinData 示例或未知节点不等于秘密活性。

## 工具依赖、停止与清理
- 文件分析使用只读读/搜能力；无需新增 n8n 客户端、插件运行器或测试工具。
- 已注册 `http-framework-test` 仅可映射另行批准的测试目标验证，不用于静态阶段。
- `trivy` 仅可映射获批本地插件依赖扫描，不能因此执行插件或触发数据库联网更新。
- 工具已注册仍需核对安装、范围及数据流；缺客户端/凭据/schema 记 `blocked`。
- 不通过 `npx`、安装包、导入流程或初始化 stdio server 来“发现”能力。
- 发现真实秘密、生产端点、外部 provider 发送或状态改变要求即停止该分支。
- 不主动访问 webhook、credential API、模型端点或隐藏子工作流。
- 清理临时脱敏副本与合成夹具；保留批准的路径证据，不保留完整秘密。

## 修复与可测正反例
- 使用凭据存储与最小作用域，按触发者/租户检查目标，不只靠流程所有者权限。
- 结构化并参数化下游输入，约束 URL/路径/对象与收件人，隔离 Code/插件执行权限。
- 模型只接收必要数据；对有实际后果的操作绑定精确参数与批准上下文。
- 失败与取消应阻止副作用，重试要考虑幂等与重复审批，不静默切换更高权凭据。
- 正例：夹具清楚连接低权输入到高权写入 sink，且无授权 guard；结果仍是静态候选。
- 反例：相同节点存在但无连接、已禁用，或目标范围校验可靠阻断输入。
- 确认例需额外运行证据：获批测试中低权输入写入另一自有租户的合成对象。
- 否定例：模型声称完成但测试目标审计无写入，不能升级为 `confirmed`。

## 跨源归属、改编与官方参考
- NeuroSploit `5d4e7e0`（本地标注 4.2.1）：`agents_md/ai/n8n_workflow_audit.md`、`agents_md/ai/n8n_ai_node_audit.md`；用于节点、连接、表达式与 AI 数据流清单，原归属 Joas A Santos & Red Team Leaders。
- 上游：https://github.com/JoasASantos/NeuroSploit/tree/5d4e7e0/agents_md/ai 。
- Strix `007ed1a`：`strix/skills/vulnerabilities/agentic_system_security.md`；用于有效权限、凭据、审批及插件身份差异，原归属 Strix / OmniSecure Inc.；https://github.com/usestrix/strix/blob/007ed1a/strix/skills/vulnerabilities/agentic_system_security.md 。
- 本文为中文重组与增补，移除上游由静态定义自动转线上探测、安装及模型响应即确认的要求。
- 官方资料按目标版本核对，未联网查最新：https://docs.n8n.io/workflows/export-import/ ；https://docs.n8n.io/data/expressions/ ；https://docs.n8n.io/advanced-ai/ ；https://modelcontextprotocol.io/specification/ 。
- Strix 原 Apache-2.0 声明：Copyright 2025 OmniSecure Inc.；本文已作中文改编与增补。
- Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0 。
- Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
- NeuroSploit 上游 MIT 许可随本篇保留如下。

> MIT License
> Copyright (c) 2026 Joas A Santos & Red Team Leaders
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
