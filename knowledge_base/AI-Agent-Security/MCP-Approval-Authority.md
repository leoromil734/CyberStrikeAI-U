# MCP 工具有效权限与精确审批绑定

## 适用范围与状态
- 适用于获授权 Model Context Protocol（MCP）客户端、server 配置、工具 schema 与审计记录。
- 本篇分析模型→路由/策略→工具→凭据→目标的真实权限，不实现运行代码或审批系统。
- `readOnlyHint` 是工具注解元数据，不是授权、安全性或无副作用的保证。
- `tentative` 表示候选，`confirmed` 表示实际目标越界被证明，`blocked` 表示授权/依赖不足。
- 模型说执行成功、工具被列出或请求返回 200 都不足以确认越权。
- 只读审计不启动未知 server，不安装 Inspector，不主动发现线上工具或模型端点。

## 协议、组件、模型与身份基线
- 记录协议修订、client/server SDK 版本、初始化/协商材料与传输方式。
- stdio、Streamable HTTP、旧 SSE 或自定义传输分别记录，不互套会话与 OAuth 语义。
- 规范链接是参考入口，必须匹配实际协议修订，不假定上游所引用修订为部署事实。
- 记录 server 发布者、包版本/制品哈希、endpoint/transport、tool name 与 schema digest。
- 记录 model/provider、固定 model ID/可变别名、adapter、提示和路由策略版本。
- 同名工具来自不同 server 或不同 schema 时，是不同批准对象。
- 记录发起用户、租户、工作空间、会话、对话、设备与委托主体。
- 记录 credential issuer、audience/resource、subject、scope/role、环境与 expiry。
- 不保存完整 token；凭据绑定使用受保护的不透明标识与版本/权限摘要。

## 有效权限原理
- 声明能力的上界来自工具、凭据、资源、文件/网络范围、委托和审批规则。
- 实际可达子集受运行策略、目标权限、参数校验、网络隔离与凭据 audience 进一步约束。
- 比较用户原有权限与工具实际权限，避免把服务账号预期操作包装成越权。
- 来源文档、工具描述、检索内容、资源和记忆可能不可信，不能成为新的批准主体。
- Prompt 拒绝是一层行为约束，目标端授权必须独立存在。
- 读取、写入、执行、外部通信、身份管理和费用动作分别分类。
- “只读”调用仍可能返回私有数据、触发外部 fetch 或消耗费用，需要明确数据与目标范围。
- Listing 不证明调用许可；发现未注册工具不允许自动回退到更宽泛 handler。
- Session ID、`_meta` 中的客户端身份与模型声明不能替代认证身份。

## 注解、schema 与目标参数
- `readOnlyHint`、`destructiveHint`、`idempotentHint`、`openWorldHint` 只能辅助展示与候选分类。
- Server 可声明错误注解，客户端仍要依据实际行为和授权决定是否允许动作。
- Schema 是输入约束，不是业务对象 ACL，也不证明实现符合声明。
- 处理缺失/额外字段、嵌套对象、类型、长度与平台路径差异时以实际解析语义为准。
- URL、路径、资源 ID、收件人、SQL 与命令选项属于能力参数，应在目标边界验证。
- 原始参数、规范化参数与真正执行参数分别留脱敏关联，避免签名对象与执行对象不同。
- Schema 变化或未知工具应失败关闭，不自动选另一 server 或更高权凭据。
- 工具返回内容不允许修改先前批准范围；模型重新规划必须重新检查。

## 审批绑定的必要语义
- 批准记录至少绑定 server 身份/版本、endpoint/transport、tool name 与 schema digest。
- 绑定规范化 args 摘要、凭据身份/权限、发起者及委托主体。
- 绑定具体 target、动作、副作用类别、环境、会话/请求关联与 expiry。
- UI 展示摘要与真正执行字段应一致，关键目标不能隐藏在宽泛“继续”之下。
- 执行前重核 server、schema、args、identity、target 与时效，变化必须重新批准。
- 审批 token 或记录不能跨用户、工具、租户、server 或目标复用。
- 批准重试是否有效、允许次数与幂等语义应明确，避免网络重试重复有实际后果的操作。
- 取消、超时、撤销或权限变更应阻止尚未执行的工作，不以旧批准无限重放。
- 并行与委托要保留原发起主体，审批不能只覆盖总任务名称而遗漏具体动作。
- 协议不包含某种多轮机制时不假设其存在；若实际存在则核对 round/request 绑定。

## 凭据与传输边界
- HTTP 传输按匹配修订核对 issuer、签名、expiry、audience/resource、tenant 与 scope。
- 给其他 API 的 token 不能仅因内容有效就被 MCP server 当作自己的认证。
- 下游访问应有独立获批凭据或授权交换，不将客户端 token 无约束透传到第三方。
- OAuth discovery、redirect、state/PKCE 与 issuer 绑定需基于实际流程和规范核对。
- 不主动 fetch 任意 metadata endpoint；配置分析不足时将 SSRF 相关面记候选。
- stdio 的 command、参数、环境与工作目录是可执行配置，启动就可能产生副作用。
- Loopback listener 是调查线索，不能据端口存在确认浏览器、容器或低权用户可访问。
- 记忆、缓存、tool session 与委托结果也需用户/租户隔离与撤销处理。

## 只读优先与基线流程
1. 固定配置、schema、版本、身份和授权范围，列出已注册且可审阅的组件。
2. 从现有材料建立权限图与工具 read/write/execute/communicate 分类。
3. 逐项追踪凭据、审批、参数、目标与返回数据，不把声明替代实现证据。
4. 建立允许身份访问自有合成目标的基线与低权/错 audience 的拒绝材料。
5. 静态检查过期、参数替换、server/schema 变更、重试与取消的绑定条件。
6. 仅另获批准的测试 server 才可进行有界验证；不启动未知 binary 或浮动包。
7. 用无害标记、合成资源与最小权限测试一个边界，设置次数/成本/时间上限。
8. 目标审计与回查证明额外能力后才确认，记录阻断条件与清理结果。

## 具体证据与反证
- 证据包括发起身份、server/tool/schema 身份、批准内容、规范化参数与真实执行参数。
- 记录 correlation ID、目标身份、时间、拒绝/允许结果及合成资源前后状态。
- 非法读取用私有合成数据与归属证明；写入/通信/费用用目标副作用与审计证明。
- 不用模型叙述、伪造 tool result、扫描标签或提示文本替代目标证据。
- 调用被 policy、schema、凭据范围、网络或目标授权阻止，是可达性的反证。
- 审批参数改变后被拒绝且目标无动作，证明该边界有效，不报审批绕过。
- 仅注解错误但实现无额外能力时，报告元数据缺陷，不自动确认高危。
- 公共缓存输出或幻觉不构成跨租户私有数据读取，应通过归属与审计辨别。
- 明确授权用户批准其有权执行的相同动作不是漏洞，即使工具具备写权限。

## 工具依赖、停止与清理
- 本地配置和既有日志只读审阅；不需要新增协议客户端或安装工具。
- 已注册 `http-framework-test` 仅映射另获授权的测试 HTTP 目标；不能代替 stdio 客户端。
- MCP Inspector、Promptfoo、未知 server 客户端属于依赖缺口，缺失记 `blocked`。
- 不运行 `npx`/`latest`，不下载模型、执行外源包或静默切换 provider/server。
- 无测试 server、无合成身份、无目标审计或无副作用批准时停止在候选。
- 真实秘密、生产写入、跨范围目标、重复动作或成本超限立即停止。
- 结束后撤销测试会话与批准记录、清理合成数据并记录取消/撤销是否有效。
- 不撤销生产 token 或关闭生产服务来完成测试清理。

## 修复与可测正反例
- 目标端落实最小权限、身份与租户授权，客户端校验工具身份和可执行参数。
- 对副作用审批精确绑定并在执行前复核，失败时阻止执行而非选择更宽泛工具。
- 隔离资源/缓存/记忆，保留脱敏审计，重试幂等与撤销语义按动作定义。
- 正例：获批目标 A 被改成另一自有租户目标 B，低权请求仍写入 B 且有审计回查。
- 反例：同样替换导致重新审批/拒绝，B 无变化；模型说已成功也不改变结论。
- 正例：readOnlyHint 工具实际执行未被批准的测试写入，且新增权限与目标副作用可证。
- 反例：工具被列出或标注错误，但调用始终被目标 ACL 拒绝。

## 来源、版本与改编许可
- 中文改编来源：Strix `007ed1a`，`strix/skills/vulnerabilities/agentic_system_security.md`；原归属 Strix / OmniSecure Inc.。
- 上游：https://github.com/usestrix/strix/blob/007ed1a/strix/skills/vulnerabilities/agentic_system_security.md 。
- 本文重组有效权限、注解、审批绑定与凭据方法，删除主动发现、安装和自动评估要求；不实现架构或算法。
- 官方链接按实际 revision/SDK 核对，未声明最新版本：https://modelcontextprotocol.io/specification/ ；https://modelcontextprotocol.io/specification/2025-06-18/server/tools ；https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization 。
- 上述固定修订仅是可核对参考，不能据链接推断当前部署采用该修订。
- Apache-2.0 原声明：Copyright 2025 OmniSecure Inc.；本文已作中文改编与增补。
- Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0 。
- Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
