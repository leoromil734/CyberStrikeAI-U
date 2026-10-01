# n8n/插件定义：节点、秘密引用与 sink 的只读审计

## 适用、版本、身份与模型
- 仅审阅获授权导出 JSON、manifest、工具配置与源码；不导入、激活或触发线上 webhook。
- 固定文件哈希、workflow ID/修订、n8n 版本、node typeVersion、插件包与子流程版本。
- 记录触发用户/租户、流程所有者、credential ref 所有者与已提供 scope/audience/expiry。
- 记录 provider/model ID、adapter、提示/检索修订、tool schema；可变模型别名保留不确定性。
- 普通节点、AI 模型连接、工具连接、记忆与子流程分别解释，不猜继承权限。
- 详见 [工作流定义知识](../../../knowledge_base/AI-Agent-Security/Workflow-Definition-Audit.md)。

## 短执行流程
1. 脱敏样本与秘密，枚举节点 ID/name/type、参数、credential refs、禁用与 pinData。
2. 按端口、分支、条件与错误路径建立连接清单；孤立/缺失子流程不默认可达。
3. 标注外部 source 的可控字段、身份与输入 schema，沿表达式/模板追踪变换。
4. 对 `={{…}}`、Code、HTTP、DB、文件/消息/发布 sink 引用准确参数路径及 guard。
5. 区分 credential 引用与秘密明文；缺所有权/作用域材料时记未知，不解密或试登录。
6. 分别追踪不可信输入→prompt、模型输出→sink 和工具参数→目标授权。
7. 核对审批的精确参数、失败/重试/取消、provider fallback 与委托身份传递。
8. 交付 source→guard→sink 证据与局限；不执行表达式、Code、安装脚本或在线流程。

## 基线、证据与状态
- 基线：同一修订的正常定义、预期身份和允许目标，非另一条流程。
- 静态夹具只改一条连接、一个 schema/参数或 credential 所属信息，不运行原代码。
- 对照包括断连/禁用、参数化 SQL、目标 allowlist、最小凭据与租户 guard。
- 保存定义哈希、node ID/typeVersion、连接端口、参数 JSON 路径、变换和缺失校验。
- 静态定义可证明路径/缺口，真实越权仍需另获授权的执行、目标副作用与拒绝对照。
- `tentative` 为影响未知候选；`confirmed` 为已证实缺陷；`blocked` 为授权/依赖不足。
- 硬编码真实秘密可证文件暴露，不把活性/权限或模型外发影响一并推断为已确认。

## 反证、停止与清理
- 正例：静态夹具连接低权输入到高权写入且无 guard，标候选；另获运行证据才确认影响。
- 反例：sink 已禁用/断连、下游参数化或目标 ACL 拒绝，不能声称已越权。
- 模型说“已发送”但目标日志无副作用，不是确认；credential ref 也不是明文秘密。
- 未知节点、子流程缺失、凭据范围未知或无动态授权时停止相关分支并记 `blocked`。
- 发现真实秘密、生产目标或外部模型发送要求即停止，不主动访问端点。
- 清理临时脱敏副本与合成夹具，保留获准路径证据与清理结果，不保存完整秘密。

## 已注册映射与修复
- 静态使用只读读/搜能力；无需新增 n8n/插件客户端。
- `http-framework-test` 只映射另行批准的测试 HTTP 目标；`trivy` 只映射获批本地依赖审阅。
- 注册不证明工具已安装，缺客户端/版本/凭据即依赖缺口，不安装或执行外源包。
- 使用最小凭据、结构化参数与目标授权，模型输入最小化、输出在 sink 重新校验。
- 敏感动作绑定具体审批，重试/取消与失败关闭需独立验证；不实现 PAIR/TAP 自动越狱。

## 跨源改编、官方资料与许可
- NeuroSploit `5d4e7e0`（本地标注 4.2.1），`agents_md/ai/n8n_workflow_audit.md`、`agents_md/ai/n8n_ai_node_audit.md`：节点/连接/AI 数据流，原归属 Joas A Santos & Red Team Leaders；https://github.com/JoasASantos/NeuroSploit/tree/5d4e7e0/agents_md/ai 。
- Strix `007ed1a`，`strix/skills/vulnerabilities/agentic_system_security.md`：有效权限/凭据/审批，原归属 Strix / OmniSecure Inc.；https://github.com/usestrix/strix/blob/007ed1a/strix/skills/vulnerabilities/agentic_system_security.md 。
- 本文中文重组并补充只读、反证与清理；移除自动线上探测、安装和模型响应即确认。
- 官方资料按目标版本核对，未联网查最新：https://docs.n8n.io/workflows/export-import/ ；https://docs.n8n.io/data/expressions/ ；https://docs.n8n.io/advanced-ai/ ；https://modelcontextprotocol.io/specification/ 。
- Strix Apache-2.0 原声明：Copyright 2025 OmniSecure Inc.；本文已作中文改编与增补。
- Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0 。
- Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
- NeuroSploit 上游 MIT 许可保留如下。

> MIT License
> Copyright (c) 2026 Joas A Santos & Red Team Leaders
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
