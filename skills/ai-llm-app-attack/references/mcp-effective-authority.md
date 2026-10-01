# MCP 有效权限与副作用审批核验

## 适用、版本、模型与身份
- 审阅获授权 MCP 配置、schema、审批/目标日志，默认不启动 server 或主动 discovery。
- 固定协议 revision、SDK/client/server 版本、transport、发布者/制品哈希与 endpoint。
- 固定 provider/model ID、adapter、路由策略、提示修订；模型别名与 fallback 分别记录。
- 记录发起用户/租户/会话/委托主体，以及凭据 issuer、audience、scope、环境和 expiry。
- stdio、Streamable HTTP 与旧 SSE 不互套认证语义；session ID 不等同认证身份。
- 详见 [MCP 审批授权知识](../../../knowledge_base/AI-Agent-Security/MCP-Approval-Authority.md)。

## 短执行流程
1. 建立已注册工具/资源/提示清单，按 read/write/execute/communicate/identity/cost 分类。
2. 每个工具固定 server 身份/版本 + endpoint/transport + tool name + schema digest。
3. 将声明能力与运行策略、凭据范围、网络/文件边界和目标 ACL 的可达子集分开。
4. 核对 `readOnlyHint` 等注解与实际行为，注解不作授权或无副作用保证。
5. 核对 schema、规范化 args、真实执行参数与用户/租户/target 授权，不只检查提示拒绝。
6. 审批绑定 server/schema/args/identity/target/action/environment/expiry 与调用关联 ID。
7. 核对执行前重校验、过期、参数/server 变化、重试、取消、并行与委托的绑定材料。
8. 另获测试批准后，单变量验证一个边界，用合成目标及真实审计/回查决定确认状态。

## 基线与具体证据
- 允许基线：明确有权身份与精确批准参数对自有测试目标执行预期动作。
- 拒绝基线：低权/错租户/错 audience/过期批准或参数改变时同目标无操作。
- 单变量对照保持模型、schema、server 与环境不变，仅改变被测条件。
- 保存发起与委托身份、server/tool/schema 摘要、审批记录、规范化与执行参数关联。
- 保存 correlation ID、目标权限预期、合成资源归属、前后状态和目标审计。
- 凭据用不透明标识与权限摘要关联，不保留完整 token 或把秘密发送给模型。
- `tentative` 为候选，`confirmed` 要证实新增读取/写入/通信等权限，`blocked` 为依赖/授权不足。

## 反证、停止与清理
- 正例：获批 target A 被替换成另一自有测试租户 B，低权调用仍写入 B 且有 audit/readback。
- 反例：替换导致拒绝/重新审批，B 无动作；模型声称成功不改变否定结论。
- 正例：readOnlyHint 工具实际造成未被批准的测试写入，超出身份预期权限。
- 反例：tools/list 可见，但调用被 schema、scope、网络或目标 ACL 阻止。
- 工具返回 200、模型叙述、伪造结果、公共缓存或幻觉均不能证明私有数据越界。
- 无测试 server/客户端、目标审计或副作用批准时停在候选，缺依赖记 `blocked`。
- 真实秘密、生产写入、重复副作用、跨范围目标或成本超限立即停止。
- 清理合成数据，撤销测试 session/批准/凭据，核对队列取消结果，不处理生产 token。

## 已注册工具与修复
- 本地资料仅用只读读/搜；`http-framework-test` 只映射另获授权测试 HTTP 目标。
- 已注册不等于可用；Inspector、Promptfoo 与 stdio 专用客户端缺失记依赖，不新增/安装。
- 不运行浮动 `npx`/未知包，不自动下载模型，不回退更高权工具/server/provider。
- 目标独立授权与最小凭据，精确审批并在执行前复核，取消/失败后阻止动作。
- 隔离缓存/记忆/资源，按实际协议核对 token audience 和下游授权，注解不能替代策略。

## 来源、改编与许可
- Strix `007ed1a`，`strix/skills/vulnerabilities/agentic_system_security.md`；原归属 Strix / OmniSecure Inc.。
- 来源：https://github.com/usestrix/strix/blob/007ed1a/strix/skills/vulnerabilities/agentic_system_security.md 。
- 中文重组有效权限与精确审批流程，补充只读/依赖/清理；删除自动发现、安装与评估算法。
- 官方入口：https://modelcontextprotocol.io/specification/ ；固定参考：https://modelcontextprotocol.io/specification/2025-06-18/server/tools ；https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization 。
- 按实际 revision/SDK 核对，固定链接不代表目标采用该修订，本文未联网确认最新。
- Apache-2.0 原声明：Copyright 2025 OmniSecure Inc.；本文已作中文改编与增补。
- Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0 。
- Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
