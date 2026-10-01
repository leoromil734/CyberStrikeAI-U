# Electron IPC sender、窗口与会话的能力核验

## 适用、版本与身份
- 只读审阅获授权 Electron 制品/源码；不启动未知应用，不部署外部页面，不改更新源。
- 固定应用哈希、Electron/Chromium/Node 与 OS 版本、preload/主进程配置及安装权限。
- 记录每个 window/webContents、senderFrame、URL/origin、session/partition、账号和租户。
- 版本默认值需按实际 Electron 核对；Tauri/Wails/NW.js/CEF 不套用相同 IPC 语义。
- 本流程无模型调用需求；模型辅助需记录 provider/model，只分析获准脱敏材料。
- 详见 [Electron IPC 授权边界](../../../knowledge_base/Desktop-App-Security/Electron-IPC-Authority.md)。

## 执行步骤
1. 定位主入口、BrowserWindow/WebContentsView、preload、桥接导出与所有 IPC handler。
2. 对每个桥接建立“页面/frame→API→channel→handler→目标副作用”的路径。
3. 核对真实 senderFrame、预期 webContents/window、session/partition 与业务身份校验。
4. 核对参数 schema、规范化 URL/路径/对象、权限与返回数据接收方，拒绝仅 renderer 校验。
5. 检查初始加载、用户/子 frame 导航、重定向、程序性加载与弹窗的策略一致性。
6. 对账号切换、窗口重用、异步排队与订阅回调检查身份是否过期或混用。
7. 仅在独立批准的隔离测试构建中改变一个条件，使用合成文件/对象验证能力。
8. 将页面脚本、桥接访问、IPC 接受、特权数据/操作分别分级，不把消息成功当执行成功。

## 基线与证据
- 允许基线：可信窗口、预期 frame/session、有权测试账号访问自己的合成目标。
- 拒绝基线：非预期 frame/window/partition 或低权账号访问同目标被拒绝。
- 单变量对照每次只改 origin、frame、会话、身份或参数之一，固定构建与配置。
- 保存构建哈希、preload/handler 位置、发送时 senderFrame、窗口/session 和真实账号。
- 保存规范化参数、校验结果、操作关联 ID、测试资源归属及目标回查/事件日志。
- `tentative` 是影响候选，`confirmed` 要有真实新增能力，`blocked` 表示依赖/权限不足。

## 反证、停止与清理
- 泛化 bridge、注册 channel、弱 contextIsolation/sandbox 配置仅是线索。
- Sender/schema/业务权限拒绝、远程页面无 bridge 或 Node 能力都是反证。
- 正例：非预期测试窗口实际读取另一自有 profile 的合成私有文件并有归属证据。
- 反例：IPC 返回值成功但文件未读取，或非预期 sender 被 handler 拒绝。
- 无运行夹具、无目标观察、无获批动态范围时停止在静态候选。
- 不读取真实凭据，不运行 native 命令，不实施钓鱼、更新劫持或持久化补证。
- 清理合成对象、窗口/订阅和测试会话，恢复测试配置，保存脱敏清理记录。

## 已注册工具与修复
- 文本定义用只读读/搜能力；`strings` 可定位线索，`ghidra` 可分析获批 native helper。
- ASAR 客户端、桌面运行时与专用协议客户端缺失记 `blocked`，不新增或安装。
- 工具注册不证明已安装或适用当前 OS；不能自动执行提取器或生命周期脚本。
- 使用固定窄桥接、严格 schema 与主进程 sender/window/session/业务权限验证。
- 隔离远程内容，导航路径统一规范化策略，回调数据按账号与 session 分区。

## 来源、改编与许可
- Strix `007ed1a`，`strix/skills/technologies/electron_desktop_apps.md`；原归属 Strix / OmniSecure Inc.。
- 来源：https://github.com/usestrix/strix/blob/007ed1a/strix/skills/technologies/electron_desktop_apps.md 。
- 中文重组为 sender 与副作用核验工作流，增补停止/清理；不搬载荷或部署步骤。
- 官方资料按目标版本核对，未联网确认最新：https://www.electronjs.org/docs/latest/tutorial/security ；https://www.electronjs.org/docs/latest/api/ipc-main ；https://www.electronjs.org/docs/latest/api/web-frame-main ；https://www.electronjs.org/docs/latest/api/session 。
- Apache-2.0 原声明：Copyright 2025 OmniSecure Inc.；本文已作中文改编与增补。
- Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0 。
- Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
