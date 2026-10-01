# Electron IPC 的文档、窗口与会话授权边界

## 适用范围与结论
- 适用于获授权 Electron 制品、已展开资源、preload、主进程源码及测试构建。
- Inter-Process Communication（IPC）是进程间通信；传输成功不等于业务操作被授权。
- 本篇追踪页面→preload→IPC→主进程→目标副作用的完整权限路径。
- 只读源码审计不自动允许启动未知桌面程序、打开外部内容或访问在线更新源。
- 使用 `tentative` 标记影响未证实候选，`confirmed` 标记已证实越界，`blocked` 标记依赖缺口。
- 不提供钓鱼页面部署、恶意更新发布或操作系统持久化流程。

## 版本与身份基线
- 记录应用版本、构建哈希、发行渠道、操作系统及安装/用户权限。
- 记录 Electron、Chromium、Node 实际版本，不用开发 lockfile 推断安装包一定一致。
- 区分 `app.asar`、unpacked 资源、辅助进程、native 模块与测试源码。
- 列出 `BrowserWindow`、`WebContentsView`、webview、子窗口及各自 webContents 标识。
- 记录当前文档 URL/origin、主 frame 与子 frame、preload 路径和加载条件。
- 记录 session/partition、应用账号、租户、profile 和窗口所属用户。
- 在目标版本上核对默认配置；缺省项不能按其他大版本默认值解释。
- 每次对照固定相同构建与配置，只改变一个身份或导航条件。
- 本流程无需模型调用；模型辅助只用获准脱敏材料，记录 provider/model，不以模型结论确认 native 能力。

## 权限原理与框架差异
- Renderer 页面、preload 隔离世界、主进程和目标服务分别持有不同权限。
- `contextIsolation` 限制页面与 preload 的直接共享，但暴露 API 仍能授予能力。
- 关闭 `nodeIntegration` 不等于 preload 无特权或桥接安全。
- sandbox、webSecurity 和 Node 集成影响不同边界，不能把一个配置当全部安全证明。
- 安全默认值还受版本、具体窗口配置与实际 native 模块影响。
- NW.js、CEF、Tauri、Wails 的桥接与权限机制不同，不直接套用 Electron 结论。
- 页面脚本执行、桥接访问、IPC 接受、特权数据读取、文件操作与 native 执行分别分级。
- 只有明确新增能力与现实攻击者前提，才能将配置线索升级为漏洞。

## 制品与入口清单
- 定位 `package.json` 的主入口、窗口创建、preload 及 IPC 注册代码。
- 枚举 `contextBridge.exposeInMainWorld` 暴露对象、方法、回调与事件订阅。
- 枚举 `ipcMain.handle`、`ipcMain.on` 与版本适用的 webContents IPC 处理器。
- 泛化 `invoke(channel, args)` 只说明候选通道较广，通道注册列表不是访问控制表。
- 检查回调是否向页面泄露原始 event、Electron 对象或可变特权对象。
- 反编译/压缩代码应关联准确文件与构建；运行时功能开关可能改变可达性。
- 未审查的 ASAR 提取器、生命周期脚本和更新器不得自动执行或安装。

## IPC sender 与参数授权
- 每个 handler 都需检查真实 `event.senderFrame`，不能只信参数中传入的 origin。
- 记录 frame URL/origin 与主/子 frame 身份；当前 frame 与发送时文档可能不同。
- 将发送者绑定到预期 webContents、窗口、session/partition 与业务状态。
- 窗口 ID 或 session ID 只是关联标识，不能单独替代用户和租户授权。
- 主进程应验证动作权限、对象归属和目标，不依赖 renderer 的按钮显示或前置检查。
- 参数 schema 应约束类型、长度、未知字段、枚举、路径、URL、选项与对象结构。
- 路径规范化后验证允许范围，处理符号链接、平台差异与实际目标解析。
- URL 用结构化解析比较协议、主机、端口和必要路径，不做可信域字符串前缀判断。
- 请求排队、异步处理和导航之间可能发生身份变化，执行前需复核授权上下文。
- 回调订阅的返回数据亦需隔离，不能把高权窗口结果广播给非预期窗口。

## 导航、协议与会话变化
- 枚举初始加载、用户导航、子 frame、重定向、弹窗和程序性 `loadURL/loadFile`。
- 配置在 webContents 上的 preload 不因导航自动变成普通网页权限。
- `will-navigate` 存在不证明程序性加载与所有重定向都被同样限制。
- 测试窗口重用、账号切换与 partition 切换后，旧桥接/订阅/缓存是否仍有能力。
- `setWindowOpenHandler` 与子窗口配置需独立分析，不继承“父窗口安全”的结论。
- 自定义协议、OS deep link 和 second-instance 参数都是独立输入来源。
- 协议解析与业务路由应绑定正确应用实例、当前用户与目标资源。
- `shell.openExternal` 需校验完整目的与允许 scheme；能调用不等于 native 执行已发生。
- 媒体、剪贴板、文件和外部协议权限要按请求 frame/origin 与 session 判断。

## 基线与有界验证流程
1. 固定制品、组件版本、身份与已获批能力，先建立静态调用路径。
2. 为每个桥接记录可调用文档、handler、schema、sender 检查与目标副作用。
3. 建立预期可信窗口、允许账号和自有目标的成功基线。
4. 建立非预期 frame/窗口/session 或低权账号的拒绝基线。
5. 仅在获批隔离测试构建中改变一个条件，不部署外部页面或启动未知代码。
6. 用合成文件/对象和无害标记观察目标操作，禁止真实秘密读取与进程执行补证。
7. 检查导航、重定向、子 frame、账号切换后的边界；分别记录版本差异。
8. 将传输、验证、执行与回查分开保存，缺任一影响环节则保留候选。

## 证据、反证与常见误报
- 最小证据：构建哈希、preload/handler 位置、实际 senderFrame、窗口与 session。
- 另记录业务身份、规范化参数、期望授权、处理器结果与目标回查。
- 文件能力用自有夹具内容/哈希证明；账号能力用对象归属和审计证明。
- IPC Promise 返回成功但目标无变化，只能说明通道响应，不确认副作用。
- Handler 存在但 sender、schema、业务状态或权限拒绝，是重要反证。
- `contextIsolation: false` 或 `sandbox: false` 而无可达特权能力，不自动确认 native 执行。
- 远程页面无可用桥接/Node/特权权限，不能只凭远程加载宣称系统接管。
- 更新 feed 可变但制品签名与版本策略独立验证，不能直接确认更新执行漏洞。
- 缺普通攻击者可达入口时，需说明需要已控制 renderer 或本机账号的前提。
- 相同账号对自己文件的预期读取不是新增能力。

## 工具依赖、停止与清理
- 已注册映射：`strings` 可定位制品线索，`ghidra` 可用于获批 native helper 分析。
- 本地文本与配置以只读读取工具分析；已注册不等于已安装或适合目标平台。
- ASAR 客户端、桌面运行时与协议测试客户端缺失时记 `blocked`，不新增或安装。
- 无测试构建、无获批 sender 夹具、无可观察副作用时停止在静态候选。
- 发现真实凭据、外部导航、生产变更或用户会话污染时停止并保留脱敏原因。
- 清理合成文件/对象、测试窗口和订阅，撤销测试会话，恢复测试配置。
- 不通过关闭 sandbox、安装外部页面或劫持更新源来强行制造验证条件。

## 修复与可测正反例
- 暴露固定操作与最小参数的 preload API，主进程统一验证 sender、schema 和业务权限。
- 远程内容使用无特权窗口或外部浏览器，不复用持有本地能力的 webContents。
- 导航和协议策略覆盖所有加载路径，按 origin/frame/session 隔离返回数据。
- 凭据与解密密钥保持在页面不可直接取得的边界；接口仍需动作授权。
- 正例：低权测试窗口被 handler 接受并读取只属于另一自有测试 profile 的合成文件。
- 反例：泛化桥接可发送消息，但主进程拒绝非预期 senderFrame，目标文件未读取。
- 正例：账号切换后旧订阅收到新账号私有夹具数据，事件与归属可关联。
- 反例：仅有弱配置、channel 名称或成功响应，无法证明新增读取/写入能力。

## 来源、版本与改编许可
- 中文改编来源：Strix `007ed1a`，`strix/skills/technologies/electron_desktop_apps.md`；保留原归属 Strix / OmniSecure Inc.。
- 上游：https://github.com/usestrix/strix/blob/007ed1a/strix/skills/technologies/electron_desktop_apps.md 。
- 本文重组为 sender/window/session/schema 证据流程，补充只读限制；未搬运载荷或部署方法。
- 官方链接按目标 Electron 版本核对，本文未联网确认最新：https://www.electronjs.org/docs/latest/tutorial/security ；https://www.electronjs.org/docs/latest/api/ipc-main ；https://www.electronjs.org/docs/latest/api/web-frame-main ；https://www.electronjs.org/docs/latest/api/session 。
- Apache-2.0 原声明：Copyright 2025 OmniSecure Inc.；本文已作中文改编与增补。
- Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
- You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0 。
- Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- See the License for the specific language governing permissions and limitations under the License.
