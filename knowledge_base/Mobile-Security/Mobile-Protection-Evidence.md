# 移动应用保护映射与服务端证据分级

## 适用范围与定义
- 适用于获授权 Android/iOS 制品中的保护识别、执行点归档及服务端信任边界复核。
- Runtime Application Self-Protection（RASP）是应用运行时自保护，不等同于系统隔离或业务授权。
- Pinning 指证书或公钥固定；完整性检测、设备检测和服务端证明分别记录。
- 本篇提供保护证据工作流，不提供免杀、持久化或保护绕过脚本。
- `tentative` 为影响未证实候选，`confirmed` 为明确边界失效，`blocked` 为授权/依赖缺口。
- 本机特权环境下可改返回值不是自动成立的远程漏洞。

## 基线与版本身份
- 固定 APK/IPA、主二进制及关键库哈希，记录签名、版本、构建号和架构。
- 记录保护 SDK 名称及版本证据；仅凭高熵库或字符串不能确定厂商与版本。
- 标明原始分发、测试、重签名、模拟器构建及符号/源码对应关系。
- 记录系统与设备版本、root/越狱、调试状态、业务账号及服务端环境。
- 动态授权需明确能否安装测试构建、观察日志、抓取流量与发送测试请求。
- 使用自有测试租户、合成资源和明确预算；取得制品不扩大业务授权。
- 比较基线必须保持构建、身份、设备状态和服务端版本一致。
- 本流程无需模型调用；模型辅助要记录 provider/model 与获准输入，模型评分不能替代目标证据。

## 控制模型与组件差异
- 保护层可以检测、上报、显示警告、禁用功能或拒绝业务；这些行为不是同一强度。
- Android JNI 初始化、iOS 原生入口、Flutter AOT 与混合框架 JS 层需分别定位。
- 壳或混淆改变观察难度，不证明敏感业务由该层强制约束。
- 客户端判定、服务端收到判定、服务端执行拒绝是三个独立事件。
- 本地签名比较、资源哈希与自检在受控制进程中可被影响，但结论需写明攻击者前提。
- 服务端证明也不是业务对象授权的替代；证明合格设备仍可能使用低权账号。
- Play Integrity、DeviceCheck 与 App Attest 的能力、验证流程和部署前提不同。
- DeviceCheck 不应被描述成与 App Attest 完全等价的逐请求应用完整性证明。
- 旧 SafetyNet 线索不能直接套用当前 Play Integrity 语义，按实际接入记录。
- 证明应关注服务端对签名、挑战、身份绑定、时效与失败状态的处理。

## 保护表面的信息映射
- 给每项控制独立编号，关联库/类/函数/偏移及代码或观察依据。
- 记录检测输入：设备状态、签名、资源摘要、调试信号、证书链或证明结果。
- 记录计算位置：主进程、辅助进程、原生库、JS/Dart 层或服务端。
- 记录判定传递：调用、回调、事件、缓存、网络字段及跨线程状态。
- 记录所有执行点：启动、登录、敏感页面、支付、恢复、后台与重新连接。
- 多处执行不能合并成“存在一个检查”；遗漏的执行点可能造成条件性差异。
- 截屏、录屏、覆盖层和键盘限制主要涉及界面泄露，应与权限越界分开。
- 证书固定需区分原生栈、WebView、第三方 SDK 与备用端点覆盖。
- 保护上报包含个人或设备信息时另记录最小化与数据接收方，不能主动扩发遥测。

## 本地完整性与服务端证明
- 本地完整性证据：签名/哈希读取位置、比较对象、返回值与实际功能拒绝。
- 源码存在校验但运行未覆盖的情况，应保留“静态存在、当前路径未证实”。
- 服务端证明证据：挑战生成、调用关联 ID、平台验证结果和目标决策日志。
- 对 App Attest 分别识别密钥登记、attestation 与后续 assertion 的处理位置。
- 对 Play Integrity 按实际模式核对请求绑定、防重放与服务端 verdict 验证。
- 不能用客户端 JSON 的 `passed` 字段替代平台验证与服务端授权证据。
- 缺失、失效、过期或不匹配证明，应按业务策略拒绝或限制，而非悄悄放宽。
- 服务端验证成功也需绑定当前用户、动作与目标，避免证明被借用到不同请求。
- 本地兼容性回退与服务端安全回退分别记录，不把产品支持策略猜成漏洞。

## 只读优先流程
1. 固定制品与环境，列出当前可观察组件和不可观察组件。
2. 从初始化、保护库及敏感动作入口建立检测→判定→执行点地图。
3. 将每个执行点连接到具体资产或动作，标明纯 UI 控制与真正授权控制。
4. 对网络边界定位客户端字段、服务端验证代码或已有审计材料。
5. 在静态权限内，输出缺口与假设；不自动安装 SDK、注入、改包或访问服务。
6. 另获批准后，在测试环境进行单变量正负对照，不进行抗检测或隐蔽部署。
7. 使用合成对象与只读回查验证目标结果，控制次数并记录关联 ID。
8. 对证明缺失或失败的处理明确写出允许、拒绝或尚不可观察。

## 基线与具体证据
- 正常基线：完整原始测试构建、合格设备和允许身份完成预期动作。
- 拒绝基线：缺少目标权限的账号即使证明有效也应被拒绝。
- 完整性对照：获批测试夹具提供缺失/失效状态，观察各执行点与服务端决策。
- 证书对照：仅在获批实验网络区分受信、错误主机名和不受信证书处理。
- 证据包括原始构建哈希、控制编号、代码位置、请求身份与期望决策。
- 运行证据应区分日志“检测到”、界面“阻止”和服务端“拒绝/接受”。
- 服务端影响必须附测试对象归属、权限预期、审计或回查，不用 UI 文案替代。
- 流量可观察性改变仅说明抓包条件，不能据此确认账号、对象或付费权限失效。
- 测试者完全控制设备时，提取其本人 token 不等于取得其他主体的 token。

## 反证与停止规则
- Pinning 缺失但系统 TLS 和服务端授权正常：通常是纵深或策略问题，不能自动报越权。
- RASP 判定只影响启动提示：报告保护覆盖，不声称服务端接纳非法状态。
- 客户端高级功能开关被改变，但服务端拒绝：不能确认订阅或账户越权。
- 本地检测失效而独立平台证明仍被服务端执行：需收窄结论。
- 有效设备证明并不让跨账号资源读取合法，应独立验证业务归属。
- 无原始构建、无服务端观察、无批准设备或关键控制版本不匹配时标记 `blocked`。
- 发现测试导致锁号、崩溃循环、真实支付、生产写入或秘密外发时立即停止。
- 不以收集更多证据为由移除生产保护、绕过运营控制或扩大身份范围。

## 工具依赖与清理
- 已注册映射：`strings` 识别线索，`ghidra` 用于获批制品的函数与调用关系分析。
- 注册不是安装证明；缺运行环境、符号或解析能力时保留依赖缺口。
- Frida、MobSF、平台证明客户端/设备是未在本流程新增的依赖；缺失即 `blocked`。
- 不安装工具，不自动下载模型或 SDK，不执行未知保护库与样本初始化代码。
- 动态结束恢复实验设备和网络设置，撤销测试会话、密钥与合成数据。
- 保留脱敏执行点地图、结果与清理凭据；不保留真实证明 token 或设备秘密。

## 修复与回归正反例
- 将关键权限与证明验证放在服务端，按动作、主体与目标绑定，失败时遵循明确策略。
- 完整性检查覆盖敏感动作的多个入口，不能只在启动时计算并永久缓存。
- 客户端保护作为纵深；降低其秘密与长期高权凭据持有量。
- Pinning 采用可维护轮换与恢复机制，不通过永久关闭证书校验解决兼容问题。
- 正例：失效证明下服务端仍授予受保护测试权益，目标回查与拒绝基线证明差异。
- 反例：本地检查返回成功，但服务端验证失败并拒绝，确认结果应保持否定。
- 正例：一个敏感执行点缺失绑定，可借用另一自有请求的证明取得不被允许的动作。
- 反例：只见保护 SDK、校验字符串或抓包成功，尚无额外敏感能力。

## 来源、版本与改编说明
- 改编来源：NeuroSploit `5d4e7e0`（本地标注 4.2.1），`neurosploit-rs/agents_md/mobile/rasp_protection_mapping.md` 与 `neurosploit-rs/agents_md/mobile/code_integrity_tamper_check.md`。
- 原归属 Joas A Santos & Red Team Leaders；上游：https://github.com/JoasASantos/NeuroSploit/tree/5d4e7e0/neurosploit-rs/agents_md/mobile 。
- 本文中文重组检测→gate→执行点方法，补充服务端边界；不采纳自动安装、本地绕过即漏洞及载荷生成要求。
- 官方参考（按目标版本核对，未声明最新）：https://developer.android.com/google/play/integrity/overview ；https://developer.apple.com/documentation/devicecheck ；https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity 。
- 上游 MIT 许可随本篇保留如下。

> MIT License
> Copyright (c) 2026 Joas A Santos & Red Team Leaders
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
