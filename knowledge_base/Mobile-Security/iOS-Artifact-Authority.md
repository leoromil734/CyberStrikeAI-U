# iOS 制品、签名权限与服务端授权边界

## 适用范围与结论边界
- 适用于获授权的 IPA、已展开的 `.app`、签名权限导出及对应应用源码。
- 静态审计默认只读；取得制品不等于允许安装、重签名、注入或请求业务服务。
- 本文区分配置事实、潜在风险、客户端可达能力和服务端越权。
- `tentative` 表示尚未证明影响的候选；`confirmed` 表示已证明指定边界失效；`blocked` 表示依赖或授权不足。
- 缺少 pinning、PIE 或 ARC 的线索不能单独证明高危漏洞。
- Keychain、ATS、签名和设备证明是不同控制，结论不得互相替代。

## 版本、身份与制品基线
- 记录制品哈希、获取渠道、Bundle ID、应用版本、构建号、架构及审计时间。
- 记录最低系统版本、实际 iOS 版本、设备类型及模拟器或真机差异。
- 标明 App Store、企业、开发、测试或重签名构建；分发类型影响可比性。
- 记录 Team ID、签名主体、Provisioning Profile 有效期及扩展组件清单。
- 动态验证另记录设备是否越狱、调试状态、账号、租户与服务端环境。
- 使用两个自有测试账号或独立测试角色，不使用真实用户秘密作证明。
- 重签名或脱密制品与原始制品分别留存哈希，不能用修改构建替代生产基线。
- 本流程无需模型调用；若使用模型辅助，记录 provider/model 与输入范围，仅提供获准脱敏材料。

## 权限原理与组件差异
- Entitlement 是签名关联的能力声明，实际有效权限还依赖系统、签名与配置约束。
- Profile 的授权范围与应用签名中的 entitlement 不是同一个证据对象。
- 分别查看宿主应用、App Extension、App Clip 和内嵌框架，避免只看主 Bundle。
- `application-identifier`、Team ID 与 access group 一起决定身份关系。
- `keychain-access-groups` 声明共享范围；声明过宽是候选，需证明实际条目可被非预期主体读取。
- `com.apple.security.application-groups` 关联共享容器，不等于任意应用可读。
- `get-task-allow` 要结合分发类型、设备前提及非预期调试能力解释。
- 设备已被完全控制后的调试能力不应包装为新增远程服务端权限。
- Mach-O 导入、字符串与符号证明代码线索，不证明相关分支在当前构建执行。
- 加密或裁剪二进制导致分析缺口时记 `blocked`，不自动下载解密工具或实施脱密。

## Keychain 与本地数据边界
- 对每类测试秘密记录用途、写入位置、访问组、可访问级别与访问控制条件。
- 区分 `WhenUnlocked`、`AfterFirstUnlock`、设备限定属性及实际业务可用性要求。
- `ThisDeviceOnly` 主要约束设备迁移，不代表所有形式的本机读取都被禁止。
- 生物识别、本机口令与交互条件由 `SecAccessControl` 等实际创建参数决定。
- 只见 `SecItemAdd` 或 `SecItemCopyMatching` 导入，不能推出条目属性正确或错误。
- 验证共享访问必须说明读取应用的签名身份、权限组及平台限制。
- 备份可见性与设备迁移策略分开验证，使用合成条目而非生产 token。
- `NSUserDefaults`、数据库、日志、剪贴板与共享容器需分别映射读取主体。
- 越狱设备读取 Keychain 只证明特定本机前提下可读，不能证明普通第三方应用可读。
- 发现硬编码字符串时先区分公开配置、测试凭据和能授权操作的秘密。

## ATS、链接与 WebView 边界
- App Transport Security（ATS）控制适用网络栈的传输策略，不承担对象或租户授权。
- 检查 `NSAppTransportSecurity` 的全局及域级例外、适用范围与实际请求库。
- ATS 例外存在不等于敏感请求一定使用明文；需要目标、路径、数据及传输证据。
- 自定义 TLS 栈与 `URLSession` 的行为可能不同，不能仅据 plist 推断全部流量。
- 自定义 URL Scheme 的登记证明接收能力，不证明敏感动作可被触发。
- Universal Links 需要关联域 entitlement、站点关联文件与系统实际路由共同分析。
- 本地看到 `applinks` 不能证明远端关联文件内容或当前设备路由成功。
- `sourceApplication` 只能作为线索，敏感操作仍需目标身份授权与必要用户确认。
- WKWebView 另查消息处理器、页面来源、frame、参数 schema 与原生能力。
- 非预期页面调用桥接成功与服务端接受其敏感操作是两个独立证据层级。

## 只读分析流程
1. 固定原始制品和导出材料的哈希，列出缺失文件与来源可信度。
2. 定位 `Payload/<App>.app`、Info.plist、Profile、主 Mach-O 与每个扩展。
3. 并列记录 Profile、签名 entitlement、源码配置，解释不一致及重签名因素。
4. 对 Keychain、共享容器、ATS、链接及桥接建立“声明→调用→读取主体/目标”的映射。
5. 引用文件路径、plist key、函数或偏移；反编译结果需注明分析器版本与不确定性。
6. 将每条线索连接到明确资产与攻击者前提，未知值保留未知。
7. 只有另获动态授权时，才用专用测试构建和合成数据验证一个边界。
8. 记录允许、拒绝和修改单一条件的对照结果，再决定候选或确认状态。

## 基线、证据与反证
- 正常基线：预期应用身份访问自己的测试条目或自有对象成功。
- 拒绝对照：不具有共享组或业务权限的测试主体不能访问相同资产。
- 单变量对照：只变更访问组、账号、对象归属、链接来源或传输路径中的一项。
- 最小证据包包含制品哈希、签名/profile 摘要、准确位置、测试身份与环境。
- 动态证据包含平台返回值、请求关联 ID、脱敏响应与服务端审计/回查。
- 证明新增能力时说明“本来允许什么、现在额外取得什么”，不能只给截图或工具结论。
- 若服务端仍校验对象归属，即使本地显示高级功能也不能确认服务端越权。
- 若 access group 只对预期同一团队组件有效，不能说“任意应用读取”。
- 若弱 ATS 域仅承载公开数据，风险应按实际暴露描述而不是自动高危。
- 若只有修改版构建失效，应限定结论并复核原始分发构建。

## 工具依赖与停止清理
- 已注册映射：`strings` 提供字符串线索，`ghidra` 可用于获批的 Mach-O 分析。
- 工具注册不等于执行环境已安装、已授权或支持当前架构；执行前核实可用性。
- `codesign`、`plutil`、`otool`、MobSF、Frida 在本流程中只是所需依赖，不新增注册或安装。
- 缺 macOS 签名解析环境时请求已有签名导出，不能猜 entitlement 或调用未注册客户端。
- 无设备、无匹配版本、无动态授权或遇到真实个人数据时停止并标记 `blocked`。
- 不为补证关闭系统控制、破坏设备、收集真实 Keychain 内容或扩大网络范围。
- 动态验证结束恢复测试设置、撤销测试凭据并删除合成条目；保存脱敏证据及清理结果。
- 本流程不自动安装应用、不主动访问关联域、不修改既有签名。

## 修复与可测正反例
- 按组件最小化 entitlement 与共享组，生产构建去除非必要调试能力。
- 按秘密用途设置 Keychain 属性和访问控制；不能把单一属性当万能修复。
- 收紧 ATS 例外，验证证书与主机名；pinning 需要轮换与恢复方案。
- 将订阅、对象权限与敏感状态迁移放在服务端验证，客户端仅提供界面与输入。
- 正例：不属预期共享组的测试组件实际读取合成秘密，并排除越狱特权前提。
- 反例：仅发现 `keychain-access-groups`，第三方测试主体始终被系统拒绝。
- 正例：低权账号通过获批测试链接取得另一自有账号资源，服务端回查证明归属越界。
- 反例：本地界面被改变，但相同低权账号请求始终被服务端拒绝。

## 来源、版本与改编说明
- 改编来源：NeuroSploit `5d4e7e0`（本地标注 4.2.1），`neurosploit-rs/agents_md/mobile/ipa_static_analysis.md`；原归属 Joas A Santos & Red Team Leaders。
- 上游：https://github.com/JoasASantos/NeuroSploit/blob/5d4e7e0/neurosploit-rs/agents_md/mobile/ipa_static_analysis.md 。
- 本文为中文重组与证据边界补充；移除上游自动安装与静态线索即确认的要求，未引入绕过载荷。
- 官方参考（需按目标版本核对，本文未联网确认最新）：https://developer.apple.com/documentation/security/keychain_services ；https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity ；https://developer.apple.com/documentation/bundleresources/entitlements 。
- 上游 MIT 许可随本篇保留如下；本项目其他文件许可不替代此上游声明。

> MIT License
> Copyright (c) 2026 Joas A Santos & Red Team Leaders
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
