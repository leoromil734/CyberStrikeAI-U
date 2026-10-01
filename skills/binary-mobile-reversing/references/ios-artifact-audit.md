# iOS 制品审计：从签名声明到真实授权

## 适用、版本与身份
- 只读审阅获授权 IPA/.app、签名导出、Profile 与源码；默认不安装、重签名或联网。
- 固定制品哈希、Bundle ID、构建号、Team ID、签名与分发类型；记录 iOS、架构、设备/模拟器及越狱状态。
- 宿主、扩展、App Clip 独立建清单；测试账号、租户和服务端环境需明确。
- 原始、测试与重签名构建不可混作基线，缺对应构建记 `blocked`。
- 本流程无模型调用需求；如使用模型辅助，记录 provider/model 并只传获准脱敏材料。
- 详见 [iOS 制品权限知识](../../../knowledge_base/Mobile-Security/iOS-Artifact-Authority.md)。

## 执行工作流
1. 固定原件及哈希，定位 Info.plist、Profile、签名 entitlement、Mach-O 和全部扩展。
2. 并列读取 Profile 与实际签名权限，记录来源差异，不根据一份文件猜有效权限。
3. 对 access groups、app groups、get-task-allow 建“组件身份→权限→资产”映射。
4. 对 Keychain 条目追踪写入参数、可访问条件、共享主体和备份/迁移策略。
5. 对 ATS 记录具体例外域、请求库与数据用途；对链接/桥接追踪 frame、参数与敏感动作。
6. 将静态线索关联到函数/偏移和实际构建，未知调用与加密区保留分析缺口。
7. 仅在独立批准的测试设备/服务端中做单变量对照，使用自有账号和合成秘密。
8. 区分平台拒绝、客户端表现与服务端回查；只在新增权限或真实泄露被证实时确认。

## 基线与最小证据
- 允许基线：预期签名主体读取自己的合成 Keychain 条目或业务对象。
- 拒绝基线：无共享组/无业务权限的测试主体访问相同合成资产被拒绝。
- 单变量：只改变访问组、账号、对象归属、设备前提或链接来源之一。
- 交付制品/签名哈希、plist key、函数位置、条目属性、读取主体、时间和平台返回值。
- 服务端越界另附请求关联 ID、对象归属、脱敏响应及审计/回查，不能只给界面截图。
- `tentative` 为影响未知候选，`confirmed` 为已证实边界失效，`blocked` 为授权/依赖不足。

## 反证、停止与清理
- 越狱环境读到本人 token、只有 entitlement 声明、缺 pinning/PIE 均不自动确认漏洞。
- ATS 例外不承载敏感请求、共享仅限预期组件或服务端仍拒绝时收窄结论。
- 正例：非预期签名组件在正常测试前提下读出合成共享秘密，有平台结果与归属证据。
- 反例：本地 UI 变成高级状态，但低权业务请求被服务端持续拒绝。
- 无 macOS 签名材料、真机或获批动态范围时停止相关分支并写 `blocked`。
- 不抓取真实 Keychain，不主动访问关联域，不为验证关闭生产控制。
- 完成获批测试后删除合成条目、撤销会话并恢复设备/网络设置；留脱敏证据与清理结果。

## 已注册工具与修复
- `strings` 仅识别线索；`ghidra` 用于获批 Mach-O 分析，先核对实际安装与版本能力。
- `codesign`、`plutil`、`otool`、Frida、MobSF 是依赖说明，不新增/安装或假定可用；缺失记 `blocked`。
- 最小化分发 entitlement，按秘密用途设置 Keychain 属性，收紧传输例外。
- 链接与原生桥接进行参数/目标校验，权限与订阅决策放在服务端。

## 来源、许可与改编
- NeuroSploit `5d4e7e0`（本地标注 4.2.1），`neurosploit-rs/agents_md/mobile/ipa_static_analysis.md`；原归属 Joas A Santos & Red Team Leaders。
- 来源：https://github.com/JoasASantos/NeuroSploit/blob/5d4e7e0/neurosploit-rs/agents_md/mobile/ipa_static_analysis.md 。
- 本文中文重组并增加授权/反证门槛，移除自动安装与静态线索即确认；不搬载荷。
- 官方资料需按目标版本核对，未联网查最新：https://developer.apple.com/documentation/security/keychain_services ；https://developer.apple.com/documentation/bundleresources/entitlements ；https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity 。
- 上游 MIT 许可保留如下。

> MIT License
> Copyright (c) 2026 Joas A Santos & Red Team Leaders
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
