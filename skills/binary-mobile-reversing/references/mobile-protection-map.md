# 移动保护执行点与服务端强制检查

## 适用、版本与组件身份
- 对获授权 APK/IPA 建保护地图；默认只读，不提供注入、绕过或免杀脚本。
- 固定构建/签名/库哈希、SDK 版本依据、架构、系统、真机/模拟器与 root/越狱状态。
- 记录测试账号、租户、环境；原始、测试与重签名构建分别保留。
- Android JNI、iOS 原生、Flutter AOT、混合 JS 分层观察，不推断保护相互覆盖。
- 无模型调用需求；模型辅助仅用批准脱敏材料，记录 provider/model，不能用其评分确认影响。
- 详见 [移动保护证据](../../../knowledge_base/Mobile-Security/Mobile-Protection-Evidence.md)。

## 短执行流程
1. 从初始化、库、敏感动作入口找检测线索，给每个控制独立编号。
2. 逐项登记检测输入、判定位置、回调/缓存、gate 与所有拒绝/禁用执行点。
3. 区分启动警告、截图限制、TLS 固定、本地签名/hash 与服务端证明。
4. 对 pinning 按请求库、WebView、第三方 SDK 与备用端点核对覆盖，不运行绕过载荷。
5. 对证明追踪挑战/请求绑定、平台验证与服务端失败处理，DeviceCheck 不等同 App Attest。
6. 将控制连接到具体资产和业务动作，客户端“通过”字段不替代服务端证据。
7. 另获动态批准后，用测试夹具对完整、缺失、失效状态逐执行点做单变量对照。
8. 用合成对象回查真实服务端权限变化，本地保护弱项与实际越界分开记录。

## 基线、证据与反证
- 允许基线：原始测试构建、合格设备和有权账号完成预期自有动作。
- 拒绝基线：低权账号即使具有有效设备证明仍不能访问不属其权限的合成对象。
- 完整性对照只在批准夹具中改变证明状态，不混用其他设备/构建/账户。
- 证据包含控制编号、函数/偏移、构建哈希、检测与执行点、身份和请求关联 ID。
- 运行记录分别保存检测日志、客户端结果、服务端验证及目标回查；平台 token 脱敏。
- `tentative` 为影响候选，`confirmed` 为明确越界，`blocked` 为依赖/授权不足。
- 正例：失效证明仍让低权测试身份取得被策略禁止的权益，审计和拒绝基线可证。
- 反例：本地检查显示通过，但服务端独立验证失败并拒绝，不确认业务越权。
- Pinning 缺失、root 后读取本人数据或可改客户端返回值不自动确认服务端漏洞。

## 停止、依赖与清理
- 无原始构建、服务端观察、设备或匹配版本时停止相关分支，标记 `blocked`。
- 崩溃循环、锁号、真实支付、生产修改、遥测/秘密外发立即停止，不扩范围。
- 已注册 `strings`、`ghidra` 仅用于获批线索与制品分析；注册不证明已安装。
- Frida、MobSF、平台证明客户端与设备是依赖说明，不新增或安装，缺失即 `blocked`。
- 不执行未知库、不下载 SDK/模型、不关闭生产保护以补证。
- 测试后恢复设备与网络配置、撤销合成密钥/会话、清理测试数据并记录恢复结果。

## 修复
- 服务端独立校验证明及业务权限，绑定用户、动作、目标与时效；明确失败与降级策略。
- 敏感执行点完整覆盖，避免一次启动判定无限缓存；客户端保护作为纵深而非唯一授权。
- TLS 固定要覆盖实际网络栈并维护轮换，不以永久关闭证书校验处理兼容问题。

## 来源与许可
- NeuroSploit `5d4e7e0`（本地标注 4.2.1），`neurosploit-rs/agents_md/mobile/rasp_protection_mapping.md`、`neurosploit-rs/agents_md/mobile/code_integrity_tamper_check.md`；原归属 Joas A Santos & Red Team Leaders。
- 来源：https://github.com/JoasASantos/NeuroSploit/tree/5d4e7e0/neurosploit-rs/agents_md/mobile 。
- 中文改编执行点地图并补充服务端证据/停止规则；移除自动安装与本地绕过脚本。
- 官方资料按实际版本核对，未声明最新：https://developer.android.com/google/play/integrity/overview ；https://developer.apple.com/documentation/devicecheck ；https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity 。
- 上游 MIT 许可保留如下。

> MIT License
> Copyright (c) 2026 Joas A Santos & Red Team Leaders
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
