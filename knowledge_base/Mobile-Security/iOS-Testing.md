# iOS 测试要点

> iOS 的关键差异：**Keychain、URL Scheme/Universal Links、ATS、越狱检测与代码签名校验**。未越狱设备上的可选路径是重签名（`ios-deploy`）与模拟器。

## 一、环境

- 越狱设备（含 `Frida`、`objection`、`frida-ios-dump` 砸壳）；或用 `ios-deploy` 安装自定义构建（需 IPA 与证书）。
- 抓包：Burp CA 装入**系统信任**（越狱后可直接改信任库；未越狱需重签名应用并把 CA 打包进去）。
- 工具：`class-dump`/`dumped` 头文件、`Hopper`/`Ghidra`、`MobSF`、`passionfruit`（旧）。

## 二、静态检查

- `Info.plist`：`NSAppTransportSecurity`（`NSAllowsArbitraryLoads`）、URL Scheme 列表、`UIBackgroundModes`、隐私权限描述。
- `embedded.mobileprovision` / 签名信息、是否启用 `get-task-allow`（可调试）。
- 二进制：`otool -L`（依赖）、`nm`/`strings`（硬编码 URL/密钥）、Swift 符号（`swift-demangle`）。
- 关键机制是否存在：`SecItemAdd`（Keychain 用法）、`SecTrustEvaluate`（pinning）、越狱检测函数（`stat` 检查 `/Applications/Cydia.app` 等）。
- `assets/`、`Localizable.strings`、`bundle` 内的配置与 plist。

## 三、动态检查

```bash
# 砸壳 + 提取
frida-ios-dump -u -o out.ipa <bundle-id>
# 越狱设备上查看容器
frida -U -f <bundle-id> -l script.js
```

检查项：

- **Keychain**：`kSecAttrAccessible` 是否为 `WhenUnlockedThisDeviceOnly`（否则可备份/迁移）；条目是否被 Frida 直接读出。
- **本地存储**：`NSUserDefaults`、plist、SQLite/Realm 中的明文敏感数据；备份文件（iTunes 备份）中的内容。
- **剪贴板**：敏感内容写入通用剪贴板（可被其他应用读取）。
- **日志**：`NSLog` 泄漏 token/口令。
- **URL Scheme**：任意应用可注册自定义 scheme → 诱导应用执行敏感操作（缺少调用方校验）；参数进入 WebView/文件路径。
- **Universal Links**：`apple-app-site-association` 配置（路径匹配过宽）。
- **WebView（WKWebView）**：`evaluateJavaScript` 注入、加载任意 URL、`allowFileAccessFromFileURLs` 等价配置。
- **生物识别/Keychain 保护**：`LAContext` 的回调可被 hook（见下篇）。
- **屏幕保护**：敏感页面是否有截屏/录屏防护（`UITextField.isSecureTextEntry` 技巧用于遮罩）。
- **JS Bridge**：`WKScriptMessageHandler` 暴露的方法、注入的 JS 是否可被页面内容影响。

## 四、服务端侧

同 Android：移动端 API 的授权、限流、JWT、批量赋值（见 `../API-GraphQL/README.md`）。iOS 独有线索：

- 客户端把"是否 Premium/是否越狱"作为服务端信任依据（可伪造）。
- 收据校验（`verifyReceipt`）仅在客户端做。
- Push token 与账号绑定缺失 → 可推送他人通知。

## 五、验证（最小证据）

1. 设备与系统版本、是否越狱、应用版本。
2. 操作命令（Frida 脚本、`frida-ios-dump`、Burp 请求）与输出。
3. 影响：读到的 Keychain/存储内容（掩码）、被劫持的 URL Scheme 触发的动作。
4. 明确"需要越狱/需要本机其他应用"这类前置条件。

## 六、常见误报

- 越狱设备上"可读 Keychain"是越狱的后果，非应用缺陷（要区分 `ThisDeviceOnly` 与备份可迁移）。
- ATS 存在例外但例外域无关紧要。
- 自定义 URL Scheme 缺校验，但所触发动作无敏感后果。
- 静态发现"pinning 未启用"，但服务端另有防护。

## 七、修复

- Keychain：使用 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`；敏感项加生物识别访问控制（`SecAccessControl`）。
- URL Scheme 处理需校验调用来源（`sourceApplication`）并二次确认敏感操作；优先 Universal Links。
- 启用 **ATS**（无例外），关键请求做 pinning（含备用 pin 与轮换策略）。
- 禁止日志输出敏感信息；剪贴板写入敏感内容要限时并提示。
- 收据/订阅校验在服务端；push token 与账号强绑定。
- 越狱检测作为纵深（可被绕过，不单独依赖）。

## 八、参考

- OWASP MASTG：iOS 测试用例；HackTricks：iOS Pentesting
- 工具：frida-ios-dump、objection、MobSF、class-dump、Ghidra
