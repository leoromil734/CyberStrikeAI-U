# 证书固定与 Root/越狱检测绕过

> 目标是**恢复可观测性**：让代理能看到流量、让脚本能在受保护环境里运行。绕过只是手段，最终仍要回到"接口是否存在授权缺陷"。

## 一、TLS 证书固定（Pinning）绕过

### 1. 通用思路（按侵入性从低到高）

| 思路 | 说明 |
|---|---|
| 修改 network security config（Android） | 重打包后允许用户 CA（`apk-mitm` 自动化）；不改代码逻辑 |
| Frida hook 校验函数 | 让校验永远返回成功（需知道实现位置） |
| 替换信任库/删除 pin | 重打包时移除 pinning 代码或替换公钥 |
| 中间层（本地 VPN + 自签 CA） | 仅在应用不 pin 或 pin 到自有 CA 时有效 |
| 逆向 native 层 | 若 pinning 在 `.so` 中（BoringSSL/自定义校验），需按符号或字符串定位 |

### 2. 常见实现与 Hook 点（Android）

- **OkHttp**：`CertificatePinner.check`（返回 void，直接替换为空实现）。
- **TrustManager**：自定义 `X509TrustManager.checkServerTrusted`、`checkClientTrusted`、`getAcceptedIssuers`。
- **HostnameVerifier**：`verify` 返回 true。
- **Conscrypt/系统层**：Java pinning 之外的 native 校验需要更底层处理。
- **Native（`.so`）**：`SSL_CTX_set_verify`、`X509_verify_cert`、`SSL_get_verify_result` 的 hook（Frida 的 `Interceptor` + 符号导出，注意 arm64 参数寄存器）。

示例（概念性，需按目标调整）：

```javascript
Java.perform(function () {
  var Pinner = Java.use("okhttp3.CertificatePinner");
  Pinner.check.overload('java.lang.String', 'java.util.List').implementation = function (h, p) { return; };
  var X509 = Java.use("javax.net.ssl.X509TrustManager");
  // 或替换为自定义 TrustManager + 空校验
});
```

- **iOS**：hook `SecTrustEvaluate`/`SecTrustEvaluateWithError`（返回 `kSecTrustResultProceed`/true）、`URLSession` 的 `didReceive challenge` 回调、AFNetworking/Alamofire 的 `evaluateServerTrust`。

> 注意：pinning 绕过**成功与否要用实际抓到的请求证明**（而不是"脚本没报错"）。

## 二、Root / 越狱 / 模拟器 / 反调试检测绕过

常见检测点：

| 检测 | Android | iOS |
|---|---|---|
| 文件存在性 | `/system/bin/su`、`/system/xbin/su`、Magisk 路径 | `/Applications/Cydia.app`、`/bin/bash`、`/usr/sbin/sshd` |
| 属性/包名 | `ro.debuggable`、`ro.secure`、检测 Magisk 包名 | `/private/var/lib/apt` |
| 命令执行 | `su -c id`、`which su` | fork 后执行受限命令 |
| 完整性 | SafetyNet/Play Integrity、签名校验 | 代码签名校验（`SecCodeCheckValidity`） |
| 调试 | `Debug.isDebuggerConnected`、`ptrace` 自附加、`/proc/self/status` 的 `TracerPid` | `ptrace(PT_DENY_ATTACH)`、`sysctl` 检查 |
| 环境 | 模拟器指纹（`ro.hardware`、传感器数量）、`x86` 架构 | 模拟器路径、`SIMULATOR` 变量 |
| 时间/交互 | 是否有真实用户交互（触摸、加速度） | 同上 |

绕过方法：

- Hook 检测函数返回"干净"值（Java 层 `System.getProperty`、`File.exists`、`Runtime.exec`）。
- 隐藏 root：**Zygisk DenyList + Shamiko**（Android）、**HideJB/Choicy**（iOS），配合改包名。
- 反调试：在 `frida-server` 之前 patch（`frida-gadget` 注入）、hook `ptrace`/`sysctl`。
- Play Integrity：需要在真机 + 通过既有服务获取有效令牌，通常超出评估所需；更实际的是**绕过客户端判定**并直接测试服务端是否真的校验。
- WebView 层伪装：`navigator.webdriver`、UA、屏幕/GPU 指纹（移动端也可被检测）。

## 三、验证（最小证据）

1. 绕过前：抓包失败/脚本被检测的原始错误（如 `SSLHandshakeException`、应用退出）。
2. 绕过后：**成功抓到目标接口的请求与响应**（这是唯一有效证据）。
3. 检测绕过：给出被 hook 的函数与返回值，以及应用功能仍正常的证明。
4. 标注前置条件（需要 root/越狱/重签名）。

## 四、常见误报

- 脚本执行无报错但流量仍未抓到（hook 目标不对）。
- 代理抓到了应用流量，但只是不 pin 的第三方 SDK 流量（目标接口仍未可见）。
- 检测绕过成功但服务端侧另有校验（如设备证明）—— 需在生产语义下验证。

## 五、修复（客户侧）

- Pinning：在 native 层做校验、校验结果参与业务逻辑（不只是一个被 hook 的布尔）、使用多 pin 与备用 pin。
- 完整性：Play Integrity/DeviceCheck 的**结果在服务端校验**，并对高风险操作做设备绑定。
- 反调试与混淆：作为纵深手段（增加成本），不承载安全决策。
- 关键结论：**服务端必须是最终的鉴权与风控决策点**；客户端检测只能提高攻击成本。

## 六、参考

- OWASP MASTG：Resilience（Anti-Reverse Engineering / Anti-Tampering）测试用例
- HackTricks：Android/iOS 反调试与 pinning 绕过；`objection` 内置脚本（`android sslpinning disable`）
- 工具：Frida、objection、Magisk（Zygisk/DenyList/Shamiko）、apk-mitm、frida-ios-dump
