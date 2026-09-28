# Android 测试要点与组件攻击

> Android 评分最高的两类问题：**导出组件被滥用**（本地/同设备攻击面）与**服务端 API 授权缺失**（远程攻击面）。

## 一、环境准备

```bash
# 取包与合并 split
adb shell pm list packages | grep <key>
adb shell pm path <pkg>            # 可能返回多个 split
# 用 APKEditor 合并：java -jar APKEditor.jar m -i splits/ -o merged.apk
# 重签名：uber-apk-signer.jar -a merged.apk --allowResign
```

抓包（用户 CA 可信任时）：

```bash
apk-mitm app.apk            # 自动 patch network security config + 重打包
# 或手工：反编译后修改 res/xml/network_security_config.xml，添加 <certificates src="user"/>
```

无 root 时可用模拟器 + Magisk；有 root 时把 Burp CA 写入系统证书库（`/system/etc/security/cacerts/<hash>.0`，注意 `chmod 644`）。

## 二、静态检查清单

```bash
apktool d app.apk -o app
jadx -d out app.apk
grep -rniE 'api[_-]?key|secret|token|password|Bearer' app/ | head -50
grep -rn 'exported="true"' app/AndroidManifest.xml
grep -rn 'usesCleartextTraffic\|debuggable\|allowBackup' app/AndroidManifest.xml
```

重点：

- 导出的 `Activity`/`Service`/`Receiver`/`Provider`（Android 12+ 需显式 `android:exported`）。
- `Content Provider` 的 `grantUriPermissions`、`file_paths.xml`（`<root-path path="/data/">` 之类 → 任意文件读取）。
- `PendingIntent` 的可变/隐式（`FLAG_MUTABLE` + 空 Intent）。
- WebView 与 JS Bridge：`addJavascriptInterface`、`setJavaScriptEnabled`、`setAllowFileAccess`、`setAllowUniversalAccessFromFileURLs`。
- `Intent.parseUri`/`startActivity` 使用外部输入。
- 自定义 URL scheme 与 App Links 的 `host`/`path` 校验。
- 生物识别调用是否只依赖 `onAuthenticationSucceeded` 回调（可被 hook）。

## 三、动态验证

```bash
# 导出 Activity
adb shell am start -n <pkg>/<activity> --es <key> <value>
# 导出 Service / Receiver
adb shell am startservice -n <pkg>/<service>
adb shell am broadcast -a <action> -n <pkg>/<receiver> --es <k> <v>
# Content Provider（无权限时枚举与读取）
adb shell content query --uri content://<authority>/<path>
adb shell content read --uri content://<authority>/<path>
# 本地存储
adb shell run-as <pkg> ls -la /data/data/<pkg>/
cat /data/data/<pkg>/shared_prefs/*.xml
```

其他方向：

- **Task Hijacking**：`singleTask` + 无 `taskAffinity` 的应用可被同名/相似名应用抢占任务栈（用户以为在用真应用）。
- **Tapjacking**：透明/部分遮挡的悬浮窗诱使用户点击被遮住的敏感按钮。
- **不安全的自更新**：检查更新包是否校验签名（`getPackageArchiveInfo` 不带签名信息 = 弱校验）→ 配合文件写入可得静默安装。
- **文件传输类应用**（附近分享/投屏）：BLE 泄露 SSID/PSK/token、控制消息可注入 `silent/autoAccept` 之类标志位、基于 HTTP 的拉取下载可被伪造（详见 HackTricks 2025 相关章节）。
- **恶意固件/预装**：`codePath` 不在 `/data/app`、`/data/local/system` 下有次级 APK、可访问性服务 + OCR 自动化。属于固件供应链问题。

## 四、验证（最小证据）

1. 命令与输出（导出的组件调用、provider 读取到的数据）。
2. 影响证明：读到的敏感内容（掩码）、以其他应用身份触发的动作。
3. 说明前置条件（是否需要 root、是否需要在设备上安装恶意应用）。
4. 服务端问题单独按 API 规范取证。

## 五、常见误报

- 组件导出但被 `android:permission` 保护（需签名级权限）。
- Provider 存在但 `path-permission` 拒绝了你的路径。
- 本地文件可读仅因为设备已 root（非应用缺陷）。
- WebView 危险配置存在但页面不可被攻击者影响。

## 六、修复

- 显式 `android:exported="false"`；必须导出时校验调用方（签名/权限/来源）。
- Provider 使用 `path-permission`，禁用 `root-path` 宽映射。
- WebView：禁用 JS Bridge、禁止 `file://` 由外部控制、固定加载白名单域名。
- 敏感数据放 Keystore/EncryptedSharedPreferences；关闭 `allowBackup`。
- 自更新必须校验签名与哈希，禁止从外部存储直接安装。
- 生物识别：使用 `BiometricPrompt` + `CryptoObject`（让密钥与验证绑定，不能仅靠回调）。

## 七、参考

- HackTricks：Android Applications Pentesting（含 2025 新增的邻近传输/恶意固件章节）
- OWASP MASTG：Android 测试用例
- 工具：jadx、apktool、MobSF、objection、Frida、drozer、apkleaks、APKiD
