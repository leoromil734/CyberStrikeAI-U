# 移动应用安全总览（Mobile Security）

> 移动端的攻击面 = **应用自身**（本地存储、组件、加密、反调试）+ **通信**（TLS、证书固定）+ **服务端 API**（占比最大）。多数高价值漏洞最终落在**服务端授权**，因此移动评估往往是"找 API 而绕过客户端限制"。

## 一、测试环境

| 平台 | 环境 |
|---|---|
| Android | Root（Magisk/Zygisk + DenyList/Shamiko）、`adb`、Frida server、`objection`、Burp CA 装入 **系统** 证书库（API 24+ 需改 `/system/etc/security/cacerts` 或用 Magisk 模块） |
| iOS | 越狱设备（palera1n/Dopamine）、`frida`、`objection`、`frida-ios-dump`（砸壳）、Burp CA 装入系统信任 |
| 通用 | `MobSF`（静态+动态）、`jadx`/`apktool`、`Ghidra`/`IDA`（native） |

Android 无越狱/无 root 时的替代：可重打包的应用（防篡改弱）、`apk-mitm` 自动 patch network security config、模拟器 + 用户证书（若 `targetSdk<24` 或应用信任用户 CA）。

## 二、静态分析要点

1. **Manifest**：
   - `android:debuggable="true"`、`allowBackup="true"`（`adb backup` 可拖数据）。
   - `android:exported="true"` 的 Activity/Service/Receiver/Provider（可被其他应用调用）。
   - `networkSecurityConfig`（明文流量、用户 CA 信任、pinning 声明）。
   - 权限与 `minSdkVersion`（旧版本更易受攻击）。
   - `launchMode="singleTask"` 且无 `taskAffinity` → **Task Hijacking** 候选。
2. **资源与字符串**：`strings.xml`、`assets/`、`res/raw` 里的 API key、内网域名、Firebase 配置、硬编码凭据。
   ```bash
   apkleaks -f app.apk          # 密钥/URL/端点
   ```
3. **代码结构**：
   - 反编译是否被混淆（`APKiD` 识别 packer/obfuscator）。
   - React Native/Xamarin/Flutter 的特殊打包（`index.android.bundle`、`libapp.so` 中的 Dart 快照）。
   - 恶意样本常见"畸形 ZIP/Manifest"以阻断工具（用 `MalFixer` 类工具规范化后再分析）。
4. **native 库**：`lib/arm64-v8a/*.so` → JNI 逻辑、密钥派生、pinning 实现。

## 三、动态分析要点

- `adb logcat` / `pidcat` 找敏感日志；剪贴板泄漏；崩溃日志。
- **本地存储**：`/data/data/<pkg>/shared_prefs`、`databases`、`files`；外部存储（全局可读）。
- **组件测试**：用 `drozer`/`adb am start`/自定义 app 调用导出的 Activity/Service/Receiver，测试 Content Provider 的 SQL 注入与路径穿越。
- **WebView**：`@JavascriptInterface` 暴露的方法、`file://` 访问、`addJavascriptInterface` + 用户内容 → RCE/文件读取；`Intent.parseUri` 逃逸。
- **网络**：代理抓包（见下节 pinning）、重放/篡改签名参数、越权调用服务端 API。
- **生物识别**：Frida hook 绕过（见 `SSL-Pinning-and-Root-Detection-Bypass.md`）。
- **IPC 与 Deep Link**：自定义 scheme/App Links 的参数进入 WebView/文件操作 → 任意文件读取/越权。

## 四、服务端侧（最高价值）

- 直接把移动端 API 当 Web 目标测：BOLA/批量赋值/限流/JWT（见 `../API-GraphQL/README.md`、`../IDOR-BOLA/README.md`）。
- 移动端特有的弱校验：只靠 `User-Agent`/`X-Platform` 判断平台、只靠客户端签名（可逆向复现）、`device_id` 可控。
- 老版本接口：`/v1/` 与新版本并存，旧接口常缺少新加的授权校验。
- 推送/短信验证码接口的限流与绑定（见 `../Authentication-Bypass/MFA-and-Passkey-Bypass.md`）。

## 五、验证（最小证据）

1. 环境与版本（App 版本、OS 版本、是否 root/越狱）。
2. 复现步骤：具体命令（`adb shell`、Frida 脚本、请求原文）与输出。
3. 影响证据：读到的本地敏感数据、被成功调用的导出组件、服务端返回的他人数据。
4. 对"仅本地"的问题（如 debug 标志）要与"可利用性"分开陈述。

## 六、常见误报

- 仅检测到"应用允许 HTTP"但实际无敏感流量走 HTTP。
- 导出的组件存在但需要特定权限/签名校验。
- 本地数据库有敏感字段但设备已加密（FBE）且未 root。
- 混淆导致"看起来没有校验"，实际在 native 层。

## 七、修复

- 不信任客户端：服务端独立鉴权与限流；签名/校验逻辑不可作为唯一防线。
- 组件默认不导出，导出前做权限与来源校验。
- WebView：禁用 `addJavascriptInterface`（除非必要并白名单）、关闭 `file://` 访问、限制 `setAllowFileAccess`。
- 存储：敏感数据用 Android Keystore/iOS Keychain，禁止明文 SharedPreferences/外部存储。
- 网络：证书固定（但要有备用策略）+ 禁止明文；对关键操作做完整性校验。
- 反分析：代码混淆、防调试、防 root 检测（作为纵深，不作为唯一防护）。

## 八、参考

- OWASP MASTG（MASVS/MASTG 测试指南）
- HackTricks：Android/iOS Pentesting
- Skill：`binary-mobile-reversing`
