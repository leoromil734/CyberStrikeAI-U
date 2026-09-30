---
name: cdn-tls-fingerprint
description: >-
  诊断 CDN/WAF 边缘的 TLS、JA3/JA4 与 HTTP/2 客户端指纹差分，并在受控对比确认后使用 curl_cffi。仅在标准客户端被边缘拦截而同条件浏览器可达时使用；看到 CDN、cf-ray 或普通 403 时不要触发。
  Use when a controlled browser-versus-CLI comparison suggests TLS/client fingerprint blocking, not merely when a site uses a CDN.
metadata:
  tags: [渗透测试, penetration-testing, CDN, Cloudflare, TLS, 红队]
---

# CDN / TLS 客户端指纹诊断

职责是**归因和换路**，不是将 `curl_cffi` 设为默认客户端。看到 CDN、cf-ray 或单次403/429/503都不等于TLS指纹拦截。

## 触发与请求状态对齐

只有同时满足以下条件才进入诊断：
1. 标准客户端同一请求低速重试后持续停在边缘：403/503、挑战页、连接重置或非业务响应。
2. 真实浏览器在相同网络出口、同 URL、同方法和同认证态能到达业务响应。
3. 已对齐 Cookie、Authorization、CSRF、请求体、Content-Type、必要 Header 和重定向。
4. 已排除明显的 JS Challenge、验证码、速率限制、IP 信誉和地区限制。

仅 `httpx -cdn`、`server: cloudflare`/`cf-ray`、所有客户端相同应用层401/403/404、浏览器靠新Cookie/JS Challenge才成功、降速/换出口后恢复：继续普通客户端或对应挑战/限流诊断，不触发TLS结论。

一次只改变一个变量，固定记录：`URL / method / body`、`network egress`、`headers / cookies / auth`、`redirect policy`、`request rate`、`client stack`、`status / response markers / edge headers`。

## S0–S3 决策与停止条件

- **S0 标准客户端低速基线**：已到业务层 → 停止，不使用 curl_cffi；边缘拦截 → S1。
- **S1 同条件真实浏览器**：浏览器也被拦 → 未确认TLS差分，转浏览器挑战/限流/IP诊断；浏览器到业务层 → S2。
- **S2 对齐 Cookie、认证、方法、请求体与重定向后复测标准客户端**：恢复 → 差异来自请求状态，不是TLS；仍停在边缘 → S3。
- **S3 安装并只发送 1 个 curl_cffi 诊断请求**：curl_cffi到业务层、标准客户端仍在边缘，且唯一变化为客户端栈 → 确认TLS/HTTP2客户端指纹；仍挑战 → 未确认，优先真实浏览器或获取挑战Cookie，不循环猜测画像。

## 全部结论分类

- `tls_fingerprint_confirmed`：同请求条件下只有浏览器TLS栈/curl_cffi到业务层。
- `cookie_or_js_challenge`：挑战Cookie或执行JS后可达；使用浏览器流程。
- `rate_or_ip_block`：降速/换出口后恢复；限速/代理策略。
- `application_denial`：各客户端相同业务401/403；回到鉴权/业务测试。
- `inconclusive`：变量未对齐或结果不稳定；不得宣称TLS指纹拦截。

## 替代路径与复用边界

- 强 JS Challenge / Turnstile → 真实浏览器完成挑战，再判断Cookie复用。
- 有Cookie仍失败 → 核对TLS画像、Cookie绑定、出口IP、浏览器请求头；不要反复更换 `impersonate` 猜测。
- 所有客户端稳定502 → 路径规则、上游故障或反向代理，不归因TLS。
- 429或批量后全403 → 降低并发/速率，先诊断限流/IP信誉。
- 已授权且存在源站线索 → 对齐 Host/SNI 做最小源站验证，保持范围约束。

安装/脚本与详细失败诊断按需读取 `references/curl-cffi-usage.md`。S3仅作单次诊断；确认后只替换**受影响的结论性请求**并复用同一个 `curl_cffi.Session`，不用于普通探活、爬取或目录枚举：资产筛选仍用 `httpx`，路径发现仍用 `ffuf`/`dirsearch`，普通API差分用标准脚本。

## 证据衔接与保真

Surface：httpx只标注CDN/边缘；Diagnose：受控差分确认或否定TLS指纹；Verify：同一已验证可达客户端做业务漏洞差分；Record：区分 `edge_block`、`app_403`、`auth_fail` 与真实漏洞证据。记录测试矩阵、响应标记、唯一变化变量和结论置信度。

默认客户端被边缘拦截不能证明“接口不存在”或“没有漏洞”；存在CDN也不能证明必须使用curl_cffi。完整原文见 `references/original-skill.md`，仅用于审计或必要时完整取回，不默认加载。
