---
name: cdn-tls-fingerprint
description: >-
  诊断 CDN/WAF 边缘的 TLS、JA3/JA4 与 HTTP/2 客户端指纹差分，并在受控对比确认后使用 curl_cffi。仅在标准客户端被边缘拦截而同条件浏览器可达时使用；看到 CDN、cf-ray 或普通 403 时不要触发。
  Use when a controlled browser-versus-CLI comparison suggests TLS/client fingerprint blocking, not merely when a site uses a CDN.
tags: [渗透测试, penetration-testing, CDN, Cloudflare, TLS, 红队]
---

# CDN / TLS 客户端指纹诊断

本 skill 的职责是**归因和换路**，不是把 `curl_cffi` 变成默认 HTTP 客户端。

```text
看到 CDN                 != TLS 指纹拦截
看到 cf-ray              != TLS 指纹拦截
单次 403/429/503         != TLS 指纹拦截
浏览器与 CLI 有受控差分  = 可以进入诊断
curl_cffi 唯一变量下到达业务层 = 才确认客户端指纹拦截
```

## 1. 触发门槛

只有同时满足以下条件，才进入 `curl_cffi` 诊断：

1. 标准客户端对同一请求低速重试后，持续停留在边缘：403/503、挑战页、连接重置或非业务响应。
2. 真实浏览器在相同网络出口访问同 URL、同方法和同认证态，能够到达业务响应。
3. 已对齐关键变量：Cookie、Authorization、CSRF、请求体、Content-Type、重定向和必要 Header。
4. 已排除明显的 JS Challenge、验证码、速率限制、IP 信誉和地区限制。

以下情况不加载本 skill，继续使用 `httpx`、系统 `curl` 或普通脚本：

- 仅 `httpx -cdn` 标出 CDN
- 响应头只有 `server: cloudflare` / `cf-ray`
- 所有客户端都得到相同应用层 401/403/404
- 浏览器依赖新 Cookie 或完成 JS Challenge 后才成功
- 降速或更换出口后标准客户端恢复

## 2. 一次只改变一个变量

使用固定测试用例记录：

```text
URL / method / body
network egress
headers / cookies / auth
redirect policy
request rate
client stack
status / response markers / edge headers
```

按顺序执行：

```text
S0 标准客户端低速基线
   -> 已到业务层：停止，不使用 curl_cffi
   -> 边缘拦截：进入 S1

S1 同条件真实浏览器
   -> 浏览器也被拦：不是已确认 TLS 差分，转浏览器挑战/限流/IP 诊断
   -> 浏览器到业务层：进入 S2

S2 对齐 Cookie、认证、方法、请求体与重定向后复测标准客户端
   -> 恢复：差异来自请求状态，不是 TLS
   -> 仍停在边缘：进入 S3

S3 安装并只发送 1 个 curl_cffi 诊断请求
   -> curl_cffi 到业务层、标准客户端仍在边缘：确认 TLS/HTTP2 客户端指纹
   -> curl_cffi 仍挑战：未确认；优先真实浏览器或获取挑战 Cookie
```

## 3. 结论分类

- `tls_fingerprint_confirmed`：相同请求条件下，只有浏览器 TLS 栈/`curl_cffi` 到达业务层。
- `cookie_or_js_challenge`：获得挑战 Cookie 或执行 JS 后才可达；使用浏览器流程。
- `rate_or_ip_block`：降速或换出口后恢复；使用限速/代理策略。
- `application_denial`：各客户端都到达相同业务 401/403；回到鉴权/业务测试。
- `inconclusive`：变量未对齐或结果不稳定；不得宣称 TLS 指纹拦截。

建议写入 fact：测试矩阵、响应标记、唯一变化变量和结论置信度。

## 4. 确认后使用 `curl_cffi`

仅在 `tls_fingerprint_confirmed` 后安装：

```bash
pip install curl_cffi
```

最小诊断/复用示例：

```python
from curl_cffi import requests

session = requests.Session(impersonate="chrome")
response = session.get(
    "https://target.example/api/v1/resource",
    headers={
        "Accept": "application/json, text/plain, */*",
        "Authorization": "Bearer <same-token-as-baseline>",
    },
    cookies={"session": "<same-cookie-as-baseline>"},
    timeout=30,
    allow_redirects=False,
)
print(response.status_code)
print(response.headers.get("server"), response.headers.get("cf-ray"))
print(response.text[:500])
```

CyberStrikeAI 中使用 `install-python-package` 安装，`execute-python-script` 执行。不要为了普通探活、爬取、目录枚举或没有拦截的网站安装它。

确认后也只替换**受影响的结论性请求**：

- 探活、批量资产筛选仍优先 `httpx`
- 路径发现仍优先 `ffuf`/`dirsearch`
- 普通 API 差分可使用标准脚本
- 只有被证实卡在 TLS/HTTP2 客户端指纹的请求才复用同一个 `curl_cffi.Session`

## 5. `curl_cffi` 仍失败时

- 强 JS Challenge / Turnstile：使用真实浏览器完成挑战，再判断是否需要复用 Cookie。
- 有 Cookie 仍失败：重新核对 TLS 画像、Cookie 绑定、出口 IP 和浏览器请求头，不要反复更换 `impersonate` 猜测。
- 所有客户端稳定 502：检查路径规则、上游故障或反向代理，不归因 TLS。
- 429 或批量后全 403：降低并发和速率，先诊断限流/IP 信誉。
- 已授权且存在源站线索：可对齐 Host/SNI 做最小源站验证，但需保持范围约束。

## 6. 与漏洞验证衔接

```text
Surface: httpx 只标注 CDN/边缘
Diagnose: 受控客户端差分，确认或否定 TLS 指纹
Verify: 在同一个已验证可达客户端上做业务漏洞差分
Record: 区分 edge_block、app_403、auth_fail 与真实漏洞证据
```

默认客户端被边缘拦截不能证明“接口不存在”或“没有漏洞”；同样，网站存在 CDN 也不能证明必须使用 `curl_cffi`。