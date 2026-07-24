---
name: cdn-tls-fingerprint
description: >-
  CDN/WAF边缘拦截与TLS指纹:Cloudflare/Akamai/Fastly/网宿识别,JA3/JA4与HTTP2指纹导致
  python-requests/curl/httpx/sqlmap被拦;curl_cffi浏览器伪装、浏览器自动化、源站绕过与接口测试换路。
  Use when Cloudflare/CDN 403/503/challenge, TLS fingerprint block, API testing blocked, need curl_cffi.
tags: [渗透测试, penetration-testing, CDN, Cloudflare, TLS, 红队]
---

## CDN / TLS 指纹与接口测试换路

授权测试中：**边缘拦截 ≠ 业务 403**。很多「接口打不开」是 CDN/Bot 管理按 **TLS/JA3/JA4 + HTTP/2 + 客户端行为** 丢弃了非浏览器流量，而不是 API 本身鉴权失败。

与 `proxy-tool-bootstrap`（IP/代理换路）、`web-attack-methods`（路径/协议绕 CDN）、`api-security-testing`（业务鉴权）配合使用。

---

### 1) 识别：你在打 CDN 还是源站？

| 信号 | 常见含义 |
|------|----------|
| 响应头 `server: cloudflare` / `cf-ray` | Cloudflare 边缘 |
| `CF-Cache-Status` / `cf-mitigated` | CF 缓存或缓解动作 |
| 正文含 `Just a moment` / `cf-browser-verification` / Turnstile / Challenge | JS/人机挑战 |
| `server: AkamaiGHost` / `X-Akamai-*` | Akamai |
| Fastly / `x-served-by` / `via: 1.1 varnish` | Fastly 等 |
| 网宿 `_jsc_ch_conf` / `ws_sec_page.js` | 网宿 JS 挑战（见 web-attack-methods） |
| PWS / gccdn / 固定时序 502 | 路径/策略过滤（未必是 TLS） |
| 同 URL：**浏览器 200，curl/python 403/503/空/连接重置** | **高度疑似 TLS/JA3 或 Bot 指纹** |
| httpx/nuclei/sqlmap 大批量后突然全 403 | 速率 + 指纹双重触发 |

**事实落库建议：**

```
fact_key: infra/cdn_edge
summary: Cloudflare边缘 + 疑似TLS/Bot拦截（浏览器可访问，python-requests 403）
body: 证据头、状态码差分、已测客户端（curl/requests/httpx/浏览器）
confidence: confirmed|tentative
```

---

### 2) 分层诊断（一次只改一个变量）

```
A. 浏览器能开、CLI 不能
   → 优先 TLS/HTTP2/JA3 指纹 或 Cookie/JS 挑战，不是先狂换 payload

B. 浏览器也 Challenge
   → 需要过挑战拿 cf_clearance 等 Cookie，再复用到脚本；或改用真实浏览器自动化

C. 全部客户端 502 且时序极稳
   → 更像 URL/WAF 规则过滤（走 web-attack-methods CDN 502 矩阵），不是指纹

D. 仅扫描器被拦、慢速 curl_cffi chrome 正常
   → 指纹 + 速率；降并发、加间隔、统一浏览器伪装客户端
```

**禁止**：把「默认 urllib/requests 被 CF 拦」写成「接口不存在」或「无越权面」。

---

### 3) 为何 python-requests / 系统 curl / 部分工具会触发拦截

边缘可见的客户端画像通常包括：

1. **TLS 指纹（JA3/JA4）**：密码套件顺序、扩展、曲线 — OpenSSL 默认 ≠ Chrome  
2. **HTTP/2 指纹**：SETTINGS、伪头顺序、优先级  
3. **HTTP 头集合**：缺 `sec-ch-ua` / 错误 `Accept-Language` / 头顺序异常  
4. **行为**：无 Cookie 直打敏感路径、极高 RPS、无 Referer 的 API 爆破  

因此：**只改 User-Agent 往往不够**；必须换 **能模拟浏览器 TLS 栈** 的客户端。

---

### 4) 主换路：`curl_cffi`（接口测试首选）

[curl_cffi](https://github.com/lexiforest/curl_cffi) 基于 curl-impersonate，可 `impersonate` Chrome/Safari/Edge 等，显著降低 Cloudflare 等对「非浏览器 TLS」的拦截。

#### 安装（会话内）

```bash
# 优先用项目已有能力
install-python-package  # 包名 curl_cffi
# 或
pip install curl_cffi
```

#### 最小可用示例（API GET/POST）

```python
from curl_cffi import requests

# impersonate 取常见浏览器画像；版本需与库支持列表一致，如 chrome, chrome120, chrome124, safari, edge
session = requests.Session(impersonate="chrome")

headers = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    # 需要时从浏览器复制：Authorization / Cookie / X-CSRF-Token / 业务自定义头
}

r = session.get("https://target.example/api/v1/resource", headers=headers, timeout=30)
print(r.status_code, r.headers.get("cf-ray"), r.text[:500])

r2 = session.post(
    "https://target.example/api/v1/resource",
    headers={**headers, "Content-Type": "application/json"},
    json={"id": 1},
    timeout=30,
)
print(r2.status_code, r2.text[:500])
```

#### 带浏览器 Cookie（已过 Challenge 时）

1. 浏览器手动或 Playwright 通过挑战  
2. 导出 `cf_clearance`、`__cf_bm` 及业务 Cookie  
3. 注入 `session.cookies` 或 `headers["Cookie"]`  
4. **仍建议** `impersonate="chrome"`，避免「有 Cookie 但 TLS 仍是 Python」再次触发  

#### 代理

```python
# HTTP/SOCKS 代理（与 proxy-tool-bootstrap 配合）
proxies = {"http": "socks5://127.0.0.1:1080", "https": "socks5://127.0.0.1:1080"}
r = session.get(url, headers=headers, proxies=proxies, timeout=30)
```

#### 批量 BOLA/越权矩阵注意

- 全场统一 `Session(impersonate="chrome")`，不要混用 requests + curl_cffi 导致有的过有的不过  
- 降速：请求间隔 0.5–2s 随机；避免 nuclei/ffuf 默认高并发顶 CF  
- 失败分类落库：`edge_block` vs `app_403` vs `auth_fail`  

#### 在 CyberStrikeAI 中的调用方式

- `install-python-package` 安装 `curl_cffi`  
- `execute-python-script` 跑上述脚本  
- 或 `exec`：`python3 -c '...'`  
- **不要**在已确认 TLS 拦截时，继续用裸 `httpx`/`requests` 做结论性 API 测试  

---

### 5) 备选换路（curl_cffi 仍不够时）

| 手段 | 适用 |
|------|------|
| **Playwright / 真实 Chrome** | 强 JS Challenge、Turnstile；拿 Cookie 再交给 curl_cffi |
| **浏览器插件 / 手工导出 HAR** | 复制真实请求头与 Cookie 做最小复现 |
| **源站 IP 直连** | 历史 DNS、证书透明度、Shodan、邮件头、SSRF、同 IP 多站；`Host`/`Sni` 对齐；**仅授权** |
| **非标端口 / 灰度域名** | 未套 CDN 的 admin/api-test 子域 |
| **协议换路** | WebSocket/gRPC 若边缘规则只拦 HTTP API（见 web-attack-methods） |
| **代理池 + 降速** | 纯 IP 信誉问题；**不能替代** TLS 伪装 |
| 系统 `curl --http2` | 仍可能是非 Chrome JA3；优先 curl_cffi |

sqlmap/nuclei/ffuf：若边缘只认浏览器 TLS，可：

- 用 curl_cffi 确认入口真实可达后，再决定是否值得上扫描器  
- sqlmap：`--proxy` + 自定义 header；或改用 curl_cffi 手测注入差分  
- 扫描器打在 **源站**（若授权且已找到）而非边缘  

---

### 6) Cloudflare 常见响应怎么处理

```
403/503 + cf-ray + 短 HTML
  → 先 curl_cffi chrome；仍 challenge → 浏览器过挑战取 Cookie

429
  → 降并发 + 代理换路（proxy-tool-bootstrap）；保留 curl_cffi

200 但正文是挑战页
  → 不要当业务 JSON 解析；检测 title/关键字后再换浏览器链路

应用 JSON: {"code":401,"msg":"unauthorized"}
  → 已到应用层；按 API 鉴权/BOLA 测，不再当 CDN 问题
```

---

### 7) 与发现闭环的衔接

```
Surface: httpx 标注 cdn/tech；写 infra/cdn_*
Verify API:
  1) 浏览器或 curl_cffi 建立「可达基线」
  2) 再在同一客户端上做 BOLA/注入/越权
  3) 扫描器命中若仅在被拦客户端出现 → 标为无效线索
Negate: 「默认 python 被 CF 拦」不得写成「无 SSRF/无接口」
```

### 8) 触发器（强制）

- **触发-CDN1**：浏览器与脚本结果不一致 → 加载本 skill，改用 `curl_cffi` 复测后再下结论  
- **触发-CDN2**：见 `server: cloudflare` / `cf-ray` → 接口测试默认走浏览器 TLS 伪装客户端  
- **触发-CDN3**：curl_cffi 仍 challenge → 浏览器 Cookie 复用或源站/协议换路；禁止无脑加大 nuclei 线程  

---

### 9) 参考

- curl_cffi / curl-impersonate（浏览器 TLS 伪装）  
- Cloudflare Bot Management / WAF 文档（概念：TLS fingerprinting）  
- 项目内：`proxy-tool-bootstrap`、`web-attack-methods` CDN 段、`api-security-testing`