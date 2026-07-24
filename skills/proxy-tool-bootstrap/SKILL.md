---
name: proxy-tool-bootstrap
description: >-
  自找代理+工具自举:SOCKS5/HTTP/Tor换路;Cloudflare等TLS指纹优先curl_cffi;工具Python自举;OOB。
  Use when blocked by 403/429/WAF/CDN/Cloudflare/TLS fingerprint/timeout, missing tools, or needing OOB.
tags: [渗透测试, penetration-testing, 红队]
---

## 自找代理 + 工具自举（被拦换路，没工具自己写）

```
🔴被拦时先分流(不要无脑只换代理):
  A. 浏览器能访问、python-requests/curl/httpx/sqlmap 不能
     → 优先 TLS/JA3 指纹或 Bot 管理，不是 IP 问题
     → 加载 skill `cdn-tls-fingerprint`，用 curl_cffi impersonate=chrome 复测
  B. 所有客户端都 403/429 且像限流
     → 再走下方代理换路 + 降速
  C. 稳定路径型 502 / 规则页
     → web-attack-methods CDN 段（路径/协议/源站），代理未必有用

🔴TLS/浏览器伪装(Cloudflare/Akamai 等接口测试高频):
  pip/install-python-package: curl_cffi
  python:
    from curl_cffi import requests
    s = requests.Session(impersonate="chrome")  # 或 chrome120/safari 等库支持值
    r = s.get(URL, headers={...}, timeout=30)
  仍 Challenge → 浏览器过验证导出 cf_clearance 等 Cookie 再注入 Session
  详情与 BOLA 基线纪律 → skill `cdn-tls-fingerprint`

🔴代理(IP信誉/限流/地区限制 → 换路。不换路=放弃=违反黑板触发器2):
  执行序列(按顺序,前一步失败才下一步):
  ①探目标地区: terminal: curl -s "http://ip-api.com/json/{目标IP}" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['country'],d['countryCode'])"
  ②获取该地区SOCKS5代理: terminal: curl -s "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&country={countryCode}&timeout=5000" | head -20
  ③验证代理可达目标: terminal: curl --socks5 {PROXY_IP:PORT} --connect-timeout 8 -s -o /dev/null -w "%{http_code}" {目标URL}
  ④200=可用,立即用此代理重新执行被拦请求; 非200=换下一个代理重复③
  ⑤全部SOCKS5失败→获取HTTP代理: terminal: curl -s "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&country={countryCode}&timeout=5000" | head -20
  ⑥HTTP代理验证: terminal: curl --proxy http://{PROXY_IP:PORT} --connect-timeout 8 -s -o /dev/null -w "%{http_code}" {目标URL}
  ⑦全代理失败→Tor: terminal: curl --socks5 127.0.0.1:9050 --connect-timeout 15 {目标URL}
  工具统一加代理参数: curl --socks5 / sqlmap --proxy=socks5://{P} / nmap --proxies socks5://{P} / nuclei -proxy socks5://{P} / ffuf -x socks5://{P}
  curl_cffi 代理: Session.get(..., proxies={"http":"socks5://...","https":"socks5://..."})
  轮换策略: 429/403→换代理,每20请求主动换 | Cloudflare→代理池+间隔2-5s随机 + 保持 curl_cffi 指纹
  🚨HTTP代理vs SOCKS5: HTTP代理会插入自己的错误页→探测优先 SOCKS5
工具自举(which X || 用Python实现):
  无nmap→socket扫端口 | 无ffuf→curl_cffi/requests爆目录 | 无sqlmap→手工payload | 无浏览器TLS→curl_cffi
  复杂工具用Python模拟:爬虫 curl_cffi/bs4 / 编码base64/hex / 哈希hashlib
字典自生成: 基于目标域名/公司名造变体 | 从网页提关键词 | 用户名+年份+特殊字符组合 | 服务默认凭据
OOB基础设施: MCP `interactsh-client` | `dnslog` | VPS nc | ngrok/cloudflared 隧道
  → 看到OOB回连才算确认 → 写Fact
```

