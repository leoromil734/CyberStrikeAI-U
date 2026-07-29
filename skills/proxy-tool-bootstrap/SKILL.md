---
name: proxy-tool-bootstrap
description: >-
  在专用工具缺失、网络代理故障或已确认边缘层差异时选择可审计的替代执行路径。
  普通 403/429/超时不自动触发；先归因 Cookie、JS、限流、IP、路径与客户端差异。
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 自找代理 + 工具自举（被拦换路，没工具自己写）

```
🔴被拦时先分流（不要无脑换代理或安装 curl_cffi）:
  A. 仅看到 CDN/cf-ray 或单次 403
     → 继续标准客户端低速基线；这些信号不能证明 TLS 指纹拦截
  B. 标准客户端持续停在边缘、同条件浏览器到业务层
     → 对齐 Cookie/认证/方法/请求体/重定向，排除 JS Challenge、限流和 IP
     → 仍有差分才加载 `cdn-tls-fingerprint`，只发 1 个 curl_cffi 诊断请求
  C. 所有客户端都 403/429 且像限流
     → 走下方代理换路 + 降速，不安装 curl_cffi
  D. 稳定路径型 502 / 规则页
     → web-attack-methods CDN 段（路径/协议/源站），代理和 TLS 客户端未必有用

🔴TLS/浏览器伪装（仅确认后）:
  确认标准: 相同请求条件下，curl_cffi 到业务层而标准客户端仍停在边缘
  确认后才 pip/install-python-package: curl_cffi，并仅替换受影响请求
  python:
    from curl_cffi import requests
    s = requests.Session(impersonate="chrome")
    r = s.get(URL, headers={...}, timeout=30)
  curl_cffi 仍 Challenge → 未确认 TLS 指纹；改用浏览器挑战流程，不要轮换 impersonate 猜测
  详情 → skill `cdn-tls-fingerprint`

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
  轮换策略: 429/403→先降速再换代理,每20请求主动换 | 已确认 TLS 指纹时才保持 curl_cffi Session
  🚨HTTP代理vs SOCKS5: HTTP代理会插入自己的错误页→探测优先 SOCKS5
工具自举(which X || 用Python实现):
  无nmap→socket扫端口 | 无ffuf→标准 requests 小规模目录探测 | 无sqlmap→手工payload | 已确认无浏览器TLS能力且存在指纹拦截→curl_cffi
  复杂工具用Python模拟:爬虫 requests/bs4（确认 TLS 指纹后才换 curl_cffi） / 编码base64/hex / 哈希hashlib
字典自生成: 基于目标域名/公司名造变体 | 从网页提关键词 | 用户名+年份+特殊字符组合 | 服务默认凭据
OOB基础设施: MCP `interactsh-client` | `dnslog` | VPS nc | ngrok/cloudflared 隧道
  → 看到OOB回连才算确认 → 写Fact
```

