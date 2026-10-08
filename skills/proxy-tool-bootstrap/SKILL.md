---
name: proxy-tool-bootstrap
description: >-
  在专用工具缺失、网络代理故障或已确认边缘层差异时选择可审计的替代执行路径。
  普通 403/429/超时不自动触发；先归因 Cookie、JS、限流、IP、路径与客户端差异。
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 项目共享住宅代理（优先路径）

已挂载 `web-search` 时，优先使用 `proxy_status` → `proxy_get`。`proxy_get` 创建当前任务的独立粘性出口，返回 `lease_id`、本地 HTTP CONNECT 代理 URL 与环境变量；它不返回住宅代理用户名/密码，也不修改系统或模型 API 的全局网络路径。其他 Agent 不应复用你的 `lease_id`。

- `exec` / `execute` / Python / curl / HTTPX / 浏览器等只给受影响请求或子进程传返回的代理地址。该地址只在 MCP 所在主机或同一容器网络空间可用，远程 MCP 应在远端部署服务，不把监听地址暴露为 `0.0.0.0`。
- HTTP(S) 与 SOCKS5/SOCKS5h 上游由共享配置决定；Agent 始终拿到本地 HTTP CONNECT 入口，不能把它当作 SOCKS5 端口。HTTPX 用显式 `proxy` 参数；curl 用 `--proxy`（或小写 `http_proxy`/`https_proxy`）。
- 确认连接/出口故障后才 `proxy_rotate(lease_id, country)` 换 sid/国家；会断开本租约旧连接，随后新建客户端连接。登录/验证码/Cookie 会话需要粘性出口，不随每次请求轮换。
- 401 为站点认证问题；407/597为代理凭据问题；**目标请求 429 先遵守 `Retry-After`/降速，确认是出口 IP 被目标/WAF 速率封禁且测试需继续时，可换出口对受影响请求限次重试并记录次数与出口**（公开搜索来源仍不轮换）；403/验证码/JS挑战先检查认证、地区与浏览器需求，不据此无限换 IP。
- `proxy_healthcheck` 经代理访问公开 IP 检测接口，可能消耗少量代理流量。请求的国家不是已验证的地理位置，换 sid 也不保证提供商每次分配不同 IP。
- 用完 `proxy_release`；空闲租约自动过期。代理不应携带平台/模型API密钥、客户资料或内网敏感流量；遵守授权范围与来源条款。

## 自找代理 + 工具自举（共享服务不可用时的显式替代路径）

仅当项目共享代理未配置或有明确故障证据，且任务允许该替代网络时，才考虑下面旧式路径。公共免费代理不可信，不发送账号密码、Cookie、密钥或敏感数据；不能自动作为全局代理。

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

🔴代理（仅在共享代理不可用且已有网络归因证据时采用替代路径）:
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
  轮换策略: 只在确认出口连接故障时有限轮换；429先等待/降速，403先归因认证/地区/验证码。认证会话不按请求数量自动换出口。
  🚨HTTP代理vs SOCKS5: HTTP代理会插入自己的错误页→探测优先 SOCKS5
工具自举(which X || 用Python实现):
  无nmap→socket扫端口 | 无ffuf→标准 requests 小规模目录探测 | 无sqlmap→手工payload | 已确认无浏览器TLS能力且存在指纹拦截→curl_cffi
  复杂工具用Python模拟:爬虫 requests/bs4（确认 TLS 指纹后才换 curl_cffi） / 编码base64/hex / 哈希hashlib
字典自生成: 基于目标域名/公司名造变体 | 从网页提关键词 | 用户名+年份+特殊字符组合 | 服务默认凭据
OOB基础设施: MCP `interactsh-client` | `dnslog` | VPS nc | ngrok/cloudflared 隧道
  → 看到OOB回连才算确认 → 写Fact
```

