# CDN / Cloudflare 与 TLS 指纹（接口测试）

> 当目标前有 Cloudflare、Akamai、Fastly、网宿等 CDN/WAF 时，**非浏览器 TLS 指纹**（Python `requests`、默认 `urllib`、部分 `curl`/`httpx`、大量扫描器）可能在边缘被拦截，表现为 403/503/挑战页/空响应，而真实浏览器或 **curl_cffi 浏览器伪装** 可正常访问 API。

## Summary

* 边缘拦截 ≠ 业务鉴权失败  
* 只改 User-Agent 通常无效，需要 **TLS(JA3/JA4) + HTTP/2** 级伪装  
* 接口/BOLA 测试基线客户端：优先 **curl_cffi**（`impersonate="chrome"`）  
* 强 JS Challenge：浏览器/Playwright 过挑战 → Cookie 注入 curl_cffi  
* 可选：找源站 IP 直连（仅授权）、代理降速、WebSocket 等协议换路  

## Detection

| 观察 | 判断 |
|------|------|
| `server: cloudflare`、`cf-ray` | CF 边缘 |
| 浏览器 200，python/curl 403 | TLS/Bot 指纹嫌疑 |
| 正文 Challenge / Turnstile | 需浏览器侧通过 |
| 稳定 502 + 路径相关 | 规则过滤（非指纹）见 Web/CDN 手法 |

## curl_cffi 最小示例

```python
from curl_cffi import requests
s = requests.Session(impersonate="chrome")
r = s.get("https://target/api/...", headers={"Accept": "application/json"}, timeout=30)
# 状态码与业务 JSON 才可作为后续 BOLA/注入的基线
```

安装：`pip install curl_cffi` 或 CyberStrike `install-python-package`。

## Verification discipline

1. 先建立「可达基线」（curl_cffi 或浏览器）  
2. 同一客户端上做安全测试  
3. 仅被拦截客户端上的失败 **不得** 记为「接口不存在」  
4. 落库区分 `edge_block` vs 应用层 401/403  

## Tools mapping (CyberStrikeAI)

* `install-python-package` + `execute-python-script`（curl_cffi）  
* `exec`、浏览器/`analyze_image`（挑战页识别，可选）  
* `interactsh-client`（OOB 与指纹问题独立）  
* Skill：`cdn-tls-fingerprint`、`proxy-tool-bootstrap`、`api-security-testing`  

## References

* [lexiforest/curl_cffi](https://github.com/lexiforest/curl_cffi)  
* curl-impersonate / JA3 fingerprinting 概念  
* 项目 skill：`skills/cdn-tls-fingerprint/SKILL.md`