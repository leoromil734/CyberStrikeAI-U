# CDN / Cloudflare 与 TLS 客户端指纹诊断

CDN/WAF 可能根据 TLS JA3/JA4、HTTP/2、Cookie、行为和 IP 信誉拦截请求，但 **CDN 存在不等于 TLS 指纹拦截**。

## 关键判断

- `server: cloudflare`、`cf-ray`：只证明请求经过 Cloudflare。
- 单次 403/429/503：可能是应用拒绝、限流、挑战或 IP 信誉。
- 浏览器成功、脚本失败：只是客户端差分线索，必须先对齐请求状态。
- 相同 URL、方法、认证、Cookie、Header、请求体、出口和速率下，仅改变客户端栈，`curl_cffi` 到业务层而标准客户端仍停在边缘：才确认 TLS/HTTP2 客户端指纹拦截。

## 诊断顺序

1. 标准客户端低速重试，记录状态码、边缘头和正文标记。
2. 同网络出口用真实浏览器复测。
3. 对齐 Cookie、Authorization、CSRF、方法、请求体和重定向。
4. 排除 JS Challenge、验证码、限流、IP/地区和应用层 401/403。
5. 仍有稳定差分时，只发一个 `curl_cffi` 诊断请求。
6. 只有诊断确认后，才在后续受影响请求中复用 `curl_cffi.Session`。

## 结论分类

- `tls_fingerprint_confirmed`：唯一改变客户端栈后到达业务层。
- `cookie_or_js_challenge`：获得 Cookie 或执行 JS 后才成功，应使用浏览器流程。
- `rate_or_ip_block`：降速或换出口后恢复。
- `application_denial`：各客户端都到达同一业务 401/403。
- `inconclusive`：变量未对齐或结果不稳定。

## 确认后的最小示例

```python
from curl_cffi import requests

session = requests.Session(impersonate="chrome")
response = session.get(
    "https://target/api/...",
    headers={"Accept": "application/json"},
    timeout=30,
    allow_redirects=False,
)
print(response.status_code, response.headers.get("cf-ray"), response.text[:500])
```

安装：`pip install curl_cffi` 或 CyberStrikeAI 的 `install-python-package`。未确认时不要安装，不要用于普通探活、目录扫描或常规 API 请求。

## 验证纪律

1. 标准工具优先：资产探活继续用 `httpx`，路径发现继续用 `ffuf`/`dirsearch`。
2. `curl_cffi` 只替换已确认受客户端指纹影响的结论性请求。
3. 边缘失败不得直接记为“接口不存在”，CDN 标记也不得直接记为“TLS 指纹拦截”。
4. 落库必须包含测试矩阵，并区分 `edge_block`、`app_403`、`auth_fail` 和真实漏洞证据。

## 关联

- Skill：`cdn-tls-fingerprint`、`proxy-tool-bootstrap`、`api-security-testing`
- 工具：`httpx`、`install-python-package`、`execute-python-script`
- 参考：[curl_cffi](https://github.com/lexiforest/curl_cffi)