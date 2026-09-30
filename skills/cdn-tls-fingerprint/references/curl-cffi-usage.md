# curl_cffi 安装与同状态请求示例

原文的安装、脚本和失败诊断完整保留如下。安装门槛的两种表述应结合入口 S0–S3：先完成受控差分与状态对齐，S3 仅发送一个诊断请求；确认后才用于受影响的结论性请求。

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
