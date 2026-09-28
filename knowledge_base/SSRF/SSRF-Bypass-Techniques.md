# SSRF 过滤绕过与现代手法

> 上游 `README.md` 覆盖判定与验证基线。本篇只讲**绕过**：当目标存在局部 SSRF 防护（黑名单、白名单、仅允许 https、解析器不一致）时如何继续验证，以及每一步的可证伪信号。

## 判定纪律

先确认"是不是 SSRF"，再谈绕过。绕过失败不代表不存在漏洞，绕过成功也不代表可打内网 —— 必须以**服务端真实出流量**为证据。

## 一、URL 解析差异（最高命中率）

过滤器与请求库用两个不同解析器时，对同一字符串得出不同 host。这属于 `Parser-Confusion-Bypass` 的子类。

| 目标解析 | 绕过字符串示例 | 说明 |
|---|---|---|
| 允许 `*.trusted.com` | `https://trusted.com@evil.com` | 过滤器读 userinfo 前段，请求库读真实 host |
| 同上 | `https://evil.com#@trusted.com` | `#` 之后对某些解析器为 fragment |
| 同上 | `https://evil.com?@trusted.com` | 同上 |
| 同上 | `https://trusted.com.evil.com` | 只看后缀的弱校验 |
| 同上 | `https://trusted.com%2eevil.com` | 解码顺序不一致 |
| 回环校验 | `http://127.1/`、`http://0177.0.0.1/`、`http://2130706433/`、`http://[::ffff:127.0.0.1]/`、`http://0x7f000001/` | IP 表示法 |
| 回环校验 | `http://[::1]`、`http://①②⑦...`（部分库会做 best-fit 归一化） | IPv6 / Unicode 归一化 |
| 协议校验 | `http://evil.com:80\@trusted.com`、反斜杠变体 | WHATWG 与 RFC 3986 分歧 |
| 重定向白名单 | `https://trusted.com/redirect?u=http://169.254.169.254/...` | 跟随跳转时未复检 |

IPv6 多 `@` 的 userinfo 解析差异曾导致 Google Cloud OAuth 回环白名单绕过（授权码窃取）。同一手法对 SSRF 校验器同样适用。

## 二、重定向与状态机

- 302/307 到内网，且客户端 `allow_redirects=True` 且不做二次校验。
- **重定向循环泄漏**：构造 A→B→A 循环，配合非典型 3xx 码（如 305/306/308 混用），可让应用进入错误态并把完整跳转链和最终 200 响应体回显出来（Assetnote 2025）。这是"盲 SSRF 变可见"的高价值手法。
- 跳转协议降级：`https` 校验通过后跳到 `http`、`file`、`gopher`、`dict`、`ldap`。

## 三、DNS 相关

- **DNS Rebinding**：短 TTL 域名首次解析为公网 IP 通过校验，第二次解析为 `127.0.0.1`/内网。需控制权威 DNS + TTL 0。A/AAAA 双记录可提高成功率。
- **通配 DNS 回环**：`*.nip.io`、`*.sslip.io`、`localtest.me`、`127.0.0.1.nip.io`。
- **TOCTOU**：校验用一次 DNS 解析，出请求用另一次。

## 四、协议与载荷

- `gopher://`：可构造任意 TCP 字节流（Redis、Memcached、FastCGI、SMTP）。
- `file://`、`dict://`、`ldap://`、`tftp://`、`netdoc://`（Java）、`jar://`。
- 云元数据需带特殊 Header：AWS IMDSv2 需 PUT 拿 token，可尝试 `gopher` 或让目标自身代理；GCP 需 `Metadata-Flavor: Google`；Azure 需 `Metadata: true`（见 `Cloud-Metadata-Access.md`）。

## 五、盲 SSRF 的可见化

1. 时间差：内网开放端口 vs 关闭端口的响应时间。
2. 错误差异：连接失败、TLS 错误、HTTP 状态差异。
3. OOB 带外：DNS/HTTP 到自控域名（Interactsh、dnslog）。
4. 重定向循环错误态回显（见上）。
5. 把 SSRF 转成"读文件/写配置"，再用第二漏洞取数。

## 验证（最小证据）

1. 受控输入成为服务端请求（参数 → 服务端 fetch）。
2. 证据三选一：带外 DNS/HTTP 命中 **或** 内网/元数据真实内容片段 **或** 稳定可复现的时间/错误差分。
3. 说明影响范围：命中的网络区域、可读数据、能否写/打内部协议。

## 常见误报

- 前端 JS 直接 fetch → 那是浏览器发起，不是 SSRF。
- 目标返回 403/连接拒绝是**服务端出网成功**的信号，不等于漏洞不可用。
- 单纯回显了输入 URL，但并未发起请求。
- WAF 拦截页 mimicking 内网响应。
- 出网被 egress 白名单挡住 → 记 `blocked_egress`，不要记 `not vulnerable`。

## 修复

- 解析 URL 后取 host，**再做 DNS 解析**并对解析结果做内网/保留地址判定（IPv4+IPv6+IPv4-mapped），校验与请求之间使用同一 IP（pin IP）。
- 出网默认拒绝，按域名白名单放行；禁止跟随重定向或对每跳复检。
- 禁用非 HTTP 协议；元数据服务启用 IMDSv2 并限制 hop limit。
- 不要把"校验字符串"当成"校验目标"。

## 工具

- `interactsh-client`、`dnslog`；`execute-python-script` + httpx 做精细时序对比；`nuclei` 仅作线索。

## 参考

- OWASP SSRF、PortSwigger SSRF、HackTricks SSRF
- Assetnote：Novel SSRF Technique Involving HTTP Redirect Loops（2025）
- Google Cloud URL Parsing Confusion 账号接管（2025）
