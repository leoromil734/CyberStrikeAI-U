# HTTP 请求走私（Desync）

> 请求走私 = 让前端与后端对"请求在哪里结束"得出不同结论，从而把自己构造的字节**拼到别人的请求前面**。2025 年《HTTP/1.1 must die》证明这一族远未被修完。

## 四种长度语义

```text
CL  = Content-Length
TE  = Transfer-Encoding: chunked
0   = 隐式零长度（没有长度头，或头不可见）
H2  = HTTP/2 自带长度（降级时丢失）
```

组合出的经典变体：`CL.TE`、`TE.CL`、`TE.TE`、`CL.0`、`H2.CL`、`H2.TE`、`H2.0`。

## 一、现代探测策略（推荐）

不要一上来就打 `CL.TE`。先用**解析分歧探测**：

```http
GET / HTTP/1.1
Host: target.example
Xost: target.example
Host: target.example
Xost: target.example
```

- 若"部分隐藏的 Host"触发了与正常 Host 不同的响应 → 链路中存在解析分歧。
- 判定方向：
  - **V-H**（前端可见、后端隐藏）：前端正常处理，后端看不到该头。
  - **H-V**（前端隐藏、后端可见）：前端不认，后端认。
- 具体状态码不重要，**"不同"才重要**。用工具：Burp 扩展 HTTP Request Smuggler v3（基于 Content-Length 分歧探测）。

## 二、把分歧变成武器

### CL.0（优先，最不易被 WAF 拦）

前提：后端（或中间层）忽略 `Content-Length`。对静态资源路径发送带 body 的 GET：

```http
GET /style.css HTTP/1.1
Host: target.example
Foo: bar
 Content-Length: 23        ← 注意前导空格，隐藏于后端

GET /404 HTTP/1.1
X: y
```

- 若 `GET /style.css` 被拒（拒绝带 body 的 GET），把方法换成 `OPTIONS`。

### 0.CL 与 double-desync（2025 新）

`0.CL` 过去被认为不可利用（会死锁），突破点是找到 **early-response gadget**（后端在不读完 body 时先响应）：

- nginx：静态文件早响应。
- IIS：请求保留设备名即可触发异常并保持连接：`/con`、`/nul`、`/aux`、`/prn`、`/com1`。
- 服务器级重定向也可作为 gadget。
- 得到 `0.CL` 之后，用**两次请求**把它转成 `CL.0`（double-desync），再用传统手法投毒受害者请求：

```http
POST /nul HTTP/1.1
Host: target.example
Content-length:
 163

POST / HTTP/1.1
Content-Length: 111

GET / HTTP/1.1
Host: target.example

GET /wrtz HTTP/1.1
Foo: bar
```

要点：前端会追加头，所以把注入点放在**头块开头**（前端追加头通常在末尾），并用 `0cl-find-offset.py`（Turbo Intruder）测算偏移。

### Expect 相关（2025 新）

`Expect: 100-continue` 把请求变成两阶段，是复杂度炸弹：

- 前端不认识/不转发 `Expect`，后端认识 → 长度语义分歧。
- 混淆写法（大小写、多余空白、多值）在部分 CDN 上产生 `0.CL`/`CL.0`（Netlify、Akamai、GitLab、T-Mobile 案例）。
- 也用于绕过"响应头移除"类防护。

### chunk 扩展与终止符歧义（TE.TE 新变体）

- 忽略 chunk 扩展导致的终止符歧义（`EXT.TERM`，w4ke 2025）。
- 超长 chunk 溢出行、trailer 段落换行处理不一致（Funky chunks 续篇，2025-10）。

### H2 降级（H2.TE / H2.CL / H2.0）

- 前端收 H2，转发到后端时降级为 H1 → 第四种长度语义 `H2`。
- 案例：某 CDN 的 H2.0 desync 使攻击者重定向**任意**站点用户（影响 2400 万站点，2025，Cloudflare Pingora 修复）。
- H2 特性滥用：`Transfer-Encoding` 在 H2 中非法但被某些代理保留；`content-length` 重复；伪头顺序。

## 三、利用方式（确认后的取向）

1. **绕过前端 ACL**：把 `GET /admin` 放在前缀里，前端只看到无害路径。
2. **请求劫持/凭据窃取**：让受害者请求带上攻击者前缀，或让受害者请求落入攻击者会话。
3. **缓存投毒**：把恶意响应写进 CDN 缓存（配合 `Cache-Poisoning-Deception.md`）。
4. **响应队列污染**：让一个用户的响应被另一个用户收到（需精确配对）。
5. **C2 隐蔽通道**：用 `CL.0` 污染 3xx 缓存的 `Location` 做回连（2025）。

## 四、验证（最小证据）

1. 探测阶段：给出歧义输入与"正常/异常"两次响应差异。
2. 武器化阶段：给出跨用户影响的证据（受害者视角的响应内容变化），或清晰地证明后端执行了隐藏的请求行。
3. 序列必须**完整可重放**（含 keep-alive、连接复用、必要的延时）。
4. 说明软件栈（前端/后端/是否 H2 降级），并标注是否依赖"响应头被移除"等附加条件。

## 五、常见误报

- 单请求异常（400）但没有跨用户影响 → 记"解析不一致"而非走私。
- 差异来自 CDN 缓存（加 cache-buster 后消失）→ 那可能是缓存本身的问题。
- 只在前端与后端**不共享连接池**时复现 → 影响有限。
- 依赖特定并发与时间的偶发现象，无法稳定复现 → 标注置信度。

## 六、修复

- 上游连接改用 HTTP/2+（从边缘到源站都不要 H1）；这是唯一根治方向。
- 拒绝歧义请求：同时存在 CL 与 TE、非法/混淆头名、chunk 扩展异常、裸 LF 作为头终止。
- 前端与后端使用同一 HTTP 解析实现与严格模式。
- AWS ALB 用户：`routing.http.desync_mitigation_mode=strictest`、`routing.http.drop_invalid_header_fields.enabled=true`（AWS 已知 ALB+IIS 的 H-V 分歧但选择不修）。
- 不要在前端做安全判断（WAF 只作为额外层）。

## 七、工具

- Burp HTTP Request Smuggler v3、Turbo Intruder（`0cl-find-offset.py`、单包攻击脚本）。
- CyberStrikeAI：`execute-python-script` + 原始 socket 精确控制字节流（推荐用单包/多连接精确时序）。

## 参考

- PortSwigger：HTTP/1.1 must die: the desync endgame（2025）、HTTP Desync Attacks（2019）、HTTP/2（2021）
- w4ke：Funky chunks + addendum（2025）
- Assured：The Single-Packet Shovel（2025）
- Cloudflare Pingora 请求走私事后分析（2025）
