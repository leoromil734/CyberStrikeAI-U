# 绕过网关鉴权（Gateway Auth Bypass）

> 网关的鉴权通常基于**它自己解析出来的路径、方法与头**。只要能构造出"网关看到 A、后端看到 B"的请求，就能跳过校验。

## 一、路径与路由歧义

| 手法 | 原理 |
|---|---|
| 大小写与尾点 | 网关前缀匹配区分大小写，后端路由不区分（`/Admin` vs `/admin`） |
| 冗余斜杠 | `//admin`、`/admin//`，nginx `merge_slashes` 默认 on 但 Envoy/其他实现不同 |
| 点段穿越 | `/public/../admin`、`/./admin`、`/%2e%2e/admin` |
| 编码差异 | `/%2fadmin`、`/admin%2f`、双重编码 `/%252e%252e/` |
| 分隔符 | `;/admin`、`/admin;foo=bar`、`/admin.`、`/admin%20`、`/admin%09` |
| 反斜杠 | `\\admin`（Windows/IIS/部分框架视作 `/`） |
| 扩展名推断 | `/admin.json`、`/admin.html`（Ruby/Rails 等按格式路由） |
| 后缀路径参数 | `/admin/index.php`、`/admin.php/nonexistent`（PathInfo） |
| 前缀白名单 | 网关允许 `/api/public`，后端把 `/api/public/../admin` 解析为 `/api/admin` |
| Unicode 归一化 | 全角斜杠/相似字符在 best-fit 后变成 `/`（见 `../WAF-Bypass/Encoding-and-Obfuscation.md`） |

**检测方法**：对同一个受保护路径，生成变体矩阵（大小写/斜杠/编码/后缀/方法），记录"网关判定"与"后端响应"的差异。响应长度、错误页模板、trace id 都能帮助判断请求是否到达后端。

关键配置差异（评估时值得确认，而不必猜）：

- Envoy：`normalize_path`、`merge_slashes`、`path_with_escaped_slashes_action`（是否解码 `%2F`）。
- nginx：`merge_slashes`、`proxy_pass` 尾斜杠影响路径拼接。
- Istio：`normalize_path`（VirtualService/EnvoyFilter）。
- Spring Cloud Gateway / Kong / APISIX 的路由匹配优先级（prefix vs exact vs regex）。

## 二、头信任链（Header Trust）

网关应**剥离**客户端提供的内部头并写入自己的可信值。常见缺陷：

```http
X-Forwarded-For: 127.0.0.1        # 内网信任判定被伪造
X-Forwarded-Host: attacker.com    # 生成绝对 URL/缓存键
X-Forwarded-Proto: https
X-Original-URL: /admin            # 前端校验看到安全路径，后端处理管理路径
X-Rewrite-URL: /admin
X-User: admin                     # 自建网关常把身份放在自定义头里
X-Authenticated-User: admin
X-Envoy-*: ...                    # 网格内部头被外部伪造
X-Forwarded-Client-Cert: ...      # XFCC 身份头被伪造（见 Mesh-Internal-Trust-Abuse.md）
```

**Hop-by-hop 滥用（进阶）**：`Connection` 头可以"提名"其他字段为逐跳字段，要求中间件消费并删除。如果防护依赖"某个字段存在"（例如网关只在看到 `X-Forwarded-For` 时才注入可信值，或应用在字段缺失时 fail-open），把它提名掉即可改变下游行为。

```http
GET /admin HTTP/1.1
Host: target
X-Forwarded-For: 127.0.0.1
Connection: close, X-Forwarded-For
```

要点：这里的攻击效果不是"转发伪造值"，而是**让下游在字段缺失时走了失败的默认分支**。测试时按跳验证（哪一跳删除了它），并记录每一跳的响应差异。相关：RFC 9110 §7.6.1；HTTP/2 与 HTTP/3 禁止连接特定字段（仅 `TE: trailers`）。

## 三、认证插件与方法的缺口

- **路由级 vs 全局策略**：新增路由忘记挂 JWT/鉴权插件；内部路由（`/internal/*`、`/debug/*`、`/metrics`、`/health`）未受保护。
- **方法差异**：只保护 `GET/POST`，`PUT/PATCH/DELETE/OPTIONS/HEAD/TRACE` 绕过；`X-HTTP-Method-Override`/`_method` 覆写。
- **路径前缀混淆**：网关保护的 `/api/v1/*` 与后端实际接受的 `/api/v1`、`/api/v1/`、`/v1/*` 不一致（影子路由）。
- **协议升级**：WebSocket（`Upgrade: websocket`）与 gRPC-Web 常被网关的 HTTP 鉴权策略遗漏（见 `gRPC-and-Protocol-Bypass.md`）。
- **CORS 集中在网关**：`Access-Control-Allow-Origin` 反射 `Origin` + `Allow-Credentials: true` → 全网关范围跨域读。
- **限流 key 可伪造**：计数键取 `X-Forwarded-For`/`X-Api-Key`（见 `../API-GraphQL/Rate-Limit-Bypass.md`）。

## 四、JWT / 认证校验的 fail-open

Istio/Envoy 体系中最常见的误区：

- **`RequestAuthentication` 只做验签，不做拒绝**。没有配套 `AuthorizationPolicy` 时：无效 token 被拒，但**完全不带 token 的请求照样通过**。
- Envoy `jwt_authn`：`allow_missing_or_failed` / `allow_missing` 配置会让校验失败时继续转发。
- 未校验 `aud`/`iss`/`nonce`；`jwksUri` 指向可接管或可被 SSRF 到达的地址（JWKS 污染 → 可用自签密钥通过校验）。
- **不转发原 token**（`forwardOriginalToken` 未开）或反之重复注入，导致下游服务误判身份。
- Token 传递链：网关校验后，后端服务是否**再次**校验？若后端信任 `X-User` 之类由网关注入的头，则该头就是唯一的信任点，必须确保外部不可注入。

## 五、验证（最小证据）

1. 基准请求（应被拒绝）与绕过请求的完整原文 + 两种响应。
2. 证据表明**到达了后端**并返回了受保护内容（不是网关的通用 403 页面）。
3. 若使用编码/路径变体，说明变体的差异点，并验证"仅改变该变量"即可绕过。
4. 若只得到"网关与后端路径处理不一致"的结论，标注为配置缺陷并说明无法落地。

## 六、常见误报

- 变体返回 200 但内容是 SPA 首页或通用错误页。
- 后端自身也做了鉴权（双重防线，不算绕过）。
- 302 到登录页被当作"绕过成功"。
- 缓存命中他人响应（属于缓存问题，另行定性）。
- 用管理员会话测试。

## 七、修复

- 网关与后端**共用同一路径规范化结果**；在规范化之后做路由与鉴权。
- 剥离客户端提供的所有内部/转发头（白名单方式），由网关写入可信值。
- 鉴权策略"默认拒绝"（Istio：`AuthorizationPolicy` 全命名空间默认 deny-all + 显式放行）。
- JWT：强制校验 `aud`/`iss`/`exp`，JWKS 固定且受控，禁止 `allow_missing` 类 fail-open。
- 覆盖所有方法与协议（含 WebSocket/gRPC/SSE），并对 `OPTIONS` 做显式策略。
- CORS 使用显式源白名单，禁止反射 `Origin` 与通配符 + 凭据组合。
- 变更管理：路由/策略变更纳入评审与审计，避免"新路由没挂插件"。

## 八、参考

- RFC 9110 §7.6.1（Connection / hop-by-hop）；Nathandavison：Abusing HTTP hop-by-hop request headers
- PortSwigger：HTTP/1.1 must die（2025，前端重写器绕过）；Astro framework and standards weaponization（2025，未校验转发头）
- HackTricks：403 & 401 Bypasses（路径/头变体清单）
