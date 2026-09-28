# API 网关与服务网格

> 网关（API Gateway / Ingress / 反向代理）与服务网格（Istio、Linkerd、Consul Connect）是**鉴权与流量的集中执行点**，因此也是"绕过一次就绕过全部"的高价值目标。本域关注四件事：绕过网关的校验、攻破网关自身、滥用网格内部的默认信任、以及协议层差异。

## 一、链路上的位置

```text
客户端
  ↓
CDN / WAF
  ↓
API 网关 / Ingress（路径重写、鉴权插件、限流、CORS、JWT 校验）
  ↓
服务网格入口（Gateway / ztunnel / sidecar）
  ↓  （mTLS、AuthorizationPolicy）
业务服务 A ──微服务调用──> 业务服务 B（同一网格，默认常为 allow-all）
  ↓
数据层
```

**关键判据**：任何一次请求都会经过多个组件，每个组件都在**自己的解析结果**上做安全决策。只要两个组件对同一请求的理解不同（路径、头、方法、协议），校验就可能被跳过 —— 这与 `../WAF-Bypass/Parser-Confusion-Bypass.md` 是同一类问题。

## 二、四类攻击面

| 类别 | 核心问题 | 文档 |
|---|---|---|
| 绕过网关校验 | 路径/路由歧义、头信任链、认证插件缺口、JWT fail-open | `Gateway-Auth-Bypass.md` |
| 网关自身被攻破 | 管理面（Admin API/Actuator）、默认凭据、插件与表达式注入 | `Gateway-Product-Hardening.md` |
| 网格内部信任滥用 | 默认 allow-all、PERMISSIVE mTLS、XFCC 信任、sidecar 绕过、xDS/调试面 | `Mesh-Internal-Trust-Abuse.md` |
| 协议层差异 | HTTP/2 降级、gRPC、WebSocket/SSE、hop-by-hop、chunked | `gRPC-and-Protocol-Bypass.md` |

## 三、判定纪律

1. **确认边界在哪一层**：先用一个"应该被拒绝"的请求验证网关是否生效（例如未带 token 访问 `/admin`），再构造变体。不要假设"有网关就等于有鉴权"。
2. **成对证据**：被拦版本 + 绕过版本，两者要能说明差异变量（路径编码？头？方法？协议？）。
3. **区分"到不了后端"与"被后端正确拒绝"**：用响应指纹（后端错误页、trace id、耗时）判断请求是否真的到达业务层。网关的 `403` 与业务的 `403` 含义不同。
4. **不要只看状态码**：绕过的判据是**拿到受保护数据或执行了受保护动作**。
5. **多租户/多集群场景**要记录你所在的租户与命名空间，避免误判为跨租户问题。

## 四、高价值目标清单（评估时优先看）

- 网关的路由清单：`/actuator/gateway/routes`、Kong Admin `/routes`、Traefik `/api/rawdata`、Envoy Admin `/config_dump`、Istiod `/debug/`。
- 认证插件的**作用范围**：哪些路由挂载了、哪些没挂（尤其新加的、内部使用的、`/health`、`/metrics`、`/debug`）。
- JWT/JWKS 配置：是否 `fail-open`、是否校验 `aud`/`iss`、`jwksUri` 是否可被接管（见 `../Authentication-Bypass/OAuth-OIDC-Attacks.md`）。
- 网格的授权策略：是否存在 `AuthorizationPolicy`（没有 = 默认 allow-all）。
- 网格的入口身份：`PERMISSIVE` vs `STRICT`。
- 出网策略：网格是否有 `REGISTRY_ONLY`/egress 限制（没有 → SSRF 可直接出网，见 `../SSRF/SSRF-Bypass-Techniques.md`）。

## 五、验证（最小证据）

1. 请求原文（含协议版本、路径原文、关键头）与响应原文。
2. 说明"网关看到什么、后端看到什么"（可用差异响应、后端错误特征、trace id、日志比对来佐证）。
3. 影响证据：他人数据、管理员动作、跨命名空间/跨租户访问。
4. 若只证明"网关配置不一致"而无法落地影响，降级为配置缺陷并说明原因。

## 六、常见误报

- 网关返回 403，但后端本身也有校验（双重防护，不算绕过成功）。
- 路径变体返回 200，实际是 SPA 的 `index.html`。
- 只观测到缓存命中的响应（加 cache-buster 后差异消失）。
- 用管理员 token 测试"未授权访问"。
- 网格内 Permission Denied 被当作"服务不存在"。

## 七、修复要点（总纲）

- **单一信任点**：鉴权只在最靠近业务的位置做最终判定，网关只做早期拒绝（纵深而非唯一防线）。
- **规范化一致性**：网关与后端使用同一路径规范化实现与同一 HTTP 解析实现。
- **头白名单**：网关剥离所有客户端提供的内部头（`X-Forwarded-*`、`X-User-*`、`X-Envoy-*`、`X-Forwarded-Client-Cert`），再由网关自己写入可信值。
- **默认拒绝**：网格启用 `STRICT` mTLS + 默认拒绝的 `AuthorizationPolicy`；出网默认拒绝。
- **管理面不外露**：Admin API/Actuator/调试端点只允许运维网段访问，且需要认证。
- **配置即代码 + 审计**：网关与网格配置纳入代码评审与变更审计（配置错误是最常见的根因）。

## 八、参考

- RFC 9110 §7.6.1（Connection 与 hop-by-hop 字段）、RFC 9113（HTTP/2）
- Istio：Authentication / Authorization 文档；Envoy：admin、路由与 `path_with_escaped_slashes_action`
- PortSwigger：HTTP/1.1 must die（2025）、Astro framework and standards weaponization（2025，转发头滥用导致 SSRF/缓存投毒）
- Skill：`api-security-testing`、`cloud-attack-methods`、`proxy-tool-bootstrap`
