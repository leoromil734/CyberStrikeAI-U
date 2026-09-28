# 服务网格内部信任滥用

> 一旦进入网格内部（一个 Pod 的 shell、一个被攻破的工作负载），默认配置下的服务网格往往**允许任意服务调用任意服务**。这会把"一个 SSRF"变成"整套微服务的横向移动"。

## 一、先判断网格类型与模式

```bash
# 是否在网格内（sidecar）
ps aux | grep -i envoy | head                     # Istio sidecar / Envoy
ls /etc/istio/proxy                               # Istio sidecar 配置
cat /etc/istio/proxy/envoy-rev*.json 2>/dev/null | head -c 500
# 环境变量线索
env | grep -Ei 'istio|linkerd|consul|envoy|mesh'
# 端口线索
ss -tulnp | grep -E '15000|15001|15006|15020|15021|15090|4143|4191'
```

常见组合：

| 网格 | 代理 | 关键端口/路径 |
|---|---|---|
| Istio（sidecar） | Envoy | 15001（出向）、15006（入向）、15000（Envoy admin）、15020/15021（健康）、15090（Prometheus） |
| Istio（ambient） | ztunnel + waypoint | HBONE（15008） |
| Linkerd | linkerd2-proxy（Rust） | 4143（入向）、4191（admin，含 `/metrics`） |
| Consul Connect | Envoy | 21000 左右的动态端口、`consul` ACL |
| Cilium Service Mesh | eBPF + Envoy | 无 sidecar，策略在 eBPF |

## 二、默认信任的四个薄弱点

### 1. 默认 allow-all

没有 `AuthorizationPolicy`（Istio）/`ServerAuthorization`（Linkerd）/intention（Consul）时，网格内**任何**工作负载都能调用任何服务，包括数据库代理、管理接口、内部 API。

判定方法：从当前 Pod 直接调用另一个服务的 ClusterIP/DNS 名，看是否成功且返回数据。

```bash
curl -s http://other-service.other-ns.svc.cluster.local:8080/admin/users | head
```

### 2. PERMISSIVE mTLS

`PeerAuthentication` 为 `PERMISSIVE` 时，代理同时接受**明文**流量。后果：

- 从非网格位置（或被攻破的 Pod 直连旁路）可伪造"网格内"来源。
- 若授权策略基于 `principals`（SPIFFE 身份），明文请求没有身份 → 依赖策略写法，可能被宽松分支放行。

检查：

```bash
kubectl get peerauthentication -A            # 需要权限
# 或从流量侧观察：明文请求是否被接受
```

### 3. XFCC（`X-Forwarded-Client-Cert`）头信任

Envoy 会把对端证书信息写入 `X-Forwarded-Client-Cert`。如果**入口网关/前置代理没有剥离客户端提供的 XFCC**，攻击者可以直接构造该头伪造身份（`By=spiffe://cluster.local/ns/kube-system/sa/...`），下游若基于它做判定即被绕过。

测试点：在外部请求中加入 `X-Forwarded-Client-Cert`，观察是否被原样转发、是否影响授权结果。

### 4. Sidecar 绕过

Envoy sidecar 依赖 iptables 重定向，存在"绕过代理"的路径：

- `iptables` 排除的 CIDR/端口（`excludeInboundPorts`、`excludeOutboundPorts`、UID 排除）。
- `hostNetwork: true` 或 `network_mode: host` 的工作负载。
- 应用使用 Unix socket 或直连本机其他容器。
- 直连 Pod IP 而非 Service（取决于拦截规则）。
- headless Service / EndpointSlice 直接访问。

**影响**：绕过代理意味着绕过 mTLS 与授权策略，同时**出网策略（REGISTRY_ONLY）也被跳过**（详见 `../SSRF/SSRF-Bypass-Techniques.md`）。

## 三、控制面与管理面（高价值）

| 目标 | 端点 | 说明 |
|---|---|---|
| Envoy admin | `:15000/`、`/config_dump`、`/clusters`、`/listeners`、`/stats`、`/quitquitquit`、`/healthcheck/fail` | 无认证即暴露时：全量配置泄漏（含内部服务拓扑、密钥引用）；`/quitquitquit` 可 DoS |
| Istiod | `/debug/`、`/debug/endpointz`、`/debug/configz`、`/debug/authorizationz` | 控制面信息泄漏 |
| Linkerd proxy admin | `:4191/`、`/metrics`、`/env` | 指标与配置 |
| Consul | `:8500/v1/acl/*`、`/v1/kv/*` | ACL 缺失 → 读写全部服务配置与 KV |
| xDS | Istiod gRPC 15012/15010 | 未认证的 xDS → 可注入配置（影响所有 sidecar） |
| CRD 可写 | `VirtualService`/`EnvoyFilter`/`Gateway`/`HTTPRoute` | 有写权限即等于可在网关层注入路由、Lua/WASM 过滤器（往往直接 RCE 或全量流量劫持） |
| Ingress Controller | Admission webhook | 配置注入类漏洞（如 CVE-2025-1974，见 `../Cloud-Container-Attack/Kubernetes-Attack.md`） |

判据：能读取 `config_dump` 已足以证明信息泄漏（其中可能含上游地址、集群信息、TLS 材料引用）；若 xDS/CRD 可写，则影响升级为"全网格流量劫持"。

## 四、网格内的横向移动路径

1. 从当前工作负载枚举可到达的服务（DNS 枚举 + 常见端口 + 探测）。
2. 找"无授权策略"的管理接口（actuator、admin、内部 API）。
3. 从网格内服务的环境变量/配置读取凭据（数据库 DSN、云凭据、其他服务 token）。
4. 用服务身份调用云元数据/云 API（若出网未被限制）。
5. 若控制面可达或 CRD 可写 → 影响面扩至整个集群。

## 五、验证（最小证据）

1. 网格类型与模式（Istio/PERMISSIVE 等）的实际配置输出。
2. 横向调用证据：从 A 服务调用 B 服务并返回数据的请求/响应。
3. XFCC 伪造：请求中的头 + 下游授权结果变化（若成立）。
4. Sidecar 绕过：证明流量未经代理（例如代理指标中无该请求、或直连 Pod IP 成功且策略未生效）。
5. 管理面：`config_dump`/`/debug` 的响应片段（敏感值掩码）。
6. 不做破坏性操作（不要调用 `/quitquitquit` 之类）。

## 六、常见误报

- 授权策略存在但**作用域不同**（例如只有默认命名空间有策略）。
- 明文请求"成功"实际是应用自身不校验（不是网格放行）。
- 直连成功的服务本身允许匿名访问。
- 读到的是已脱敏的配置。
- 只在测试集群复现（生产策略更严）。

## 七、修复

- **默认拒绝**：全网关/全命名空间 `AuthorizationPolicy` deny-all + 显式放行（基于 `principals` + 方法/路径）。
- **STRICT mTLS**：`PeerAuthentication: mode: STRICT`；禁止 `PERMISSIVE` 长期存在。
- **剥离 XFCC**：入口处删除客户端提供的 `X-Forwarded-Client-Cert` 与 `X-Envoy-*`。
- **出网策略**：`REGISTRY_ONLY`/egress gateway + 网络策略默认拒绝（防止 SSRF 直达云元数据与外部）。
- **管理面隔离**：Envoy admin 只绑定 `127.0.0.1` 或受限网段；Istiod/Consul/xDS 需认证（mTLS + RBAC）。
- **CRD 最小权限**：严格限制谁能创建/修改 `VirtualService`/`EnvoyFilter`/`HTTPRoute`/`Gateway`（等价于流量劫持权限）。
- **监控**：代理日志（`DENY` 事件）、异常的跨命名空间调用、xDS 配置变更审计、`config_dump` 访问告警。

## 八、参考

- Istio：Security（PeerAuthentication/AuthorizationPolicy）、Ambient mode 文档；Envoy：admin interface
- Linkerd：Authorization Policy / mTLS 文档；Consul Connect Intentions
- 上游 `../Cloud-Container-Attack/Kubernetes-Attack.md`、`../HTTP-Protocol-Attacks/HTTP2-HTTP3-Attacks.md`
