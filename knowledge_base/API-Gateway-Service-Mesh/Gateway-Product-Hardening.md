# 网关产品加固与管理面检查

> 本页是**检查清单**：网关自身的管理面与默认配置常被忽略，而它们通常等价于"拿到全部路由与凭据"。评估时按清单逐项确认（只读优先）。

## 一、通用检查项

- [ ] 管理/监控端口是否暴露在业务网段或公网（应仅运维网段 + 认证）。
- [ ] 是否使用默认凭据或默认密钥（见下表的常见默认值）。
- [ ] 管理 API 是否可读全量配置（路由、上游、插件、密钥引用）。
- [ ] 是否可写配置（能改路由/插件/上游 = 流量劫持）。
- [ ] 插件或表达式注入（SpEL、Lua、WASM、模板）。
- [ ] 是否有未认证的 `/health`、`/metrics`、`/debug`、`/actuator`、`/pprof`。
- [ ] 版本是否对应已知漏洞（以厂商公告与 CISA KEV 为准，不背 CVE 编号）。
- [ ] 配置变更是否有审计与评审。

## 二、按产品的常见管理面与关注点

### Envoy / Istio

| 端点 | 说明 |
|---|---|
| `:15000/`（admin） | 应绑定 `127.0.0.1` 或受限接口 |
| `/config_dump`、`/clusters`、`/listeners`、`/stats` | 配置与拓扑泄漏 |
| `/quitquitquit`、`/healthcheck/fail` | **DoS**，评估时不要调用 |
| Istiod `/debug/`、`/debug/configz`、`/debug/authorizationz` | 控制面信息 |
| xDS（15010/15012）、CRD（`VirtualService`/`EnvoyFilter`/`Gateway`/`HTTPRoute`） | 可写 = 全网格流量劫持 |

加固：admin 仅本地；控制面 mTLS + RBAC；严格限制 CRD 写权限（详见 `Mesh-Internal-Trust-Abuse.md`）。

### Kong（含 Kong Gateway / Ingress Controller）

- Admin API：`8001`（`/routes`、`/services`、`/plugins`、`/consumers`、`/certificates`）；`/status`。
- 关注：Admin API 无认证暴露 → 可新增路由与 `key-auth` 凭据；插件删除（`DELETE /plugins/<id>`）可移除鉴权。
- 加固：Admin API 仅内网 + RBAC（Enterprise）；Kong Ingress Controller 使用 `KongPlugin` 时注意 CRD 权限。

### Apache APISIX

- Admin API：`9180`（`/apisix/admin/routes`、`/upstreams`、`/consumers`、`/ssl`）。
- **历史与默认 `X-API-KEY`** 常见于示例配置（如 `edd1c9f034335f136f87ad84b625c8f1`）—— 检查是否仍在使用默认值。
- 加固：修改 Admin Key、绑定内网、启用 Admin API 认证（`admin_key` + RBAC）。

### Traefik

- Dashboard/API：`8080`（`/api/rawdata`、`/api/http/routers`、`/api/http/middlewares`）；`/metrics`。
- 关注：暴露后可见全部路由与中间件（含 BasicAuth 用户、转发头配置）；`/api/rawdata` 泄漏内部服务拓扑。
- 加固：Dashboard 需 `basicauth`/`digestauth` 且不暴露公网；只读 API 也要限制。

### Spring Cloud Gateway / Spring Boot 系

- `management.endpoints.web.exposure.include` 常含 `gateway`、`env`、`heapdump`。
- 历史高危：`/actuator/gateway/routes` 的新增/刷新接口配合 SpEL 表达式注入 → RCE（评估时**只读**读取路由，不注入）。
- 加固：关闭/限制 actuator（尤其 `gateway`、`env`、`jolokia`、`heapdump`）；升级到已修版本；网关配置不从外部输入构建。

### 云托管网关

- AWS API Gateway：`/restapis`、`/apikeys`（IAM 控制）；关注资源策略过宽、API Key 被当作唯一鉴权、Lambda 授权器返回宽松策略（`Allow` 全部资源）、WAF 未挂。
- Azure APIM：`/subscriptions/.../service`、开发者门户（Portal）常暴露内部 API 定义与测试控制台；订阅键（`Ocp-Apim-Subscription-Key`）被当作唯一鉴权。
- GCP Apigee / API Gateway：关注 API Key + Quota 策略当作鉴权、IaC 中的 service account 权限过大。
- Cloudflare API Shield / Workers：注意 Worker 变量与 secret 的绑定错误、`/cdn-cgi/` 路径处理差异。

### Nginx / OpenResty / HAProxy

- `stub_status`、`location /nginx_status`、OpenResty 的 `/_` 调试端点。
- 关注：`merge_slashes`、`proxy_pass` 尾斜杠的路径拼接差异（见 `Gateway-Auth-Bypass.md`）；`X-Accel-Redirect` 与内部 location（`internal;`）误配导致内部资源可读。
- HAProxy：stats 页面（`stats uri`）默认无认证；runtime API（`/;csv`、动态开关）若暴露可改配置。

## 三、验证（最小证据）

1. 管理面访问的请求与响应（含未认证即可读取的配置片段，敏感值掩码）。
2. 若可写：**不要实际修改**；用只读证据（例如 `OPTIONS`/接口文档）说明可写性，或经客户同意后做一次可回滚的最小验证并记录清理过程。
3. 版本信息（响应头、`/version`、错误页、行为特征）与厂商公告比对。
4. 影响评估：能读到的拓扑/密钥引用；若可写 → 影响升级为全量流量劫持。

## 四、常见误报

- 管理端口开放但要求 mTLS/客户端证书（未通过即无法访问）。
- 只暴露了 `/health` 与 `/metrics`（信息价值有限，除非含敏感标签，如内部主机名、token）。
- 默认 `X-API-KEY` 已被修改但仍被示例文档误导。
- 版本号看似陈旧，但分发版已反向移植补丁。

## 五、修复要点

- 管理面：默认不暴露、绑定本地或专用网段、强制认证 + MFA + 审计。
- 密钥：替换全部默认密钥/口令，纳入密钥管理（KMS/Vault）并轮换。
- 最小暴露：关闭不需要的插件、模块、调试端点与 Dashboard。
- 权限：管理 API 的写权限等同管理员权限，按最小权限授予（避免 CRD/Admin API 的过宽 RBAC）。
- 升级与巡检：纳入资产库，关注厂商公告与 KEV；定期用配置扫描（`kube-bench`、`trivy config`、`checkov`、`kubesec`）与规则巡检。
- 变更管理：网关配置纳入代码评审与审计日志，变更即告警。

## 六、参考

- 各产品官方安全文档（Envoy admin、Kong/APISIX/Traefik Admin API、Spring Boot Actuator 安全建议）
- OWASP API Security Top 10（API8 配置错误、API9 资产管理）
- CISA KEV 与厂商安全公告（以公告为准，不依赖 CVE 编号记忆）
- 上游 `../Cloud-Container-Attack/README.md`、`../Recon-OSINT/JS-and-Secrets-Discovery.md`
