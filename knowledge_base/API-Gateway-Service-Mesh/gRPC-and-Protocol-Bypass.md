# gRPC 与协议层绕过

> 网关对 HTTP/1.1 REST 的保护往往**不覆盖** gRPC、gRPC-Web、WebSocket、SSE。协议升级、降级与二进制语义会成为绕过鉴权与限流的通道。

## 一、gRPC 攻击面

| 面 | 要点 |
|---|---|
| **服务反射** | `grpcurl -plaintext host:443 list` / `describe` —— 未关闭反射即可拿到完整服务与方法签名，等于拿 API 文档 |
| **认证缺失** | gRPC 服务常被当作"内部协议"而不做鉴权；网关只对 REST 路由挂了插件 |
| **元数据（metadata）** | 等价于 HTTP 头：`authorization`、`x-user-id`、`x-forwarded-*`、`x-envoy-*` 可被伪造；元数据大小限制不当可 DoS |
| **Deadline/超时** | 不设 deadline → 长连接占用；设置不当 → 资源放大 |
| **流控** | 单连接多流（HTTP/2 特性）绕过按连接计数的限流 |
| **反射 + 枚举** | 结合 `grpcurl` 遍历所有方法，寻找未授权的高危方法（`Delete*`、`Admin*`、`Export*`） |
| **gRPC-Web** | 浏览器可通过 gRPC-Web 发请求 → **不受 CORS 预检保护**（取决于网关是否做了 Origin 校验），可与 CSWSH 类比（见 `../CSRF-WebSocket/CSRF-and-CSWSH-Bypass.md`） |
| **protobuf 解析差异** | 未知字段、重复字段、`oneof` 冲突、字段编号复用、`Any` 类型 —— 不同语言/版本实现行为不同，可能造成鉴权判定与实际处理不一致（同 `../WAF-Bypass/Parser-Confusion-Bypass.md`） |
| **HTTP/2 特性** | 伪头（`:path`/`:authority`）特殊值、重复 `content-length`、非法头名容忍度、H2→H1 降级（见 `../HTTP-Protocol-Attacks/HTTP2-HTTP3-Attacks.md`） |
| **Server Streaming** | 长连接下逐条推送，便于在单次"已鉴权"调用中持续取数；也可用于绕过按请求计费 |

实践要点：

```bash
# 反射枚举（授权范围内）
grpcurl -plaintext target:50051 list
grpcurl -plaintext target:50051 describe svc.PackageName
# 带元数据调用
grpcurl -plaintext -H 'authorization: Bearer <token>' -d '{}' target:50051 svc.Package/Method
# 关闭反射时的探测：从 .proto 文件、前端 JS、APK 中提取服务定义
```

## 二、协议升级/降级绕过

- **WebSocket**：网关常只对 HTTP 路由鉴权。若 WS 端点（`/ws`、`/socket.io`、`/graphql-ws`）未挂策略，则可跨站或未授权读写（含 PNA 不适用于 WebSocket，见 `../CSRF-WebSocket/CSRF-and-CSWSH-Bypass.md`）。
- **SSE / 长轮询**：鉴权只在建立连接时校验，之后的数据流不再校验；连接复用导致"撤销 token 后连接仍在推数据"。
- **HTTP/2 CONNECT**：可把单条连接变成内网端口扫描隧道（见 `../HTTP-Protocol-Attacks/HTTP2-HTTP3-Attacks.md`）。
- **HTTP/1.1 去同步**：`CL.0`/`H2.TE`/`Expect` 等让前端重写器（网关的 rewrite 规则）与后端解析不一致 → 绕过基于路径的重写与鉴权（PortSwigger 2025：request tunnelling 绕过前端规则）。
- **hop-by-hop 语义**：`Connection: X-Forwarded-Client-Cert`、`TE: trailers` 的转发差异会让某些组件跳过校验（见 `Gateway-Auth-Bypass.md` 与 RFC 9110 §7.6.1）。
- **方法与内容类型**：网关按 `Content-Type` 分发到不同插件；`application/grpc`、`application/grpc-web+proto`、`application/json` 混用可能落到无鉴权分支。

## 三、限流与配额在协议层的绕过

- HTTP/2 单连接多流：按连接计数的限流不生效。
- 流式 RPC：按请求计数的配额不生效（一次调用内多次取数）。
- 长连接保持：token 过期后连接仍存活。
- WebSocket 消息：按 HTTP 请求计数的策略完全不覆盖。

## 四、验证（最小证据）

1. 协议与端点：完整的 HTTP/2 帧或 gRPC 调用记录（含元数据）。
2. 反射/枚举结果（服务与方法清单），并指出其中未受保护的方法。
3. 绕过证据：未带 token 或使用低权 token 成功调用高权方法，附响应（protobuf 解码后的字段）。
4. 流式/长连接场景要说明"鉴权只发生一次"以及数据在连接内持续可取。
5. 若是去同步类，按 `../HTTP-Protocol-Attacks/Request-Smuggling.md` 的证据要求（跨用户影响）。

## 五、常见误报

- gRPC 端点实际要求 mTLS 客户端证书（未通过即失败）。
- 网关已对 `application/grpc` 做了统一鉴权（需实测而非假设）。
- 反射开启但所有方法都返回 `PermissionDenied`。
- protobuf 解析差异存在但不影响安全判定。
- WebSocket 握手成功但消息层逐条校验。

## 六、修复

- 网关对**所有协议**（REST/gRPC/gRPC-Web/WS/SSE）应用同一鉴权与限流策略；显式覆盖 `OPTIONS` 与升级请求。
- 生产**关闭 gRPC 反射**（或限制到内网）；对外只暴露必要方法（allowlist）。
- 元数据/头部白名单：剥离客户端提供的 `x-user-*`、`x-forwarded-*`、`x-envoy-*`。
- 对 WebSocket/SSE：**消息级**鉴权 + 会话失效联动（token 撤销即断开连接）。
- 限流按"消息/流/请求"多维计数，并考虑 HTTP/2 多流。
- 统一 HTTP 解析实现，关闭前端重写器的模糊匹配；上游连接使用 HTTP/2+（`../HTTP-Protocol-Attacks/Request-Smuggling.md`）。
- 监控：异常的 `:path`/伪头、反射调用、单连接多流激增、长连接数量。

## 七、参考

- gRPC 官方文档：Reflection / Metadata / Deadlines；Envoy gRPC-JSON transcoder
- PortSwigger：HTTP/1.1 must die（2025，request tunnelling 绕过前端规则）、HTTP/2 研究
- IncludeSecurity：Cross-Site WebSocket Hijacking Exploitation in 2025
- 上游 `../HTTP-Protocol-Attacks/`、`../CSRF-WebSocket/`
