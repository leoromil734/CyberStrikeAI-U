---
name: api-security-testing
description: >-
  API 安全 / REST / GraphQL / RPC / BOLA / BFLA / IDOR / JWT / OAuth / API Key /
  批量赋值 / 影子 API / OpenAPI / Swagger / OWASP API Top10 / graphql-scanner /
  api-schema-analyzer / jwt-analyzer。用于接口库存、双身份授权差分、Token 校验、
  业务流与 SSRF；用户说「测 API」「接口越权」「JWT」「GraphQL」「对象级授权」
  「BOLA」「BFLA」「Swagger」时加载。不是通用 Web 注入清单；缺少可达基线时不得宣称接口安全。
allowed-tools: httpx http-framework-test api-schema-analyzer graphql-scanner jwt-analyzer arjun x8 ffuf katana jsluice interactsh dnslog nuclei sqlmap exec record_vulnerability list_vulnerabilities upsert_project_fact
metadata:
  tags:
    - penetration-testing
    - api
  source_augment: Hi-FullHouse/CyberSecurity-Skills
---

# API 安全测试路由

API 测试优先建立「端点 × 身份 × 对象归属 × 动作」差分矩阵，而不是扫漏洞类别全集。

## 入口决策

- 端点/schema/版本/影子环境：`references/inventory.md`
- BOLA/BFLA/字段授权/批量赋值/双身份：`references/authorization-matrix.md`
- JWT/OAuth/API key/session/撤销/scope：`references/token-auth.md`
- SSRF/业务流/回调/GraphQL/异常：`references/business-server-side.md`

## CSS / OWASP API 手册（按需）

| 主题 | 路径 |
| --- | --- |
| OWASP API 测试 | `references/csskills-api/OWASP API安全测试-OWASPAPISecurityTesting.md` |
| 认证与授权 | `references/csskills-api/API认证与授权安全-APIAuthAuthorizationSecurity.md` |
| GraphQL/微服务 | `references/csskills-api/GraphQL与微服务API安全-GraphQLMicroserviceAPISecurity.md` |

一次只读与当前候选相关的 reference。通用证据链：`pentest-verification`。

## 最小流程

1. 可达基线：协议、base URL、版本、认证、Content-Type、标准客户端响应。
2. 端点表：方法、对象 ID、角色、副作用、敏感度；JS 路由必须展开到逐端点。
3. 允许时最少测试账号 + 双主体差分。
4. 一次只改身份 / 对象 ID / 字段 / 状态之一。
5. 比较数据、字段、副作用与后续 GET，不单靠状态码。
6. 正负结果都记适用身份与请求摘要；记录漏洞须完整 POC + `validation`。

## 系统工具补全（场景 → MCP）

| 场景 | 优先工具 | 备选 |
| --- | --- | --- |
| 可达/指纹 | `httpx` / `http-framework-test` | — |
| OpenAPI | `api-schema-analyzer` | `katana`/`jsluice` |
| GraphQL | `graphql-scanner` | 手工 introspection |
| JWT | `jwt-analyzer` | — |
| 隐藏参数 | `arjun` / `x8` | `ffuf` |
| 端点发现 | `jsluice` / `katana` | — |
| OOB | `interactsh` / `dnslog` | — |
| 线索 | `nuclei` | `sqlmap`（适用时） |
| 落库 | `list_vulnerabilities` → `record_vulnerability` | `upsert_project_fact` |

CDN 403 不代表接口不存在。客户端差分对齐后，再考虑 `cdn-tls-fingerprint`。