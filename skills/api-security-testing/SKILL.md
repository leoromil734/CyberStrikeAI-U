---
name: api-security-testing
description: >-
  API安全测试清单:OWASP API Top10 2023,GraphQL/JWT/OpenAPI；标准客户端优先，仅在受控差分确认 TLS 指纹拦截后使用 curl_cffi。
  Use when testing REST/GraphQL APIs, BOLA/IDOR, JWT, mass assignment, or diagnosing a controlled browser-versus-CLI edge-block discrepancy.
tags: [渗透测试, penetration-testing, API, 红队]
---

## API 安全测试（可执行清单）

对齐 [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)。**扫描≠漏洞**；每条 confirmed 需最小证据包（见 `pentest-verification`）。

```
=== -1. 客户端基线（标准客户端优先）===
- 默认使用 httpx、系统 curl 或普通脚本建立业务响应基线；存在 CDN/Cloudflare 不改变默认客户端
- 只有“标准客户端持续停在边缘 + 同条件浏览器到达业务层”时，才加载 `cdn-tls-fingerprint` 做受控差分
- 先对齐 Cookie、Authorization、CSRF、方法、请求体、重定向和速率；排除 JS Challenge、限流与 IP 信誉
- 仅当 curl_cffi 成为唯一变化且到达业务层时，确认 TLS/HTTP2 指纹拦截；之后只替换受影响请求
- 强 JS Challenge 使用浏览器；不得仅因 `cf-ray`、CDN 标记或普通 403 就安装 curl_cffi
- 未建立可达基线前，禁止把边缘失败写成“无此接口/无越权”

=== 0. 库存 (API9) ===
- 收集: Swagger/OpenAPI/GraphQL introspection、JS 打包 API、移动端 baseURL
- 工具: api-schema-analyzer, graphql-scanner, katana, gau, httpx；仅在已确认 TLS 指纹拦截后用 curl_cffi 拉 schema
- 产出: endpoint 表 + 版本/影子环境 → fact: target/api_inventory (tentative ok)

=== 1. 认证 (API2) ===
- 无 token / 过期 token / 错误 alg JWT / 密码重置链 / MFA 跳过
- 工具: jwt-analyzer, httpx, execute-python-script；受控差分确认 TLS 指纹后才使用 curl_cffi
- 正证据: 获得他户会话或绕过登录；负证据: 一致 401

=== 2. BOLA 对象级授权 (API1) — 最高产 ===
- 自有对象 ID → 换他户 ID；批量 GET/导出/下载
- GraphQL: node(id)、全局 ID 解码后横向
- 正证据: 响应含他户 PII/资源；负证据: 403/空且无泄露

=== 3. 属性级授权 / 批量赋值 (API3) ===
- POST/PATCH 多加 role,isAdmin,price,balance 等
- 对比响应与再 GET；过度暴露: 响应多字段敏感信息
- 正证据: 非法字段生效或敏感字段对低权可见

=== 4. 功能级授权 BFLA (API5) ===
- 低权调用 /admin、/internal、管理 mutation
- 正证据: 管理动作成功

=== 5. SSRF (API7) ===
- webhook、avatar URL、pdf render、导入 URL
- 工具: interactsh-client / dnslog；内网仅授权环境
- 正证据: OOB 或内网内容

=== 6. 注入与异常 ===
- JSON/query/header: SQLi(sqlmap)、命令注入、SSTI
- GraphQL: 嵌套 DoS 慎用；批量查询权限

=== 7. 配置与清单 (API8/API9) ===
- 开放 swagger、graphql playground、DEBUG、CORS * + credentials
- 旧版 API v1 仍在线

=== 8. 业务流 (API6) — 有限验证 ===
- 下单/领券/验证码绕过：证明可自动化滥用即可，避免真打爆生产

=== 9. 第三方 (API10) ===
- 回调/透传字段是否当可信输入

=== 落库 ===
- 线索: tentative fact
- 可复现: record_vulnerability + finding/ body 含请求差分
```

### 推荐工具顺序

`httpx` 探活并标记 CDN → schema/introspection → 双身份会话 → BOLA 矩阵 → jwt-analyzer → SSRF OOB → sqlmap（入口已证明可达时）。仅当受控客户端差分确认 TLS 指纹拦截，才在受影响步骤中插入 `curl_cffi`。

### 与角色

单代理选 **API安全测试** 角色；多代理 Verify 阶段 `penetration` + 本 skill + 必要时 `cdn-tls-fingerprint`。