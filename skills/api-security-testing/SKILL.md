---
name: api-security-testing
description: >-
  REST、GraphQL 与 RPC API 的安全测试路由。用于 API 库存、双身份 BOLA/BFLA、JWT、字段级授权、
  批量赋值、SSRF 或业务流验证；不是通用 Web 注入清单，也不能在缺少可达基线时宣称接口安全。
metadata:
  tags:
    - penetration-testing
    - api
---

# API 安全测试路由

API 测试优先建立“端点 × 身份 × 对象归属 × 动作”的差分矩阵，而不是扫描漏洞类别全集。

## 入口决策

- 需要端点、schema、版本和影子环境清单：读取 `references/inventory.md`。
- 需要 BOLA、BFLA、字段授权、批量赋值或双身份对照：读取 `references/authorization-matrix.md`。
- 需要 JWT、OAuth、API key、session 或撤销/scope 校验：读取 `references/token-auth.md`。
- 需要 SSRF、业务流、第三方回调、GraphQL 或异常处理：读取 `references/business-server-side.md`。

一次只读取与当前候选相关的 reference。通用证据阈值由 `pentest-verification` 提供。

## 最小流程

1. 建立可达基线：协议、base URL、版本、认证方式、内容类型和标准客户端响应。
2. 形成端点表：方法、对象标识、所需角色、读写副作用和数据敏感度。
3. 至少准备基线身份和攻击身份；没有双身份时，明确哪些授权结论无法验证。
4. 一次只改变身份、对象 ID、字段或状态中的一个变量。
5. 比较状态码之外的数据、字段、副作用和后续 GET；通用 200/500 不能单独证明成功。
6. 正负结果都记录适用身份、对象、请求和响应摘要。

## 边缘层注意

CDN 标记或 403 不代表接口不存在。标准客户端与浏览器不一致时，先对齐 Cookie、Authorization、CSRF、方法、请求体、重定向和速率；只有受控差分证明客户端指纹因素后，才加载 `cdn-tls-fingerprint`。