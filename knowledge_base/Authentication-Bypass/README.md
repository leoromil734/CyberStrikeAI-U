# 认证与授权绕过总览

> 认证（Authentication）绕过 = 让系统认为你是别人；授权（Authorization）绕过 = 让系统认为你有权做某事。两者手法不同，证据要求也不同。

## 分类与入口

| 类别 | 典型入口 | 详述 |
|---|---|---|
| 访问控制绕过 | 403/401、路径规范化、方法切换、Header 伪造 | `403-401-Access-Bypass.md` |
| 协议级认证 | OAuth/OIDC、SAML、SSO | `OAuth-OIDC-Attacks.md`、`SAML-XSW-Bypass.md` |
| 多因素 | OTP 爆破、响应篡改、WebAuthn 绑定错误 | `MFA-and-Passkey-Bypass.md` |
| 令牌/会话 | JWT、Cookie、重置令牌可预测 | `../JWT/JWT-Attack-Matrix.md` |
| 逻辑绕过 | 步骤跳过、状态机混乱、客户端校验 | 本篇"逻辑绕过" |
| 索引/边缘 | 直连后端、备用域名、旧版本接口 | 本篇"边缘通道" |

## 一、逻辑绕过（认证流程）

- **步骤跳过**：直接请求第 3 步的接口（如 `POST /reset/finish`）而不走 1、2 步。
- **状态机混乱**：在 `pending` 状态下即可访问需要 `verified` 的资源。
- **客户端判定**：`localStorage.isAdmin`、隐藏按钮、`X-Role` 头。
- **参数注入**：`{"is_admin":false,"is_admin":true}`（重复键）、`role=x&role=admin`（HPP）。
- **类型混淆**：`{"user_id":["1","2"]}`、`{"id":{"$ne":null}}`。
- **大小写/别名**：`/admin` vs `/Admin` vs `/ADMIN`，`/api/v1/admin` vs `/api/v2/admin`。
- **默认凭据与文档泄漏**：`/swagger`、`/actuator/env`、`/.env`、`/debug`。

## 二、边缘通道（常被忽略的高命中点）

1. **方法切换**：`GET /admin` 403，`POST`/`PUT`/`DELETE`/`OPTIONS`/`TRACE`/`PATCH` 可能 200。
2. **路径变体**：`/admin/`、`//admin`、`/./admin`、`/%2e/admin`、`/admin%20`、`/admin.json`、`/admin;/`。
3. **Header 覆盖**：`X-Forwarded-For: 127.0.0.1`、`X-Original-URL`、`X-Rewrite-URL`、`X-Forwarded-Host`、`X-HTTP-Method-Override`。
4. **Host 头**：内部 vhost 直接匹配（见 `HTTP-Protocol-Attacks/Host-Header-Attacks.md`）。
5. **直连后端**：绕 CDN/WAF 用源站 IP + `Host` 头。
6. **旧接口/影子 API**：移动端 JS、历史版本、`/api/internal/*`、gRPC-gateway 路径。
7. **静态化后门**：`*.bak`、`*.old`、`*.swp`、`WEB-INF/web.xml`、`.git/HEAD`。

## 三、判定纪律

1. 首先确认**基线**：匿名、普通用户、管理员三种身份下同一请求的响应（状态码 + 关键字段 + 长度）。
2. 只改一个变量，保留三次响应证据。
3. "响应长度变化"或"状态码变化"**不等于**越权成功 —— 必须有受保护数据或受保护动作。
4. 无法拿到数据但确认校验失效时，结论写"校验可绕过（未证实数据访问）"。

## 验证（最小证据）

1. 两个身份（或匿名 + 认证）。
2. 同一端点在两种身份下行为不同，且低权限侧获得高权限能力。
3. 数据/动作证据：他人数据片段、成功的管理操作、服务端状态变化。
4. 请求与响应原文，含被绕过的具体校验点。

## 常见误报

- 403 → 200 但响应体是通用错误页。
- 前端路由跳转成功（SPA 本地状态），后端 API 仍 403。
- 缓存返回了别人的响应（实为缓存投毒，另行定性）。
- 自建测试账号本身就是管理员。

## 修复

- 服务端统一鉴权中间件，默认拒绝；路由与资源级别都校验。
- 规范化路径与主机名后再匹配；不信任任何客户端可控的身份相关 Header。
- 认证流程改为无状态、可校验的一次性令牌（服务端持有状态），关键步骤不可跳过。
- 消除解析差异（见 `WAF-Bypass/Parser-Confusion-Bypass.md`）。

## 参考

- OWASP WSTG：Authentication / Authorization Testing
- PortSwigger Access Control、OAuth、SAML 研究
