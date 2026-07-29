---
name: web-attack-methods
description: >-
  Web 安全方法路由器。用于已确认 Web 入口后，在注入、认证授权、服务端处理或边缘代理中选择一个专项参考；
  API/BOLA 优先使用 api-security-testing，不应把本 Skill 当作一次性全漏洞清单。
metadata:
  tags:
    - penetration-testing
    - web
---

# Web 方法路由

先建立正常请求基线、认证态、入口参数和预期安全边界，再选择一个最相关参考文件。不要一次读取全部 references。

| 观察到的攻击面 | 读取 | 目标 |
|---|---|---|
| 查询、模板、命令、浏览器渲染等可控输入 | `references/injection.md` | 证明输入到危险汇的可控差分 |
| 登录、会话、OAuth/SAML、角色/对象访问 | `references/auth-access.md` | 证明跨用户、角色或身份边界 |
| 文件、上传、SSRF、解析器、反序列化、服务端路径 | `references/server-side.md` | 证明服务器侧读写、请求或执行能力 |
| CDN/WAF/反向代理与应用行为不一致 | `references/edge-proxy.md` | 区分边缘拒绝、规范化差异和真实业务响应 |

REST/GraphQL、BOLA、批量赋值和 API 业务流优先加载 `api-security-testing`。组件/版本命中只加载 `component-vuln-intel` 形成候选；动态确认仍使用 `pentest-verification`。

## 共同流程

1. 保存正常请求：URL、方法、参数、header、Cookie、身份、响应状态与关键内容。
2. 写出单一假设、控制变量、正证据和否定信号。
3. 使用最小 payload 或状态变化验证，不同时改变编码、身份、路径和客户端栈。
4. 观察差分后复测稳定性，并排除缓存、限流、通用错误页和边缘挑战。
5. 只有可复现且跨越实际安全边界时确认；否则记录 tentative 或负结果。

## 工具选择

优先使用与入口匹配的专用工具：SQLi 用 sqlmap，XSS 用 dalfox，参数发现用 arjun/x8，OOB 用 interactsh-client/dnslog，JWT 用 jwt-analyzer。nuclei 只负责线索，不能替代目标侧复现。