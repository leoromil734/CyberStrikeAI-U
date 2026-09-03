---
name: web-attack-methods
description: >-
  Web 漏洞测试 / SQL 注入 / XSS / SSRF / 命令注入 / 文件包含 / 文件上传 / 认证绕过 /
  反序列化 / 模板注入 / 越权 / 会话劫持 / Web Exploitation / sqlmap / dalfox /
  interactsh / dnslog / jwt-analyzer / http-framework-test。已确认 Web 入口后选择
  注入、认证授权、服务端或边缘代理专项；用户说「测 Web」「打站」「注入」「XSS」
  「SSRF」「命令执行」「上传绕过」「SQL注入」时加载。出现 SRC、漏洞赏金、挖集团/品牌、
  白帽或中文 SRC 报告上下文时优先 `src-hunting`，本 skill 主动让路；API/BOLA 优先
  api-security-testing；不应一次加载全部漏洞类别清单。
allowed-tools: sqlmap dalfox xsser arjun x8 ffuf httpx http-framework-test jwt-analyzer interactsh dnslog nuclei jaeles nikto wafw00f gobuster dirsearch feroxbuster dotdotpwn metasploit exec record_vulnerability list_vulnerabilities upsert_project_fact
metadata:
  tags:
    - penetration-testing
    - web
    - exploitation
  source_augment: Hi-FullHouse/CyberSecurity-Skills
---

# Web 方法路由

先建立正常请求基线、认证态、入口参数和预期安全边界，再选择一个最相关 reference。不要一次读取全部 references。

| 观察到的攻击面 | 读取 | 目标 |
|---|---|---|
| 查询、模板、命令、浏览器渲染等可控输入 | `references/injection.md` | 证明输入到危险汇的可控差分 |
| 登录、会话、OAuth/SAML、角色/对象访问 | `references/auth-access.md` | 证明跨用户、角色或身份边界 |
| 文件、上传、SSRF、解析器、反序列化、服务端路径 | `references/server-side.md` | 证明服务器侧读写、请求或执行能力 |
| CDN/WAF/反向代理与应用行为不一致 | `references/edge-proxy.md` | 区分边缘拒绝、规范化差异和真实业务响应 |

## CSS 利用手册（按漏洞类型按需读）

| 类型 | 路径 |
| --- | --- |
| Web 利用总览 | `references/csskills-exploit/Web漏洞利用-WebExploitation.md` |
| SQLi | `references/csskills-exploit/SQL注入利用-SQLInjection.md` |
| XSS | `references/csskills-exploit/XSS跨站脚本-XSSExploitation.md` |
| 文件包含/上传 | `references/csskills-exploit/文件包含利用-FileInclusion.md` |
| 命令注入 | `references/csskills-exploit/命令注入-CommandInjection.md` |
| SSRF | `references/csskills-exploit/SSRF服务端请求伪造-SSRF.md` |
| 认证绕过 | `references/csskills-exploit/认证绕过-AuthBypass.md` |
| Metasploit | `references/csskills-exploit/Metasploit框架利用-Metasploit.md` |

REST/GraphQL、BOLA 优先 `api-security-testing`。组件情报用 `component-vuln-intel`（tentative）；确认用 `pentest-verification`。

## 共同流程

1. 保存正常请求：URL、方法、参数、header、Cookie、身份、响应。
2. 写出单一假设、控制变量、正证据和否定信号。
3. 最小 payload 验证，不同时改变编码、身份、路径和客户端栈。
4. 复测稳定性，排除缓存、限流、通用错误页和边缘挑战。
5. 可复现且跨越安全边界才确认；正式记录须完整 POC + `validation`；CORS/CSRF 等低危默认不记。

## 系统工具补全（场景 → MCP）

| 场景 | 优先工具 | 备选 |
| --- | --- | --- |
| 基线 HTTP | `http-framework-test` / `httpx` | `exec`+curl |
| SQLi | `sqlmap` | 手工 |
| XSS | `dalfox` | `xsser` |
| 参数 | `arjun` / `x8` | `ffuf` |
| 路径/上传 | `ffuf` / `gobuster` / `dirsearch` | `dotdotpwn` |
| OOB | `interactsh` / `dnslog` | — |
| JWT | `jwt-analyzer` | — |
| 线索 | `nuclei` / `metasploit` | `jaeles` |
| 落库 | `list_vulnerabilities` → `record_vulnerability` | `upsert_project_fact` |

尚无资产清单 → `recon-osint-playbook` / `attack-surface-recon`。纯 API 授权 → `api-security-testing`。