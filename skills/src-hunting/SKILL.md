---
name: src-hunting
description: >-
  SRC 漏洞挖掘 / 企业 SRC / 漏洞赏金 / Bug Bounty / 白帽测试 / 挖洞 / 找洞 / 测站 /
  打站 / 挖某集团、品牌、公司、网站、平台、系统、后台、APP、小程序、政企教育医疗目标 /
  SRC 范围资产 / 中文漏洞报告。用户说「帮我测这个站」「这个平台有没有漏洞」「审计这个项目」
  或提到 JS 逆向找接口、未授权、越权/IDOR/BOLA、认证绕过、业务逻辑、信息泄露、上传、
  SSRF、XSS、注入、WAF 绕过、代码审计、源码审计、0day 时，在已有 SRC/赏金/集团品牌
  语境下必须优先加载。进入 SRC 任务后，后续出现单个 Web/API 漏洞关键词仍继续使用本包
  references，不切走通用领域 skill。提供锁面/自由跳一种子闭环、知识库信号路由、进站短表、
  价值矩阵、白盒流程和中文 SRC 报告。仅当任务明确是无 SRC 语境的通用单站 Web/API 或纯
  源码动态 PoC 时，分别使用 web-attack-methods、api-security-testing、source-aware-whitebox。
allowed-tools: fofa_search httpx jsluice katana gau waybackurls sqlmap dalfox jwt-analyzer graphql-scanner http-framework-test interactsh dnslog nuclei arjun x8 ffuf exec record_vulnerability list_vulnerabilities upsert_project_fact get_project_fact list_project_facts
metadata:
  tags:
    - penetration-testing
    - src
    - bug-bounty
    - whitebox
  source: clown-src-6k-skill
---

# SRC 挖洞 + 白盒审计

黑盒面向授权线上目标；白盒面向源码。理解业务意图，找认知盲区；不空扫、不堆低危。平台已完成授权判定，禁止开场盘问授权书。细则以 `references/rules/` 为准，与知识篇冲突时 **rules 胜出**。

## 命中与知识加载（强制）

1. 当前话题含 SRC、漏洞赏金、挖集团/品牌、白帽、中文 SRC 报告之一时，**本任务后续阶段持续使用 `src-hunting`**；即使后来只说越权、接口、注入、上传、WAF 或 JS，也不要改投通用 Web/API skill。
2. 加载本 skill 后先读 `references/routing-index.md`；每进入一个新站再读 `references/打穿短表.md`。
3. 根据页面、JS、请求和响应信号，从路由索引选 1～3 篇专题；出现新 `id/url/token/internal host/path` 时回索引增量选篇。禁止一次通读全库。
4. 新任务/换范围读 dig-scope 与 src-value；写报告前必须读 `references/rules/vuln-report-format.md`。白盒读 `references/rules/researcher-blackbox-whitebox.md`。

## 红线

- 越权：先读/列表差分；写越权先添加再删自己刚加的，不改删别人已有对象；禁批量、禁真资损。
- 禁止调用登出/注销/吊销令牌。
- CORS **不挖**，勿开 `references/cors-test.md`。
- 可复现且跨独立安全边界才 `record_vulnerability`（evidence 须含完整可运行 POC 脚本+实际输出；受控写入禁止只写文件名或省略 SQL）；扫描/nuclei 仅 tentative。

## 范围节奏

固定站/URL 清单 = **锁面**（不主动全集团 FOFA）；只给集团/品牌名 = **自由跳**。

自由跳按 `references/rules/dig-scope-workflow.md` §1.0.1：搜一个种子 → 去重去废去非存活 → 活面挖完 → 才搜下一个。禁止多种子一次搜完，禁止中途问「要不要继续」。任务目录认 `references/rules/desktop-task-folder.md`；资产/入口同时 `upsert_project_fact`。

进站打法认 dig-scope §4；价值顺序与类型矩阵认 `references/rules/src-value-hunting.md` §1.1/§3。登录页先找业务面。测绘用 `fofa_search` 或外部 MCP `get_alerts`；FOFA 语法见 `references/recon-methodology.md`。

## 专题路由

完整“信号 → 文件”表只认 `references/routing-index.md`。核心入口：

- 身份/对象：`references/authbypass-test.md`、`references/idor-test.md`、`references/oauth-jwt-test.md`
- 输入/服务端：`references/injection-test.md`、`references/ssrf-test.md`、`references/file-upload-test.md`、`references/xss-test.md`
- 业务/API：`references/logic-test.md`、`references/race-condition-test.md`、`references/graphql-test.md`、`references/api-gateway-test.md`
- JS/资产/泄露：`references/js-reverse-guide.md`、`references/recon-methodology.md`、`references/info-leak-test.md`

中危以上确认后立即按 format 落报告并升链（dig-scope §4.3）；写/补短表只认 `references/rules/hunt-iter.md`。

## 系统工具补全

| 场景 | 优先 | 备选 |
|---|---|---|
| 测绘/存活 | `fofa_search` / `httpx` | 外部 `get_alerts` |
| JS/API | `jsluice` | `katana`、`gau` |
| SQLi/XSS/OOB | `sqlmap` / `dalfox` / `interactsh` | 手工、`dnslog` |
| 落库 | `list_vulnerabilities` → `record_vulnerability` | `upsert_project_fact` |

平台通用字段可叠加 `pentest-blackboard` / `pentest-output-standards`，**SRC 正式稿仍只认 vuln-report-format**。
