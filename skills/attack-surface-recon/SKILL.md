---
name: attack-surface-recon
description: >-
  授权范围内的攻击面测绘与侦察调度。按目标类型选择 subfinder、OneForAll、dnsx、httpx、naabu、katana、gau、ffuf、nuclei，去重并输出高价值入口与覆盖缺口。
  Use when starting recon, mapping assets, discovering endpoints, fingerprinting technology, or preparing vulnerability verification.
tags: [渗透测试, penetration-testing, 红队]
---

# 攻击面测绘

成功标准不是“调用很多工具”，而是产出：

- 可解析资产、存活服务、技术栈、入口与参数
- 按影响和可验证性排序的 Top-N 候选
- 已完成范围、失败参数集、覆盖缺口
- 每项事实的来源与置信度

## 0. 先判定输入类型

```text
root_domain  -> 子域增量收集 -> DNS 清洗 -> HTTP/端口测绘
single_url   -> 跳过全量子域 -> 当前站点爬取、历史 URL、路径与参数发现
ip_or_cidr   -> 端口/服务优先 -> 仅对证书或反向解析得到的域名做关联
host_list    -> 去重 -> DNS/HTTP 批处理
```

先读取项目黑板和 Do-Not-Repeat。上游已有结果时只补缺口，不重跑同一范围和参数集。

## 1. 子域调度

仅 `root_domain` 进入本阶段。

1. `subfinder` 做快速被动首轮，尽快形成第一批主机。
2. 满足任一条件时，本轮必须调用一次 `oneforall`：
   - 用户要求完整/深度攻击面
   - subfinder 结果少或关键业务域明显缺失
   - 高价值根域，且交接未要求快速模式
3. 正常深度侦察中，最迟第二阶段调用 `oneforall`；跳过时必须记录明确原因：单 URL/IP、快速模式、已确认通配 DNS、或交接禁止全量枚举。
4. `amass` 用于 ASN/组织关联、被动数据源补齐或前两者结果冲突；不要无条件重复。
5. 合并来源并去重，再交给 `dnsx`。保留 `source -> hostname`，便于判断工具增量价值。

OneForAll 只负责增量发现，不重复其 HTTP 探测；统一由 `dnsx -> httpx` 清洗。

## 2. 存活、指纹与端口

- `dnsx`：先过滤不可解析主机，收集 A/AAAA/CNAME。
- `httpx`：使用 MCP 参数 `target` 或 `target_list`，默认收集 status/title/tech/server/content-length/CDN。
- `naabu`：批量快速端口发现；只对高价值主机用 `nmap -sCV` 精扫。
- 识别组件或版本后立即加载 `component-vuln-intel`，但检索命中只记 tentative。

不要在命令行直接调用裸 `httpx`。MCP 工具 `httpx` 对应 ProjectDiscovery 的 `httpx-pd`，用于避免 Python `httpx` CLI 同名冲突。

## 3. URL、路径与参数面

对存活 Web 资产并行补齐不同来源：

- 当前站点：`katana`
- 历史 URL：`gau`、`waybackurls`
- 参数候选：`arjun`、`paramspider`、`x8`
- API 契约：Swagger/OpenAPI、GraphQL、JS 中的 base URL 和路由
- 路径发现：`ffuf` 为主，`dirsearch` 作异构补充

`ffuf` 纪律：

1. 先请求 2–3 个随机不存在路径，判断 catch-all 的状态码和响应大小。
2. `url` 必须包含 `FUZZ`。
3. 默认不传 `wordlist`，让工具从已验证候选路径选择；禁止猜测 `/usr/share/wordlists/dirb/common.txt`。
4. 若显式传字典，必须确认它在执行节点真实存在。
5. 先小字典 + 自动校准；发现命名规律或高价值目录后再升级字典。
6. 保留 401/403/405/500 和稳定响应差分，不只看 200。

## 4. 线索扫描与漏洞覆盖

`nuclei` 只在存活、去重后的目标上运行，并按技术栈/严重性裁剪模板。扫描命中必须进入验证阶段，禁止直接作为漏洞。

每个高价值入口至少检查适用的风险面：

```text
auth       -> 匿名/低权/高权差分、重置、MFA、JWT
object     -> BOLA/IDOR、批量导出、下载
input      -> SQLi、XSS、SSTI、命令注入、路径穿越
server     -> SSRF、上传、反序列化、XXE
api        -> schema 暴露、批量赋值、BFLA、GraphQL
config     -> 默认路径、备份、调试、CORS、旧版本 API
business   -> 状态机跳步、重放、并发、额度与价格边界
```

自动化负责覆盖，专项工具和最小 PoC 负责确认。优先验证“高影响 + 有输入面 + 有响应差分”的候选。

## 5. CDN 与 `curl_cffi` 门控

`httpx -cdn`、`server: cloudflare`、`cf-ray` 只说明存在边缘/CDN，不能证明 TLS 指纹拦截，不能据此安装或切换 `curl_cffi`。

只有完成同 URL、同方法、同认证态、同 Cookie/Header、低速重试的客户端差分，并满足以下条件，才加载 `cdn-tls-fingerprint` 做一次诊断：

- 标准客户端持续收到边缘 403/503、挑战页或连接重置
- 同条件真实浏览器能够到达业务响应
- 差异不能由 Cookie、JS Challenge、速率限制、IP 信誉或请求参数解释

仅当 `curl_cffi` 诊断请求到达业务层，而标准客户端仍停留在边缘，才确认 TLS/HTTP2 客户端指纹拦截，并在后续受影响请求中复用它。否则继续用标准工具；强 JS Challenge 应走浏览器，不要把 `curl_cffi` 当默认 HTTP 客户端。

## 6. 失败恢复

- `httpx` 报 `No such option '-u'`：命中了 Python CLI。停止重试，修复/安装 `httpx-pd` 后再调用 MCP `httpx`。
- `ffuf` 报字典不存在：去掉显式 `wordlist` 重试，让工具解析候选路径；仍无字典则改用 `dirsearch` 或生成目标定制小字典。
- 工具缺失或单源失败：切换异构工具，不阻塞整条链路。
- 连续三次无新增：停止同参数重跑，转向覆盖缺口或专项验证。

## 7. 记录与交付

每确认资产、服务、版本、入口或认证特征，立即 `upsert_project_fact`。输出固定为：

1. Assets
2. Live Services & Fingerprints
3. Entry Points & Parameters
4. Prioritized Verification Top-N
5. Tool Coverage & Incremental Yield
6. Do-Not-Repeat
7. Remaining Gaps

侦察阶段默认不 `record_vulnerability`；只有最小 PoC 已证明实际影响时才进入漏洞记录。