---
name: recon-osint-playbook
description: >-
  信息收集 / OSINT / 侦察 / recon / 子域名 / DNS 枚举 / 资产发现 / 网络空间搜索 /
  FOFA / Shodan / ZoomEye / Quake / 证书透明度 / Google Dork / theHarvester /
  技术栈指纹 / Whois / 被动侦察 / 主动侦察 / 邮箱收集 / 员工情报 / 端口前摸底 /
  amass / subfinder / oneforall / dnsx / httpx / naabu / masscan / nmap /
  wayback / gau / katana。当用户或任务涉及「信息收集」「收集信息」「侦察」
  「recon」「osint」「找子域」「资产测绘」「打点」「扫端口前先摸底」「目标摸清」
  「全面侦察」「外网资产」「空间引擎」时必须优先 skill 加载本包。
  已有 SRC、漏洞赏金、挖集团/品牌上下文时优先 `src-hunting`，再按其路由索引读取
  侦察方法；本包只用于独立 OSINT 阶段。提供可执行 MCP 工具顺序与多源交叉验证；
  覆盖账本/退出门禁叠加 attack-surface-recon。
allowed-tools: subfinder amass oneforall dnsx dnsenum fierce httpx naabu nmap masscan rustscan fofa_search shodan_search zoomeye_search quake_search waybackurls gau katana jsluice nuclei fscan exec upsert_project_fact
metadata:
  tags:
    - penetration-testing
    - recon
    - osint
    - information-gathering
  source: Hi-FullHouse/CyberSecurity-Skills
  license_note: MIT content adapted as Agent Skill references
---

# 信息收集 / OSINT 实战手册

**触发即加载**：渗透任务第一步若涉及目标摸底、域名/IP/邮箱/员工/子域、端口前侦察，先 `skill recon-osint-playbook`，再按需 `read_file` 打开 `references/`。

与 `attack-surface-recon` 分工：

| 本 Skill | `attack-surface-recon` |
| --- | --- |
| 命令级 OSINT、dork、空间引擎语法、MCP 工具调用顺序 | 覆盖账本、fact 字段、退出门禁、Deep 硬闸门 |
| 快速可执行清单 | 项目黑板与阶段 ledger |

## 最小执行顺序（提高完成率）

```text
被动 OSINT → 子域多源 → DNS 清洗 → 空间引擎交叉 → 技术栈指纹 → 主动端口/HTTP
```

1. **被动**：Google/Bing/Baidu dork、WHOIS、证书 CT、GitHub 泄露关键字（可用 `exec` 调 dig/curl/whois；无专用工具时不要空跑）。
2. **子域**：至少两个异构来源，禁止单工具宣称完整。
3. **DNS**：`dnsx`/`dnsenum`/`fierce` 验证 A/AAAA/CNAME/MX/TXT；识别通配。
4. **空间引擎**：`fofa_search` / `shodan_search` / `zoomeye_search` / `quake_search` 用域名、证书、favicon、body 交叉。
5. **指纹**：`httpx`（title/tech/status）；再决定 `nuclei` 模板范围（结果仅 tentative）。
6. **主动**：`naabu`/`masscan`/`rustscan` 分层端口 → 高价值 `nmap -sCV`；`httpx` 存活与标题。

## 系统工具补全表（优先 MCP 名，勿臆造工具名）

| 阶段 | 优先调用 | 备选 / 补充 | 落库 |
| --- | --- | --- | --- |
| 子域被动 | `subfinder` | `amass`、`oneforall` | `upsert_project_fact` → `recon/source/{tool}/{target}` |
| DNS | `dnsx` | `dnsenum`、`fierce`、`exec`(dig) | 同上 + 通配基线 |
| 空间测绘 | `fofa_search` | `shodan_search`、`zoomeye_search`、`quake_search` | 资产增量 fact |
| HTTP 存活/指纹 | `httpx` | `exec`+curl | 存活列表 |
| 端口 | `naabu` | `masscan`、`rustscan`、`nmap`、`fscan` | 开放端口 fact |
| 历史 URL | `waybackurls`、`gau` | `katana` 主动爬 | `recon/endpoint/*` |
| JS/API 抽取 | `jsluice` | `katana`、手工 `httpx` | endpoint 清单 |
| 线索扫描 | `nuclei` | `jaeles`、`nikto` | **仅 tentative**，禁止直接 `record_vulnerability` |
| 通用兜底 | `exec` | `execute-python-script` | 仅无专用 YAML 工具时 |

### 调用纪律

- 工具名必须与系统已注册 MCP/YAML **完全一致**（上表为准）；未配置的工具记 `blocked` + `alt_tried`，换备选。
- 同阶段连续失败 2 次 → 换异构来源，不重复同一参数。
- 每确认一批新资产/解析结果 → **立即** `upsert_project_fact`，勿等侦察结束。
- 需要覆盖门禁、Deep 硬闸门、fact schema → 再 `skill attack-surface-recon`。

## 按场景读 references（一次只开相关文件）

| 场景关键词 | 读取 |
| --- | --- |
| 被动、OSINT、dork、whois、邮箱 | `references/被动信息搜集-PassiveRecon.md` |
| nmap、masscan、主动探测 | `references/主动信息搜集-ActiveRecon.md` |
| dig、dnsenum、记录类型 | `references/DNS枚举-DNSEnumeration.md` |
| 子域、subfinder、amass | `references/子域名探测-SubdomainDiscovery.md` |
| FOFA、Shodan、ZoomEye、Quake | `references/网络空间搜索引擎-OSINT-SearchEngine.md` |
| 社工、员工、LinkedIn、用户名 | `references/社会工程学信息-SocialEngineeringInfo.md` |
| 技术栈、CMS、框架指纹 | `references/目标技术栈识别-TechStackFingerprint.md` |

同源扩展（扫描器自动化，仍 tentative）：见 `attack-surface-recon` 下 `references/csskills-scan/`。

## 交付要求

- 输出：来源列表、新增资产增量、失败/替代来源、下一步验证 Top-N。
- **禁止**把扫描器命中直接 `record_vulnerability`。
- 需要覆盖门禁与 fact schema 时：再 `skill` 加载 `attack-surface-recon`。