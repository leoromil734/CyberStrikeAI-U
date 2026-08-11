---
name: attack-surface-recon
description: >-
  攻击面测绘 / 信息收集 / 侦察 / recon / OSINT / 子域名枚举 / DNS / 端口存活 / httpx /
  资产发现 / JS API 提取 / 目录参数 / 证书透明度 / FOFA Shodan ZoomEye Quake /
  wayback / katana / jsluice / arjun / x8 / ffuf / 覆盖账本 / recon fact /
  退出门禁 / Deep 硬闸门。用于 Surface、摸底、打点前资产清单、阶段 ledger；
  用户说「信息收集」「收集信息」「侦察」「找资产」「扫子域」「全面侦察」
  「攻击面」「资产清单」「覆盖率」时优先加载（可与 recon-osint-playbook 联用）。
  不用于深度漏洞确认；测试深度由 pentest-scan-quick/standard/deep 选择。
allowed-tools: subfinder amass oneforall dnsx httpx naabu nmap masscan fofa_search shodan_search zoomeye_search quake_search waybackurls gau katana jsluice arjun x8 ffuf gobuster dirsearch feroxbuster nuclei fscan upsert_project_fact list_project_facts search_project_facts
metadata:
  tags: [渗透测试, penetration-testing, recon, osint, information-gathering]
  source_augment: Hi-FullHouse/CyberSecurity-Skills
---

# 攻击面测绘（增强版）

输入必须包含目标类型、in-scope 边界、已完成来源和扫描模式。先读 Do-Not-Repeat；上游已有结果时只补缺口。

- 完整矩阵、资产评分与 JS/API：`references/comprehensive-recon.md`
- 来源/端点 fact 与退出门禁：`references/recon-fact-schema.md`（Deep 必读）
- **命令级 OSINT 清单**：优先 `skill recon-osint-playbook`，或 `references/csskills-recon/`
- **扫描器自动化线索**（仍 tentative）：`references/csskills-scan/`

## 工具流水线（MCP 名 = 实际调用名）

1. 根域：Quick=`subfinder`+CT；Standard=`subfinder`+异构来源+`dnsx`；Deep=`subfinder` + `oneforall` + 补 amass/CT/历史/空间测绘，逐项记 raw/增量。
2. `dnsx` 清洗与通配基线；品牌关联先记证据再主动测。
3. `httpx` 指纹；`naabu` 重点端口；高价值 `nmap -sCV`；Deep 补长尾端口。空间引擎：`fofa_search`/`shodan_search`/`zoomeye_search`/`quake_search`（有 key 才调）。
4. Web：`katana`/`gau`/`waybackurls` + JS/`jsluice` → `recon/endpoint/*`。
5. 参数/路径：`arjun`/`x8`/`ffuf`（可补 `gobuster`/`dirsearch`/`feroxbuster`），先建 SPA catch-all 基线。
6. `nuclei` 仅 tentative，禁止直接 `record_vulnerability`。

### 系统工具补全速查

| 阶段 | 优先 MCP | 备选 |
| --- | --- | --- |
| 子域 | `subfinder`、`oneforall` | `amass` |
| DNS | `dnsx` | `dnsenum`/`fierce` |
| HTTP/端口 | `httpx`、`naabu` | `nmap`/`masscan`/`fscan` |
| 历史/爬取/JS | `waybackurls`、`gau`、`katana`、`jsluice` | — |
| 参数 | `arjun`、`x8`、`ffuf` | 目录爆破工具 |
| 落库 | `upsert_project_fact` | `list_project_facts`/`search_project_facts` |

### 触发衔接

- 纯命令/语法/OSINT 百科 → `skill recon-osint-playbook`。
- 进入验证 → `web-attack-methods` / `api-security-testing` + `pentest-verification`。
- 每步成功或 blocked → 立即 fact；结案前核对缺口。

## 按目标类型裁剪

```text
root_domain → 被动 OSINT → 子域增量 → DNS 清洗 → HTTP/重点端口
single_url  → 当前站点爬取 → 历史 URL → 路径/参数
ip_or_cidr  → 端口/服务 → 证书与反向解析关联
host_list   → 去重 → DNS/HTTP 批处理
```

## CSS 知识库索引（按需 read_file）

| 主题 | 路径 |
| --- | --- |
| 被动 OSINT | `references/csskills-recon/被动信息搜集-PassiveRecon.md` |
| 主动侦察 | `references/csskills-recon/主动信息搜集-ActiveRecon.md` |
| DNS | `references/csskills-recon/DNS枚举-DNSEnumeration.md` |
| 子域 | `references/csskills-recon/子域名探测-SubdomainDiscovery.md` |
| 空间引擎 | `references/csskills-recon/网络空间搜索引擎-OSINT-SearchEngine.md` |
| 社工情报 | `references/csskills-recon/社会工程学信息-SocialEngineeringInfo.md` |
| 技术栈 | `references/csskills-recon/目标技术栈识别-TechStackFingerprint.md` |

## 交付与退出门禁

输出 Source Coverage、Assets、Live Services、Entry Points、Top-N、增量、Do-Not-Repeat、Gaps。

**全面/Deep 侦察只有在以下账本**满足 `recon-fact-schema` 硬闸门时才可结案；高价值 gap 存在时不得结案。