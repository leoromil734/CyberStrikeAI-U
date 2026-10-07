---
name: attack-surface-recon
description: >-
  攻击面测绘 / 信息收集 / 侦察 / recon / OSINT / 子域名枚举 / DNS / 端口存活 / httpx /
  资产发现 / JS API 提取 / 目录参数 / 证书透明度 / FOFA Shodan ZoomEye Quake /
  wayback / katana / jsluice / dirsearch / arjun / x8 / ffuf / 覆盖账本 / recon fact /
  退出门禁 / Deep 硬闸门。用于 Surface、摸底、打点前资产清单、阶段 ledger；
  用户说「信息收集」「收集信息」「侦察」「找资产」「扫子域」「全面侦察」
  「攻击面」「资产清单」「覆盖率」时优先加载（可与 recon-osint-playbook 联用）。
  已有 SRC、漏洞赏金、挖集团/品牌上下文时以 `src-hunting` 为领域入口，本 skill 仅在
  独立侦察/覆盖账本阶段加载；不用于深度漏洞确认；测试深度由 pentest-scan-quick/standard/deep 选择。
allowed-tools: exec subfinder amass oneforall dnsx httpx naabu nmap masscan fofa_search crtsh_search shodan_search zoomeye_search quake_search waybackurls gau katana jsluice arjun x8 ffuf gobuster dirsearch feroxbuster nuclei fscan upsert_project_fact list_project_facts search_project_facts
metadata:
  tags: [渗透测试, penetration-testing, recon, osint, information-gathering]
  source_augment: Hi-FullHouse/CyberSecurity-Skills
---

# 攻击面测绘（增强版）

输入含目标、in-scope、来源与模式。先读 Do-Not-Repeat，复用本轮 FOFA 证据，缺来源才补。

- 完整矩阵、资产评分与 JS/API：`references/comprehensive-recon.md`
- 来源/端点 fact 与退出门禁：`references/recon-fact-schema.md`（Deep 必读）
- **命令级 OSINT 清单**：优先 `skill recon-osint-playbook`，或 `references/csskills-recon/`
- **扫描器自动化线索**（仍 tentative）：`references/csskills-scan/`

## 工具流水线（MCP 名 = 实际调用名）

0. 线上初始侦察先实际调用 `fofa_search`；范围/原件/失败/复用见`recon-osint-playbook` 的 FOFA 起手规则。锁面只查当前host/IP，其他引擎仅补充；缺工具/key/配额记blocked，不冒充成功。
1. 根域：Quick=`subfinder`+crt.sh；Standard再加异构来源+`dnsx`；Deep=`subfinder` + `oneforall`+补源。尽早调`crtsh_search`，复用本轮证据；历史/通配证书仅候选，不证明存活/归属授权，不扩跨域SAN。去重后DNS/HTTP核实；partial/限流/失败记缺口，换来源，不循环查。
2. `dnsx` 清洗与通配基线；逐 IP 记录 CDN/范围证据，已证实 CDN 边缘不扩裸 IP；Hetzner 等托管商不是 CDN，范围内非 CDN IP 独立补服务/入口，unknown 留 gap/blocked，共享 IP 不推定归属。细节见 comprehensive-recon.md §2.1。
3. `httpx` 指纹；`naabu` 重点端口；高价值 `nmap -sCV`；Deep 补长尾端口。`shodan_search`/`zoomeye_search`/`quake_search` 按可用性补缺，不替代首步 FOFA。
4. Web：`katana`/`gau`/`waybackurls` + JS/`jsluice` + 实际 `grep/rg` 检索全部原源码 → 合并 `recon/endpoint/*`；命令与两路证据见 comprehensive-recon.md §4。
5. 目录、文件和扩展名枚举优先 `dirsearch`；参数、虚拟主机和自定义请求模糊测试优先 `ffuf`，隐藏参数用 `arjun`/`x8`。未链接路径尚未覆盖或发现需继续枚举的目录时做有界目录发现；先建 SPA catch-all 基线，同范围、认证态和候选集已有充分有效证据可引用复用，否则执行或留具体 blocked/N/A 理由（见 comprehensive-recon.md §3.1）。
6. `nuclei` 仅 tentative，禁止直接 `record_vulnerability`。

### 系统工具补全速查

| 阶段 | 优先 MCP | 备选 |
| --- | --- | --- |
| 首步 FOFA（必调） | `fofa_search` | 失败留 blocked；其他来源只补缺 |
| 子域 | `subfinder`、`oneforall` | `amass` |
| DNS | `dnsx` | `dnsenum`/`fierce` |
| HTTP/端口 | `httpx`、`naabu` | `nmap`/`masscan`/`fscan` |
| 历史/爬取/JS | `waybackurls`、`gau`、`katana`、`jsluice` | — |
| 目录/文件/扩展名 | `dirsearch` | `ffuf` 等价有界扫描 |
| 参数/虚拟主机/自定义请求模糊测试 | `ffuf` | `arjun`/`x8` 仅补隐藏参数 |
| 落库 | `upsert_project_fact` | `list_project_facts`/`search_project_facts` |

### 触发衔接

- 命令速查 → `skill recon-osint-playbook`。
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

完成状态以证据与所选候选集为准：目录发现仅爬取/JS 提取不算覆盖，超时未完成留 gap/blocked；同范围有效证据可以复用，不要求凑齐扫描器调用次数。

**全面/Deep 侦察只有在以下账本**满足 `recon-fact-schema` 硬闸门时才可结案；高价值 gap 存在时不得结案。