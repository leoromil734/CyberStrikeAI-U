# CyberSecurity-Skills 集成说明

来源：https://github.com/Hi-FullHouse/CyberSecurity-Skills （MIT）

## 集成策略

| 做法 | 原因 |
| --- | --- |
| 新建 `recon-osint-playbook` | 信息收集场景 description 关键词极密，提高 skill 工具命中率 |
| 把 01/02/03/04/05/06/16/17/32/34 等手册挂到现有 skill 的 `references/csskills-*` | 渐进披露：索引只见 name+description，细节按需 read_file |
| 强化 `pentest-agent-os` 路由表 | 默认先 OSINT/recon，再 Web/API 验证 |
| 各 skill 增加 **系统工具补全表** + `allowed-tools` | 把 CSS 百科工具名映射到本仓库 `tools/*.yaml` / 内置 MCP，降低臆造工具名 |
| 不注册全部 195 个为顶层 skill | 避免路由互相抢触发、上下文膨胀 |

## 路径一览

```text
skills/recon-osint-playbook/          # 新建：OSINT 高触发入口 + 工具表
skills/attack-surface-recon/references/csskills-recon/
skills/attack-surface-recon/references/csskills-scan/
skills/web-attack-methods/references/csskills-exploit/
skills/api-security-testing/references/csskills-api/
skills/post-exploitation/references/csskills-privesc|post|lateral/
skills/ai-llm-app-attack/references/csskills-llm/
skills/cloud-attack-methods/references/csskills-cloud/
skills/active-directory-attack/references/csskills-iam/
```

## 触发与工具补全约定

1. **触发**：靠 front matter `description` 中文/英文关键词；索引层只暴露 name+description，故关键词必须覆盖用户口语（「信息收集」「打域」「测 API」等）。
2. **补全**：每个增强 skill 正文含「系统工具补全」表，列为「场景 → 优先 MCP → 备选」；`allowed-tools` 列出建议工具名（空格分隔，与 agentskills 规范一致），运行时仍以实际注册工具为准。
3. **映射原则**：CSS 文档里的第三方 CLI 若无对应 YAML，用 `exec` / `execute-python-script` 兜底，并在 fact 记 `blocked`+`alt_tried`。
4. **落库**：侦察用 `upsert_project_fact`；可交付漏洞用 `record_vulnerability`（POC + validation），扫描器命中禁止直记。

### Skill → 核心 MCP 速查

| Skill | 核心工具簇 |
| --- | --- |
| `recon-osint-playbook` | subfinder, amass, oneforall, dnsx, httpx, naabu, nmap, fofa/shodan/zoomeye/quake_search, waybackurls, gau, katana, jsluice |
| `attack-surface-recon` | 同上 + arjun/x8/ffuf + list/search project facts |
| `web-attack-methods` | sqlmap, dalfox, http-framework-test, interactsh, dnslog, jwt-analyzer |
| `api-security-testing` | api-schema-analyzer, graphql-scanner, jwt-analyzer, http-framework-test |
| `post-exploitation` | linpeas, netexec, impacket, hydra, hashcat, responder |
| `active-directory-attack` | bloodhound, impacket, netexec, responder, enum4linux-ng |
| `cloud-attack-methods` | pacu, prowler, scout-suite, kube-hunter, trivy, checkov |
| `ai-llm-app-attack` | http-framework-test, interactsh, execute-python-script |

## 使用注意

- CSS 原文偏「工具百科」；本系统仍以 fact 账本、验证门禁、POC 与低危过滤为准。
- 扫描器输出一律 tentative，禁止直接 `record_vulnerability`。
- 更新上游时：浅克隆仓库后覆盖对应 `csskills-*` 目录即可；工具表以本仓库 `tools/` 为准同步修订。

## 更新命令示例

```bash
git clone --depth 1 https://github.com/Hi-FullHouse/CyberSecurity-Skills.git _tmp_csskills
# 再按模块复制到 skills/*/references/csskills-*
```