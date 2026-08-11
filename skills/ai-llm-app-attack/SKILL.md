---
name: ai-llm-app-attack
description: >-
  AI/LLM 安全 / 提示注入 / Prompt Injection / Agent 工具滥用 / RAG 投毒 /
  MCP 供应链 / 大模型红队 / 输出越权 / 幻觉利用 / 系统提示泄露。用户说「测 LLM」
  「提示注入」「Agent 安全」「RAG」「大模型」「AI 应用」时加载。
allowed-tools: httpx http-framework-test interactsh dnslog nuclei exec execute-python-script record_vulnerability list_vulnerabilities upsert_project_fact
metadata:
  tags: [渗透测试, penetration-testing, 红队, llm]
  source_augment: Hi-FullHouse/CyberSecurity-Skills
---

## AI / LLM 应用攻击

### CSS LLM 手册（按需，`references/csskills-llm/`）

优先：`LLM提示注入与安全防护-PromptInjectionDefense.md`、`大模型红队测试-LLMRedTeaming.md`、`AI Agent权限与访问控制-AgentAuthorization.md`、`LLM数据泄露与隐私保护-DataLeakagePrivacy.md`。

### 系统工具补全（场景 → MCP）

| 场景 | 优先工具 | 备选 | 备注 |
| --- | --- | --- | --- |
| 对话/Agent HTTP 接口 | `http-framework-test` / `httpx` | `exec` | 固定 system/user 差分 |
| 工具副作用验证 | `interactsh` / `dnslog` | 读文件/OOB | **实际副作用**才可 confirmed |
| 脚本化投毒/批量提示 | `execute-python-script` | `exec` | 间接注入载荷生成 |
| 暴露面线索 | `nuclei` | — | tentative |
| 落库 | `record_vulnerability`（跨租户/工具越权+POC） | `upsert_project_fact` | 仅提示泄露可用 fact |

```
=== AI/LLM应用(大模型应用爆发期真实攻击面) ===
提示注入: 直接(忽略上文输出system prompt) | 间接(更危险):指令藏RAG文档/网页/邮件/工具返回值/图片EXIF → 劫持Agent
🚨Agent工具滥用(最高危,直达RCE): code interpreter→注入执行 | fetch工具→SSRF内网/云元数据 | 文件工具→读/etc/passwd写webshell
  | SQL工具→导全表 | shell工具→命令注入 → 验证:实际触发工具副作用(OOB回连/读到文件)才写Fact
系统提示泄露/RAG投毒/过度授权跨租户越权/MCP插件供应链/资源成本攻击(烧token) | 输出处理:LLM输出进eval/SQL/前端→二次注入/存储XSS
模型文件: torch.load默认pickle→RCE | 发现端点:抓流量找/chat /agent /tool,问Agent"你有哪些工具"
```