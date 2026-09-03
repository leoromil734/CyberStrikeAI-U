# SRC Hunting Skill 集成说明

来源：工作区 `clown-src-6k-skill`（SRC 挖洞 + 白盒审计技能包）。

## 集成策略

| 做法 | 原因 |
| --- | --- |
| 新建顶层 `src-hunting` | 口语触发极密（挖 SRC / 挖某集团 / 测这个站 / 写漏洞报告），避免被 `web-attack-methods` 抢走 |
| 知识库进 `skills/src-hunting/references/` | 渐进披露：索引只见 name+description，进站先短表再开单篇 |
| 规则进 `references/rules/` | 挖什么、锁面/自由跳、报告版式、短表迭代不再依赖 `~/.grok/rules` |
| 工具名改成本仓库 MCP/YAML | `fofa` / `fofa__get_alerts` → `fofa_search`（内置）或外部 `get_alerts` |
| 不把 48 篇知识库注册成独立 skill | 避免索引稀释、上下文膨胀 |

与 CSS 手册的关系：`web-attack-methods` 仍负责单站注入/XSS 等通用 Web 方法；`src-hunting` 负责国内 SRC 节奏（一种子闭环、价值矩阵、中文报告闸）。同一阶段只选一个领域 skill。

## 路径一览

```text
skills/src-hunting/SKILL.md
skills/src-hunting/references/          # 48 篇测试模块 + 打穿短表
skills/src-hunting/references/rules/    # dig-scope / src-value / vuln-report-format 等
mcp-servers/fofa_MCP/                   # 三账号限流切换的外部 FOFA MCP（可选）
```

## 运行时怎么走

1. 用户说「挖某某集团 / 测这个站 / 写 SRC 报告」，或已在 SRC/漏洞赏金/白帽上下文中继续说越权、接口、注入、上传、WAF、JS → `skill src-hunting`。
2. 加载后先读 `references/routing-index.md`；每个新站再读 `references/打穿短表.md`，由现场信号选 1～3 篇专题。
3. 固定 URL 清单 = 锁面；只有集团名 = 自由跳一种子闭环。
4. 测绘：优先内置 `fofa_search`；需要三账号自动切流时再启外部 `mcp-servers/fofa_MCP` 的 `get_alerts`。
5. 中危/高危/严重确认后按 `references/rules/vuln-report-format.md` 落盘，并 `record_vulnerability`（须完整 POC + validation）。CORS 不挖。

## 更新上游

覆盖 `references/` 与 `references/rules/` 后，把文中的 `~/.grok/rules`、`知识库/`、`fofa__get_alerts` 再映射回本仓库路径与工具名。不要把 `.env` 或 helper 脚本里的真实 Key 提交进仓库。
