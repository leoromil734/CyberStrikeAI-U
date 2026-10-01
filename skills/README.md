# Skills 目录（Agent Skills / Eino）

每个 Skill 是独立子目录，根文件为 `SKILL.md`，目录名必须与 front matter 的 `name` 一致。格式遵循 [Agent Skills specification](https://agentskills.io/specification.md)。

允许的顶层 front matter 字段只有：`name`、`description`、`license`、`compatibility`、`metadata`、`allowed-tools`。标签放在 `metadata.tags`，不要使用顶层 `tags`。

## 三层渐进披露

```text
系统提示：共享运行契约
  ↓
Skill 索引：name + description，用于路由
  ↓ skill
SKILL.md：短决策树、执行流程、系统工具补全表
  ↓ read_file（仅在命中场景时）
references/：详细矩阵、检查表和专题证据要求
```

Eino Skill 中间件只在配置启用时向模型披露索引；模型调用 `skill` 后才加载正文。`references` 不会自动进入上下文，入口页应明确何时读取哪个文件。

## 触发与工具补全（增强 skill）

| 层级 | 作用 |
| --- | --- |
| `description` 关键词 | 提高「信息收集 / 测 API / 打域 …」等口语命中，决定是否调用 `skill` |
| `allowed-tools` | 声明本 skill 建议使用的 MCP/YAML 工具名（空格分隔）；未注册工具不可用 |
| 正文「系统工具补全」表 | 场景 → 优先工具 → 备选 → 落库，避免 CSS 百科名与本系统工具名不一致 |

集成细节见 `CSSKILLS_INTEGRATION.md`。

## 最小加载策略

一次任务通常最多加载：

1. 一个扫描模式：`pentest-scan-quick`、`pentest-scan-standard` 或 `pentest-scan-deep`。
2. 一个领域 Skill：例如 `web-attack-methods`、`api-security-testing`、`source-aware-whitebox`；**侦察阶段**可用 `recon-osint-playbook`（+ 可选 `attack-surface-recon`）。
3. 一个验证 Skill：`pentest-verification`。

需要黑板字段细节时再加载 `pentest-blackboard`；需要报告格式时再加载 `pentest-output-standards`。不要把所有方法 Skill 当作常驻前置。

### 扫描模式不是编排模式

- `quick`：时间盒初筛和高信号入口。
- `standard`：默认深度，平衡覆盖与验证。
- `deep`：复杂身份/状态机、源码白盒或高价值候选的深入闭合。

它们描述**测试深度**，与 single、Deep、Supervisor、Plan-Execute 的**执行编排**相互独立。用户未指定测试深度时选择 `standard`。

## 推荐路由

- 任务起点不清楚：`pentest-agent-os` 只负责选择最小 Skill 集。
- **信息收集 / OSINT / 子域 / FOFA 等（高触发）**：扫描模式 + `recon-osint-playbook`；需要覆盖账本/门禁时再加 `attack-surface-recon`。
- 资产与入口测绘：扫描模式 + `attack-surface-recon`（含 `references/csskills-recon|scan`）。
- **SRC / 挖集团 / 写中文 SRC 报告**：扫描模式 + `src-hunting` + `pentest-verification`；与 `web-attack-methods` 二选一，不要叠成两个领域。集成说明见 `SRC_HUNTING_INTEGRATION.md`。
- Web 候选：`web-attack-methods`（含 `references/csskills-exploit`），再按入口读单个 reference。
- API/BOLA/JWT/GraphQL：`api-security-testing`（含 `references/csskills-api`）。
- 源码或构建配置可用：`source-aware-whitebox`。
- 组件版本情报：`component-vuln-intel`，输出保持 tentative。
- 云 / LLM / AD / 后渗透：`cloud-attack-methods`、`ai-llm-app-attack`、`active-directory-attack`、`post-exploitation`（均挂了 CSS 手册 references + 工具表）。
- 浏览器与标准客户端稳定边缘差分：先排除状态差异，再 `cdn-tls-fingerprint`。
- 已确认 Next.js/NestJS/FastAPI/Django 安全边界：切 `framework-security-testing`，只读对应框架。
- 已确认 Supabase/Firebase 项目/对象：切 `managed-backend-security`，区分真实授权引擎。
- Vault、消息缓存、监控数据源、SCM/CI、IaC 产物、IdP 或 CMS/LMS 产品权限：切 `infra-control-plane-testing`，每次一份 reference；端口/非404不是可靠触发。
- 获准 diff、补丁或历史 PoC：切 `security-regression-testing`；它是工作流，不是第四扫描深度。
- OCI、iOS、移动保护、Electron、n8n 和 MCP 审批在现有云/移动/AI 入口按需展开；已有 AD、Android、固件知识复用，不重复注册近义技能。

### 外部知识来源（取长补短）

部分 `references/csskills-*` 与 `recon-osint-playbook` 改编自 [Hi-FullHouse/CyberSecurity-Skills](https://github.com/Hi-FullHouse/CyberSecurity-Skills)（MIT）。策略：

- **不**把 195 个百科条目全部注册为顶层 Skill（避免索引稀释、误触发）。
- **做**高触发 `description` 关键词 + 按阶段挂载 references + 路由器强制「先 recon 后利用」+ **系统工具名映射表**。

扫描、搜索、版本匹配和静态命中都只是 tentative 线索；只有 `pentest-verification` 定义的目标侧证据闭环完成后，才能记录 confirmed 漏洞。负结果同样需要保留测试条件和 Do-Not-Repeat。

### 三项目知识增量（2026-10-01）

本次对照 Strix `007ed1a`、NeuroSploit `5d4e7e0`、Dark-Moon `cb0d9b8`，只引入知识与 skills，不移植运行引擎、全局提示、部署或其他架构设计。能力/来源/落点及正反案例见 `docs/knowledge-skill-integration/manifest.json`，说明与许可见同目录 README 和 licenses。

- 知识库保存独立原理/验证资料；短 references 保存可直接执行的决策流程，不依赖知识服务开启。
- 新增四个独立入口保留 SRC 让路、一次一个领域和验证规则；旧入口保留并挂按需资料。
- Apache/MIT 归属保留；Dark-Moon 已记录用户原作者改编许可，本批文档仍保留原 GPLv3 标注和完整文本，根 LICENSE 不变。
- 内容/引用/路由测试和临时库目录扫描为离线验收；没有自动调用 embedding、重建现网索引或测试外部目标，未以文件数宣称发现率提升。

## 包内容

Skill 可按需包含：

- `references/`：只读的详细方法与矩阵。
- `scripts/`：可复用脚本，由 `execute` 运行。
- `assets/`：模板、字典或示例产物。

Web 管理接口由 `internal/skillpackage` 统一校验和保存；运行时与管理端必须接受同一套 front matter。