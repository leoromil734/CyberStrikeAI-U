# Skills 目录（Agent Skills / Eino）

每个 Skill 是独立子目录，根文件为 `SKILL.md`，目录名必须与 front matter 的 `name` 一致。格式遵循 [Agent Skills specification](https://agentskills.io/specification.md)。

允许的顶层 front matter 字段只有：`name`、`description`、`license`、`compatibility`、`metadata`、`allowed-tools`。标签放在 `metadata.tags`，不要使用顶层 `tags`。

## 三层渐进披露

```text
系统提示：共享运行契约
  ↓
Skill 索引：name + description，用于路由
  ↓ skill
SKILL.md：短决策树与执行流程
  ↓ read_file（仅在命中场景时）
references/：详细矩阵、检查表和专题证据要求
```

Eino Skill 中间件只在配置启用时向模型披露索引；模型调用 `skill` 后才加载正文。`references` 不会自动进入上下文，入口页应明确何时读取哪个文件。

## 最小加载策略

一次任务通常最多加载：

1. 一个扫描模式：`pentest-scan-quick`、`pentest-scan-standard` 或 `pentest-scan-deep`。
2. 一个领域 Skill：例如 `web-attack-methods`、`api-security-testing`、`source-aware-whitebox`。
3. 一个验证 Skill：`pentest-verification`。

需要黑板字段细节时再加载 `pentest-blackboard`；需要报告格式时再加载 `pentest-output-standards`。不要把所有方法 Skill 当作常驻前置。

### 扫描模式不是编排模式

- `quick`：时间盒初筛和高信号入口。
- `standard`：默认深度，平衡覆盖与验证。
- `deep`：复杂身份/状态机、源码白盒或高价值候选的深入闭合。

它们描述**测试深度**，与 single、Deep、Supervisor、Plan-Execute 的**执行编排**相互独立。用户未指定测试深度时选择 `standard`。

## 推荐路由

- 任务起点不清楚：`pentest-agent-os` 只负责选择最小 Skill 集。
- 资产与入口测绘：扫描模式 + `attack-surface-recon`。
- Web 候选：`web-attack-methods`，再按入口读取单个 reference。
- API/BOLA/JWT/GraphQL：`api-security-testing`，优先建立身份/对象差分矩阵。
- 源码或构建配置可用：`source-aware-whitebox`，从运行版本、入口、数据流和鉴权点生成动态 PoC。
- 组件版本情报：`component-vuln-intel`，输出保持 tentative。
- 浏览器与标准客户端存在稳定边缘差分：先排除状态差异，再使用 `cdn-tls-fingerprint`。

扫描、搜索、版本匹配和静态命中都只是 tentative 线索；只有 `pentest-verification` 定义的目标侧证据闭环完成后，才能记录 confirmed 漏洞。负结果同样需要保留测试条件和 Do-Not-Repeat。

## 包内容

Skill 可按需包含：

- `references/`：只读的详细方法与矩阵。
- `scripts/`：可复用脚本，由 `execute` 运行。
- `assets/`：模板、字典或示例产物。

Web 管理接口由 `internal/skillpackage` 统一校验和保存；运行时与管理端必须接受同一套 front matter。