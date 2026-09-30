# Token 与上下文保真优化

## 实施范围

本次只改变重复内容的表示与资料加载时机，不减少测试方向或工具能力。

- 保留全部共享范围、证据、独立安全边界、全面覆盖、负结果与收尾契约。
- 工具注册表、角色工具白名单、常驻/动态划分和参数 schema 不变；完整工具名称索引仍保留。
- 没有下调上下文窗口、单条输出上限、用户输入上限、事实索引或模型输出上限；没有修改线上配置。
- 普通唯一用户输入保持原文；没有引入按相关性过滤用户历史或由模型自由摘要约束的步骤。

## 1. 共享提示去重

`injectShellToolGuidance` 仅检测完全相同的共享 Shell 说明：已由 `ComposeSystemPrompt` 注入时不再复制；自定义或不同版本的说明仍保留。工具名称索引中的重复操作提醒改为紧凑表达，但仍要求：

1. 名称不是参数 schema，不能猜测参数或臆造工具名。
2. 动态工具的 schema 尚未可见或参数不确定时，必须先 `tool_search`。
3. `regex_pattern` 按名称检索；搜索仅返回名称，下一轮看到并读取 schema 后才调用。
4. 不得为节省 token 或赶进度跳过该顺序。

## 2. 子任务交接的无损复用

Deep 的 `task` 交接仍包含全部用户输入与完整项目索引。仅对两类逐字相同的内容进行字典复用：

- 多轮输入共享的完整角色 `user_prompt` 前缀。
- 较长且完全相同的用户输入。

表示中保留每轮的 `turn`；`prefix` 引用完整前缀，`ref` 引用此前轮次的完整原文。`A → B → A` 仍有三个有序轮次，最后一次 A 不被当成无效重复删除。URL、身份、禁止项、请求体、Payload、内部空格与换行均可逐字节还原。

压缩表示不比原文短、内容不重复或存在无效 UTF-8 时，回退原文。没有删除独有输入，也没有选择“最相关”的历史。

默认 `sub_agent_user_context_max_runes: 0` 仍完整保留全部轮次。已有显式正数上限的兼容行为保留：先尝试无损表示；若仍超限，使用既有首尾预览，而不是截断 JSON 或产生无法解析的引用。本次没有新增、更严格的截断预算；严格保真任务应维持默认 0，不将小字符上限当成语义保真方案。

已包含同一完整交接块的任务在重试时不会再次追加该块。

## 3. Skill 渐进加载

### specialized-attack-playbooks

原来全内联的资料移为九个可读取专题：GoEdge、CDN 取证、同二层网络场景、CDN/S3 链、宝塔、UniApp、ChengZi、AI IDE 接口方案、OCS/MinIO。入口保留每个方向、前提、升级判断和实际文件路径；选一个专题无需读取其他专题。

原支持索引中的发卡、PHPCMS、Spring/Actuator、WebSocket/SockJS/STOMP、nginx/PHP 等探索线索仍可见，完整名称索引在原文归档。原项目并未附带那些额外文件或脚本，所以标注为历史未附带材料，不伪造路径，也不据此将方向记成已测或已排除。

### cdn-tls-fingerprint

入口继续保留受控客户端差分条件、请求状态对齐、S0–S3 全部分支、五类结论、停止/替代路径及证据要求。安装、复用脚本和详细失败诊断放到按需参考，不把 `curl_cffi` 变成默认客户端。

### 原文保真

两个包各有 `references/original-skill.md`，保存优化前 c0bb176 的完整 Git 文件内容（含 frontmatter、所有正文、历史索引、空格与文件末尾）。SHA-256、Git blob 标识及字节数均固定在回归测试中。

归档使用包内 `.gitattributes` 禁用文本换行转换，保持仓库 LF 原始字节。Windows `core.autocrlf` 的 CRLF 检出形式不是归档基线。正文迁移测试只对跨平台换行作等价处理；原文归档哈希校验本身不归一化。

原文归档是审计和必要时取回入口，不默认预加载。

## 4. 完整请求预算

最终预算校验计入当前请求的全部工具 schema，并预留当前模型已经配置的输出额度。单代理、Deep/监督者、子代理及 Plan-Execute 规划/执行路径均使用同一计算方式。

预算紧张时使用已有历史压缩与溢出恢复机制，不删除工具、参数定义或共享契约。工具/输出预留本身超过窗口，或计数不可用时，保持上下文完整交给恢复路径，不在本地伪造“已压缩成功”。

## 回归与测量

相关测试覆盖：

- 每轮输入逐字节重建、非相邻重复的顺序、多前缀确定性、Payload 空白、无效 UTF-8 回退。
- 任务重试不重复追加，项目索引和当前约束完整保留。
- 全部工具名称及共享契约保留，动态 schema 加载顺序不变。
- 全部专题路由真实可读、元数据不变、完整原文归档及各专题正文保留。
- CDN 触发、决策、结论、替代路径、脚本及证据条件。
- 预算包含 schema/输出预留，当前约束和最近工具往返成对保留，工具集合不变。

固定样本用 `gpt-4o` 对应分词器估算，结果不是供应商账单或真实任务整体降幅：

- 完整系统提示 + 61 个工具名称：3821 → 3399 tokens，减少 11.0%；共享契约和名称全部保留。
- 8 轮重复角色前缀交接：5000 → 934 tokens，减少 81.3%；8 轮均逐字节重建。
- 专题 Skill 首次完整入口文本：3988 → 1324 tokens，减少 66.8%。
- 专题入口 + 最大单篇完整专题：3988 → 2030 tokens，减少 49.1%；包含实际详细资料读取成本。
- CDN Skill 首次完整入口文本：1528 → 1218 tokens，减少 20.3%。

如果最终读取全部专题，按需读取也会产生 token；本次没有以首层数字承诺整场任务费用下降。实际收益应通过同一任务的总输入/输出、工具调用、摘要与重试次数，以及覆盖账本和证据完整性对比确认。

## 验证命令

针对保真与体量：`go test -count=1 -v -run 'Test(LosslessUserContext|TaskContext|ConfiguredRolePrompts|ToolIndexOptimization|ContextTokenOptimization|ContextLayering|ModelInputSoftBudget|InjectShellToolGuidance)' ./internal/multiagent ./internal/skillpackage`

相关包完整回归：`go test -count=1 -p 4 ./internal/coverage ./internal/projectprompt ./internal/skillpackage ./internal/agents ./internal/vulnquality ./internal/database ./internal/agentfinalizer ./internal/handler ./internal/multiagent ./internal/project ./internal/knowledge ./internal/app`

编译检查：`go build ./...`

Windows 上 SQLite 的 C 编译可受本机 GCC 对大对象文件支持限制影响；本次测试进程临时使用 Zig cc，未改变 go.mod 或持久工具链配置。
