# 角色配置文件说明

本目录包含所有角色配置文件，每个角色定义了 AI 的行为模式与可用工具。

## 创建新角色

创建新角色时，请在 `roles/` 目录下创建 YAML 文件，格式如下：

**方式1：显式指定工具列表（推荐，利于挖洞聚焦）**

```yaml
name: 角色名称
description: 角色描述
user_prompt: |
  用户提示词（追加到用户消息前）
  建议写清：发现闭环、技能名、禁止把扫描当漏洞、落库节奏
icon: "图标（可选）"
tools:
  - httpx
  - nuclei
  - record_vulnerability
  - upsert_project_fact
  - list_knowledge_risk_types
  - search_knowledge_base
enabled: true
```

**方式2：不设置 tools 字段（使用所有已开启的工具）**

```yaml
name: 角色名称
description: 角色描述
user_prompt: 用户提示词
icon: "图标（可选）"
# 不设置 tools → 全部已开启 MCP 工具（噪声大，挖洞场景不推荐）
enabled: true
```

## 挖洞相关角色（已加强）

| 角色 | 侧重点 |
|------|--------|
| 信息收集 | 攻击面与入口，默认不结案漏洞 |
| Web应用扫描 | Web 闭环验证 |
| API安全测试 | Schema/JWT/越权 |
| Web框架测试 | 框架/中间件特征与复现 |
| 渗透测试 | 全链路发现与验证 |
| 综合漏洞扫描 | 扫描线索 + 强制验证段 |

## 核心内置工具（写了 tools 时建议包含）

1. `record_vulnerability` / `list_vulnerabilities` / `get_vulnerability`
2. `upsert_project_fact` 及 get/list/search/deprecate/restore
3. `list_knowledge_risk_types` / `search_knowledge_base`
4. 长任务：`get_tool_execution` / `wait_tool_execution` / `cancel_tool_execution`
5. 结果原件与覆盖库存：`list_result_artifacts` / `read_result_artifact` / `assemble_result_evidence` / `query_recon_inventory` / `register_result_artifact`

覆盖检查依赖数据库中的真实发现库存；承担发现、验证或交付的角色需要第 5 组工具读取原件及工作组，再按实际证据写入处置事实。`discovery-*` 是数据库标识，不是文件路径。结果工具仍执行原有用户、会话及项目访问检查；工具可见不代表允许访问其他会话或扩大测试范围。

非空白名单会先过滤工具，内置工具的“常驻”设置不能恢复被过滤的工具。`tool_search` 只检索非常驻工具，返回空不代表常驻工具不可用；应以当前工具 schema 为准。自定义角色的显式白名单不会被自动扩展。

**Skills**：多代理 / Eino 会话中由 `skill` 工具加载 `skills/`，与角色 YAML 无自动绑定；请在 `user_prompt` 中写明建议加载的 skill 名。

## 字段说明

- **name** / **description** / **enabled**：必填语义字段
- **user_prompt**：追加到用户消息前，引导方法与纪律
- **tools**：非空=白名单；省略或空列表在运行时通常表示不限制（与 Agent 一致：空=全部）
- **icon**：可选

注意：子代理 `agents/*.md` 的 `tools` 与角色相互独立；子代理可 `bind_role` 在未写 tools 时继承角色工具列表。

## 生效方式

`roles/*.yaml` 在服务加载配置时读入内存，单改磁盘文件不会更新当前进程；可通过角色管理保存配置，或在合适窗口重启服务加载。`agents/*.md` 在下一次构建运行对象时读取。已经运行的工具集合不会被热替换，修改代码中的工具提示还需要重新构建并部署服务；不要为更新工具而中断其他任务。
