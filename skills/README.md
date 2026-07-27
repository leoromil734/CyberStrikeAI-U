# Skills 目录（Agent Skills / Eino）

- 每个技能为**子目录**，根上必须有 **`SKILL.md`**（YAML front matter：`name`、`description` + Markdown 正文），见 [agentskills.io](https://agentskills.io/specification.md)。
- **目录名须与 `name` 一致**。
- **运行时加载**：在 **Eino DeepAgent（多代理）** 会话中由 ADK **`skill` 中间件**渐进披露（系统提示中列出各 skill 的 name/description，模型再调用 **`skill`** 工具拉取 `SKILL.md` 全文）。可选开启 **`multi_agent.eino_skills.filesystem_tools`**，使用与本机相同的 `read_file` / `execute` 等访问包内脚本与资源。
- **Web 管理**：HTTP `/api/skills/*` 仍用于列表、编辑、上传包内文件（实现为 `internal/skillpackage`，非 MCP）。
- **运行时**：多代理（DeepAgent）会话内由 ADK **`skill`** 工具渐进加载；单代理 MCP 循环不含 Skills，需开多代理或后续单代理 Eino 路径。

## 挖洞推荐加载顺序

1. `pentest-agent-os`（索引与触发器）  
2. `pentest-verification` + `pentest-blackboard`（纪律）  
3. `attack-surface-recon`（Surface）  
4. 组件指纹后：`component-vuln-intel`  
5. Web 验证：`web-attack-methods`；API：`api-security-testing`；稳定浏览器/脚本边缘差分诊断：`cdn-tls-fingerprint`；深挖：`zero-day-discovery`

### 推荐 MCP 工具链（2025–2026 赏金向）

`subfinder` →（深度根域补 `oneforall`）→ `dnsx` → `httpx` → `naabu` → `nmap` → `katana`/`gau`/`ffuf` → `nuclei`(线索) → `sqlmap`/`dalfox`/`jwt-analyzer` + `interactsh-client`(OOB)
CDN 仅标注；标准客户端与浏览器有稳定受控差分时才加载 `cdn-tls-fingerprint`，确认 TLS 指纹后再安装 `curl_cffi`。

编排与角色提示已要求上述路由；**skill 不会自动执行**，需模型调用 `skill` 工具加载全文。

知识库补充目录（需启用 knowledge 并重新索引）：`SQL Injection/`、`XSS/`、`SSRF/`、`IDOR-BOLA/`、`API-Security-Top10/`、`JWT/`、`CDN-TLS-Fingerprint/`、`Prompt Injection/`。
