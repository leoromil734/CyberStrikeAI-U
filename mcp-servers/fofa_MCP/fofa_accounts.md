# FOFA 三账号（挖洞用）

策略：**优先主号** → 遇 429 / 请求频繁 / 820041 / 日上限 → **自动切备用1** → 再用 **备用2**。

| 角色 | 环境变量 | 备注 |
|------|----------|------|
| 主号 primary | `FOFA_EMAIL` / `FOFA_KEY` | 必填 Key |
| 备用 backup | `FOFA_EMAIL_BACKUP` / `FOFA_KEY_BACKUP` | Email 可空，只传 key 也可 |
| 备用2 backup2 | `FOFA_EMAIL_BACKUP2` / `FOFA_KEY_BACKUP2` | 前两个用尽才用 |

Key 只写在本目录 `.env` 或外部 MCP 的 env 配置里，不要抄进对话 / skill / 知识库 / 报告。

## 配置位置

- `mcp-servers/fofa_MCP/.env`（推荐）
- CyberStrikeAI 外部 MCP 条目的 env
- 内置单账号路径：`config.yaml` → `fofa.api_key`（工具名 `fofa_search`）
- 逻辑：`fofa.py` 内 `_account_list` + `_exhausted` + `_is_rate_limited`

## 注意

- MCP 改 env 后需**重启该外部 MCP** 才进进程。
- 三个都限流 → 停 FOFA，挖已入库资产。
- 备用 PowerShell：`fofa_dual.ps1` 读同一套环境变量，禁止把 Key 写进脚本。
