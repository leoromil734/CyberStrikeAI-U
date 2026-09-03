# FOFA MCP（三账号限流切换）

[English](README.md)

独立 stdio MCP，用于 FOFA 资产搜索。相对内置 YAML 工具 `fofa_search`，本服务在 429 / 820041 / 日上限时会按 **主号 → backup → backup2** 自动切账号。

## 工具

| 工具 | 说明 |
|------|------|
| `get_alerts` | 按域名 / IP / 端口 / host / body / icon_hash / icp / 状态码组合查询。 |

## 依赖

- Python 3.10+
- 推荐 `uv`；或 `pip install httpx python-dotenv "mcp>=1.9.0,<2"`

## 凭证

复制 `.env.example` 为 `.env`（已 gitignore）。**禁止**把 Key 写进 skill、报告或对话。

```env
FOFA_EMAIL=your_email@example.com
FOFA_KEY=your_fofa_api_key
FOFA_EMAIL_BACKUP=
FOFA_KEY_BACKUP=
FOFA_EMAIL_BACKUP2=
FOFA_KEY_BACKUP2=
```

`FOFA_API_KEY` 可作为 `FOFA_KEY` 的别名。

## 在 CyberStrikeAI 中接入

Web 界面 → **设置** → **外部 MCP**，填入（路径换成你的绝对路径）：

```json
{
  "fofa": {
    "command": "uv",
    "args": ["run", "--directory", "/你的路径/CyberStrikeAI/mcp-servers/fofa_MCP", "python", "fofa.py"],
    "description": "FOFA 搜索（主号/备用号限流切换）",
    "timeout": 60,
    "external_mcp_enable": true
  }
}
```

或使用项目 venv 的 Python，`args` 指向本目录 `fofa.py`。保存后点击 **启动**。

`src-hunting` 默认先走内置 `fofa_search`；需要三账号自动切流时再启本 MCP。

## 备用脚本

`fofa_dual.ps1` 读取同样的环境变量，不要把真实 Key 写进脚本。
