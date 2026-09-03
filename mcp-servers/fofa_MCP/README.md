# FOFA MCP（三账号限流切换）

[中文](README_CN.md)

Standalone stdio MCP for FOFA asset search. Compared with the built-in `fofa_search` YAML tool, this server can rotate **primary → backup → backup2** when FOFA returns 429 / 820041 / daily quota.

## Tools

| Tool | Description |
|------|-------------|
| `get_alerts` | Search FOFA by domain / IP / port / host / body / icon_hash / icp / status_code. |

## Requirements

- Python 3.10+
- `uv` (recommended) or `pip install httpx python-dotenv "mcp>=1.9.0,<2"`

## Credentials

Copy `.env.example` to `.env` (gitignored). Never put keys in skills, reports, or chat.

```env
FOFA_EMAIL=your_email@example.com
FOFA_KEY=your_fofa_api_key
FOFA_EMAIL_BACKUP=
FOFA_KEY_BACKUP=
FOFA_EMAIL_BACKUP2=
FOFA_KEY_BACKUP2=
```

`FOFA_API_KEY` is accepted as an alias of `FOFA_KEY`.

## Setup in CyberStrikeAI

Web UI → **Settings** → **External MCP** → paste (replace paths):

```json
{
  "fofa": {
    "command": "uv",
    "args": ["run", "--directory", "/absolute/path/to/CyberStrikeAI/mcp-servers/fofa_MCP", "python", "fofa.py"],
    "description": "FOFA search with primary/backup/backup2 rotation",
    "timeout": 60,
    "external_mcp_enable": true
  }
}
```

Or with project venv:

```json
{
  "fofa": {
    "command": "/absolute/path/to/CyberStrikeAI/venv/bin/python3",
    "args": ["/absolute/path/to/CyberStrikeAI/mcp-servers/fofa_MCP/fofa.py"],
    "timeout": 60,
    "external_mcp_enable": true
  }
}
```

Save and **Start**. SRC hunting (`src-hunting`) prefers built-in `fofa_search` first; use this MCP when you need multi-account failover.

## Cursor / other MCP clients

```json
{
  "mcpServers": {
    "fofa": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/CyberStrikeAI/mcp-servers/fofa_MCP", "python", "fofa.py"]
    }
  }
}
```

## Fallback helper

`fofa_dual.ps1` reads the same env vars. Do not hardcode keys in the script.
