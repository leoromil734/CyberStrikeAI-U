#!/usr/bin/env python3
"""通过 stdio 连接 CloakBrowser MCP Server，验证工具列表与真实调用。"""

import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = sys.argv[1] if len(sys.argv) > 1 else "/opt/CyberStrikeAI-U/mcp-servers/cloakbrowser/mcp_cloakbrowser.py"
PYTHON = "/opt/cloakbrowser-mcp/venv/bin/python"


async def main() -> int:
    params = StdioServerParameters(command=PYTHON, args=[SERVER], env=None)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print(f"TOOLS({len(names)}): {', '.join(names)}")

            async def call(name, args=None):
                result = await session.call_tool(name, args or {})
                text = "\n".join(
                    part.text for part in result.content if getattr(part, "type", "") == "text"
                )
                print(f"\n=== {name} {args or ''} ===")
                print(text[:900])
                return text

            await call("browser_navigate", {"url": "https://example.com"})
            await call("browser_snapshot")
            await call("browser_extract", {"format": "text", "max_chars": 400})
            await call("browser_screenshot", {"name": "verify"})
            await call("browser_state", {"action": "status"})
            await call("browser_close")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
