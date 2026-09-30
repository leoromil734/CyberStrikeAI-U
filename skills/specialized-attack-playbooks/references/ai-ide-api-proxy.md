### AI IDE API反代/key泄露目录(发现并评估AI编程工具反代方案)
```
背景: Cursor Web免费API 2026-04起只剩gemini-3-flash,Claude全砍 → 拿Claude 4.6+需其他渠道
可用方案: freemodel-cc-proxy(免费,FreeModel真Claude,伪装Claude Code指纹绕403,Opus4.8/Sonnet4.6) | WindsurfAPI(dwgx,Windsurf gRPC转API,100+模型,账号池轮询)
  askalf/dario(Claude Pro/Max订阅转API,绕headless计费) | bypass/chatgpt-adapter(xllm-go,多家逆向接口聚合转OpenAI格式)
已废: cursor2api/cursor2api-go(只剩gemini-3-flash) | 辅助: claude-tap(MITM拦AI Agent真实流量研究system prompt/工具调用)
GitHub搜索法: api.github.com/search/repositories?q=cursor+api+reverse+proxy&sort=stars → 过滤desc → /repos/<o>/<r>/readme(base64解码读) → /search/issues查最新状态
关键词: cursor api reverse proxy / cursor workos token / claude proxy cursor / AI IDE api reverse engineering
```
