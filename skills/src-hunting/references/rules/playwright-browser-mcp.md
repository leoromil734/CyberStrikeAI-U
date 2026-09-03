# 浏览器交互（SRC 任务）

需要真实点击、登录、填表、看渲染后的页面时，优先用系统已注册的浏览器 MCP（Playwright / 内置 browser）。不要用 shell 里的 `npx playwright` 或裸 CDP 脚本顶替。

静态公开 HTTP（无需交互）用 `httpx` / `http-framework-test` / `exec`+curl。

没有浏览器 MCP 时：记 `blocked` + `alt_tried`，降级到 HTTP 工具继续挖业务 API，不要停工。
