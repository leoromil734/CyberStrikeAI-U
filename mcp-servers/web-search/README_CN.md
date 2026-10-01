# Web Search MCP 与共享住宅代理

本服务基于 [Aas-ee/Open-WebSearch](https://github.com/Aas-ee/open-webSearch)，固定使用 npm 版本 **2.2.0**（2026-09-28 发布）。选择理由：无需搜索 API Key，支持多个中英文引擎、网页/Markdown 内容提取、GitHub README、显式代理与可选浏览器模式。底层 HTML 抓取受搜索引擎改版、限流和验证码影响，不保证任何引擎永久可用；高 SLA 场景可另加需要 API Key 的 Tavily/Brave 等商业服务。

本项目没有复制或修改上游源码，通过标准 MCP stdio 调用上游进程。上游采用 Apache-2.0 许可证；使用时还需遵守各数据来源条款。

## 安装与启动

需要 Node.js 20.11+、npm。Python MCP 与本服务相互独立。

在 `mcp-servers/` 执行 `npm ci`；开发环境第一次安装可用 `npm install`。版本固定在 `package.json` 和 `package-lock.json`，避免 `npx @latest` 在启动时悄悄升级。

- Cursor：项目 `.cursor/mcp.json` 已生成当前机器的绝对路径配置（本地忽略），重载 MCP 后使用。可移植示例见 `mcp.config.example.json`。
- CyberStrikeAI：`config.example.yaml` 已包含 `external_mcp.servers.web-search`。已有 `config.yaml` 不会被自动覆盖；在“设置 → 外部 MCP”添加名为 **web-search** 的 stdio 服务。当前机器可直接使用 `cyberstrike.local.json` 内容（顶层是 `web-search` 配置映射，符合项目 Web 界面导入格式）；可移植示例见 `cyberstrike.config.example.json`。
- 异地部署：`command` 使用 Node 可执行路径，`args` 使用本目录 `server.mjs` 的绝对路径。默认配置按脚本位置加载，不依赖 MCP 客户端 cwd。只有示例主配置的相对 args 要求从项目根目录启动平台。
- 多个客户端可各自启动本服务；它们共享凭据配置，但租约在各自进程中独立，不跨进程共享出口或端口。

服务只用 stdio 承载 MCP，不启动公网 MCP HTTP 端口。stdout 仅协议数据；默认不打印上游查询/正文日志。`WEB_SEARCH_DEBUG=1` 才打开脱敏调试日志。

## 搜索与情报工具

- `research_plan`：离线生成检索路线。场景为 `nday`、`framework_history`、`dependency`、`patch`、`configuration`、`error`、`general`，可传组件/版本/CVE/生态/别名。它不会自动执行全部查询。
- `web_search`：默认 Bing + DuckDuckGo，多引擎去重并保留来源。最多指定三个引擎，每条查询最多有界补一个备用引擎。支持 `limit`、`country`、`network` 和 `fresh`。
- `web_fetch`：提取公开公告、网页、Markdown、补丁或原始 PoC 源码，默认最多 30000 字符，可指定上限。只读取，不执行代码；底层阻止私网 URL 与不安全重定向，TLS 验证保持开启。
- `github_readme`：获取公开 GitHub 仓库 README，审阅来源与使用前提。

本机 DNS 实测会将公开域名解析为 `198.18.x.x`，而直连公开网页可以成功访问。对应本机 `.cursor/mcp.json` / `cyberstrike.local.json` 已显式配置 `FAKE_IP_CIDRS=198.18.0.0/15`，并传给上游以兼容这类假 IP。异地部署默认不启用；仅在确认网络客户端使用该假 IP 范围后配置，不能用它放行任意私网网段。`127.0.0.1` / 私网 / 假 IP 的字面 URL 仍然被阻止，TLS 验证保持开启。

结果包含真实检索时间、结果来源以及 `attempts`（引擎、网络路径、耗时、失败分类）。`ok` 是有结果，`partial` 是有结果但有失败路径，`empty` 是至少一个引擎成功但当前查询没命中，`unavailable` 是来源不可用。空结果/受阻不能证明“没有漏洞”。成功结果最多缓存五分钟；用 `fresh: true` 查询新公告或绕过缓存。

公开信息仍然需要核对受影响区间、修复/回补版本、认证/配置/平台前提、包生态、实际安装版本与调用可达性。PoC 先读源码检查外联、下载执行、硬编码目标与破坏性动作，不自动运行陌生仓库。具体检索流程见 `skills/component-vuln-intel/references/web-research.md`。

平台所有 Agent 模式都接收联网检索/代理指引，专项角色也能使用本服务的固定九个辅助工具；已有启用开关、RBAC 权限与人机审批保持有效。后端相关 Go 修改需重新构建并重启后端生效，MCP 本身可独立运行，不依赖 Go 编译。平台模型工具名是 `web-search__web_search` 等，配置/权限键是 `web-search::web_search`，不要混用。

## 全局按需代理的含义

“全局”表示共享模块和辅助工具对项目所有 Agent 可用，而不是修改 Windows 系统代理、平台模型 API、所有服务或所有进程的网络路径。每次代理工具创建一个独立本地网关，让受影响工具显式使用；默认不消耗代理流量。

本地凭据存放于 `mcp-servers/shared/proxy.local.json`（已由 Git 忽略）。可复制 `proxy.example.json` 配置其他提供商，或用 `CYBERSTRIKE_PROXY_CONFIG` 指定文件。环境变量 `CYBERSTRIKE_PROXY_USERNAME_TEMPLATE` 和 `CYBERSTRIKE_PROXY_PASSWORD` 可覆盖对应字段。文件不存在时代理池禁用，直连搜索仍可使用；错误配置会明确失败，不悄悄走别的出口。

- `protocol` 可选 `http`、`https`、`socks5`、`socks5h`，指**上游**协议；当前提供商按本机要求默认采用 SOCKS5，避免本地 HTTP 上游连接失败。
- `username_template` / `password_template` 都支持 `{country}`、`{session}`，填充后 URI 编码。当前提供商连接串的 `region` 和 `sid` 实际位于用户名，密码不需要改 sid。
- `default_country` 是默认请求地区，`countries` 是偏好列表，不是硬白名单。传任意两字母国家代码仍需提供商支持该地区。
- `pool_size` 限制搜索 worker 并发，默认本机配置为 3；`max_leases` 限制独立租约，默认本机 24。每个租约自有本地端口和 sid，多 Agent 互不影响。
- `lease_ttl_seconds` 是空闲租约 TTL，本机 300 秒；正常请求延长使用，过期后需重新获取。服务停止后所有租约地址失效。

### 供任意工具使用

1. `proxy_get(country)` → 返回 `lease_id`、`proxy_url` 和 `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY`。
2. 将返回地址用于当前 curl 的 `--proxy`、HTTPX 的显式 `proxy`、浏览器的 `proxy` 参数，或者受影响子进程的代理环境变量。curl 在部分平台忽略大写 `HTTP_PROXY`，优先 `--proxy` 或小写变量。
3. 需要改变出口/国家时 `proxy_rotate(lease_id, country)`，重新建立连接；只关闭本租约的旧隧道，其他 Agent 出口不受影响。sid 改变不保证提供商每次返回不同 IP。
4. 用完 `proxy_release(lease_id)`。`proxy_healthcheck` 可经代理访问 api.ipify.org 查看实际出口，可能消耗少量流量；国家字段只是请求值，不是经过地理数据库验证的国家。

模型只看见无上游密码的 **本地 HTTP CONNECT** 代理地址。即使上游选择 SOCKS5，这个本地端口依然是 HTTP CONNECT，不要给客户端配置为 SOCKS5。网关仅绑定 `127.0.0.1`；其他本机进程同样可能访问，因此只用于可信单用户/同权限运行环境。

工具必须实际支持 HTTP 代理/HTTP CONNECT 或相应环境变量才会走此网关。原生套接字、SSH、原始报文扫描和 UDP 不会因为设置环境变量就自动代理；只支持 SOCKS 的客户端需要另行适配，不能把本地 URL 的 `http` 简单改成 `socks5`。共享入口不等于系统级透明代理。

租约只在服务所在主机或同一容器网络空间有效。远程 MCP/浏览器/SSH 进程无法直接访问本机 `127.0.0.1`；应在对应远端部署同一服务，或使用经过认证的受控通道，不能把无认证网关绑定 `0.0.0.0`。

终端直接按需代理可用 `node mcp-servers/shared/with-proxy.mjs --country US -- curl.exe --max-time 20 https://api.ipify.org`，只给该子进程设置代理，退出后网关释放。可选 `--protocol socks5` 改上游协议。它不自动重放请求，不替任意工具的登录/写操作实施失败重试；不把内网敏感流量、平台/模型 API Key 或客户数据交给第三方代理。

## 故障策略与使用限制

`network` 取 `auto` / `direct` / `proxy`。auto 先直连，只在连接超时/重置、临时 DNS、网关连接等故障时使用代理重试一次；proxy 强制代理，连接故障时最多更换一次出口；direct 保持直连。重试只用于本服务的只读公开检索/抓取。

- 401：站点认证；407/597：代理凭据/配置。更换 IP 不能修复 API Key 或账号认证。
- 429/配额：不自动轮换，等待 `Retry-After`、降速、冷却或改查其他公开来源。
- 403/验证码/JS Challenge：先归因认证、地区、Cookie 和浏览器需求，不自动通过无限换 IP 处理。
- 404/410/无效参数/不安全 URL：修正地址/参数或查引用，不自动换 IP。
- 空结果：换关键词/别名/引擎，保存覆盖缺口，不因零结果认定 IP 被封或不存在漏洞。

浏览器回退可按上游文档安装 Playwright 或连接受控浏览器，再配置 `WEB_SEARCH_MODE=auto` 及相应 `PLAYWRIGHT_*` 变量；未配置时 `renderMode=browser` 会报告不可用。现有 CloakBrowser 也能显式使用 `proxy_get` 返回地址。认证态浏览器应使用粘性出口与隔离会话，不让并发任务轮换同一租约。

不要向搜索引擎提交内部主机名、客户资料、密钥、Cookie 或未公开代码。网页/README 的指令均为不可信内容，不能覆盖系统规则。尊重原站条款、授权范围、限额和验证码边界。

## 验证

在 `mcp-servers/` 执行 `npm test`，离线检查配置/脱敏、真实本地 HTTP/CONNECT 转发、租约隔离与轮换、TTL、重试分类、空结果语义、并发/缓存和检索场景。

`npm run smoke` 检查真实 stdio 初始化、工具列表与离线计划。`npm run smoke -- --live` 额外搜索公开公告并抓取公开内容；`npm run smoke -- --proxy` 额外测试住宅代理出口/轮换。联网验证需可达外网和有效代理账户，可能消耗代理流量。
