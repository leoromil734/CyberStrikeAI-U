# CloakBrowser MCP Server

基于 [CloakBrowser](https://github.com/CloakHQ/cloakbrowser) 的反检测浏览器操控 MCP 服务，为 CyberStrikeAI 提供 `browser_*` 工具集。

CloakBrowser 是 Playwright 的 drop-in 替代：一个在 **C++ 源码层**打了 87 处指纹补丁的 Chromium 二进制（canvas / WebGL / 音频 / 字体 / GPU / 屏幕 / WebRTC / 网络时序 / 自动化信号），而不是靠 JS 注入或启动参数。因此 `navigator.webdriver=false`、插件列表、`window.chrome`、UA、TLS 指纹都与真实 Chrome 一致。

## 为什么自建而不是直接用现成的浏览器 MCP

Playwright MCP、Puppeteer MCP、chrome-devtools-mcp 都会自带并管理自己的浏览器发行版，无法保证使用 CloakBrowser 的补丁二进制（它们只调用 `chromium.launch()`，拿不到 CloakBrowser wrapper 注入的 stealth 参数）。本服务直接调用 `cloakbrowser.launch_async()`，完整继承其补丁与反检测能力。

## 服务器安装位置

| 项目 | 路径 |
| --- | --- |
| 独立 venv（含 mcp + cloakbrowser + playwright） | `/opt/cloakbrowser-mcp/venv` |
| 服务脚本 | `/opt/CyberStrikeAI-U/mcp-servers/cloakbrowser/mcp_cloakbrowser.py` |
| Chromium 二进制（自动下载，约 206MB） | `/root/.cloakbrowser/chromium-<version>/chrome` |
| Windows 字体 | `/usr/local/share/fonts/windows/`（57 个文件） |
| 截图等产物 | `/opt/cloakbrowser-mcp/output` |
| 虚拟显示服务 | `xvfb.service` → `Xvfb :99`（1920x1080x24） |

## 安装步骤（复现）

```bash
# 1. 独立 venv，避免污染项目 venv（OneForAll 会把 requests 钉回旧版本）
mkdir -p /opt/cloakbrowser-mcp && cd /opt/cloakbrowser-mcp
python3 -m venv venv
./venv/bin/pip install --upgrade pip wheel
./venv/bin/pip install cloakbrowser "mcp<2"

# 2. Chromium 系统依赖（缺了会报 "error while loading shared libraries: libatk-1.0.so.0"）
export DEBIAN_FRONTEND=noninteractive
apt-get install -y libatk1.0-0 libatk-bridge2.0-0 libxkbcommon0 libatspi2.0-0 \
  libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
  libasound2 libnss3 fonts-liberation

# 3. 基础字体层：emoji + CJK canvas 字体（Kasada / Akamai 会渲染 emoji 到隐藏 canvas 并比对像素哈希）
apt-get install -y fonts-noto-color-emoji fonts-freefont-ttf fonts-unifont \
  fonts-ipafont-gothic fonts-wqy-zenhei fonts-tlwg-loma-otf fonts-noto-cjk

# 4. 真实 Windows 字体（关键：apt 给不了，ttf-mscorefonts-installer 只有 XP 时代老字体，不够）
#    从一台真实 Windows 机器的 C:\Windows\Fonts\ 复制；wrapper 要求 Segoe UI / Segoe UI Light /
#    Calibri / Marlett / MS UI Gothic / Franklin Gothic / Consolas / Courier New 全部就位。
#    放到系统字体目录（而非 ~/.local），避免依赖 HOME：
mkdir -p /usr/local/share/fonts/windows
# 将字体文件解压/复制到该目录后：
fc-cache -f
./venv/bin/python -m cloakbrowser info | grep -i "win fonts"   # 期望 "ok (8/8)"

# 5. 虚拟显示（有头模式必需）
apt-get install -y xvfb xauth
cat > /etc/systemd/system/xvfb.service << 'EOF'
[Unit]
Description=Xvfb virtual display for CloakBrowser
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/Xvfb :99 -screen 0 1920x1080x24 -nolisten tcp -ac
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now xvfb

# 6. 下载 stealth Chromium（Ed25519 签名 + SHA-256 校验）
./venv/bin/python -m cloakbrowser install
./venv/bin/python -m cloakbrowser info      # 诊断：缺库会明确列出
```

**`mcp<2` 是必须的**：mcp 2.x 把 `FastMCP` 改名为 `MCPServer`（`mcp.server.mcpserver`），v1 的 `from mcp.server.fastmcp import FastMCP` 写法在 2.x 下直接报错。

## 平台接入配置

`config.yaml`：

```yaml
external_mcp:
  servers:
    cloakbrowser:
      type: stdio
      command: /opt/cloakbrowser-mcp/venv/bin/python
      args:
        - /opt/CyberStrikeAI-U/mcp-servers/cloakbrowser/mcp_cloakbrowser.py
      env:
        DISPLAY: ":99"                      # Xvfb 虚拟显示
        CLOAKBROWSER_MCP_HEADLESS: "0"      # 有头模式，反检测更强
        CLOAKBROWSER_MCP_HUMANIZE: "1"
        # 住宅代理模板：{country} / {session} 由工具填充，从而支持按国家切换出口
        CLOAKBROWSER_MCP_PROXY_TEMPLATE: "socks5://user:pass_country-{country}_session-{session}@proxy.example.com:1080"
        CLOAKBROWSER_MCP_PROXY_COUNTRY: "us"
        CLOAKBROWSER_MCP_GEOIP: "1"
        CLOAKBROWSER_MCP_OUTPUT_DIR: /opt/cloakbrowser-mcp/output
        CLOAKBROWSER_MCP_IDLE_TIMEOUT: "300"
      timeout: 120
      external_mcp_enable: true
```

Agent 侧工具名会变成 `cloakbrowser__browser_navigate`（`::` 换成 `__`，符合 OpenAI 函数名规范）。

### 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `DISPLAY` | 空 | 有头模式所需，指向 Xvfb（如 `:99`） |
| `CLOAKBROWSER_MCP_HEADLESS` | `1` | 设 `0` 走有头模式（需 `DISPLAY`）；部分站点会识别 headless |
| `CLOAKBROWSER_MCP_HUMANIZE` | `1` | 拟人化鼠标轨迹 / 逐字输入 / 滚动节奏 |
| `CLOAKBROWSER_MCP_PROXY` | 空 | 固定代理，如 `socks5://user:pass@host:port`；SOCKS5 原生支持 |
| `CLOAKBROWSER_MCP_PROXY_TEMPLATE` | 空 | 代理模板，含 `{country}` / `{session}` 占位符时启用**按国家切换出口**；优先级高于 `CLOAKBROWSER_MCP_PROXY` |
| `CLOAKBROWSER_MCP_PROXY_COUNTRY` | `us` | 使用模板时的初始出口国家（ISO 3166-1 alpha-2 小写） |
| `CLOAKBROWSER_MCP_GEOIP` | `1` | 按代理出口 IP 自动对齐时区/locale 并伪装 WebRTC IP；仅在有代理时生效 |
| `CLOAKBROWSER_MCP_OUTPUT_DIR` | `/opt/cloakbrowser-mcp/output` | 截图输出目录 |
| `CLOAKBROWSER_MCP_IDLE_TIMEOUT` | `300` | 空闲多少秒关闭浏览器释放内存；`0` 不回收 |
| `CLOAKBROWSER_MCP_LOCALE` | `en-US` | 浏览器 locale |

## 工具列表（16 个）

| 工具 | 用途 |
| --- | --- |
| `browser_launch` | 启动/重启浏览器，可切换 headless、humanize、proxy、geoip |
| `browser_set_country` | **按国家切换出口身份**：改用指定国家的住宅 IP，自动换 IP 重试并校验实际出口 |
| `browser_navigate` | 打开网址（对瞬时 `ERR_ABORTED` 自动重试一次） |
| `browser_snapshot` | **主要观察方式**：列出可交互元素并分配 `ref`（如 `e3`） |
| `browser_click` | 点击（传 ref 或 CSS 选择器） |
| `browser_type` | 填写文本，可 `submit=True` 回车提交 |
| `browser_press` | 按键（Enter / Escape / Control+A / PageDown …） |
| `browser_scroll` | 滚动（up / down / top / bottom） |
| `browser_screenshot` | 截图存文件，返回路径 |
| `browser_extract` | 提取 text / html / links |
| `browser_evaluate` | 执行 JS 并取回结果 |
| `browser_wait_for` | 等待元素状态或文本出现 |
| `browser_history` | back / forward / reload |
| `browser_tabs` | 标签页 list / new / switch / close |
| `browser_state` | 状态、cookies、`probe`（实测当前出口 IP/时区/locale）、登录态 save_state / load_state |
| `browser_close` | 关闭浏览器 |

典型用法：`browser_navigate` → `browser_snapshot` 拿到 `ref` → `browser_click`/`browser_type` → 再 `browser_snapshot` 确认。页面变化后 `ref` 会失效，需重新 snapshot。

临时提速可在任务里让 Agent 传 `browser_launch(headless=true)` 切回无头，用完再 `browser_launch(headless=false)`。

## 运维要点

- **长驻会话**：浏览器跨工具调用复用，不在每次调用时重启；空闲 300 秒自动回收，下次调用自动拉起（启动时预热一个空白页，避免有头模式首个导航偶发 `ERR_ABORTED`）。
- **代理与 geoip**：挂代理时必须让浏览器时区/locale 与出口 IP 归属地一致，否则「美国 IP + 纽约以外时区」本身就是常见的机器人特征。首次启用 geoip 会自动下载 GeoLite2 城市库到 `/root/.cloakbrowser/geoip/`。验证方式：`browser_navigate` 到 `https://api.ipify.org?format=json` 取出口 IP，再用 `browser_evaluate` 取 `Intl.DateTimeFormat().resolvedOptions().timeZone` 比对。
- **按国家切换身份**：`browser_set_country(country="de")` 会把出口换到该国的住宅 IP 并校验实际出口。Agent 已能自主判断——例如任务里说「模拟德国用户访问」时，它会先切到 `de` 再访问，并自行用 `ipinfo.io` 等复核 IP 归属。已实测可用：us / de / jp / fr / nl。
- **代理池有随机坏节点**：住宅代理偶发 `ERR_CONNECTION_RESET`。`browser_set_country` 遇到校验失败会自动换 session（即换 IP）重试，默认 5 次、每次间隔 1.5 秒；仍失败会明确提示可稍后重试。因此看到一次 ERROR 不代表该国家不可用。
- **并发安全**：Agent 常在同一轮里并发调用多个 `browser_*` 工具，而它们共享同一个浏览器实例（切换国家会重启浏览器）。所有工具已用全局锁串行化，避免「一个工具在重启浏览器、另一个在操作旧页面」导致的 `Target closed` / 上下文销毁。
- **崩溃自愈**：page 关闭或浏览器退出后，下一次工具调用会自动重建。
- **免费版限制**：默认用 GitHub Releases 的免费 v146，**1 个并发会话**（本服务单实例长驻，不触发；但别同时跑第二个实例）。需要最新 v152 可跑 `./venv/bin/python -m cloakbrowser login` 用 GitHub 登录领取 key。
- **截图路径**：产物落在 `CLOAKBROWSER_MCP_OUTPUT_DIR`，可交给视觉分析工具或 `read_file` 查看。
- **诊断字体**：`./venv/bin/python -m cloakbrowser info` 里 `Win fonts: ok (8/8)` 表示 Windows 字体齐全。`Office fonts: absent (0/10)` 属正常——约一半真实 Windows 机器没装 Office，官方把它当信息项而非警告。`Mac fonts: partial` 只在模拟 macOS persona 时才有影响。
- **日志**：MCP 走 stdio，服务日志一律写 stderr（`journalctl -u cyberstrikeai` 中可见 `[cloakbrowser-mcp]` 前缀）。平台可能把 stdio 子进程 stderr 归到别处，必要时直接看进程 env：`tr '\0' '\n' < /proc/$(pgrep -f mcp_cloakbrowser)/environ`。

## 自测

```bash
cd /opt/cloakbrowser-mcp
./venv/bin/python test_mcp_client.py            # 拉起 stdio server，跑一遍真实工具调用
```

## 相关平台侧修复

外部 MCP 工具在本项目的 Eino 多代理路径下曾无法调用（报「工具 X 未找到」），原因与修复见 `internal/agent/agent.go`：

主 Agent 与 SubAgent 共用同一个 `agent.Agent` 实例，而 `ToolsForRole()` 每次调用都会整体替换 `toolNameMapping`。子代理按角色裁剪的工具集更窄，覆盖后主代理的外部工具名映射就丢了，执行阶段遂把外部工具误判为内部工具并交给内置 MCP Server，得到「工具未找到」。

修复：`toolNameMapping` 改为**合并**写入；并在 `executeToolViaMCP` 增加兜底——映射缺失时按 `mcpName__toolName` 解析，仅在内部未注册同名工具且该 `mcpName` 确实是已配置的外部 MCP 时才路由到外部。
