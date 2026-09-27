#!/usr/bin/env python3
"""CloakBrowser MCP Server — 反检测浏览器操控服务

用 CloakBrowser（源码级反检测 Chromium，Playwright API）为 CyberStrikeAI 提供浏览器工具。
以 stdio 方式运行，在「设置 → 外部 MCP」中接入。

环境变量：
  CLOAKBROWSER_MCP_HEADLESS      1/0，默认 1。部分站点能识别 headless，必要时设 0（需 Xvfb）
  CLOAKBROWSER_MCP_HUMANIZE      1/0，默认 1。拟人化鼠标轨迹、逐字输入、滚动节奏
  CLOAKBROWSER_MCP_PROXY         代理，如 http://user:pass@host:8080 或 socks5://...
  CLOAKBROWSER_MCP_OUTPUT_DIR    截图等产物目录，默认 /opt/cloakbrowser-mcp/output
  CLOAKBROWSER_MCP_IDLE_TIMEOUT  空闲回收秒数，默认 300；0 表示不回收
  CLOAKBROWSER_MCP_LOCALE        浏览器 locale，默认 en-US

注意：MCP 走 stdio，stdout 只能承载协议数据，日志一律写 stderr。
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

OUTPUT_DIR = Path(os.environ.get("CLOAKBROWSER_MCP_OUTPUT_DIR", "/opt/cloakbrowser-mcp/output"))
IDLE_TIMEOUT = float(os.environ.get("CLOAKBROWSER_MCP_IDLE_TIMEOUT", "300"))
DEFAULT_LOCALE = os.environ.get("CLOAKBROWSER_MCP_LOCALE", "en-US")
DEFAULT_VIEWPORT = {"width": 1440, "height": 900}

# 可见性判断 + ref 标注脚本：把可交互元素标记为 data-cloak-ref，便于后续按 ref 操作。
_MARK_REFS_JS = """
(max) => {
  document.querySelectorAll('[data-cloak-ref]').forEach((el) => el.removeAttribute('data-cloak-ref'));
  const selector = 'a[href],button,input,select,textarea,[role=button],[role=link],[role=checkbox],[role=radio],[role=tab],[role=menuitem],[onclick],[contenteditable=true]';
  const out = [];
  let index = 0;
  for (const el of Array.from(document.querySelectorAll(selector))) {
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);
    const visible = rect.width > 1 && rect.height > 1
      && style.visibility !== 'hidden' && style.display !== 'none'
      && style.opacity !== '0' && el.getAttribute('aria-hidden') !== 'true';
    if (!visible) continue;
    if (index >= max) break;
    index += 1;
    const ref = 'e' + index;
    el.setAttribute('data-cloak-ref', ref);
    let label = (el.innerText || el.value || '').trim().replace(/\\s+/g, ' ');
    if (!label) {
      label = (el.getAttribute('aria-label') || el.getAttribute('title')
        || el.getAttribute('placeholder') || el.getAttribute('name') || '').trim();
    }
    out.push({
      ref: ref,
      tag: el.tagName.toLowerCase(),
      type: el.getAttribute('type') || '',
      name: el.getAttribute('name') || '',
      href: el.getAttribute('href') || '',
      label: label.slice(0, 120),
    });
  }
  return out;
}
"""

_EXTRACT_LINKS_JS = """
(limit) => {
  const seen = new Set();
  const out = [];
  for (const a of Array.from(document.querySelectorAll('a[href]'))) {
    const href = a.href;
    if (!href || seen.has(href)) continue;
    seen.add(href);
    out.push({ text: (a.innerText || '').trim().replace(/\\s+/g, ' ').slice(0, 100), href: href });
    if (out.length >= limit) break;
  }
  return out;
}
"""


def log(message: str) -> None:
    """日志写 stderr，避免污染 MCP 的 stdout 协议通道。"""
    print(message, file=sys.stderr, flush=True)


def new_session_id() -> str:
    """生成随机会话 ID。住宅代理用 session 片段维持粘性，换值即换出口 IP。"""
    return secrets.token_hex(5)


class BrowserSession:
    """长驻浏览器会话：跨工具调用复用，空闲自动回收，崩溃后自动重建。"""

    def __init__(self) -> None:
        self.browser: Any = None
        self.context: Any = None
        self.page: Any = None
        self.last_used = 0.0
        self.lock = asyncio.Lock()
        # 工具级串行锁：Agent 常在同一轮里并发调用多个 browser_* 工具，而它们共享同一个
        # 浏览器实例（例如「切换国家」会重启浏览器），串行化可避免互相踩踏。
        self.op_lock = asyncio.Lock()
        self.watchdog: asyncio.Task | None = None
        self.headless = os.environ.get("CLOAKBROWSER_MCP_HEADLESS", "1") != "0"
        self.humanize = os.environ.get("CLOAKBROWSER_MCP_HUMANIZE", "1") != "0"
        self.proxy = os.environ.get("CLOAKBROWSER_MCP_PROXY") or None
        # 代理模板：包含 {country} / {session} 占位符时，支持按国家切换出口 IP。
        self.proxy_template = os.environ.get("CLOAKBROWSER_MCP_PROXY_TEMPLATE") or None
        self.country = (os.environ.get("CLOAKBROWSER_MCP_PROXY_COUNTRY") or "").strip().lower()
        self.session_id = ""
        if self.proxy_template:
            if not self.country:
                self.country = "us"
            self.session_id = new_session_id()
            self.proxy = self.render_proxy()
        # geoip：按代理出口 IP 自动对齐时区/locale，并注入 WebRTC IP 伪装。
        # 仅在使用代理时有意义；时区与 IP 不一致本身就是常见的机器人特征。
        self.geoip = os.environ.get("CLOAKBROWSER_MCP_GEOIP", "1") != "0"
        self.launch_count = 0

    def render_proxy(self, country: str | None = None, session_id: str | None = None) -> str | None:
        """按国家与会话 ID 渲染代理 URL；未配置模板时原样返回固定代理。"""
        if not self.proxy_template:
            return self.proxy
        cc = (country if country is not None else self.country) or "us"
        sid = (session_id if session_id is not None else self.session_id) or new_session_id()
        return self.proxy_template.format(country=cc.lower(), session=sid)

    def switch_country(self, country: str, rotate_session: bool) -> str:
        """切换出口国家（必要时换会话 ID 以更换出口 IP），返回新的代理 URL。"""
        self.country = (country or "").strip().lower() or "us"
        if rotate_session or not self.session_id:
            self.session_id = new_session_id()
        self.proxy = self.render_proxy()
        return self.proxy

    @property
    def running(self) -> bool:
        return self.page is not None and not self.page.is_closed()


SESSION = BrowserSession()


def serialized(fn):
    """把工具执行串行化到 op_lock 上，避免同一浏览器实例被并发操作互相破坏。"""

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        async with SESSION.op_lock:
            return await fn(*args, **kwargs)

    return wrapper


async def _launch() -> None:
    """启动 CloakBrowser 并建立 context/page。"""
    from cloakbrowser import launch_async

    kwargs: dict[str, Any] = {
        "headless": SESSION.headless,
        "humanize": SESSION.humanize,
    }
    if SESSION.proxy:
        kwargs["proxy"] = SESSION.proxy
        if SESSION.geoip:
            kwargs["geoip"] = True

    log(f"[cloakbrowser-mcp] launching browser headless={SESSION.headless} "
        f"humanize={SESSION.humanize} country={SESSION.country or '-'} "
        f"proxy={bool(SESSION.proxy)} geoip={SESSION.geoip and bool(SESSION.proxy)}")
    SESSION.browser = await launch_async(**kwargs)
    SESSION.context = await SESSION.browser.new_context(
        viewport=DEFAULT_VIEWPORT,
        locale=DEFAULT_LOCALE,
    )
    SESSION.page = await SESSION.context.new_page()
    # 预热：有头模式（Xvfb）下首个导航偶发 ERR_ABORTED，先加载空白页让浏览器完全就绪。
    try:
        await SESSION.page.goto("about:blank", timeout=20000)
    except Exception as exc:  # noqa: BLE001 - 预热失败不阻断，后续导航仍可能成功
        log(f"[cloakbrowser-mcp] warmup skipped: {exc}")
    SESSION.last_used = time.time()
    SESSION.launch_count += 1
    log("[cloakbrowser-mcp] browser ready")


async def _shutdown() -> None:
    """关闭浏览器并清空句柄。"""
    browser = SESSION.browser
    SESSION.browser = None
    SESSION.context = None
    SESSION.page = None
    if browser is not None:
        try:
            await browser.close()
        except Exception as exc:  # noqa: BLE001 - 关闭失败不影响后续重建
            log(f"[cloakbrowser-mcp] close browser failed: {exc}")


async def _watchdog() -> None:
    """空闲回收：长时间无操作时释放 Chromium 占用的内存。

    与工具执行共用 op_lock，避免在工具操作页面时把浏览器关掉。
    """
    while True:
        await asyncio.sleep(30)
        if IDLE_TIMEOUT <= 0:
            continue
        if not SESSION.running or time.time() - SESSION.last_used <= IDLE_TIMEOUT:
            continue
        async with SESSION.op_lock:
            if SESSION.running and time.time() - SESSION.last_used > IDLE_TIMEOUT:
                log("[cloakbrowser-mcp] idle timeout, closing browser")
                await _shutdown()


async def _ensure_page() -> Any:
    """返回可用 page，必要时启动或重建浏览器。"""
    if SESSION.watchdog is None or SESSION.watchdog.done():
        SESSION.watchdog = asyncio.create_task(_watchdog())
    if SESSION.running:
        SESSION.last_used = time.time()
        return SESSION.page
    async with SESSION.lock:
        if SESSION.running:
            SESSION.last_used = time.time()
            return SESSION.page
        if SESSION.browser is not None:
            await _shutdown()
        await _launch()
        return SESSION.page


def _resolve(argument: str | None) -> str | None:
    """把 ref 或 CSS 选择器统一解析为 Playwright 选择器。"""
    if not argument:
        return None
    value = argument.strip()
    if not value:
        return None
    if value.startswith("e") and value[1:].isdigit():
        return f'[data-cloak-ref="{value}"]'
    return value


def _describe_error(exc: Exception) -> str:
    text = str(exc).strip() or exc.__class__.__name__
    if len(text) > 600:
        text = text[:600] + " ...(truncated)"
    return f"ERROR: {text}"


async def _probe_exit() -> dict[str, str]:
    """用当前页面探测出口 IP、时区与 locale，用于确认代理切换是否真的生效。"""
    page = await _ensure_page()
    await page.goto("https://api.ipify.org?format=json", wait_until="domcontentloaded", timeout=45000)
    raw = (await page.inner_text("body")).strip()
    ip = ""
    try:
        ip = str(json.loads(raw).get("ip", ""))
    except (ValueError, AttributeError):
        ip = raw[:64]
    timezone = await _evaluate_with_retry(page, "Intl.DateTimeFormat().resolvedOptions().timeZone")
    locale = await _evaluate_with_retry(page, "navigator.language")
    return {"ip": ip, "timezone": str(timezone), "locale": str(locale)}


async def _evaluate_with_retry(page: Any, expression: str) -> Any:
    """执行 JS；页面正在导航时 evaluate 会报上下文销毁，等待加载完成后重试一次。"""
    last_error: Exception | None = None
    for _ in range(2):
        try:
            return await page.evaluate(expression)
        except Exception as exc:  # noqa: BLE001
            text = str(exc)
            transient = ("Execution context was destroyed" in text or "Target closed" in text
                         or "Cannot find context" in text)
            if not transient:
                raise
            last_error = exc
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=10000)
            except Exception:  # noqa: BLE001 - 等待失败则直接进入重试
                pass
    if last_error is not None:
        raise last_error
    raise RuntimeError("evaluate failed")


async def _reset_page() -> None:
    """探测后把页面恢复到空白，避免 JSON 响应干扰后续操作。"""
    try:
        if SESSION.running:
            await SESSION.page.goto("about:blank", timeout=15000)
            # 给导航一点收尾时间，避免紧随其后的 evaluate/extract 撞上上下文重建。
            await asyncio.sleep(0.3)
    except Exception:  # noqa: BLE001 - 恢复失败不影响结果
        pass


mcp = FastMCP("cloakbrowser")


@mcp.tool()
@serialized
async def browser_launch(headless: bool | None = None, humanize: bool | None = None,
                         proxy: str | None = None, geoip: bool | None = None) -> str:
    """启动或重启反检测浏览器（CloakBrowser）。

    参数均为可选：headless 是否无头；humanize 是否拟人化操作；proxy 代理地址
    （如 http://user:pass@host:8080 或 socks5://host:1080，传空字符串清除）；
    geoip 是否按代理出口 IP 自动对齐时区/locale（仅在有代理时生效，建议保持开启）。
    首次调用任何 browser_* 工具也会自动启动，此工具用于显式预热或更换代理。
    """
    async with SESSION.lock:
        if headless is not None:
            SESSION.headless = bool(headless)
        if humanize is not None:
            SESSION.humanize = bool(humanize)
        if proxy is not None:
            SESSION.proxy = proxy.strip() or None
        if geoip is not None:
            SESSION.geoip = bool(geoip)
        if SESSION.browser is not None:
            await _shutdown()
        await _launch()
    return (f"浏览器已启动：headless={SESSION.headless} humanize={SESSION.humanize} "
            f"proxy={SESSION.proxy or '无'} geoip={SESSION.geoip and bool(SESSION.proxy)} "
            f"country={SESSION.country or '-'} locale={DEFAULT_LOCALE}")


@mcp.tool()
@serialized
async def browser_set_country(country: str = "us", rotate_session: bool = True,
                              verify: bool = True, attempts: int = 5) -> str:
    """把浏览器出口切换到指定国家的住宅 IP，并校验实际出口（需配置代理模板）。

    何时使用：目标站点有地区限制、要求本地身份，或需要访问来源与目标语种/时区一致时，
    先切到对应国家再访问。country 用 ISO 3166-1 alpha-2 小写代码，如 us / de / jp / fr / nl。

    rotate_session=True 更换会话 ID，即换一个新的出口 IP。住宅代理池存在随机不可用节点，
    verify=True 时每次失败都会换 IP 重试（默认最多 5 次），因此偶发的 ERROR 可以再试一次。
    """
    if not SESSION.proxy_template:
        return "ERROR: 未配置 CLOAKBROWSER_MCP_PROXY_TEMPLATE，无法按国家切换出口"
    cc = (country or "").strip().lower()
    if len(cc) != 2 or not cc.isalpha():
        return f"ERROR: country 需为两位 ISO 代码（如 us / de / jp），收到 {country!r}"

    max_attempts = max(1, min(int(attempts or 1), 6))
    last_error = ""
    for attempt in range(max_attempts):
        if attempt > 0:
            # 住宅代理的失败节点通常很快恢复，稍等再换 IP 重试。
            await asyncio.sleep(1.5)
        async with SESSION.lock:
            # 首次按调用方要求决定是否换会话；后续重试必须换 IP，否则大概率仍然失败。
            SESSION.switch_country(cc, rotate_session=rotate_session if attempt == 0 else True)
            if SESSION.browser is not None:
                await _shutdown()
            await _launch()
        if not verify:
            return f"已切换出口国家：country={cc}（未校验）"
        try:
            info = await _probe_exit()
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)[:200]
            continue
        if not info["ip"]:
            last_error = "未能取到出口 IP"
            continue
        await _reset_page()
        return (f"出口已切换并校验：country={cc} IP={info['ip']} "
                f"timezone={info['timezone']} locale={info['locale']}"
                f"（第 {attempt + 1} 次尝试）")
    await _reset_page()
    return (f"ERROR: 切换到 country={cc} 后校验失败，已重试 {max_attempts} 次：{last_error}"
            f"（该国家当前节点可能不稳定，可稍后重试）")


@mcp.tool()
@serialized
async def browser_navigate(url: str, wait_until: str = "domcontentloaded",
                          timeout_ms: int = 60000) -> str:
    """打开一个网址。

    url 需带协议（http/https）；wait_until 可选 domcontentloaded | load | networkidle；
    打开后建议调用 browser_snapshot 获取可操作元素。
    """
    # 有头模式首次导航偶发 ERR_ABORTED（页面尚未就绪），这种瞬时错误重试即可成功。
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            page = await _ensure_page()
            response = await page.goto(url, wait_until=wait_until, timeout=timeout_ms)
            SESSION.last_used = time.time()
            status = response.status if response is not None else None
            title = await page.title()
            return (f"已打开：{page.url}\nHTTP 状态：{status}\n标题：{title}\n"
                    f"下一步可用 browser_snapshot 查看可交互元素")
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            text = str(exc)
            transient = ("ERR_ABORTED" in text or "Target closed" in text
                         or "Navigation interrupted" in text)
            if not transient or attempt == 1:
                break
            log(f"[cloakbrowser-mcp] transient navigation error, retrying: {text[:200]}")
            await asyncio.sleep(1.0)
    return _describe_error(last_error if last_error is not None else RuntimeError("navigate failed"))


@mcp.tool()
@serialized
async def browser_snapshot(max_elements: int = 120) -> str:
    """获取当前页面的可交互元素清单（链接、按钮、输入框等），每个元素带 ref。

    这是主要的页面观察方式：先用它看清有什么可操作，再用 browser_click / browser_type
    传入 ref（如 e3）操作。页面变化后 ref 会失效，需重新调用本工具。
    """
    try:
        page = await _ensure_page()
        SESSION.last_used = time.time()
        elements = await page.evaluate(_MARK_REFS_JS, max_elements)
        title = await page.title()
        lines = [f"URL: {page.url}", f"标题: {title}",
                 f"可交互元素: {len(elements)} 个"]
        for item in elements:
            parts = [f"[{item['ref']}]", item["tag"]]
            if item.get("type"):
                parts.append(f"type={item['type']}")
            if item.get("name"):
                parts.append(f"name={item['name']}")
            if item.get("href"):
                parts.append(f"href={item['href']}")
            if item.get("label"):
                parts.append(f"文本={json.dumps(item['label'], ensure_ascii=False)}")
            lines.append(" ".join(parts))
        if not elements:
            lines.append("(未发现可交互元素，可尝试 browser_extract 取正文或 browser_screenshot 看渲染结果)")
        return "\n".join(lines)
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_click(target: str, double_click: bool = False,
                        timeout_ms: int = 30000) -> str:
    """点击元素。target 传 browser_snapshot 给出的 ref（如 e5）或 CSS 选择器。"""
    try:
        page = await _ensure_page()
        selector = _resolve(target)
        if selector is None:
            return "ERROR: target 不能为空，请传 ref（如 e1）或 CSS 选择器"
        if double_click:
            await page.dblclick(selector, timeout=timeout_ms)
        else:
            await page.click(selector, timeout=timeout_ms)
        SESSION.last_used = time.time()
        return f"已点击 {target}，当前 URL：{page.url}"
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_type(target: str, text: str, submit: bool = False,
                       clear_first: bool = True, timeout_ms: int = 30000) -> str:
    """在输入框填写文本。target 传 ref 或 CSS 选择器。

    submit=True 会在填写后按回车（提交表单/触发搜索）；clear_first 先清空原有内容。
    """
    try:
        page = await _ensure_page()
        selector = _resolve(target)
        if selector is None:
            return "ERROR: target 不能为空，请传 ref（如 e1）或 CSS 选择器"
        if clear_first:
            await page.fill(selector, "", timeout=timeout_ms)
        await page.type(selector, text, timeout=timeout_ms)
        if submit:
            await page.press(selector, "Enter", timeout=timeout_ms)
        SESSION.last_used = time.time()
        return f"已向 {target} 输入 {len(text)} 个字符" + ("，并已回车提交" if submit else "")
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_press(key: str, target: str | None = None,
                       timeout_ms: int = 30000) -> str:
    """按键。key 如 Enter、Escape、Tab、ArrowDown、Control+A、PageDown。

    不传 target 时作用于当前页面（先确保页面已聚焦）。
    """
    try:
        page = await _ensure_page()
        selector = _resolve(target)
        if selector:
            await page.press(selector, key, timeout=timeout_ms)
        else:
            await page.keyboard.press(key)
        SESSION.last_used = time.time()
        return f"已发送按键 {key}"
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_scroll(direction: str = "down", amount: int = 800) -> str:
    """滚动页面。direction 可选 up | down | top | bottom；amount 为像素数。"""
    try:
        page = await _ensure_page()
        if direction == "top":
            await page.evaluate("() => window.scrollTo(0, 0)")
        elif direction == "bottom":
            await page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
        else:
            delta = -abs(amount) if direction == "up" else abs(amount)
            await page.mouse.wheel(0, delta)
        SESSION.last_used = time.time()
        position = await page.evaluate("() => ({y: Math.round(window.scrollY), h: document.body.scrollHeight})")
        return f"已滚动（{direction}），当前位置 {position['y']} / {position['h']}"
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_screenshot(full_page: bool = False, name: str = "") -> str:
    """截图并保存为 PNG 文件，返回绝对路径（可交给视觉分析工具或 read_file 查看）。

    full_page=True 截取整页（含需滚动部分）；name 可用来自定义文件名。
    """
    try:
        page = await _ensure_page()
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_")[:40]
        filename = f"{stamp}-{safe}.png" if safe else f"{stamp}.png"
        path = OUTPUT_DIR / filename
        await page.screenshot(path=str(path), full_page=full_page)
        SESSION.last_used = time.time()
        size = path.stat().st_size
        return f"截图已保存：{path}（{size} 字节，full_page={full_page}）\nURL: {page.url}"
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_extract(format: str = "text", target: str | None = None,
                         limit: int = 200, max_chars: int = 15000) -> str:
    """提取页面内容。

    format 可选 text（可见文本）| html（源码）| links（链接清单）；
    target 传 ref 或 CSS 选择器可只提取该元素，留空则提取整个页面。
    """
    try:
        page = await _ensure_page()
        selector = _resolve(target)
        if format == "links":
            links = await page.evaluate(_EXTRACT_LINKS_JS, limit)
            lines = [f"URL: {page.url}", f"共提取 {len(links)} 条链接"]
            lines += [f"- {json.dumps(item['text'], ensure_ascii=False)} -> {item['href']}"
                      for item in links]
            SESSION.last_used = time.time()
            return "\n".join(lines)
        if format == "html":
            content = await (page.inner_html(selector) if selector else page.content())
        else:
            content = await (page.inner_text(selector) if selector else page.inner_text("body"))
        SESSION.last_used = time.time()
        truncated = len(content) > max_chars
        if truncated:
            content = content[:max_chars]
        header = f"URL: {page.url}  format={format}"
        if selector:
            header += f"  target={target}"
        if truncated:
            header += f"  (内容超长，已截断到 {max_chars} 字符)"
        return f"{header}\n{'-' * 40}\n{content}"
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_evaluate(expression: str) -> str:
    """在页面上下文执行 JavaScript 表达式并返回结果（JSON 序列化）。

    适合读取 DOM 状态、调用页面接口、绕过界面直接取数据。
    """
    try:
        page = await _ensure_page()
        result = await _evaluate_with_retry(page, expression)
        SESSION.last_used = time.time()
        try:
            text = json.dumps(result, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            text = str(result)
        if len(text) > 15000:
            text = text[:15000] + " ...(truncated)"
        return f"执行成功，返回：\n{text}"
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_wait_for(target: str = "", text: str = "",
                           timeout_ms: int = 30000, state: str = "visible") -> str:
    """等待元素出现/消失，或等待页面出现某段文本。

    target 传 ref 或 CSS 选择器；state 可选 visible | attached | hidden | detached；
    也可改用 text 等待文本出现。
    """
    try:
        page = await _ensure_page()
        if text:
            await page.wait_for_function(
                "() => document.body && document.body.innerText.includes(arguments[0])",
                arg=text, timeout=timeout_ms)
            SESSION.last_used = time.time()
            return f"文本已出现：{text}"
        selector = _resolve(target)
        if selector is None:
            return "ERROR: 需要提供 target（ref 或 CSS 选择器）或 text"
        await page.wait_for_selector(selector, state=state, timeout=timeout_ms)
        SESSION.last_used = time.time()
        return f"元素已满足条件（{state}）：{target}"
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_history(action: str = "back", timeout_ms: int = 30000) -> str:
    """浏览器历史操作。action 可选 back（后退）| forward（前进）| reload（刷新）。"""
    try:
        page = await _ensure_page()
        if action == "forward":
            response = await page.go_forward(timeout=timeout_ms)
        elif action == "reload":
            response = await page.reload(timeout=timeout_ms)
        else:
            response = await page.go_back(timeout=timeout_ms)
        SESSION.last_used = time.time()
        status = response.status if response is not None else None
        return f"已执行 {action}，当前 URL：{page.url}（HTTP {status}）"
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_tabs(action: str = "list", index: int = -1,
                      url: str = "", timeout_ms: int = 60000) -> str:
    """标签页管理。action 可选 list（列出）| new（新建，可带 url）| switch（切换，需 index）| close（关闭，需 index）。

    index 从 0 开始，指当前 context 内页面顺序。
    """
    try:
        page = await _ensure_page()
        context = SESSION.context
        if action == "new":
            new_page = await context.new_page()
            if url:
                await new_page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            SESSION.page = new_page
            SESSION.last_used = time.time()
            return f"已新建标签页：{new_page.url}"
        if action == "switch":
            pages = context.pages
            if index < 0 or index >= len(pages):
                return f"ERROR: index 越界，当前共 {len(pages)} 个标签页"
            SESSION.page = pages[index]
            SESSION.last_used = time.time()
            return f"已切换到标签页 {index}：{SESSION.page.url}"
        if action == "close":
            pages = context.pages
            if index < 0 or index >= len(pages):
                return f"ERROR: index 越界，当前共 {len(pages)} 个标签页"
            target_page = pages[index]
            await target_page.close()
            remaining = context.pages
            SESSION.page = remaining[0] if remaining else await context.new_page()
            SESSION.last_used = time.time()
            return f"已关闭标签页 {index}，剩余 {len(remaining)} 个"
        lines = [f"共 {len(context.pages)} 个标签页："]
        for i, item in enumerate(context.pages):
            mark = " <- 当前" if item is SESSION.page else ""
            lines.append(f"[{i}] {item.url}{mark}")
        return "\n".join(lines)
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_state(action: str = "status", path: str = "") -> str:
    """查看/校验/保存/加载浏览器状态。

    action 可选 status（运行状态、UA、cookies 数量）| probe（实测当前出口 IP、时区、locale）
    | cookies（列出 cookies）| save_state（保存登录态到 path）
    | load_state（从 path 恢复登录态，便于复用会话）。
    """
    try:
        if action == "status":
            lines = [
                f"浏览器运行中：{SESSION.running}",
                f"headless={SESSION.headless} humanize={SESSION.humanize} "
                f"proxy={SESSION.proxy or '无'} geoip={SESSION.geoip and bool(SESSION.proxy)}",
                f"country={SESSION.country or '-'} session={SESSION.session_id or '-'}",
                f"启动次数={SESSION.launch_count}",
            ]
            if SESSION.running:
                lines.append(f"URL：{SESSION.page.url}")
                lines.append(f"UA：{await SESSION.page.evaluate('() => navigator.userAgent')}")
            return "\n".join(lines)
        if action == "probe":
            info = await _probe_exit()
            await _reset_page()
            SESSION.last_used = time.time()
            return (f"当前出口：IP={info['ip']} timezone={info['timezone']} "
                    f"locale={info['locale']} country={SESSION.country or '-'}")
        if action == "cookies":
            page = await _ensure_page()
            cookies = await SESSION.context.cookies()
            lines = [f"共 {len(cookies)} 个 cookie："]
            lines += [f"- {c.get('domain')} {c.get('name')}={str(c.get('value'))[:60]}"
                      for c in cookies[:80]]
            SESSION.last_used = time.time()
            return "\n".join(lines)
        if action == "save_state":
            if not path:
                return "ERROR: save_state 需要 path"
            await _ensure_page()
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            await SESSION.context.storage_state(path=path)
            SESSION.last_used = time.time()
            return f"登录态已保存：{path}"
        if action == "load_state":
            if not path:
                return "ERROR: load_state 需要 path"
            if not Path(path).exists():
                return f"ERROR: 文件不存在：{path}"
            async with SESSION.lock:
                if SESSION.browser is not None:
                    await _shutdown()
                from cloakbrowser import launch_async

                kwargs: dict[str, Any] = {"headless": SESSION.headless, "humanize": SESSION.humanize}
                if SESSION.proxy:
                    kwargs["proxy"] = SESSION.proxy
                    if SESSION.geoip:
                        kwargs["geoip"] = True
                SESSION.browser = await launch_async(**kwargs)
                SESSION.context = await SESSION.browser.new_context(
                    viewport=DEFAULT_VIEWPORT, locale=DEFAULT_LOCALE, storage_state=path)
                SESSION.page = await SESSION.context.new_page()
                SESSION.launch_count += 1
                SESSION.last_used = time.time()
            return f"已用保存的登录态重启浏览器：{path}"
        return f"ERROR: 不支持的 action：{action}"
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


@mcp.tool()
@serialized
async def browser_close() -> str:
    """关闭浏览器，释放内存。下次调用其他 browser_* 工具会自动重新启动。"""
    try:
        async with SESSION.lock:
            if SESSION.browser is None:
                return "浏览器当前未运行"
            await _shutdown()
        return "浏览器已关闭"
    except Exception as exc:  # noqa: BLE001
        return _describe_error(exc)


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    log(f"[cloakbrowser-mcp] starting; output_dir={OUTPUT_DIR} idle_timeout={IDLE_TIMEOUT}s")
    mcp.run()


if __name__ == "__main__":
    main()
