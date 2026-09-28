# 403 / 401 访问控制绕过

> 403 表示"服务器知道你是谁但不允许"，401 表示"未认证"。两者都可能有路径/方法/头部的绕过缝隙。**纪律**：绕过成功必须看到受保护内容或受保护动作，不能只看状态码。

## 一、路径变形清单

```text
/admin          →  /admin/            /Admin         /ADMIN
                →  //admin           /./admin        /admin/./
                →  /%2fadmin         /admin%2f       /%2e/admin
                →  /admin%20         /admin%09       /admin%00
                →  /admin;/          /admin;foo=bar  /admin..
                →  /admin.json       /admin.html     /admin/~
                →  /./admin/../admin  /public/../admin
                →  /AdMiN            /ADMIN/
```

- 编码层级不同：`%2e` / `%252e` / 反斜杠 `\`（Windows/IIS）。
- 大小写：Windows/IIS 与部分框架不区分大小写。
- 尾部扩展名与 `PathInfo`：`/admin.php/nonexistent`、`/admin/index.php`。
- Tomcat 路径参数：`/admin;a=b/`。

## 二、方法切换

| 方法 | 说明 |
|---|---|
| `OPTIONS` | 常被路由直接放行，可能返回 Allow 列表 |
| `POST`/`PUT`/`PATCH`/`DELETE` | 权限中间件常按方法分支，配置遗漏 |
| `TRACE` | 回显请求（含 Cookie/自定义头） |
| `HEAD` | 部分实现只校验 GET/POST |
| `PROPFIND`/`PROPPATCH`/`MKCOL`/`COPY`/`MOVE` | WebDAV 未禁用时的额外入口 |

配合 `X-HTTP-Method-Override: PUT`、`X-Method-Override`、`_method=PUT` 绕过方法级限制。

## 三、Header 覆盖

```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: localhost
X-Forwarded-Proto: https
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Original-URI: /admin
Referer: https://internal.example.com/
```

- `X-Original-URL`/`X-Rewrite-URL` 在 IIS/ARR 与部分框架下可让**前端校验**看到安全路径、**后端**处理管理员路径。
- 内网 IP 伪造需配合信任链（应用信任 `X-Forwarded-For` 的最后一个/第一个值时）。
- 自定义头：`X-Admin: true`、`X-Internal-Request: 1` 常被当作"内网调用"放过。

## 四、Host 与虚拟主机

- 用一个 IP + 不同 `Host` 探测内部 vhost（`Host: internal.local`）。
- `Host` 与路径规范化组合可绕基于 vhost 的 ACL。
- 见 `HTTP-Protocol-Attacks/Host-Header-Attacks.md`。

## 五、编码与解析差异

- 多 `@` userinfo、反斜杠、`%00` 截断（老 Java/PHP）。
- 双重 URL 编码：网关解一次、后端解两次。
- Unicode 归一化：全角/相似字符在 best-fit 后变成目标字符。
- 见 `WAF-Bypass/Parser-Confusion-Bypass.md`。

## 六、边缘通道

- 源站 IP 直连（历史 DNS、证书透明度日志、`/favicon.ico` 哈希匹配、SSRF 回显）。
- 备用域名/测试域名/`staging`/`beta` 前缀。
- 内部工具端口（`/actuator`、`/debug/pprof`、`/_internal`）。
- 缓存副本（CDN 缓存了认证内容，见 `Cache-Poisoning-Deception.md`）。
- `403` 页面的源码、注释、错误堆栈常泄漏内部路径与参数名。

## 验证（最小证据）

1. 基线：`GET /admin` → 403（记录响应体长度与指纹）。
2. 变体：给出绕过请求 → 200 **且**响应体是管理员内容（非通用页）。
3. 记录被绕过的具体校验（路径规范化？方法分支？Header 信任？）。
4. 若只得到 200 但内容无法区分，用响应长度/标题/字段差异辅助，并在结论中标注不确定性。

## 常见误报

- 200 是 SPA 的 index.html（前端路由），后端接口仍 403。
- 403 → 404 变化：可能是路径不存在，不是绕过。
- 缓存/代理返回了他人内容。
- 目标为软 404（始终 200 + "not found" 文案）。

## 修复

- 路径在整个链路上只规范化一次，且规范化后**再**做 ACL 判断。
- 不依赖可伪造 Header 判定来源身份；如需反代信息，使用签名头（如 `X-Sig`）与网络层白名单。
- 方法白名单显式声明；禁用 TRACE/WebDAV。
- 统一错误响应，避免泄漏内部路径。
- 边缘节点与源站使用同一套 ACL（避免"边缘拦、源站放"）。

## 工具

`ffuf`/`dirsearch`（配合 `-mc all` 与过滤长度）、`nuclei`（403 绕过模板，仅线索）、`arjun`（隐藏参数）、`execute-python-script`（变体矩阵）。

## 参考

- HackTricks：403 & 401 Bypasses（思路）；PayloadsAllTheThings：403 Bypass
- PortSwigger Access Control
