# 文件上传绕过与利用

> 上传功能的判定链通常是三层：**前端 JS 校验 → 服务端 MIME/后缀校验 → 存储与解析**。绕过 = 找到三层之间的缝隙，最终以**能执行/能被其他组件危险解析**为证据。

## 判定顺序

1. 服务端是否真的校验？（去掉前端 JS、直接 multipart 重放）
2. 校验什么？（后缀名 / `Content-Type` / magic bytes / 图像可解码 / 尺寸重编码）
3. 存到哪？（同域静态目录、独立对象存储域、可执行目录）
4. 谁解析？（Web 服务器、图像库、PDF/Office 渲染器、模板引擎、下游服务）

## 绕过维度

| 维度 | 手法 | 文档 |
|---|---|---|
| 后缀 | 黑名单绕过、双后缀、大小写、特殊字符、`.htaccess`/`web.config` | `Extension-and-Content-Type-Bypass.md` |
| 内容类型 | `Content-Type` 伪造、magic bytes 前缀、polyglot | `Magic-Bytes-and-Polyglot.md` |
| 解析器 | Web 服务器映射、`.pyc`/`.so` 覆盖、视图引擎编译、Zip Slip | `Upload-to-RCE-Chains.md` |
| 传输 | 文件名编码、`filename*`、multipart 解析差异、双次上传竞态 | `WAF-Bypass/Parser-Confusion-Bypass.md` |

## 高价值后果（按影响排序）

1. **RCE**：可执行后缀、配置覆盖、图像库 CVE、模板编译。
2. **XSS**：`svg`/`html` 同域直出，或 `Content-Type` 被推断为 `text/html`。
3. **SSRF**：上传的 URL 文件/文档被服务端拉取解析（PDF/Office/XML）。
4. **访问控制绕过**：覆盖已有文件（改名覆盖 `index.html`、覆盖配置文件）。
5. **存储型攻击**：超大文件/压缩炸弹导致 DoS。

## 验证（最小证据）

1. 上传成功且**能通过 HTTP 取回**（给出访问 URL 与响应头 `Content-Type`）。
2. 若声称 RCE：给出执行证据（命令回显、带外 DNS/HTTP 命中、写入标记文件）。
3. 若声称 XSS：给出同域且浏览器按 HTML/SVG 渲染的证据（响应头 + 实际渲染）。
4. 若仅为"上传成功但不可访问/不可解析"，结论降级为低危，并说明障碍。

## 常见误报

- 上传成功但存储域与业务域分离、`Content-Disposition: attachment` 且 `nosniff` → 无法 XSS。
- 上传的文件被重命名为随机 UUID + 非可执行后缀 → 无法 RCE。
- 图像被强制重编码（GD/ImageMagick 重采样）→ 内嵌 payload 被破坏。
- 前端提示"上传成功"但服务端拒绝（仅前端校验被绕过，后端仍有校验）。

## 修复

- 白名单后缀 + 服务端 magic bytes 校验 + 强制重编码图像。
- 存储到独立域/对象存储，返回 `Content-Type` 显式固定 + `X-Content-Type-Options: nosniff` + `Content-Disposition: attachment`。
- 上传目录禁止脚本执行（nginx `location ~ \.php$ { deny all; }`、IIS 请求筛选）。
- 文件名服务端生成，禁止用户控制路径（防 Zip Slip、防覆盖）。
- 对压缩包做条目路径与体积校验。

## 工具

`ffuf`/`burp` 类手工重放、`execute-python-script`（构造 multipart 与文件名编码）、`exiftool`/`file` 校验 polyglot。

## 参考

- PortSwigger File Upload、PayloadsAllTheThings Upload Insecure Files
- isec：Disguises Zip Past Path Traversal（2025）
- 上游 `Extension-and-Content-Type-Bypass.md`、`Upload-to-RCE-Chains.md`
