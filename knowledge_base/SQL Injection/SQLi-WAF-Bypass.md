# SQL 注入 WAF 与过滤器绕过

> 上游 `README.md` 已有通用 WAF 绕过（空格/逗号/等号/大小写）。本篇补充**现代 WAF、解析器差异、预编译语句与 ORM 新手法**，并强调绕过必须可复现、可证伪。

## 绕过维度总览

1. 语法缝隙（关键字边界、注释嵌套、空白字符）
2. 编码与归一化（Unicode、双重 URL 编码、GBK 宽字节）
3. 参数位置（Header、JSON、multipart、路径、Cookie）
4. 协议层（HTTP/1.1 拆包、chunked 分块、H2 降级）
5. 解析器差异（WAF 解析 ≠ DB 驱动解析）

## 一、关键字与空白

- 注释替空白：`/**/`、`/*!50000select*/`（MySQL 版本注释）、`--`（需空白）、`#`、`;%00`。
- 非常规空白：`%09 %0a %0b %0c %0d`、`%a0`、`%e0`、全角空格；SQL Server 中的 `%0b`。
- 关键字拆分：`sel/**/ect`、`un/**/ion`、`SEL%00ECT`（部分驱动会剥 `\0`）。
- 等价函数替换：`substr`→`substring`/`mid`/`left`，`ascii`→`hex`/`ord`，`concat`→`||`/`+`，
  `information_schema`→`sys`/`pg_catalog`/`mysql.innodb_table_stats`。
- 引号替代：`"` `'` 反引号、`0x68 0x65 0x6c` 十六进制字面量、`CHAR(0x61)`。
- 逗号替代：`LIMIT 1 OFFSET 1`、`LIMIT 1,1`→`LIMIT 1 OFFSET 1`、`JOIN` 替 `UNION SELECT 1,2`。

## 二、编码与归一化

- 双重/多重 URL 编码，依赖解码顺序差异。
- GBK/GB2312 宽字节：`%df'` → 转义后形成非法多字节，尾部引号"逃逸"。
- Unicode 归一化（`U+FF07`、`U+02B9` 等）在 best-fit 映射后变成 `'`；Unicode 截断与溢出见 `WAF-Bypass/Parser-Confusion-Bypass.md`。
- Base64/JSON 内嵌参数的后端二次解码。

## 三、参数位置与协议层

- 把 payload 放入 WAF 不检查的位置：`User-Agent`、`X-Forwarded-For`、`Cookie`、`Referer`、JSON 深层字段、multipart 文件名、路径段。
- chunked 分块发送使关键字跨越 chunk 边界：`Content-Length` 删除、每块一小段，绕过基于缓冲区的检测。
- H2 降级/请求走私（见 `HTTP-Protocol-Attacks/Request-Smuggling.md`）：让 WAF 看到一个请求、后端看到另一个。
- 参数污染（HPP）：同名参数多次出现，WAF 取首个、后端取末尾。

## 四、预编译语句与 ORM（新手法）

- **PDO 模拟预编译**：`ATTR_EMULATE_PREPARES=true` 时，PDO 自带 SQL 解析器会误判引号/注释边界，已知可用 `%00` 与转义边界让用户输入被重新解释为**占位符**（Assetnote 2025 "Novel SQL Injection Technique in PDO Prepared Statements"）。
- 占位符数量可控时，可构造 `?`/`$1` 数量错位，把"值"变成"结构"。
- ORM 过滤表达式部分覆写怪癖：如 Beego filter-expression 段覆写可夹带未校验字段；Prisma 类型混淆可把用户输入强制转换为 operator 对象（Elttam 2025 "ORM Leaking More Than You Joined For"）。
- 二次注入：污点写入 DB，后续拼接查询触发。

## 五、按 DBMS 的绕过要点

- MySQL：`/*!50000...*/`、`||` 默认非拼接（需 `PIPES_AS_CONCAT`）、`information_schema` 被限权时用 `mysql.innodb_table_stats`、`sys.schema_auto_increment_columns`。
- MSSQL：`%0b`、`EXEC`、`WAITFOR DELAY`、堆叠查询常可用；`sa` 权限下的 `xp_cmdshell`。
- PostgreSQL：`$$` 字符串、`::cast`、`pg_sleep`、`COPY ... TO PROGRAM`（超级用户）、`lo_import`。
- Oracle：`UTL_HTTP`/`DBMS_LDAP` 带外、`ROWNUM` 替代 `LIMIT`、`CHR()` 拼接。
- 盲注替代带外：DNS/HTTP 到 Interactsh（MySQL `LOAD_FILE`、MSSQL `xp_dirtree`、Oracle `UTL_HTTP`、PG `COPY TO PROGRAM`）。

## 验证（最小证据）

1. 明确的注入点与参数（请求原文）。
2. 可复现的类型判定：布尔差分、时间差分（多次采样取中位数）、带外回调、报错回显。
3. 影响证据：可读表名/列名/数据片段，或可证明可写（谨慎，勿破坏数据）。
4. 记录 WAF 行为：被拦 payload 与绕过 payload 成对出现才有说服力。

## 常见误报

- 统一错误页模仿 SQL 报错。
- WAF 拦截页（含 `Request blocked`）被当作注入成功。
- 时间差来自网络抖动 → 必须多次采样并做基线对比。
- 参数化查询正常返回但含 `'` 字符 → 不是注入。

## 修复

- 全量参数化查询/预编译，关闭 PDO 模拟预编译（`ATTR_EMULATE_PREPARES=false`）。
- DB 账号最小权限，禁用 `xp_cmdshell`/`COPY TO PROGRAM` 等。
- 统一错误处理，但保留服务端安全日志。
- WAF 作为纵深防御，不作为修复手段。

## 工具

`sqlmap`（`--tamper`、`--random-agent`、`--technique=B/T`）、`interactsh-client`、`execute-python-script` 做自定义编码与时序。

## 参考

- PortSwigger SQLi / WAF bypass 研究；PayloadsAllTheThings SQL Injection
- Assetnote：PDO 预编译语句中的新注入技术（2025）
- Elttam：ORM Leaking More Than You Joined For（2025）
