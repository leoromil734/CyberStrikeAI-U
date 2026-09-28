# 上传到 RCE 的利用链

> 单个"能上传文件"往往只是中低危；**链式利用**才是高价值。本篇按落地链路组织，每条链都给出前置条件与验证证据。

## 链路一览

| 链 | 前置条件 | 关键步骤 | 证据 |
|---|---|---|---|
| A. 可执行后缀 | 目录允许脚本执行 | 上传脚本 → 请求触发 | 命令回显 / 带外命中 |
| B. 配置覆盖 | 允许 `.htaccess`/`web.config` | 上传配置 → 上传文本 → 触发 | 文本被脚本引擎执行 |
| C. 图像库利用 | 服务端处理图像（ImageMagick/GD/Sharp） | 构造恶意图（MSL/MVG、Exif、ICC） | 带入外回调或写文件 |
| D. 文档渲染 | PDF/Office/SVG 被服务端渲染 | 内嵌 URL/脚本/外链 XML | SSRF 回调、本地文件读取 |
| E. Zip Slip | 解压逻辑未校验条目路径 | 压缩包含 `../` 条目 | 写到目标路径的标记文件 |
| F. 字节码/共享库覆盖 | 应用可 import 用户目录（Python/Node） | 覆盖 `.pyc` / 放置 `.so` / `node_modules` 投毒 | 进程 reload 后执行 |
| G. 视图/模板落地 | 框架按约定从可写目录加载视图 | 上传满足视图命名的文件 → 触发路由 | 路由返回模板执行结果 |
| H. 覆盖既有文件 | 文件名可控且无冲突处理 | 覆盖静态资源/配置 | 页面内容被替换 |

## B. 配置覆盖要点

- Apache：目录需 `AllowOverride`；`AddType`/`SetHandler` 任一可行。
- IIS：`web.config` 只能存在于应用根或子目录；handler 需指向真实 ISAPI/CGI。
- nginx 不支持 `.htaccess`，但若有 `include`/`alias` 配置或上传目录被 `fastcgi` 覆盖则另论。
- 上传后**必须**对目标后缀发一次请求验证映射生效，否则不算 RCE。

## C. 图像处理链

- ImageMagick 的 delegate 机制（MSL/MVG/HTTPS 等），历史上多次导致任意文件读/RCE（ImageTragick 家族）。
- 注意现代版本默认禁用多数 coder，先探测版本与策略文件（`policy.xml`）。
- 备选：SVG 中的 `<image xlink:href="http://...">`、`<use>` 外链、滤镜里的 URL（可造成 SSRF）。
- 图形库崩溃/超时也可作为 DoS 证据，但需谨慎测试。

## D. 文档渲染链

- 服务端把上传的 PDF/Office/SVG 渲染为缩略图/预览 → 天然 SSRF 与文件读取出口（PDF 的 `/URI`、`/GoToR`、外部 XObject；Office 的外部关系；SVG 的外链）。
- 若渲染器支持 `phar://`、`file://`、`data:` 等包装器，可能升级为反序列化（PHP `phar://` 触发 `__wakeup`）。
- 路径穿越常通过 URL 编码/双重编码绕过（PT Security 2025 "Blind trust" 研究）。
- XXE 变体：libxml2 的实体扩展怪癖 + 流包装器 + filter chain 可绕 `noent`/doctype 检查（2025 "Impossible XXE in PHP"）。

## F. 字节码与依赖覆盖

- Python：覆盖合法 `.pyc` 头部即可让注入字节码在导入时加载；更强的做法是放置**编译扩展模块**（`.so`/`.pyd`），导入解析优先级高于 `.py`/`.pyc`（siunam321 2025）。
- Node：覆盖 `node_modules` 内文件或投放 `package.json` 同名包（依赖混淆）。
- Java：覆盖 class/JSP 预编译目录 → 通常需应用重启。

## E. Zip Slip 与解压

```text
malicious.zip
  └── ../../../../var/www/html/shell.jsp
```

- 某些实现只检查文件名，不检查解压后的绝对路径；注意 Windows 的 `..\`、`%2e%2e%5c`、绝对路径 `C:\`。
- 大型日志/镜像格式（tar、cpio、7z、rar、jar）同样适用。
- 2025 年该类漏洞回归（"Disguises Zip Past Path Traversal"）。

## 验证（最小证据）

1. 上传内容可预测（含唯一标记，如随机串）。
2. 通过 HTTP 或副作用（新文件、回调、命令回显）确认落地**且被执行/被危险解析**。
3. 记录链路每一跳（上传 → 触发 → 效果），缺少任何一跳就降级结论。

## 常见误报

- 上传成功但处理流水线异步且失败（无重试队列）→ 等不到效果。
- 声称"RCE"但没有执行证据，仅有文件落地。
- 沙箱/容器内执行但无外联 → 影响需按隔离程度重新评估。

## 修复

- 上传与执行彻底分离：独立域、只读挂载、禁用执行。
- 解压前校验每个条目的规范化路径必须位于目标目录内。
- 图像/文档处理放在沙箱化 worker（无凭据、无内网访问、限制资源）。
- 禁止用户控制文件名与目录；配置目录不可写。

## 参考

- PT Security：Blind trust（PDF 生成链，2025）、Impossible XXE in PHP（2025）
- siunam321：Python dirty arbitrary file write to RCE（2025）
- iSec：Disguises Zip Past Path Traversal（2025）
- PayloadsAllTheThings：Upload Insecure Files / Zip Slip
