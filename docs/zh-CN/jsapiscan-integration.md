# JSAPIscan 接入与发布版检查

## 主工具与保留工具

在线 JS/API 发现默认使用 `tools/jsapiscan.yaml`；入口是范围内 URL 或 URL 清单。旧 `tools/jsluice.yaml` 与已安装的 jsluice 保留，只将配置设为 `enabled: false`，后续可恢复；没有删除源码、配置或旧程序。纯离线 JS 文件分析用本地解析/grep/rg，不把文件路径传给 jsapiscan 的 `-u`。

`jsapiscan` 是主动 HTTP 爬取程序，不是离线静态解析器。每个任务仍需工具发现/保存源码 + 对全部 JS/chunk/worker/source map 原源码的 grep/rg 两路证据，合并候选后做可达性、方法/参数和独立风险验证。

## 安装与来源

- 上游：`https://github.com/ruisika/jsapiscan`。
- 固定发布：`v1.1.2`，Linux/amd64，官方附件 `JSAPIscan_linux_amd64`，12,103,842 字节。
- SHA-256：`bf829b3e754a98c2817b5aa73dd138cf63a761dec669b1227e24a7f316958b68`，与 GitHub 资产 `digest` 一致。
- 原始程序：`/opt/jsapiscan/releases/v1.1.2/JSAPIscan_linux_amd64`，root 所有、只读可执行。
- 推荐入口：`/usr/local/bin/jsapiscan` → `scripts/recon/jsapiscan_runner.py`，每次启动再次校验上述 hash。
- 官方仓库与 v1.1.2 自动源码包目前只有 README；未做源码编译。用户确认允许发布二进制后，才下载官方编译版，没有使用第三方修改版。

## 最小检查范围与局限

安装前以 file/readelf、Go 构建信息、可疑字符串/URL、专用低权限无外网 systemd 单元和 strace 做基础检查。帮助模式和离线 HTTP 夹具运行中，观察到的网络连接仅为夹具 `127.0.0.1`，没有发现额外进程启动、生产凭据路径读取或持久化操作。静态 URL 中有 Rod 浏览器下载相关公开域名，不据字符串本身认定恶意；这些模式未在基础检查中启用。

构建信息显示 Go 1.26.1、静态链接、内部 revision `111b7a2960fe1e7e3bad00e45f86ccdd49956e28`，`vcs.modified=true`，内部 banner 为 `v1.0.1-9-g111b7a2-dirty`，与发布标签不是同一个版本字符串。哈希证明文件与官方发布附件一致，不证明作者构建完全可复现，也不证明“绝无后门”。检查没有覆盖混淆/加密载荷、定时/特定目标/特定身份触发、全部参数组合及 Rod 无头行为；保持低权限运行、谨慎交付凭据，不给二进制读取宿主生产配置的权限。

服务器检查原件保存于 `/opt/jsapiscan/audit/v1.1.2-20261002/`：来源元数据、Go 构建信息、静态指示、系统调用轨迹、夹具请求与结果。检查不扫描真实业务目标。

## 与 README 不同的实际 CLI

完整参数字段及默认值由 YAML 给出，以下差异必须保持：

- `-api` 实际存在，默认关闭；采集仍可能对发现路径发 GET 基线/补探，因此关闭该开关不等于完全不访问 API。
- `-ft` 是单目标层内抓取并发，默认上游 10、系统 2；`-t` 只控制顶层目标，`-u` 单目标为1。
- `-Ineedparms` 在帮助页出现，实际传入会报 `flag provided but not defined`。启动器/YAML不暴露它，参数由源码 grep/rg 和请求上下文补齐。
- `-o` 仅接受 txt/html；`-op` 才是文件名。启动器禁止路径穿越/绝对输出路径并隔离每轮工作目录。
- `-sc` 隐藏给定状态码，不是只显示这些码。
- `-person/-ey/-scan-libs/-wl/-rod` 是实际存在的附加能力，按任务范围显式选用。
- API 默认关闭、GET-only 默认开启；只有同时 `api_tests=true`、`get_only=false`、`allow_post_retry=true` 才允许 405 后 POST 重试。不用自动 POST 代替逐接口验证和副作用判断。

## 启动器与输出

Linux/root 宿主负责编排，实际二进制运行于不可登录的专用用户 `csai-jsapiscan`。每轮使用 systemd 文件系统隔离、不可访问生产应用目录、只写独立工作目录、无权限提升与能力集、内存/进程/CPU预算和总时间上限。普通在线任务需要访问其授权目标，所以生产启动器不是 `PrivateNetwork=yes`；审计夹具使用无外网模式。网络可达不代表范围许可，外链与跨域主动扫描仍需明确在范围内。

默认限制：1个顶层目标并发、2个抓取并发、深度8、单次8秒、JS类别1000/HTML40/API测试200、整轮300秒；maxreq/maxhtml/maxapi不是所有 HTTP 请求的严格总计。禁止0/负数不限模式；输入最多20个唯一 URL、128KiB。达到预算时记录已测子集、剩余 gap/blocked，不把正常进程退出或预览数量当全覆盖。

结果位于 `/var/lib/jsapiscan/runs/run-*/`，回包给出 `work_dir/stdout_file/manifest.json`、原件列表/hash与最多50条候选预览。原始 CSV/源码才是完整证据；CSV中的 Body 不回显到预览，原件按项目权限读取。请求头文件复制到受限工作目录，结束后移除副本；原用户文件不改动。不要把原始报告/源码秘密放进公开目录。

工具/角色/Skill 默认引用已经切换到 jsapiscan；服务器工具 YAML 更新后需应用正常的工具重载或下一次重启才更新 MCP 内存注册，修改磁盘文件不冒充已完成运行时重载。后端共享提示代码需正常发布；仅安装独立工具不自动替换后端程序或修改生产模型/数据库配置。
