# 本地侦察工具运行适配（离线回归与部署准备）

本改动不关闭工作区沙箱、不把 `/opt` 改成可写、不以 root 运行扫描，也不把非零退出码改为成功。本文命令是待人工维护窗口执行的步骤，本次开发没有部署、SSH、重启或目标扫描。

## Nmap / Nuclei：工具端机读契约

- `tools/nmap.yaml`：默认扫描参数仍为 `-sT -sV -sC`；独立参数 `xml_output` 默认 `"-"`，实际生成 `-oX -`。stdout 是 Nmap 原生 XML，stderr 是诊断。`scan_type` 替换扫描类型时不会丢掉 XML 参数。
- Nmap 显式 `xml_output="reports/result.xml"`：XML 写到该文件，stdout 恢复人类文本。显式 `xml_output=""`：不生成默认 `-oX`。需要自行通过 `additional_args` / `scan_type` 提供 `-oX`、`-oA` 或 `-oN -` 时应同时设空；避免重复输出选项或 stdout 混流。原始附加参数不被重写成另一种格式。默认 XML stdout 可以另配 `-oN human.txt` 保存人类文本副本。
- `tools/nuclei.yaml`：`json_output=true` 默认生成 `-jsonl`，`silent=true` 默认生成 `-silent`。stdout 是原生 JSONL，每行一条发现，stderr 不属于数据流。
- Nuclei 显式 `json_output=false` 保留原生人类文本，不自动补回 JSONL；`silent=false` 保留进度诊断。自定义附加输出模式时先关闭 `json_output`。`-json-export` / `-jsonl-export` 指文件导出，不能据此把 stdout 标成 JSON/JSONL。
- 空 Nuclei stdout 可以表示零发现，不是格式错误，但必须结合退出码、超时/截断信息判定是否完整。`Finished`、零条目等单一特征都不是成功依据。

**交给结果解析工作流的接口：** 使用上述实际参数与原件识别格式，不再把所有 Nmap 固定标为 `text`；也不能反向把显式文本或文件导出误标为 XML/JSONL。人类摘要应由展示层生成，原生机读 stdout 与 stderr 分开保存。此改动不修改 `internal/app/result_pipeline.go`、`result_tools.go` 或 `internal/recon/*`。

## OneForAll：安装阶段修复，运行阶段只读

生产失败源自 `common/utils.py:get_massdns_path` 无条件执行 `path.chmod(S_IXUSR)`。不仅只读目录会失败，该调用还会将权限替换成 `0100`，不是“追加执行位”。

新增两部分：

1. `scripts/recon/oneforall_prepare.py` 只在安装/维护阶段运行。它用 Python AST 校验指定函数及路径赋值，仅替换已识别结构；上游改版或自定义路径不匹配时明确拒绝，不猜测、不覆盖操作者配置。它把宿主架构的 massdns 设置为 `0755`，将运行时 chmod 改成只读的存在/读/执行权限检查，并将 `config/default.py`、`config/setting.py`、`config/log.py` 的默认 data/results 指向受控运行目录。`config/api.py`、venv、requirements 和 git 状态保持不动。
2. `scripts/recon/oneforall_runner.py` 随安装复制到 OneForAll 根目录。保留指定 venv 解释器路径（不解析 venv 的 python 符号链接）、原始 CLI 参数、当前工作目录、上游退出码。每次执行在服务注入的 `CSAI_ARTIFACT_DIR` 下创建 `oneforall-*` 私有目录，只复制 vendor `data`，不复制 API 配置、源代码或 venv。日志、SQLite、临时文件、缓存和默认导出分别落在该目录的 `results` / `data` 下。

运行要求：

- 外部现有 OS 沙箱仍是安全边界；适配器本身不提供沙箱。它要求 `CSAI_WORKSPACE_SANDBOX=1`、合法的服务执行 UUID、路径匹配的 `…/executions/<UUID>` 产物目录，缺失时不回退宿主机执行。
- 拒绝产物路径与 data 内的符号链接、非普通 data 文件；复制预算为 256 MiB / 10000 个目录与文件。预算超限明确失败并清理未完成的私有目录。
- 源码 hash 清单 `.csai-oneforall.json` 验证适配安装完整性。上游源码或受管配置变化后需审核并重跑准备脚本。初次改写文件及启动器保留 `.csai-original` 备份（权限 `0600`），幂等重跑不覆盖最初备份。
- 显式 `--path` 等参数和相对路径语义不被重写；不合法的宿主机写路径仍由沙箱拒绝。默认 fmt 沿用上游配置，通常是 CSV；控制台日志并不是 JSON。
- 上游 exit 2 原样返回，不因 `Finished OneForAll` 改成 success。建议负责统一失败分类的工作流移除“所有 exit 2 都是参数错误”的假设，结合原件判断。此次没有修改该分类实现或 `tool_preflight.go`。
- `--help` / `--runner-help` 是离线适配器帮助，`--check-runtime` 是只读安装/权限检查；两者均不会导入上游扫描代码。缺依赖不能靠执行阶段提权或安装包修复。

### 后续维护窗口需要执行的步骤（尚未执行）

1. 确认没有运行中的工具任务，备份既有安装和启动器；确认当前 `/usr/local/bin/oneforall` 使用的 venv 解释器绝对路径。不要直接用系统 Python 替换既有 venv。
2. 将本仓库的 `scripts/recon/oneforall_prepare.py` 和 `oneforall_runner.py` 一起用于安装准备。以下解释器路径需替换为第 1 步核实的值：

   ```sh
   python3 scripts/recon/oneforall_prepare.py \
     --install-dir /opt/OneForAll \
     --python /opt/OneForAll/venv/bin/python \
     --launcher /usr/local/bin/oneforall
   python3 scripts/recon/oneforall_prepare.py \
     --install-dir /opt/OneForAll \
     --python /opt/OneForAll/venv/bin/python \
     --launcher /usr/local/bin/oneforall --check
   /usr/local/bin/oneforall --check-runtime
   ```

   只有安装写入阶段需要管理安装目录的权限；运行工具继续使用原有非特权身份与沙箱。自定义 fork、缺少宿主架构 massdns、非标准存储赋值需人工审核；不要用开放整个 `/opt` 写权限处理。
3. 原有 `/opt/OneForAll` 仍作为只读 runtime 挂载。新适配器不依赖 `/opt/OneForAll/results` 的可写挂载，不需要新增广泛写目录。已有最小运行目录挂载的移除应由沙箱工作流另行审查。
4. 将三份工具 YAML 与配套结果解析改动一并纳入发布，保留生产覆盖参数；先在隔离 Linux 环境做无网络回归。不要仅覆盖 YAML 后声称所有历史 partial 已修复。

`install-tools-ubuntu24.sh` 已接入该准备步骤：即便旧 `oneforall` 命令存在也不会跳过适配；已有安装不再自动 `git pull` 或 `rm -rf`，优先复用 `.venv` / `venv`，也支持安装时设置 `ONEFORALL_HOME` / `ONEFORALL_PYTHON`。现有特殊 venv 路径应显式提供 `ONEFORALL_PYTHON`。新安装依赖失败会报错，不再继续登记一个不可用启动器。

## jsluice：官方静态 CLI 安装准备

已核对 [BishopFox/jsluice 官方 README](https://github.com/BishopFox/jsluice)、[go.mod](https://github.com/BishopFox/jsluice/blob/main/go.mod) 和 [Go 模块版本元数据](https://proxy.golang.org/github.com/%21bishop%21fox/jsluice/@latest)。官方 CLI 安装路径为 `github.com/BishopFox/jsluice/cmd/jsluice`，依赖 `go-tree-sitter`，需要 C 编译环境。

安装器的默认 core/full 已包含 jsluice，改为专用 `install_jsluice`：安装 `build-essential`，以 `CGO_ENABLED=1` 编译；默认固定 `v0.0.0-20240110145140-0ddfab153e06`，可通过安装环境 `JSLUICE_VERSION` 显式覆盖。`--skip-env` 不会漏掉该 C 编译依赖。已有二进制仍遵循安装器的跳过策略，需要替换时显式 `--force` 或单独安装固定版本。

维护环境可单独准备（仅安装，不分析或访问任何目标）：

```sh
apt-get install -y --no-install-recommends build-essential
CGO_ENABLED=1 GOBIN=/usr/local/bin go install github.com/BishopFox/jsluice/cmd/jsluice@v0.0.0-20240110145140-0ddfab153e06
go version -m /usr/local/bin/jsluice
```

本工作流不修改 `tools/jsluice.yaml`、JS runner 或 JSAPIscan 行为。

## 离线回归

在仓库根目录执行，不需要真实工具二进制、目标或外部服务：

```sh
python3 -B -m unittest scripts.recon.oneforall_runtime_test -v
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./internal/config -count=1
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./internal/security \
  -run 'TestReconMachineOutputCommandContracts|TestBuildCommandArgs_OneForAllCanonicalAndAlias' -count=1
bash -n install-tools-ubuntu24.sh
```

要求本机 Go >= 1.25，依赖已预缓存。Python 测试只执行自造安装目录、假入口和样本输出，massdns 占位文件从不执行。覆盖幂等准备、EROFS 下无 chmod、权限缺失、源变更、路径/符号链接边界、独立数据目录、预算失败清理、保留参数/相对路径与 exit 2，以及 jsluice 安装依赖契约。

Windows 若无法创建符号链接，相应两项测试会明确跳过；需在 Linux 完成同一套测试的符号链接与 POSIX 权限回归。当前 Windows cgo 工具链若报 `cannot parse gcc output ... _cgo_.o`，需在具备可用 C 编译器的隔离 Linux 环境执行 security 包命令测试；关闭 cgo 也不能编译本项目依赖的部分 SQLite API，不能把该失败当作测试通过。
