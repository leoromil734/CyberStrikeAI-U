# BBOT 接入（攻击面侦察）

BBOT（[blacklanternsecurity/bbot](https://github.com/blacklanternsecurity/bbot)，当前 3.0.2）以“沙箱托管 + 部署期预装依赖”的方式接入，不改变既有工作区沙箱边界。

## 组成

| 位置 | 作用 |
| --- | --- |
| `tools/bbot.yaml` | 工具配方：`command: /usr/local/bin/csai-bbot`，参数只映射到显式 flag |
| `scripts/recon/bbot_runner.py` | 托管启动器；发布到 `/opt/cyberstrike-tool-runtime/scripts/recon/bbot_runner.py` |
| `/usr/local/bin/csai-bbot` | shell 包装：`exec /opt/pipx/venvs/bbot/bin/python3 -B .../bbot_runner.py "$@"` |
| `/opt/pipx/venvs/bbot` | pipx 安装的 BBOT（只读挂载 `local_sandbox_runtime_paths: /opt/pipx`） |
| `/opt/bbot-home` | 部署期预装的 BBOT home：`tools/`（外部工具）、`cache/`（模型与依赖标记）、可选 `config/`（`bbot.yml`、`secrets.yml`） |
| `config.yaml` | `security.local_sandbox_runtime_paths` 增加 `- /opt/bbot-home`（只读挂载；改动后需重启服务生效） |

`/opt/bbot-home` 以 **只读** 方式进入沙箱，运行期不写入。

## 运行期布局

启动器只在工作区与本次执行产物目录内写入：

- `$HOME/.bbot`（工作区 `.home/.bbot`）：BBOT home，按工作区持久
  - `tools/`：真实可写目录（BBOT 会校验其可写），从 `/opt/bbot-home/tools` 播种；≤8MiB 复制，更大体积的外部工具用符号链接，避免在工作区重复几十上百 MB
  - `cache/`：首次从 `/opt/bbot-home/cache` 播种（词表预测模型、依赖安装标记），之后本地保留
  - `lib/`、`temp/`、`scans/`、`logs/`：本地可写
- `$HOME/.config/bbot/{bbot.yml,secrets.yml}`：仅当工作区还没有时，链接到 `/opt/bbot-home/config/` 的集中配置
- 扫描输出：`$CSAI_ARTIFACT_DIR/bbot-out/<扫描名>/`（`output.json`、`output.csv`、`output.txt`、`subdomains.txt`、`scan.log` 等）

启动器固定注入（调用方显式给出同名选项时不重复注入）：

- `-c home=$HOME/.bbot`：运行目录由托管方决定，不接受配方改写
- `--no-deps`：关闭依赖安装器（安装需要 root，且运行目录只读）
- `-o $CSAI_ARTIFACT_DIR/bbot-out`、`-y`、`--no-color`
- 多值 flag（`-t/--targets`、`-p/--preset`、`-m/--modules`、`-rf`、`-ef`、`--event-types` 等）会把单个配方值按空格/逗号展开为多个 token，`-c` 的值不会被拆分

沙箱要求：`CSAI_WORKSPACE_SANDBOX=1`、合法执行 UUID、位于 `executions/<UUID>` 的产物目录；缺失即拒绝执行，不回退宿主机。

## 部署步骤（已完成，供重建参考）

```sh
# 1) 安装 BBOT（沿用既有 pipx home/bin 约定）
PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install bbot

# 2) 部署期预装模块依赖（root、无目标流量：--dry-run 只加载模块）
mkdir -p /opt/bbot-home
bbot -t example.com -p subdomain-enum web spider --dry-run -y -c home=/opt/bbot-home
# 需要完整模块集时再执行：bbot -c home=/opt/bbot-home --install-all-deps

# 3) 沙箱身份（uid 65534）必须可读
chmod -R a+rX /opt/bbot-home

# 4) 发布启动器与包装
install -m 0644 scripts/recon/bbot_runner.py /opt/cyberstrike-tool-runtime/scripts/recon/bbot_runner.py
cat > /usr/local/bin/csai-bbot <<'EOF'
#!/bin/sh
exec /opt/pipx/venvs/bbot/bin/python3 -B /opt/cyberstrike-tool-runtime/scripts/recon/bbot_runner.py "$@"
EOF
chmod 0755 /usr/local/bin/csai-bbot

# 5) tools/bbot.yaml 发布到生产 tools 目录；config.yaml 增加 /opt/bbot-home 只读运行路径；重启服务
```

维护期建议同时执行 `/usr/local/bin/csai-bbot --check-runtime`（只读检查 pipx 安装、预装目录与权限）。

## 升级与维护

- 升级 BBOT：`PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx upgrade bbot`，然后重跑步骤 2 的依赖预装。
- 新增模块依赖：用 `--install-all-deps` 或指定预设的 `--dry-run` 重跑，完成后 `chmod -R a+rX /opt/bbot-home`。
- API Key：放在 `/opt/bbot-home/config/secrets.yml`（格式与 BBOT 官方一致），运行期以只读链接进入各工作区；未配置密钥的被动数据源模块会 soft-fail 并给出原因。
- 旧缓存/工具变化后，工作区里已播种的 `$HOME/.bbot/{tools,cache}` 不会自动更新：删除对应工作区的 `.home/.bbot`（或只删标记文件 `.csai-tools-seed-v1` / `.csai-cache-seed-v1`）后下次运行重新播种。

## 已知限制

- 系统单次工具超时（`agent.tool_timeout_minutes`，默认 10 分钟）会终止长扫描；已输出的事件留在 stdout 与输出目录中。建议用窄预设或被动模式：`require_flags: "passive"`。
- 主动模块（`dnsbrute`、`dnsbrute_mutations`、`webbrute`、`portscan`、`nuclei`、`lightfuzz` 等）会向目标发起大量请求，仅限授权目标。
- 上游个别模块存在缺陷（例如本次验证中 `crt` 返回 400、`wayback` 参数类型报错），属 BBOT 侧问题，不影响其它模块。
- 预装的模块集决定可用预设：未预装依赖的模块在运行期报错但不影响整轮扫描（`--no-deps`）。

## 回归

```sh
python3 -B -m unittest scripts.recon.bbot_runtime_test -v          # 启动器离线测试
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./internal/security -run BBOT -count=1
CSAI_DEPLOYMENT_SMOKE=1 GOTOOLCHAIN=local go test ./internal/security \
  -run TestBBOTDeploymentSandboxSmoke -count=1 -v                  # 真实沙箱内 dry-run，不接触目标
```

`cmd/tool-doctor -names bbot` 用于校验配方可加载、命令可执行。
