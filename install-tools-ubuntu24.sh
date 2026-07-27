#!/usr/bin/env bash
# =============================================================================
# CyberStrikeAI — Ubuntu 24.04 安全工具一键安装脚本
#
# 背景：tools/*.yaml 只是 MCP 工具描述，不会自动安装二进制。
# 本脚本负责把常用命令装进 PATH，供 CyberStrikeAI 调用。
#
# 用法：
#   chmod +x install-tools-ubuntu24.sh
#   sudo ./install-tools-ubuntu24.sh              # 默认 core 套件
#   sudo ./install-tools-ubuntu24.sh --profile full
#   sudo ./install-tools-ubuntu24.sh --profile core --skip-env
#   sudo ./install-tools-ubuntu24.sh --list
#   sudo ./install-tools-ubuntu24.sh --dry-run
#
# 环境变量（可选）：
#   GOPROXY          默认 https://goproxy.cn,direct
#   PIP_INDEX_URL    默认 https://pypi.tuna.tsinghua.edu.cn/simple
#   GO_VERSION       默认 1.25.0（官方 tarball，覆盖 apt 过旧的 golang）
#   TOOLS_BIN_DIR    默认 /usr/local/bin
# =============================================================================

set -euo pipefail

# ---------- 颜色与日志 ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()     { echo -e "${RED}[ERR]${NC}   $*" >&2; }
section() { echo -e "\n${CYAN}======== $* ========${NC}"; }

# ---------- 默认配置 ----------
PROFILE="core"          # core | full | minimal
SKIP_ENV=0
DRY_RUN=0
DO_LIST=0
FORCE_REINSTALL=0

GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"
GO_VERSION="${GO_VERSION:-1.25.0}"
TOOLS_BIN_DIR="${TOOLS_BIN_DIR:-/usr/local/bin}"
GO_MIN_MAJOR=1
GO_MIN_MINOR=21
PY_MIN_MAJOR=3
PY_MIN_MINOR=10

# 统计
STAT_OK=0
STAT_SKIP=0
STAT_FAIL=0
FAILED_TOOLS=()

# ---------- 参数解析 ----------
usage() {
  cat <<'EOF'
CyberStrikeAI Ubuntu 24.04 工具安装脚本

用法:
  sudo ./install-tools-ubuntu24.sh [选项]

选项:
  --profile <name>   安装套件: minimal | core(默认) | full
  --skip-env         不检查/安装 Go、Python（仅装工具）
  --force            已存在的工具也强制重装（go/pip）
  --dry-run          只打印将要执行的操作
  --list             列出各 profile 包含的工具
  -h, --help         显示帮助

套件说明:
  minimal  扫描基础：nmap masscan sqlmap hydra nikto ffuf nuclei subfinder httpx
  core     渗透测试常用（默认，推荐；含 dalfox/trivy/oneforall 等）
  full     core + 云安全/容器/取证/二进制分析等（体积大、耗时长）
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --skip-env) SKIP_ENV=1; shift ;;
    --force) FORCE_REINSTALL=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --list) DO_LIST=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "未知参数: $1"; usage; exit 1 ;;
  esac
done

case "$PROFILE" in
  minimal|core|full) ;;
  *) err "无效 profile: $PROFILE（支持 minimal|core|full）"; exit 1 ;;
esac

# ---------- 工具集合定义 ----------
# 格式: 每行一个 "name|check_cmd|install_kind|install_spec"
# install_kind:
#   apt      -> apt-get install -y <spec>
#   go       -> go install <spec>@latest
#   pip      -> pipx/pip install <spec>
#   github   -> 从 GitHub release 下载二进制 (spec=owner/repo:asset_glob:bin_name)
#   cargo    -> cargo install <spec>
#   script   -> 自定义函数名
#   skip     -> 仅提示，不安装

# 替换策略（与 tools/*.yaml 对齐）：
#   clair→trivy | xsser→dalfox | gobuster→ffuf | jaeles→nuclei | scout→prowler
# shellcheck disable=SC2034
TOOLS_MINIMAL=(
  "nmap|nmap|apt|nmap"
  "masscan|masscan|apt|masscan"
  "sqlmap|sqlmap|apt|sqlmap"
  "nikto|nikto|apt|nikto"
  "hydra|hydra|apt|hydra"
  "john|john|apt|john"
  "binwalk|binwalk|apt|binwalk"
  # 保证最小安装也有可用字典，ffuf YAML 会优先选此路径
  "web-wordlist|/opt/cyberstrike/wordlists/raft-small-directories.txt|script|install_web_wordlist"
  # 主用：ffuf（替代 gobuster）
  "ffuf|ffuf|go|github.com/ffuf/ffuf/v2@latest"
  # 主用：nuclei（替代 jaeles）
  "nuclei|nuclei|go|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "subfinder|subfinder|go|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  # 探活主用：单独命名为 httpx-pd，避免被 Python httpx CLI 抢占
  "httpx|httpx-pd|script|install_httpx_pd"
)

TOOLS_CORE_EXTRA=(
  # apt
  "hashcat|hashcat|apt|hashcat"
  "dnsenum|dnsenum|apt|dnsenum"
  "nbtscan|nbtscan|apt|nbtscan"
  "smbmap|smbmap|apt|smbmap"
  "exiftool|exiftool|apt|libimage-exiftool-perl"
  "foremost|foremost|apt|foremost"
  "steghide|steghide|apt|steghide"
  "strings|strings|apt|binutils"
  "xxd|xxd|apt|xxd"
  "objdump|objdump|apt|binutils"
  "gdb|gdb|apt|gdb"
  "arp-scan|arp-scan|apt|arp-scan"
  "rpcclient|rpcclient|apt|smbclient"
  "wafw00f|wafw00f|apt|wafw00f"
  "whatweb|whatweb|apt|whatweb"
  "sslscan|sslscan|apt|sslscan"
  "netcat|nc|apt|netcat-openbsd"
  "jq|jq|apt|jq"
  "whois|whois|apt|whois"
  "traceroute|traceroute|apt|traceroute"
  "tcpdump|tcpdump|apt|tcpdump"
  "ncat|ncat|apt|ncat"
  # Web 小字典由 minimal 中的 install_web_wordlist 提供；不依赖 Kali 专属 seclists/wordlists 包
  # go（目录爆破主用 ffuf；不再装 gobuster/jaeles）
  "katana|katana|go|github.com/projectdiscovery/katana/cmd/katana@latest"
  "naabu|naabu|go|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "dnsx|dnsx|go|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  # OAST/OOB（YAML: tools/interactsh.yaml，命令 interactsh-client）
  "interactsh-client|interactsh-client|go|github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "gau|gau|go|github.com/lc/gau/v2/cmd/gau@latest"
  "waybackurls|waybackurls|go|github.com/tomnomnom/waybackurls@latest"
  # XSS 主用 dalfox（替代 xsser）
  "dalfox|dalfox|go|github.com/hahwul/dalfox/v2@latest"
  "amass|amass|go|github.com/owasp-amass/amass/v4/...@master"
  # pip / pipx
  "dirsearch|dirsearch|pip|dirsearch"
  "arjun|arjun|pip|arjun"
  "paramspider|paramspider|pip|paramspider"
  "fierce|fierce|pip|fierce"
  "impacket|impacket-secretsdump|pip|impacket"
  "bloodhound|bloodhound-python|pip|bloodhound"
  "netexec|netexec|pip|netexec"
  "enum4linux-ng|enum4linux-ng|pip|enum4linux-ng"
  "checkov|checkov|pip|checkov"
  # YAML command 为 volatility3（不是 vol）
  "volatility3|volatility3|pip|volatility3"
  "ropgadget|ROPgadget|pip|ropgadget"
  "ropper|ropper|pip|ropper"
  "jwt-analyzer|jwt_tool|script|install_jwt_tool"
  "fscan|fscan|github|shadow1ng/fscan:fscan:fscan"
  "feroxbuster|feroxbuster|github|epi052/feroxbuster:x86_64-linux-feroxbuster.zip:feroxbuster"
  # 容器扫描主用 trivy（替代 clair）
  "trivy|trivy|script|install_trivy"
  "rustscan|rustscan|script|install_rustscan"
  "wpscan|wpscan|script|install_wpscan"
  "x8|x8|cargo|x8"
  "zsteg|zsteg|script|install_zsteg"
  # 子域深度收集（YAML: tools/oneforall.yaml）；与 subfinder 互补
  "oneforall|oneforall|script|install_oneforall"
)

TOOLS_FULL_EXTRA=(
  # 云审计主用 prowler（scout 默认不装）
  "prowler|prowler|pip|prowler"
  "pacu|pacu|pip|pacu"
  "kube-hunter|kube-hunter|pip|kube-hunter"
  "checksec|checksec|pip|checksec.py"
  "pwntools|pwn|pip|pwntools"
  "angr|python3|pip|angr"
  "one-gadget|one_gadget|script|install_one_gadget"
  "pwninit|pwninit|cargo|pwninit"
  "radare2|r2|script|install_radare2"
  "kube-bench|kube-bench|script|install_kube_bench"
  "terrascan|terrascan|script|install_terrascan"
  "hashpump|hashpump|apt|hashpump"
  "linpeas|linpeas.sh|script|install_linpeas"
  # 体积大 / 已弃用 / 需额外仓库
  "metasploit|msfconsole|skip|请手动安装 Metasploit（含 msfvenom）"
  "ghidra|analyzeHeadless|skip|请手动安装 Ghidra (需要 JDK)"
  "zap|zap-cli|skip|请手动安装 OWASP ZAP"
  "clair|clair|skip|已弃用，请用 trivy"
  "gobuster|gobuster|skip|已弃用，请用 ffuf"
  "jaeles|jaeles|skip|已弃用，请用 nuclei"
  "xsser|xsser|skip|已弃用，请用 dalfox"
  "scout-suite|scout|skip|次选，主用 prowler；需要时: pipx install scoutsuite"
  "falco|falco|skip|需官方仓库，见 https://falco.org/docs/install-operate/installation/"
  "cloudmapper|cloudmapper|skip|见 duo-labs/cloudmapper 文档"
  "responder|Responder.py|skip|git clone https://github.com/lgandx/Responder"
  "dotdotpwn|dotdotpwn|skip|git clone https://github.com/wireghoul/dotdotpwn"
  "graphql-scanner|graphqlmap|skip|git clone https://github.com/swisskyrepo/GraphQLmap"
  "api-schema-analyzer|spectral|skip|npm i -g @stoplight/spectral-cli"
)

build_tool_list() {
  TOOLS=()
  case "$PROFILE" in
    minimal) TOOLS=("${TOOLS_MINIMAL[@]}") ;;
    core)
      TOOLS=("${TOOLS_MINIMAL[@]}")
      TOOLS+=("${TOOLS_CORE_EXTRA[@]}")
      ;;
    full)
      TOOLS=("${TOOLS_MINIMAL[@]}")
      TOOLS+=("${TOOLS_CORE_EXTRA[@]}")
      TOOLS+=("${TOOLS_FULL_EXTRA[@]}")
      ;;
  esac
}

list_tools() {
  build_tool_list
  echo "Profile: $PROFILE  (共 ${#TOOLS[@]} 项)"
  printf '%-22s %-18s %-8s %s\n' "NAME" "CHECK" "KIND" "SPEC"
  printf '%-22s %-18s %-8s %s\n' "----" "-----" "----" "----"
  for entry in "${TOOLS[@]}"; do
    IFS='|' read -r name check kind spec <<<"$entry"
    printf '%-22s %-18s %-8s %s\n' "$name" "$check" "$kind" "$spec"
  done
}

# ---------- 权限与系统检查 ----------
need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "请使用 root 或 sudo 运行: sudo $0 $*"
    exit 1
  fi
}

check_ubuntu() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    info "系统: ${PRETTY_NAME:-unknown}"
    if [[ "${ID:-}" != "ubuntu" ]]; then
      warn "非 Ubuntu 系统，脚本按 Ubuntu 24.04 编写，可能部分失败"
    elif [[ "${VERSION_ID:-}" != "24.04" ]]; then
      warn "当前版本 ${VERSION_ID:-?}，目标为 24.04，继续尝试..."
    fi
  fi
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) ARCH_GO=amd64; ARCH_GH=amd64; ARCH_TRIVY=64bit ;;
    aarch64|arm64) ARCH_GO=arm64; ARCH_GH=arm64; ARCH_TRIVY=ARM64 ;;
    *) err "不支持的架构: $ARCH"; exit 1 ;;
  esac
  ok "架构: $ARCH"
}

run_cmd() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "[dry-run] $*"
    return 0
  fi
  "$@"
}

# ---------- 基础依赖 ----------
install_base_deps() {
  section "安装系统基础依赖"
  export DEBIAN_FRONTEND=noninteractive
  run_cmd apt-get update -qq
  run_cmd apt-get install -y --no-install-recommends \
    ca-certificates curl wget git unzip zip tar gzip xz-utils \
    build-essential pkg-config libssl-dev \
    python3 python3-pip python3-venv python3-dev \
    software-properties-common apt-transport-https gnupg \
    jq ripgrep
  ok "基础依赖就绪"
}

# ---------- Python ----------
version_ge() {
  # version_ge A.B C.D  => A.B >= C.D
  local a_major a_minor b_major b_minor
  a_major=$(echo "$1" | cut -d. -f1)
  a_minor=$(echo "$1" | cut -d. -f2)
  b_major=$(echo "$2" | cut -d. -f1)
  b_minor=$(echo "$2" | cut -d. -f2)
  if (( a_major > b_major )); then return 0; fi
  if (( a_major < b_major )); then return 1; fi
  (( a_minor >= b_minor ))
}

ensure_python() {
  section "检查 Python 环境"
  if ! command -v python3 >/dev/null 2>&1; then
    info "安装 python3..."
    run_cmd apt-get install -y python3 python3-pip python3-venv python3-dev
  fi
  local ver
  ver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  if ! version_ge "$ver" "${PY_MIN_MAJOR}.${PY_MIN_MINOR}"; then
    err "Python $ver 过旧，需要 >= ${PY_MIN_MAJOR}.${PY_MIN_MINOR}"
    exit 1
  fi
  ok "Python: $(python3 --version 2>&1)"

  # pipx：隔离 CLI 工具，避免污染系统 site-packages（Ubuntu 24 PEP 668）
  if ! command -v pipx >/dev/null 2>&1; then
    info "安装 pipx..."
    run_cmd apt-get install -y pipx || true
    if ! command -v pipx >/dev/null 2>&1; then
      run_cmd python3 -m pip install --break-system-packages pipx || true
      run_cmd python3 -m pipx ensurepath || true
    fi
  fi
  # 确保 pipx 的 bin 在 PATH
  export PATH="${PATH}:/root/.local/bin:${HOME}/.local/bin"
  if command -v pipx >/dev/null 2>&1; then
    run_cmd pipx ensurepath >/dev/null 2>&1 || true
    ok "pipx: $(pipx --version 2>&1 || echo ready)"
  else
    warn "pipx 不可用，将回退到 pip --break-system-packages"
  fi
}

# ---------- Go ----------
ensure_go() {
  section "检查 Go 环境"
  local need_install=0
  if ! command -v go >/dev/null 2>&1; then
    need_install=1
  else
    local ver major minor
    ver=$(go version | awk '{print $3}' | sed 's/go//')
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)
    if (( major < GO_MIN_MAJOR )) || { (( major == GO_MIN_MAJOR )) && (( minor < GO_MIN_MINOR )); }; then
      warn "Go $ver 过旧（需要 >= ${GO_MIN_MAJOR}.${GO_MIN_MINOR}），将安装 ${GO_VERSION}"
      need_install=1
    else
      ok "Go: $(go version)"
    fi
  fi

  if [[ "$need_install" -eq 1 ]]; then
    info "安装 Go ${GO_VERSION} (官方 tarball → /usr/local/go)..."
    local tarball="go${GO_VERSION}.linux-${ARCH_GO}.tar.gz"
    local url="https://go.dev/dl/${tarball}"
    # 国内镜像兜底
    local mirrors=(
      "$url"
      "https://mirrors.aliyun.com/golang/${tarball}"
      "https://golang.google.cn/dl/${tarball}"
    )
    local tmp
    tmp=$(mktemp -d)
    local ok_dl=0
    for m in "${mirrors[@]}"; do
      info "下载: $m"
      if run_cmd curl -fsSL --connect-timeout 15 -o "${tmp}/${tarball}" "$m"; then
        ok_dl=1
        break
      fi
      warn "下载失败，尝试下一个镜像..."
    done
    if [[ "$ok_dl" -ne 1 && "$DRY_RUN" -eq 0 ]]; then
      err "无法下载 Go ${GO_VERSION}"
      rm -rf "$tmp"
      exit 1
    fi
    if [[ "$DRY_RUN" -eq 0 ]]; then
      rm -rf /usr/local/go
      tar -C /usr/local -xzf "${tmp}/${tarball}"
      rm -rf "$tmp"
    fi
    export PATH="/usr/local/go/bin:${PATH}"
    # 写入 profile（幂等）
    local line='export PATH=/usr/local/go/bin:$PATH'
    for f in /etc/profile.d/golang.sh /root/.bashrc; do
      if [[ -f "$f" ]] || [[ "$f" == /etc/profile.d/golang.sh ]]; then
        if [[ "$DRY_RUN" -eq 0 ]]; then
          grep -qF '/usr/local/go/bin' "$f" 2>/dev/null || echo "$line" >>"$f"
        fi
      fi
    done
    if [[ "$DRY_RUN" -eq 0 ]]; then
      echo "$line" >/etc/profile.d/golang.sh
      chmod 644 /etc/profile.d/golang.sh
    fi
    ok "Go 已安装: $(go version 2>/dev/null || echo go${GO_VERSION})"
  fi

  export GOPROXY
  export GOPATH="${GOPATH:-/root/go}"
  export GOBIN="${GOBIN:-${TOOLS_BIN_DIR}}"
  export PATH="${GOBIN}:/usr/local/go/bin:${GOPATH}/bin:${PATH}"
  mkdir -p "$GOPATH" "$GOBIN" 2>/dev/null || true
  info "GOPROXY=$GOPROXY  GOBIN=$GOBIN"
}

# ---------- Rust（cargo 工具：core 的 x8 / full 的 pwninit 等） ----------
ensure_rust() {
  local need_rust=0
  case "$PROFILE" in
    core|full) need_rust=1 ;;
  esac
  if [[ "$need_rust" -eq 0 ]]; then
    return 0
  fi
  section "检查 Rust (cargo 工具需要)"
  if command -v cargo >/dev/null 2>&1; then
    ok "cargo: $(cargo --version)"
    return 0
  fi
  info "安装 rustup..."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "[dry-run] curl rustup | sh"
    return 0
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck source=/dev/null
  source "$HOME/.cargo/env" 2>/dev/null || true
  export PATH="${HOME}/.cargo/bin:${PATH}"
  # 系统级软链，方便非 interactive shell
  if [[ -x "$HOME/.cargo/bin/cargo" && ! -e /usr/local/bin/cargo ]]; then
    ln -sf "$HOME/.cargo/bin/cargo" /usr/local/bin/cargo 2>/dev/null || true
    ln -sf "$HOME/.cargo/bin/rustc" /usr/local/bin/rustc 2>/dev/null || true
  fi
  ok "Rust 已安装"
}

# ---------- 安装原语 ----------
already_ok() {
  local check="$1"
  if [[ "$FORCE_REINSTALL" -eq 1 ]]; then
    return 1
  fi
  command -v "$check" >/dev/null 2>&1
}

mark_ok()   { STAT_OK=$((STAT_OK + 1)); ok "$*"; }
mark_skip() { STAT_SKIP=$((STAT_SKIP + 1)); warn "跳过: $*"; }
mark_fail() {
  STAT_FAIL=$((STAT_FAIL + 1))
  FAILED_TOOLS+=("$1")
  err "失败: $*"
}

install_apt() {
  local name="$1" check="$2" pkg="$3"
  if already_ok "$check"; then
    mark_skip "$name (已存在: $(command -v "$check"))"
    return 0
  fi
  info "apt 安装 $name ($pkg)..."
  if run_cmd apt-get install -y --no-install-recommends "$pkg"; then
    if already_ok "$check" || [[ "$DRY_RUN" -eq 1 ]]; then
      mark_ok "$name"
    else
      # 有些包名与命令名不一致，装上了也算成功
      mark_ok "$name (package installed)"
    fi
  else
    mark_fail "$name" "apt 安装失败: $pkg"
  fi
}

install_go() {
  local name="$1" check="$2" module="$3"
  if already_ok "$check"; then
    mark_skip "$name (已存在)"
    return 0
  fi
  if ! command -v go >/dev/null 2>&1; then
    mark_fail "$name" "go 不可用"
    return 0
  fi
  info "go install $module ..."
  if run_cmd env GOBIN="$GOBIN" GOPROXY="$GOPROXY" go install "$module"; then
    # 部分模块产出的二进制名与 check 一致
    if already_ok "$check" || [[ -x "${GOBIN}/${check}" ]] || [[ "$DRY_RUN" -eq 1 ]]; then
      mark_ok "$name"
    else
      # go install 成功但二进制名与 check 不一致时仍记成功
      mark_ok "$name (go install ok)"
    fi
  else
    mark_fail "$name" "go install 失败: $module"
  fi
}

install_pip() {
  local name="$1" check="$2" pkg="$3"
  if already_ok "$check"; then
    mark_skip "$name (已存在)"
    return 0
  fi
  info "pip 安装 $name ($pkg)..."
  local ok_install=0
  if command -v pipx >/dev/null 2>&1; then
    if run_cmd pipx install --force "$pkg" 2>/dev/null || run_cmd pipx install "$pkg"; then
      ok_install=1
    fi
  fi
  if [[ "$ok_install" -eq 0 ]]; then
    if run_cmd python3 -m pip install --break-system-packages -i "$PIP_INDEX_URL" "$pkg"; then
      ok_install=1
    fi
  fi
  if [[ "$ok_install" -eq 1 ]]; then
    export PATH="${PATH}:/root/.local/bin:${HOME}/.local/bin"
    mark_ok "$name"
  else
    mark_fail "$name" "pip/pipx 安装失败: $pkg"
  fi
}

install_cargo() {
  local name="$1" check="$2" crate="$3"
  if already_ok "$check"; then
    mark_skip "$name (已存在)"
    return 0
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    mark_fail "$name" "cargo 不可用（需 full 套件自动装 rust）"
    return 0
  fi
  info "cargo install $crate ..."
  # shellcheck source=/dev/null
  source "$HOME/.cargo/env" 2>/dev/null || true
  if run_cmd cargo install "$crate"; then
    mark_ok "$name"
  else
    mark_fail "$name" "cargo install 失败: $crate"
  fi
}

# GitHub release 下载：spec = owner/repo:asset_keyword:bin_name
install_github() {
  local name="$1" check="$2" spec="$3"
  if already_ok "$check"; then
    mark_skip "$name (已存在)"
    return 0
  fi
  local repo asset_key bin_name
  repo=$(echo "$spec" | cut -d: -f1)
  asset_key=$(echo "$spec" | cut -d: -f2)
  bin_name=$(echo "$spec" | cut -d: -f3)
  info "GitHub release 安装 $name ($repo)..."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    mark_ok "$name (dry-run)"
    return 0
  fi
  local api="https://api.github.com/repos/${repo}/releases/latest"
  local json
  if ! json=$(curl -fsSL "$api"); then
    mark_fail "$name" "无法获取 release: $repo"
    return 0
  fi
  local download_url
  download_url=$(echo "$json" | python3 -c "
import sys, json, re
data=json.load(sys.stdin)
key='${asset_key}'.lower()
arch='${ARCH}'.lower()
for a in data.get('assets', []):
    n=a['name'].lower()
    if key in n or '${bin_name}'.lower() in n:
        if 'darwin' in n or 'windows' in n or 'mac' in n: continue
        if arch in ('x86_64','amd64') and ('arm' in n and 'amd' not in n): continue
        if arch in ('aarch64','arm64') and 'arm' not in n and 'aarch' not in n: continue
        print(a['browser_download_url']); break
" 2>/dev/null || true)

  if [[ -z "${download_url:-}" ]]; then
    # 兜底：按 asset_key 模糊匹配
    download_url=$(echo "$json" | python3 -c "
import sys, json
data=json.load(sys.stdin)
key='${asset_key}'.lower()
for a in data.get('assets', []):
    if key in a['name'].lower():
        print(a['browser_download_url']); break
" 2>/dev/null || true)
  fi

  if [[ -z "${download_url:-}" ]]; then
    mark_fail "$name" "未找到匹配的 release asset"
    return 0
  fi

  local tmp
  tmp=$(mktemp -d)
  local fname="${tmp}/asset"
  if ! curl -fsSL -L -o "$fname" "$download_url"; then
    rm -rf "$tmp"
    mark_fail "$name" "下载失败: $download_url"
    return 0
  fi

  # 解压或直接拷贝
  case "$download_url" in
    *.zip)
      unzip -qo "$fname" -d "$tmp"
      ;;
    *.tar.gz|*.tgz)
      tar -xzf "$fname" -C "$tmp"
      ;;
    *.tar.xz)
      tar -xJf "$fname" -C "$tmp"
      ;;
    *)
      # 可能是裸二进制
      cp "$fname" "${tmp}/${bin_name}"
      ;;
  esac

  local found
  found=$(find "$tmp" -type f -name "$bin_name" 2>/dev/null | head -n1)
  if [[ -z "$found" ]]; then
    # 找任意可执行文件
    found=$(find "$tmp" -type f -executable 2>/dev/null | head -n1)
  fi
  if [[ -z "$found" ]]; then
    # 找最大文件当二进制
    found=$(find "$tmp" -type f ! -name 'asset' -printf '%s %p\n' 2>/dev/null | sort -nr | head -n1 | awk '{print $2}')
  fi
  if [[ -n "$found" ]]; then
    install -m 755 "$found" "${TOOLS_BIN_DIR}/${bin_name}"
    mark_ok "$name → ${TOOLS_BIN_DIR}/${bin_name}"
  else
    mark_fail "$name" "解压后未找到二进制"
  fi
  rm -rf "$tmp"
}

# ---------- 自定义安装函数 ----------
install_web_wordlist() {
  local name="web-wordlist"
  local dest_dir="/opt/cyberstrike/wordlists"
  local dest="${dest_dir}/raft-small-directories.txt"
  if [[ -s "$dest" ]]; then mark_skip "$name (已存在)"; return 0; fi
  info "安装 ffuf 小字典 → $dest ..."
  if [[ "$DRY_RUN" -eq 1 ]]; then mark_ok "$name (dry-run)"; return 0; fi
  if ! mkdir -p "$dest_dir"; then
    mark_fail "$name" "无法创建目录: $dest_dir"
    return 0
  fi
  if curl -fsSL -o "$dest" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt" \
    && [[ -s "$dest" ]]; then
    chmod 0644 "$dest"
    mark_ok "$name → $dest"
    return 0
  fi

  rm -f "$dest"
  if printf '%s\n' \
    admin api api/v1 api/v2 assets backup backups config dashboard debug docs download \
    graphql health login management metrics openapi.json robots.txt server-status static swagger \
    swagger-ui uploads .env .git/config >"$dest" && [[ -s "$dest" ]]; then
    chmod 0644 "$dest"
    mark_ok "$name → $dest (内置最小兜底字典)"
  else
    rm -f "$dest"
    mark_fail "$name" "字典下载及最小兜底生成均失败"
  fi
}

install_httpx_pd() {
  local name="httpx" check="httpx-pd"
  if already_ok "$check"; then mark_skip "$name (已存在)"; return 0; fi
  if ! command -v go >/dev/null 2>&1; then
    mark_fail "$name" "go 不可用"
    return 0
  fi
  info "安装 ProjectDiscovery httpx → ${TOOLS_BIN_DIR}/httpx-pd ..."
  if [[ "$DRY_RUN" -eq 1 ]]; then mark_ok "$name (dry-run)"; return 0; fi

  local tmp
  tmp=$(mktemp -d)
  if env GOBIN="$tmp" GOPROXY="$GOPROXY" go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && [[ -x "$tmp/httpx" ]]; then
    install -m 0755 "$tmp/httpx" "${TOOLS_BIN_DIR}/httpx-pd"
    mark_ok "$name → ${TOOLS_BIN_DIR}/httpx-pd"
  else
    mark_fail "$name" "ProjectDiscovery httpx 安装失败"
  fi
  rm -rf "$tmp"
}

install_jwt_tool() {
  local name="jwt-analyzer" check="jwt_tool"
  if already_ok "$check"; then mark_skip "$name"; return 0; fi
  info "安装 jwt_tool..."
  if [[ "$DRY_RUN" -eq 1 ]]; then mark_ok "$name"; return 0; fi
  local dest="/opt/jwt_tool"
  if [[ ! -d "$dest" ]]; then
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git "$dest" || {
      mark_fail "$name" "clone 失败"; return 0
    }
  fi
  python3 -m pip install --break-system-packages -i "$PIP_INDEX_URL" -r "$dest/requirements.txt" 2>/dev/null || true
  cat >"${TOOLS_BIN_DIR}/jwt_tool" <<EOF
#!/bin/bash
exec python3 /opt/jwt_tool/jwt_tool.py "\$@"
EOF
  chmod +x "${TOOLS_BIN_DIR}/jwt_tool"
  mark_ok "$name"
}

install_trivy() {
  local name="trivy" check="trivy"
  if already_ok "$check"; then mark_skip "$name"; return 0; fi
  info "安装 trivy..."
  if [[ "$DRY_RUN" -eq 1 ]]; then mark_ok "$name"; return 0; fi
  # 官方 apt 源
  if curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/dev/null; then
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
      >/etc/apt/sources.list.d/trivy.list
    apt-get update -qq
    if apt-get install -y trivy; then
      mark_ok "$name"; return 0
    fi
  fi
  # 回退：GitHub release
  local ver
  ver=$(curl -fsSL https://api.github.com/repos/aquasecurity/trivy/releases/latest | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))" 2>/dev/null || echo "0.58.0")
  local url="https://github.com/aquasecurity/trivy/releases/download/v${ver}/trivy_${ver}_Linux-${ARCH_TRIVY}.tar.gz"
  local tmp
  tmp=$(mktemp -d)
  if curl -fsSL -L -o "${tmp}/t.tgz" "$url" && tar -xzf "${tmp}/t.tgz" -C "$tmp" trivy; then
    install -m 755 "${tmp}/trivy" "${TOOLS_BIN_DIR}/trivy"
    mark_ok "$name"
  else
    mark_fail "$name" "下载失败"
  fi
  rm -rf "$tmp"
}

install_rustscan() {
  local name="rustscan" check="rustscan"
  if already_ok "$check"; then mark_skip "$name"; return 0; fi
  info "安装 rustscan..."
  if [[ "$DRY_RUN" -eq 1 ]]; then mark_ok "$name"; return 0; fi
  local url json download_url tmp
  json=$(curl -fsSL https://api.github.com/repos/RustScan/RustScan/releases/latest) || {
    mark_fail "$name" "api 失败"; return 0
  }
  download_url=$(echo "$json" | python3 -c "
import sys,json
data=json.load(sys.stdin)
for a in data.get('assets',[]):
    n=a['name'].lower()
    if 'linux' in n and ('amd64' in n or 'x86_64' in n or n.endswith('.deb')):
        print(a['browser_download_url']); break
" 2>/dev/null || true)
  if [[ -z "${download_url:-}" ]]; then
    mark_fail "$name" "无匹配 asset"; return 0
  fi
  tmp=$(mktemp -d)
  curl -fsSL -L -o "${tmp}/rs.asset" "$download_url"
  if [[ "$download_url" == *.deb ]]; then
    dpkg -i "${tmp}/rs.asset" || apt-get install -f -y
  else
    tar -xzf "${tmp}/rs.asset" -C "$tmp" 2>/dev/null || unzip -qo "${tmp}/rs.asset" -d "$tmp"
    local bin
    bin=$(find "$tmp" -type f -name rustscan | head -n1)
    [[ -n "$bin" ]] && install -m 755 "$bin" "${TOOLS_BIN_DIR}/rustscan"
  fi
  if command -v rustscan >/dev/null 2>&1; then mark_ok "$name"; else mark_fail "$name" "安装后仍不可用"; fi
  rm -rf "$tmp"
}

install_radare2() {
  local name="radare2" check="r2"
  if already_ok "$check"; then mark_skip "$name"; return 0; fi
  info "安装 radare2..."
  if run_cmd apt-get install -y radare2; then
    mark_ok "$name"; return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then mark_ok "$name"; return 0; fi
  git clone --depth 1 https://github.com/radareorg/radare2 /tmp/radare2-src \
    && /tmp/radare2-src/sys/install.sh \
    && mark_ok "$name" \
    || mark_fail "$name" "源码安装失败"
}

install_kube_bench() {
  local name="kube-bench" check="kube-bench"
  if already_ok "$check"; then mark_skip "$name"; return 0; fi
  info "安装 kube-bench..."
  if [[ "$DRY_RUN" -eq 1 ]]; then mark_ok "$name"; return 0; fi
  local ver
  ver=$(curl -fsSL https://api.github.com/repos/aquasecurity/kube-bench/releases/latest \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))" 2>/dev/null || echo "0.9.0")
  local url="https://github.com/aquasecurity/kube-bench/releases/download/v${ver}/kube-bench_${ver}_linux_${ARCH_GH}.tar.gz"
  local tmp; tmp=$(mktemp -d)
  if curl -fsSL -L -o "${tmp}/k.tgz" "$url" && tar -xzf "${tmp}/k.tgz" -C "$tmp"; then
    install -m 755 "${tmp}/kube-bench" "${TOOLS_BIN_DIR}/kube-bench"
    mark_ok "$name"
  else
    mark_fail "$name" "下载失败"
  fi
  rm -rf "$tmp"
}

install_terrascan() {
  local name="terrascan" check="terrascan"
  if already_ok "$check"; then mark_skip "$name"; return 0; fi
  info "安装 terrascan..."
  if [[ "$DRY_RUN" -eq 1 ]]; then mark_ok "$name"; return 0; fi
  local ver
  ver=$(curl -fsSL https://api.github.com/repos/tenable/terrascan/releases/latest \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))" 2>/dev/null || echo "1.19.0")
  local arch_t="$ARCH_GO"
  local url="https://github.com/tenable/terrascan/releases/download/v${ver}/terrascan_${ver}_Linux_${arch_t}.tar.gz"
  local tmp; tmp=$(mktemp -d)
  if curl -fsSL -L -o "${tmp}/t.tgz" "$url" && tar -xzf "${tmp}/t.tgz" -C "$tmp"; then
    install -m 755 "${tmp}/terrascan" "${TOOLS_BIN_DIR}/terrascan"
    mark_ok "$name"
  else
    mark_fail "$name" "下载失败"
  fi
  rm -rf "$tmp"
}

install_one_gadget() {
  local name="one-gadget" check="one_gadget"
  if already_ok "$check"; then mark_skip "$name"; return 0; fi
  info "安装 one_gadget (ruby gem)..."
  run_cmd apt-get install -y ruby ruby-dev || true
  if run_cmd gem install one_gadget; then
    mark_ok "$name"
  else
    mark_fail "$name" "gem install 失败"
  fi
}

install_wpscan() {
  local name="wpscan" check="wpscan"
  if already_ok "$check"; then mark_skip "$name"; return 0; fi
  info "安装 wpscan..."
  run_cmd apt-get install -y ruby ruby-dev build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev || true
  if run_cmd gem install wpscan; then
    mark_ok "$name"
  else
    mark_fail "$name" "gem install 失败"
  fi
}

install_linpeas() {
  local name="linpeas" check="linpeas.sh"
  if already_ok "$check" || [[ -x "${TOOLS_BIN_DIR}/linpeas.sh" ]]; then
    mark_skip "$name"; return 0
  fi
  info "下载 linpeas.sh..."
  if [[ "$DRY_RUN" -eq 1 ]]; then mark_ok "$name"; return 0; fi
  if curl -fsSL -L -o "${TOOLS_BIN_DIR}/linpeas.sh" \
    "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"; then
    chmod +x "${TOOLS_BIN_DIR}/linpeas.sh"
    mark_ok "$name"
  else
    mark_fail "$name" "下载失败"
  fi
}

install_zsteg() {
  local name="zsteg" check="zsteg"
  if already_ok "$check"; then mark_skip "$name"; return 0; fi
  info "安装 zsteg (ruby gem)..."
  run_cmd apt-get install -y ruby ruby-dev || true
  if run_cmd gem install zsteg; then
    mark_ok "$name"
  else
    mark_fail "$name" "gem install 失败"
  fi
}

# OneForAll：子域收集框架（https://github.com/shmilylty/OneForAll）
# 可装；与 subfinder 互补。依赖多、首次慢，装到 /opt 并用包装脚本暴露 oneforall 命令。
install_oneforall() {
  local name="oneforall" check="oneforall"
  if already_ok "$check"; then mark_skip "$name"; return 0; fi
  info "安装 OneForAll → /opt/OneForAll ..."
  if [[ "$DRY_RUN" -eq 1 ]]; then mark_ok "$name"; return 0; fi

  local dest="/opt/OneForAll"
  if [[ ! -d "$dest/.git" ]]; then
    rm -rf "$dest"
    if ! git clone --depth 1 https://github.com/shmilylty/OneForAll.git "$dest"; then
      mark_fail "$name" "git clone 失败"
      return 0
    fi
  else
    git -C "$dest" pull --ff-only 2>/dev/null || true
  fi

  # 依赖：优先项目 requirements
  if [[ -f "$dest/requirements.txt" ]]; then
    python3 -m pip install --break-system-packages -i "$PIP_INDEX_URL" -r "$dest/requirements.txt" \
      || python3 -m pip install --break-system-packages -r "$dest/requirements.txt" \
      || warn "OneForAll 部分 Python 依赖安装失败，仍写入包装脚本"
  fi

  # 入口：上游为 oneforall.py；部分 fork 可能是 oneforall/oneforall.py
  local entry=""
  if [[ -f "$dest/oneforall.py" ]]; then
    entry="$dest/oneforall.py"
  elif [[ -f "$dest/oneforall/oneforall.py" ]]; then
    entry="$dest/oneforall/oneforall.py"
  else
    entry=$(find "$dest" -maxdepth 2 -name 'oneforall.py' | head -n1)
  fi
  if [[ -z "$entry" ]]; then
    mark_fail "$name" "未找到 oneforall.py"
    return 0
  fi

  cat >"${TOOLS_BIN_DIR}/oneforall" <<EOF
#!/usr/bin/env bash
# CyberStrikeAI wrapper for OneForAll
export PYTHONPATH="${dest}:\${PYTHONPATH:-}"
exec python3 "${entry}" "\$@"
EOF
  chmod +x "${TOOLS_BIN_DIR}/oneforall"

  if command -v oneforall >/dev/null 2>&1 || [[ -x "${TOOLS_BIN_DIR}/oneforall" ]]; then
    mark_ok "$name → ${TOOLS_BIN_DIR}/oneforall"
  else
    mark_fail "$name" "包装脚本写入失败"
  fi
}

# ---------- 调度 ----------
install_one() {
  local entry="$1"
  local name check kind spec
  IFS='|' read -r name check kind spec <<<"$entry"
  case "$kind" in
    apt)    install_apt "$name" "$check" "$spec" ;;
    go)     install_go "$name" "$check" "$spec" ;;
    pip)    install_pip "$name" "$check" "$spec" ;;
    cargo)  install_cargo "$name" "$check" "$spec" ;;
    github) install_github "$name" "$check" "$spec" ;;
    script)
      if declare -f "$spec" >/dev/null 2>&1; then
        "$spec"
      else
        mark_fail "$name" "未定义函数: $spec"
      fi
      ;;
    skip)
      mark_skip "$name — $spec"
      ;;
    *)
      mark_fail "$name" "未知 install_kind: $kind"
      ;;
  esac
}

post_nuclei_templates() {
  if command -v nuclei >/dev/null 2>&1 && [[ "$DRY_RUN" -eq 0 ]]; then
    section "更新 nuclei templates"
    nuclei -update-templates 2>/dev/null || warn "nuclei templates 更新失败（可稍后手动 nuclei -update-templates）"
  fi
}

print_summary() {
  section "安装汇总"
  echo "  Profile : $PROFILE"
  echo "  成功    : $STAT_OK"
  echo "  跳过    : $STAT_SKIP"
  echo "  失败    : $STAT_FAIL"
  if [[ "$STAT_FAIL" -gt 0 ]]; then
    echo "  失败列表:"
    for t in "${FAILED_TOOLS[@]}"; do
      echo "    - $t"
    done
  fi
  echo ""
  info "PATH 提示（若新开终端找不到命令）:"
  echo "  export PATH=\"/usr/local/go/bin:${TOOLS_BIN_DIR}:\$HOME/.local/bin:\$HOME/go/bin:\$PATH\""
  echo ""
  info "验证示例:"
  echo "  command -v nmap nuclei subfinder ffuf httpx-pd sqlmap dirsearch oneforall dalfox trivy prowler"
  echo ""
  info "主用工具映射（已弃用项默认不装/YAML disabled）："
  echo "  容器: trivy（非 clair） | XSS: dalfox（非 xsser） | 目录: ffuf（非 gobuster）"
  echo "  模板扫描: nuclei（非 jaeles） | 云审计: prowler（非 scout）"
  echo "  子域: subfinder + oneforall + amass | 探活: MCP httpx → httpx-pd"
  echo ""
  info "说明: tools/*.yaml 无需修改；命令在 PATH 中即可被 CyberStrikeAI 调用。"
  echo "      未安装的工具执行时会跳过或报 command not found，不影响平台本身。"
}

# ---------- main ----------
main() {
  if [[ "$DO_LIST" -eq 1 ]]; then
    list_tools
    exit 0
  fi

  echo ""
  echo "=============================================="
  echo "  CyberStrikeAI Tools Installer"
  echo "  Target : Ubuntu 24.04"
  echo "  Profile: $PROFILE"
  echo "  Dry-run: $DRY_RUN"
  echo "=============================================="
  echo ""

  need_root "$@"
  check_ubuntu
  build_tool_list

  if [[ "$SKIP_ENV" -eq 0 ]]; then
    install_base_deps
    ensure_python
    ensure_go
    ensure_rust
  else
    warn "已跳过环境安装 (--skip-env)"
    export PATH="/usr/local/go/bin:${TOOLS_BIN_DIR}:${HOME}/.local/bin:${HOME}/go/bin:${PATH}"
    export GOPROXY GOBIN="${GOBIN:-$TOOLS_BIN_DIR}"
  fi

  section "安装工具 (共 ${#TOOLS[@]} 项)"
  # 先批量装 apt 包，减少 apt-get 往返；再逐项校验/补装
  local apt_entries=()
  local rest=()
  local apt_pkgs=()
  for entry in "${TOOLS[@]}"; do
    IFS='|' read -r name check kind spec <<<"$entry"
    if [[ "$kind" == "apt" ]]; then
      apt_entries+=("$entry")
      if ! already_ok "$check"; then
        apt_pkgs+=("$spec")
      fi
    else
      rest+=("$entry")
    fi
  done

  if [[ ${#apt_pkgs[@]} -gt 0 ]]; then
    info "批量 apt 安装 ${#apt_pkgs[@]} 个包..."
    local unique_pkgs
    unique_pkgs=$(printf '%s\n' "${apt_pkgs[@]}" | sort -u | tr '\n' ' ')
    if [[ "$DRY_RUN" -eq 1 ]]; then
      info "[dry-run] apt-get install -y $unique_pkgs"
    else
      # shellcheck disable=SC2086
      apt-get install -y --no-install-recommends $unique_pkgs || warn "部分 apt 包安装失败，将逐个重试"
    fi
  fi

  # apt：批量后按 check 统计；仍缺失则单包装一次
  for entry in "${apt_entries[@]}"; do
    IFS='|' read -r name check kind spec <<<"$entry"
    if already_ok "$check" || [[ "$DRY_RUN" -eq 1 ]]; then
      if already_ok "$check"; then
        # 区分「本来就有」与「本轮装上」意义不大，统一记成功
        mark_ok "$name"
      else
        mark_ok "$name (dry-run)"
      fi
    else
      install_apt "$name" "$check" "$spec" || true
    fi
  done

  for entry in "${rest[@]}"; do
    install_one "$entry" || true
  done

  post_nuclei_templates
  print_summary

  if [[ "$STAT_FAIL" -gt 0 ]]; then
    exit 2
  fi
}

main "$@"