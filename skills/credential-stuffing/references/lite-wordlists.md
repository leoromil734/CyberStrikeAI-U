# 分档字典与执行预算

常规候选池使用 `/opt/wordlists/cyberstrike-standard`，快速子集保留在 `/opt/wordlists/cyberstrike-lite`。原有 `/opt/wordlists` 和 `/opt/cyberstrike/wordlists` 文件不覆盖、不删除。字典本身可以有适中的覆盖量，耗时主要由每轮候选数量、速率和时间预算控制；不因为怕慢而默认把所有任务都压缩到极小字典。

## 标准档（常规候选池）

来源统一为 [SecLists](https://github.com/danielmiessler/SecLists)，固定提交 `bd8f9b5501f9257e9d39c733540e793602c3da6f`，只下载所需文本文件，不克隆全集、不解压 rockyou。保留上游顺序并删除空行、注释、重复与无效条目：

- `passwords-top3000.txt`：常见密码备选池，最多 **3000 条**，来源 `Passwords/Common-Credentials/10k-most-common.txt`；大于原 SSH 密码的 1723 条。
- `usernames-top500.txt`：产品默认用户名参考，最多 **500 条**，来源 `Usernames/cirt-default-usernames.txt`；大于原 SSH 用户名的 222 条。它不是允许枚举陌生账号的名单，实际认证仍只用已有/产品默认身份。
- `subdomains-top5000.txt`：常见子域补缺，最多 **5000 条**，来源 `Discovery/DNS/subdomains-top1million-20000.txt`。
- `web-paths-top25000.txt`：Web 路径候选，最多 **25000 条**，来源 `Discovery/Web-Content/raft-medium-directories.txt`；大于原目录字典的 20115 条。
- `api-paths-top1000.txt`：API 路径补缺，最多 **1000 条**，来源 `Discovery/Web-Content/api/api-seen-in-wild.txt`。

总上限 **34500 条**，仍不采用百万级全集。每份字典和原始来源的 SHA-256、真实条数、字节数、安装时间和 profile 记录在 `manifest.json`；许可保留为 `LICENSE.SecLists`。

## 精简档（快速首轮，可选）

`/opt/wordlists/cyberstrike-lite` 保持原文件：

- `passwords-top100.txt`：最多 100 条。
- `usernames-short.txt`：最多 20 条，上游实际 17 条。
- `subdomains-top1000.txt`：最多 1000 条。
- `web-paths-top1000.txt`：最多 1000 条。
- `api-paths-top150.txt`：最多 150 条。

精简档总上限 **2270 条**，已安装版本实际 2267 条。仅在快速首轮、明确低预算或粗筛任务使用；不能拿它替代标准档并宣称覆盖了更大候选池。安装前读取对应目录的 `manifest.json`，确认本机真实路径和数量。

## 时间与请求预算

字典条数不是在线尝试配额：

- 弱口令预算不随字典扩容放大，分两档：轻量首轮每账号累计≤8次、每入口≤5账号/40组合/300秒，并发1、间隔≥3秒；深度档（高价值认证入口第二轮，前提见 SKILL.md）每账号≤30次、每入口≤10账号/300组合/20分钟，并发≤4、间隔≥1秒。默认对、失败对照与重试计入同一预算；保护机制出现即停。
- 从标准档按产品、已知身份和上下文挑选高价值候选，先保存有界 pair 清单并核对行数；用户名和密码不得全量相乘。**优先用 `scripts/wordlist_gen.py` 生成针对性字典**（品牌名、人名、邮箱前缀、域名、年份），保存输出行数与 SHA-256，按序在预算内递进使用。Hydra 使用找到即停、并发与间隔按档位（轻量 `-t 1 -c 3`；深度 `-t 4 -W 1`）并保持外部超时/取消；保护机制出现即停。
- 子域 DNS 补缺默认≤10 QPS；HTTP 路径/API 补缺默认≤5请求/秒、每资产≤300秒。先基于真实 JS/API 和技术栈选子集；更严任务限制优先，不默认把 25000 路径全量运行。
- 先建立随机不存在路径的 SPA/catch-all 基线，去重后仅测范围内入口，不无限递归目录或跨域跳转。字典补缺不能替代全部 JS 的静态工具 + grep/rg 两路分析。
- 达到时间/请求边界时保存已测子集、停止原因与可恢复位置，剩余项记 gap/blocked，不能按文件总行数宣称已覆盖。
- 邮件只验证认证，不发送邮件、不读取信箱；不启用换 IP 或挑战绕过继续猜口令。

## 复现安装

仓库根目录执行 `python3 scripts/install_lite_wordlists.py --profile standard --output /opt/wordlists/cyberstrike-standard`；省略 profile 时默认 standard。历史脚本名保留以兼容已有调用。

快速档显式执行 `python3 scripts/install_lite_wordlists.py --profile lite --output /opt/wordlists/cyberstrike-lite`。已存在目录拒绝覆盖；更新版本应使用新目录并校验后再切换。仅需 Python 3 标准库，单来源最多 2 MiB、25秒网络超时；全部下载、解析与清单成功后才原子发布，不留下可误用的半份字典。

自检：`python3 -m unittest discover -s scripts -p test_install_lite_wordlists.py -v`。安装不会连接任何测试目标，也不会自动启动扫描或弱口令尝试。
