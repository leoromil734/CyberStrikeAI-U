---
name: attack-surface-recon
description: >-
  明确范围内的资产、服务、URL、参数与技术指纹测绘流程。用于 recon/Surface 阶段并输出增量与覆盖缺口；
  不用于深度漏洞验证，测试深度由 pentest-scan-quick/standard/deep 单独选择。
metadata:
  tags: [渗透测试, penetration-testing, recon]
---

# 攻击面测绘

输入必须包含目标类型、in-scope 边界、已完成来源和扫描模式。先读 Do-Not-Repeat；上游已有结果时只补缺口。完整矩阵、资产评分与 JS/API 提取读取 `references/comprehensive-recon.md`。**来源/端点 fact 字段与退出门禁**读取 `references/recon-fact-schema.md`（Deep 必读）。

## 按目标类型裁剪

```text
root_domain → 子域增量 → DNS 清洗 → HTTP/重点端口
single_url  → 当前站点爬取 → 历史 URL → 路径/参数
ip_or_cidr  → 端口/服务 → 证书与反向解析关联
host_list   → 去重 → DNS/HTTP 批处理
```

## 工具流水线

1. 根域：
   - Quick 可只用 `subfinder` 首轮。
   - Standard 至少组合 `subfinder` 与一个异构来源，再用 `dnsx` 验证。
   - Deep/全面必须运行 `subfinder` + `oneforall`，并按可用性补 `amass`、证书透明度、历史/搜索引擎或空间测绘；逐项记录 raw、去重后数量与增量。某工具失败时保留错误并切换同类别来源，不能直接宣称子域完整。
2. `dnsx` 去除不可解析主机并保留 A/AAAA/CNAME、解析链和通配 DNS 基线；品牌关联资产先记录关联证据，确认 in-scope 后再主动测试。
3. `httpx` 收集 status/title/tech/server/content-length/CDN；`naabu` 找重点端口，仅对高价值主机用 `nmap -sCV`。Deep 对高价值 IP/主机补长尾端口策略，不能用 top-ports 结果表述“全端口覆盖”。
4. Web 入口由 `katana`、`gau`、`waybackurls` 互补；下载 HTML 引用、懒加载 chunk、worker 和 source map；优先 `jsluice` 抽 URL/路径，再补 WebSocket、上传/回调、认证与环境配置；每端点写 `recon/endpoint/*`，再对目标侧可达性去重验证。
5. `arjun`/`x8` 补参数，`ffuf`/`dirsearch` 补路径；先建立随机不存在路径和 SPA shell 的 hash/title/length 基线，通配 200 不计为命中。
6. `nuclei` 只在存活去重目标上按技术栈裁剪运行，输出全部视为 tentative，**不得**直接 `record_vulnerability`。

Quick 省略全量子域、全端口、深爬和大字典；Standard 覆盖主要服务与入口；Deep 扩展异构来源、品牌关联、前端静态资源、长尾端口和复杂身份/业务入口。

## 差分与失败恢复

- 路径扫描前请求随机不存在路径，识别 catch-all 的状态和大小。
- CDN/WAF 标记不自动触发 curl_cffi；浏览器与标准客户端稳定差分时再加载 `cdn-tls-fingerprint`。
- 单工具失败切换异构来源；同参数连续无新增时停止重跑并记录覆盖缺口。

## 交付与退出门禁

输出 **Source Coverage**（对齐 `recon/source/*`）、Assets、Live Services、Entry Points、Prioritized Verification Top-N、Tool Incremental Yield、Do-Not-Repeat 和 Remaining Gaps。每项保留来源与置信度；侦察默认不记录正式漏洞。

- 全面/Deep 侦察只有在以下账本均有 `covered` 或带原因的 `blocked` 记录后才能交接：独立资产来源、DNS/通配清洗、HTTP 与非 HTTP 服务、品牌关联证据、Web/历史 URL、全部已发现 JS/chunk/source map、API/参数清单、认证入口和资产价值分级。`blocked` 必须包含失败证据和已尝试替代来源；任何未处理项保持 `gap`，禁止使用“主域及子域已全覆盖”。
- Deep 根域结案前黑板须有 `recon/source/subfinder/*`、`recon/source/oneforall/*`（或等价异构子域来源的 blocked）、`recon/source/dnsx/*`；缺一只能输出进度。
- Recon 的 Top-N 只定义后续处理顺序。协调者必须继续推进枚举、认证态和风险验证；范围内可执行候选不能停留在最终“下一步建议”。