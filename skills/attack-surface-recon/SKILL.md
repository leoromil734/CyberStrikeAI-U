---
name: attack-surface-recon
description: >-
  明确范围内的资产、服务、URL、参数与技术指纹测绘流程。用于 recon/Surface 阶段并输出增量与覆盖缺口；
  不用于深度漏洞验证，测试深度由 pentest-scan-quick/standard/deep 单独选择。
metadata:
  tags: [渗透测试, penetration-testing, recon]
---

# 攻击面测绘

输入必须包含目标类型、in-scope 边界、已完成来源和扫描模式。先读 Do-Not-Repeat；上游已有结果时只补缺口。

## 按目标类型裁剪

```text
root_domain → 子域增量 → DNS 清洗 → HTTP/重点端口
single_url  → 当前站点爬取 → 历史 URL → 路径/参数
ip_or_cidr  → 端口/服务 → 证书与反向解析关联
host_list   → 去重 → DNS/HTTP 批处理
```

## 工具流水线

1. 根域：`subfinder` 快速首轮；Standard/Deep 且结果不足时用 OneForAll 补异构来源；ASN/组织关联按需用 `amass`。
2. `dnsx` 去除不可解析主机并保留 A/AAAA/CNAME 来源。
3. `httpx` 收集 status/title/tech/server/content-length/CDN；`naabu` 找重点端口，仅对高价值主机用 `nmap -sCV`。
4. Web 入口由 `katana`、`gau`、`waybackurls` 互补；参数用 `arjun`/`x8`，目录用小范围 `ffuf`/`dirsearch`。
5. `nuclei` 只在存活去重目标上按技术栈裁剪运行，输出全部视为 tentative。

Quick 省略全量子域、全端口、深爬和大字典；Standard 覆盖主要服务与入口；Deep 才扩展异构来源、长尾端口和复杂身份/业务入口。

## 差分与失败恢复

- 路径扫描前请求随机不存在路径，识别 catch-all 的状态和大小。
- CDN/WAF 标记不自动触发 curl_cffi；浏览器与标准客户端稳定差分时再加载 `cdn-tls-fingerprint`。
- 单工具失败切换异构来源；同参数连续无新增时停止重跑并记录覆盖缺口。

## 交付

输出 Assets、Live Services、Entry Points、Prioritized Verification Top-N、Tool Incremental Yield、Do-Not-Repeat 和 Remaining Gaps。每项保留来源与置信度；侦察默认不记录正式漏洞。