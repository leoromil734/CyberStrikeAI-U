# 外部侦察与攻击面测绘

> 目标：把"一个域名"扩展成"一个组织在互联网上的真实资产与边界"。所有结论都要能回溯到来源，**未经确认的资产不得直接扫描或攻击**。

## 一、资产发现（由组织出发）

1. **子公司/关联公司**：Crunchbase、Wikipedia、SEC/EDGAR 文件、投资人关系页、OpenCorporates、GLEIF（LEI 库）。跨境主体看当地注册机构（如英国 Companies House）。
2. **ASN 与 IP 段**：`bgp.he.net`、`bgpview.io`、`ipinfo.io`，区域注册库（ARIN/RIPE/APNIC/LACNIC/AFRINIC）。命令行：`amass intel -org <name>`、`amass intel -asn <asn>`；`bbot -t <domain> -f subdomain-enum` 会汇总 ASN。
3. **反向 whois（递归）**：以邮箱、组织名、地址为关键字反复查询（`viewdns.info`、`domaineye`、`whoxy`、`ip.thc.org`）。每发现一个新域，重复该流程。
4. **共享指纹**：
   - 追踪器 ID（Google Analytics/AdSense）：BuiltWith、Publicwww、SpyOnWeb。
   - **favicon hash**：MMH3(base64(favicon)) → 用 Shodan `http.favicon.hash:<hash>` / FOFA `icon_hash=` 找同类资产。`httpx -favicon` 可批量算哈希。
   - 版权字符串 / 页脚唯一串：`shodan search http.html:"<string>"`。
   - 证书主体：`shodan search ssl:"Org Name"`。
   - 错误页模板、`robots.txt` 特征、默认 vhost 页。
5. **证书透明度（CT）**：`crt.sh`、`certspotter`、Censys、`chaos.projectdiscovery.io`（含 bug bounty 范围数据）。
   - 证书签发时间可聚类：同一 cron 续签的域名往往互相关联。
6. **DMARC/邮箱域**：`dmarc.live`、`dmarc-subdomains`、`dmarcian` —— 相同 DMARC 记录常指向同一组织。

## 二、域名与子域枚举

- 被动：`subfinder`、`amass enum -passive`、`assetfinder`、`bbot`；`gau`/Wayback/Common Crawl；JS 文件抓取（`SubDomainizer`、`subscraper`）。
- 主动 DNS 爆破：`massdns`/`shuffledns`/`puredns`（需可信 resolver 列表，如 trickest resolvers），词表用 SecLists / Assetnote best-dns-wordlist。
- 二次置换：`dnsgen`、`gotator`、`alterx`、`subzuf`（响应引导）、`regulator`（从已发现名称学习模式）。
- 区域传送：`dnsrecon -a -d <domain>`（若成功即为真实配置缺陷）。
- 反向 DNS：对 IP 段做 PTR 扫描（需管理员配置 PTR 才有效），`ptrarchive.com`。
- **vhost 枚举**：对 IP 用 `ffuf -H "Host: FUZZ.<domain>" -ac`、`gobuster vhost`、`VHostScan`，可发现未在 DNS 中公开的内部站点。
- **CORS 探测子域**：`ffuf -H 'Origin: http://FUZZ.<domain>' -mr "Access-Control-Allow-Origin"`。

## 三、被动 DNS 与历史记录

SecurityTrails、RiskIQ、DomainTools、DNSDB。历史记录的价值：

- 已废弃但仍解析的 CNAME/A 记录 → 接管候选。
- 旧 IP 上的服务、旧 CDN 配置、旧对象存储。

## 四、JS 与前端资产（见专篇）

`JS-and-Secrets-Discovery.md`：sourcemap、隐藏 API、密钥、内网域名、GraphQL schema。

## 五、云资产（见专篇）

`Cloud-Asset-Enumeration.md`：对象存储桶、Firebase、Azure blob、GCP 存储、SaaS 子域。

## 六、验证与纪律

1. 每条资产标注**来源与时间**（工具/接口/日期），避免把"曾经存在"当作"现在存在"。
2. 归属确认：证书主体、页面内容、ASN 归属、WHOIS 组织。**未确认归属的资产不扫描**。
3. 范围外资产（CDN、SaaS 供应商、客户共享基础设施）要显式排除。
4. 侦察结果落库为一组可复核的条目（域名、IP、端口、指纹、来源），后续扫描以该集合为输入。

## 七、常见误报

- 共享 IP 上的旁站被误认为目标资产。
- CNAME 指向 CDN/SaaS（属于其基础设施，非目标可攻击面）。
- 已过期但仍在被动 DNS 中的记录。
- favicon 哈希碰撞或通用图标（模板/占位页）。

## 八、工具映射

`subfinder`、`amass`、`bbot`、`dnsx`、`dnsrecon`、`httpx`、`katana`、`gau`、`ffuf`、`nuclei`（线索）；CyberStrikeAI skill：`attack-surface-recon`、`recon-osint-playbook`。

## 参考

- HackTricks：External Recon Methodology；OWASP WSTG-INFO
- SecLists、ProjectDiscovery 工具链文档
