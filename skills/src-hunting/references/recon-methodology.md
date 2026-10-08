# recon-and-methodology

> **测绘节奏只认** `dig-scope` §1.0.1 / §2.1：只搜**当前这一个**种子；本种子剩余活面没挖完禁止新搜。认到短表形态只打当前站，禁止拿 Morph 去全网 FOFA。优质根域只回灌，本种子挖完才搜。
>
> **全量 nuclei 不当进度。** nuclei 只在需要已知 CVE / 暴露面（actuator、swagger、已知中间件）时辅助；禁止把「全量模板扫一遍」当本站矩阵。
>
> 初始线上信息收集必须先实际调用 `fofa_search`；锁面也要查指定 host/IP，但不搜全集团。详细口径见 `rules/dig-scope-workflow.md` §0.3 与根路径 `skills/recon-osint-playbook/references/fofa-first.md`。外部 MCP `get_alerts` 只补缺，不能替代本次 FOFA。凭据由 `config.yaml` 的 `fofa.api_key` 或 `FOFA_API_KEY` 注入，不自己 curl，不打印 key。缺工具/key/配额、调用失败真实记 blocked；成功零结果保存原始回包，不标目标安全。限流闸认 `dig-scope` §2.1.4，备用账号仅按实际已配置能力使用，不假定自动切换。

### FOFA 起手最短语法（必调后按当前种子补缺）

```
qbase64：查询语句 UTF-8 再 Base64
fields：host,ip,port,title,server
size：先小后翻；本种子结果可翻页，不是换种子

domain="target.com"
header="application/json"
body="actuator"
port="8080"
server="nginx" && domain="target.com"
cert.subject="品牌"
icon_hash="xxx"
status_code="200"
组合 && ；排除 !=
```

Quake / 凤鸟只补**当前种子**缺口，不当开场必跑。语法对照与 ROI 过滤见下文各节；过滤仍服从 `dig-scope` 去废 / 去非存活 / 股权闸。

# Recon and Methodology

## 品牌 IP 分类与精简补充字典

品牌扩测时逐个解析 IP 保存范围、CNAME/ASN 和 CDN 证据；只有当前 IP 已证实为 Cloudflare/Akamai 等 CDN 边缘才排除裸 IP 扩测，域名业务仍继续。**Hetzner 等云/托管商不是 CDN**，范围内非 CDN IP 必须作为独立资产枚举服务/入口并做品牌关联补缺，不因供应商名字跳过。CDN unknown 留 gap/blocked，不默认排除；共享 IP/ASN 不代表品牌归属，不扩供应商网段或无关租户。

分类字段、浅测边界与阶段证据读根路径 `skills/attack-surface-recon/references/comprehensive-recon.md` §2.1；少量 DNS/路径/API 补缺字典读 `skills/credential-stuffing/references/lite-wordlists.md`，默认不用全集。固定 URL/资产清单任务仍服从原范围，不能借品牌关联扩圈。

范围内 SSH、数据库、SMTP/IMAP/POP3 认证入口也须交接简单弱口令验证，按 `credential-stuffing.md` 分档预算（轻量首轮起步，高价值入口可进深度档）；不把“不爆破”当作免测依据。


## 1. RECON HIERARCHY

```
Target Selection
└── Scope Definition (in-scope assets)
    └── Asset Discovery (subdomains, IPs, domains)
        └── Tech Fingerprinting (what's running)
            └── Endpoint Discovery (attack surface)
                └── Vulnerability Testing (per vulnerability type)
```

---

## 2. SUBDOMAIN ENUMERATION (CRITICAL FIRST STEP)

### Passive (no DNS queries to target)
```bash
# Subfinder (aggregates multiple sources):
subfinder -d target.com -o subdomains.txt

# Amass passive:
amass enum -passive -d target.com

# Certsh (certificate transparency):
# Prefer the registered crtsh_search tool with domain="target.com". It records
# certificate provenance, rejects cross-domain SANs and reports partial results.
# Historical/wildcard names are candidates only; verify scope, DNS and liveness.
# Reuse this run's evidence; use another source after bounded upstream failures.
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# SecurityTrails API, Shodan:
# Web: https://securitytrails.com/list/apex_domain/target.com
```

### Active (DNS brute force + resolution)
```bash
# Massdns + wordlist:
massdns -r /path/to/resolvers.txt -t A -o S -w output.txt \
  <(cat wordlist.txt | sed 's/$/.target.com/')

# ffuf for subdomain brute:
ffuf -w subdomains-wordlist.txt -u https://FUZZ.target.com \
  -mc 200,301,302,403 -H "Host: FUZZ.target.com"

# DNSx for bulk resolution:
cat subdomains.txt | dnsx -a -resp -o resolved.txt

# Recommended wordlist: SecLists/Discovery/DNS/
```

### Virtual Host Discovery
```bash
# ffuf vhost mode:
ffuf -w wordlist.txt -u https://target.com \
  -H "Host: FUZZ.target.com" -mc 200,301,403

# gobuster vhost:
gobuster vhost -u https://target.com -w wordlist.txt
```

---

## 3. SERVICE AND PORT DISCOVERY

```bash
# Fast port scan (common ports):
nmap -T4 -F target.com -oN ports.txt

# Comprehensive scan on resolved subdomains:
cat resolved_ips.txt | nmap -iL - --open -p 80,443,8080,8443,8888,3000,5000 -oG scan.txt

# httpx for HTTP probing:
cat subdomains.txt | httpx -title -tech-detect -status-code -o live_hosts.txt

# masscan for speed on large IP ranges:
masscan -p 80,443,8080,8443 10.0.0.0/8 --rate=1000
```

---

## 4. WEB TECHNOLOGY FINGERPRINTING

```bash
# Wappalyzer (browser extension) or:
whatweb https://target.com

# httpx with tech detection:
httpx -u https://target.com -tech-detect

# Check headers manually:
curl -sI https://target.com | grep -i "server\|x-powered-by\|x-generator\|cf-ray"

# Fingerprint from:
- Server header: nginx/1.18, Apache/2.4, IIS/10.0
- X-Powered-By: PHP/7.4, ASP.NET
- Cookies: PHPSESSID (PHP), JSESSIONID (Java), _rails_session (Rails)
- HTML comments: <!-- Drupal 9 -->
- Meta generator: <meta name="generator" content="WordPress 6.2">
- JS framework files: /static/js/angular.min.js
```

---

## 5. ENDPOINT DISCOVERY

### Directory and File Discovery

目录、文件和扩展名枚举优先 `dirsearch`；参数、虚拟主机和自定义请求模糊测试优先 `ffuf`。任务包含 Web 攻击面发现且未链接路径尚未覆盖，或发现需继续枚举的目录时，执行有界目录发现，或记录具体 blocked/N/A 理由及证据。仅爬取/JS 提取不算目录覆盖；同 origin/路径范围/认证态/候选集已有充分有效证据可引用复用，不为工具调用次数重复扫描。

先用同认证态的 2–3 个随机不存在路径建立 catch-all 基线，按实测长度、正文特征或不存在页面路径配置过滤；不一概排除 401/403/405/500，不批量否定真实 JS/API。字典路径先验存在，扩展名按技术栈缩小；`-e` 默认仅替换 `%EXT%`，小字典无占位符且需要追加时才显式 `--force-extensions`。示例预算服从用户更严限制；递归仅对已确认需补枚举目录开启并设深度。

```bash
# 首选：目录/文件发现；省略 -w 使用自带字典，按技术栈调整 -e
dirsearch -u https://example.test/ -e html,js,txt,json -t 20 \
  --max-rate 50 --timeout 30 --max-time 900

# 替代：需要自定义请求或 dirsearch 不可用时；先确认字典存在
ffuf -u https://example.test/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt \
  -mc all -ac -t 20 -rate 50 -timeout 30 -maxtime 900
```

保存范围、认证态、字典/hash/候选数、扩展名、基线/过滤、预算、实际进度、停止原因和执行/原件引用。完成所选候选集且零新增才是该范围负结果；超时/限流/中断未完成留 gap/blocked，不以成功退出宣称全覆盖。先验证就绪候选，再补独立缺口；续跑只处理剩余候选。记录规范见根路径 `skills/attack-surface-recon/references/comprehensive-recon.md` §3.1。

### Parameter Discovery
```bash
# Arjun (hidden parameter finder):
arjun -u https://target.com/api/endpoint

# x8:
x8 -u https://target.com/api/endpoint -w params-wordlist.txt
```

### JavaScript Source Mining
```bash
# Extract endpoints from JS files:
gau target.com | grep '\.js$' | httpx -mc 200 | xargs -I{} curl -s {} | \
  grep -oE '"/[a-zA-Z0-9/_-]+"' | sort -u

# LinkFinder:
python3 linkfinder.py -i https://target.com -d -o output.html

# GetAllURLs (gau):
gau target.com | sort -u > all_urls.txt

# Wayback URLs:
waybackurls target.com | sort -u > wayback_urls.txt
```

### API Endpoint Discovery
```bash
# Common API paths（路径枚举，不替代逐接口验证；先确认字典存在）:
dirsearch -u https://example.test/ -w /SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -t 20 --max-rate 50 --timeout 30 --max-time 900

# Swagger/OpenAPI:
test: /swagger.json /api-docs /openapi.json /v2/api-docs /.well-known/ /docs/

# GraphQL:
test: /graphql /gql /v1/graphql /api/graphql
```

---

## 6. SOURCE CODE RECON

### GitHub / GitLab Exposure
```bash
# trufflehog (secret scanner in git history):
trufflehog git https://github.com/target-org/target-repo

# gitleaks:
gitleaks detect --source /path/to/cloned/repo

# Manual GitHub search:
# site:github.com "target.com" "api_key" OR "secret" OR "password"
# site:github.com "target.com" ".env" OR "config.php" OR "db_password"

# GitHub dorks:
# "target.com" extension:env
# "target.com" filename:*.config password
# org:target-org secret OR password OR apikey
```

### Exposed Environment Files
```
# Check common paths:
https://target.com/.env
https://target.com/.git/config
https://target.com/config.json
https://target.com/config.yaml
https://target.com/credentials.json
https://target.com/secrets.json
https://target.com/wp-config.php
https://target.com/backup.sql
https://target.com/backup.zip
```

---

## 7. ZSEANO'S TESTING METHODOLOGY

> **节奏不听本节。** 自由跳 / 一种子 / 力气先砸哪认 `dig-scope` + `src-value` §1.1。本节只当：参数怎么想、错误页/旧版本/移动端 API 别漏。命令和思路仍用。

### Core Philosophy
1. **Go deep on one program** rather than spread across many — learn the application thoroughly
2. **Build a profile of the company** — tech stack, developers, processes
3. **Look where others don't** — check error pages, admin paths, old versions, mobile API
4. **Follow the filter** — if input is filtered somewhere, that functionality exists and may be bypassed

### Testing Sequence (One Page / Feature)
```
For each input point:
1. Non-malicious HTML tags (<h2>, <img>) → are they reflected?
2. Incomplete tags → what happens? (<iframe src=//evil.com )
3. Encoding tests → %0d, %0a, %09, <%00
4. Observe the OUTPUT too (not just response) — where does your input appear?
5. Test same input in ALL similarly-structured pages (shared code → shared vuln)
6. Check if the same parameter exists in mobile/API endpoint (less protected)
```

### Parameter Insights
```
- Each parameter tells a story: "what does this do server-side?"
- Filename → OS interaction → Path Traversal / CMDi
- URL/location → HTTP fetch → SSRF
- Template/HTML parameter → render function → SSTI
- XML field → parser → XXE
- SQL filter → query → SQLi
- User-content → storage → Stored XSS
```

---

## 8. BUG BOUNTY PROGRAM TRIAGE (WHERE TO SPEND TIME)

> **节奏不听本节。** 自由跳种子/换站认 `dig-scope`；力气先砸哪认 `src-value` §1.1。下面 Priority 不是第二套测绘，也不是 SRC 定级。命令和参数思路仍用。

### High-Value Target Selection
```
✓ Programs with large scope (*.target.com)
✓ Programs that pay for P2/P3 (not just RCE)
✓ Programs with recent tech changes (migrations = new bugs)
✓ Programs with active development (new features = new attack surface)
× Avoid: frozen/old codebases with well-known CVEs (already claimed)
× Avoid: strict programs with narrow scope (less surface)
```

### High-Value Feature Focus (by bug probability)
```
Priority 1: Authentication, password reset, 2FA → account takeover
Priority 2: File upload, profile edit, API endpoints → stored XSS, IDOR
Priority 3: Admin panels, user management → BFLA, privilege escalation
Priority 4: Payment flows, subscription → business logic
Priority 5: Import/export, template rendering → XXE, SSTI
```

---

## 9. NUCLEI TEMPLATES (AUTOMATED SCANNING)

全量模板扫一遍不当进度。只在已知 CVE / 暴露面需要时收窄模板。

```bash
# 收窄：已知 CVE / 暴露面，不要当开场全量
nuclei -u https://target.com -t cves/ -severity critical,high
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t misconfiguration/

# On subdomain list:
cat subdomains.txt | nuclei -t exposures/ -t misconfiguration/ -o exposed.txt
```

---

## 10. COMMON MISCONFIGURATIONS (QUICK WINS)

```
□ CORS: SRC 永久跳过（不挖不写；见 cors-vuln-report-priority）— 勿当 quick win
□ S3 bucket public: curl https://target.s3.amazonaws.com/
□ Directory listing: response contains "Index of /"
□ .git exposed: curl https://target.com/.git/config
□ .env exposed: curl https://target.com/.env
□ Debug mode: stack traces in production (source code exposure)
□ Default credentials: admin:admin, admin:password on admin panels
□ phpinfo.php: curl https://target.com/phpinfo.php
□ Backup files: config.bak, database.sql.gz, app.zip
□ GraphQL introspection enabled: POST /graphql {"query":"{__schema{types{name}}}"}
□ Admin panels: /admin /manager /console /phpmyadmin /wp-admin
```

---

## 11. QUICK REFERENCE TOOLS

| Category | Tool |
|---|---|
| Subdomain enum | subfinder, amass, massdns |
| Port scan | nmap, masscan |
| HTTP probe | httpx |
| Dir/file/extension enum | dirsearch; ffuf for equivalent fallback |
| Parameter/vhost/custom request fuzz | ffuf |
| JS mining | LinkFinder, gau, waybackurls |
| Secret scan | trufflehog, gitleaks |
| Hidden parameter discovery | arjun, x8 |
| Vuln scan | nuclei |
| Proxy/intercept | Burp Suite Pro |
| JWT attacks | jwt_tool |
| SQLi | sqlmap |
| XSS | dalfox, XSStrike |
| SSRF | SSRFmap, Gopherus |

---

## 12. JAVA MIDDLEWARE FINGERPRINT MATRIX

| Middleware | Detection Path | Key Indicators |
|---|---|---|
| Apache Tomcat | `/manager/html`, `/manager/status` | Default creds: `tomcat:tomcat`, `admin:admin` |
| JBoss / WildFly | `/jmx-console/`, `/web-console/` | JMX MBean access, WAR deployment |
| WebLogic | `/console/`, `/wls-wsat/` | T3 protocol on 7001/7002, IIOP |
| Spring Boot Actuator | `/actuator/`, `/actuator/env`, `/actuator/heapdump` | JSON endpoint listing, heap dump contains secrets |
| Spring Boot (alt paths) | `/actuator/jolokia`, `/actuator/gateway/routes` | Jolokia JMX bridge, Gateway route injection |
| Jenkins | `/script`, `/manage` | Groovy console, API token in cookie |
| GlassFish | `/common/`, `/theme/` | Admin on 4848, default empty password |
| Jetty | `/jolokia/` | JMX access |
| Resin | `/resin-admin/` | Admin panel |

### Spring Boot Actuator Exploitation Priority

```
/actuator/env          → Leak environment variables (DB creds, API keys)
/actuator/heapdump     → Download JVM heap → search for passwords in memory
/actuator/jolokia      → JMX → possible RCE via MBean manipulation
/actuator/gateway/routes → Spring Cloud Gateway → SpEL injection (CVE-2022-22947)
/actuator/configprops  → All configuration properties
/actuator/mappings     → All URL mappings (hidden endpoints)
/actuator/beans        → All Spring beans
/actuator/shutdown     → POST to shutdown application (DoS)
```

---

## 13. INFORMATION LEAK DETECTION CHECKLIST

### Version Control & Backup Leaks

```
/.git/HEAD                    → Git repository exposed
/.svn/entries                 → SVN metadata
/.svn/wc.db                   → SVN SQLite database
/.hg/requires                 → Mercurial
/.bzr/README                  → Bazaar
/.DS_Store                    → macOS directory listing
```

### Backup File Patterns

```
/backup.zip    /backup.tar.gz    /backup.sql
/wwwroot.rar   /www.zip          /web.zip
/db.sql        /database.sql     /dump.sql
/config.php.bak    /config.php~    /config.php.swp
/.config.php.swp   /wp-config.php.bak
/.env          /.env.bak         /.env.production
```

### API Documentation & Debug

```
/swagger-ui.html              → Swagger/OpenAPI
/swagger-ui/                  → Swagger UI
/api-docs                     → API documentation
/graphql                      → GraphQL playground
/graphiql                     → GraphQL IDE
/debug/                       → Debug endpoints
/phpinfo.php                  → PHP configuration
/server-status                → Apache status
/server-info                  → Apache info
/nginx_status                 → Nginx status
```

### Cloud & Infrastructure

```
/.aws/credentials             → AWS credentials
/.docker/config.json          → Docker registry auth
/robots.txt                   → Disallowed paths (hint list)
/sitemap.xml                  → Full URL listing
/crossdomain.xml              → Flash cross-domain policy
/.well-known/                 → Various well-known URIs
```
