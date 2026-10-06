---
id: 02-003
title: "📡 Web漏洞扫描 (Web Vulnerability Scanning)"
category: 漏洞扫描
category_en: "Vulnerability Scanning"
difficulty: ★★★
tools: "Burp Suite, Nikto, Acunetix, OWASP ZAP"
last_updated: 2025-07
tags: ["vulnerability-scanning", "web-security", "network-security", "database-security"]
subdomain: vulnerability-scanning
nist_csf: ["ID.RA-01", "DE.CM-08", "PR.IP-12"]
mitre_attack: ["T1595", "T1589", "T1592"]
---
# 📡 Web漏洞扫描 (Web Vulnerability Scanning)

## 概述
使用自动化扫描器和手动技术发现Web应用程序中的安全漏洞，包括OWASP Top 10中的常见风险。

## 核心技能

### 1. 自动化漏洞扫描器

```bash
# Nikto - Web服务器扫描器
nikto -h https://example.com -ssl -Format html -output nikto_report.html

# Skipfish - 高速Web扫描
skipfish -o skipfish_report http://example.com

# WPScan - WordPress专用扫描
wpscan --url https://example.com --enumerate u,vp,vt --api-token YOUR_API_TOKEN

# Acunetix (商业扫描器)
# 支持自动爬虫、SQL注入、XSS等深度检测

# AppScan (商业扫描器)
# 支持登录扫描、会话管理、多步骤表单
```

### 2. 目录/文件枚举

目录、文件和扩展名枚举优先 `dirsearch`；参数、虚拟主机和自定义请求模糊测试优先 `ffuf`。爬取/JS 外的未链接路径尚未覆盖或发现需要继续枚举的目录时才补缺；同范围已有充分有效证据可复用，不叠加多个扫描器凑次数。先建随机路径 catch-all 基线，以实测大小/正文/不存在页面过滤，不一概排除 401/403/405/500。缺依赖留 blocked，超时未完成留 gap/blocked；记录规范见上级 `comprehensive-recon.md` §3.1。

```bash
# 首选目录/文件枚举：按技术栈调整扩展名，默认不递归
# -e 默认仅替换字典 %EXT%，小字典确需逐条追加时才开启 --force-extensions
dirsearch -u https://example.test/ -e php,html,txt -t 20 \
  --max-rate 50 --timeout 30 --max-time 900

# dirsearch 不可用或需要自定义请求时的等价替代；先确认字典存在
ffuf -u https://example.test/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt \
  -mc all -ac -t 20 -rate 50 -timeout 30 -maxtime 900
```

### 3. 参数发现与模糊测试

```bash
# Arjun - HTTP参数发现
arjun -u https://api.example.com/endpoint

# ffuf参数模糊测试
ffuf -u 'https://example.com/page?FUZZ=test' -w params.txt -fc 400,403,404

# 值模糊测试
ffuf -u 'https://example.com/page?id=FUZZ' -w ids.txt -fc 400,404,500
```

### 4. 敏感信息泄露检测

```bash
# 检测.js文件中的敏感信息
curl -s https://example.com/app.js | grep -iE "apikey|api_key|password|secret|token|aws|s3|bucket"

# 检查常见敏感文件
for file in robots.txt sitemap.xml .env .git/config .svn/entries crossdomain.xml clientaccesspolicy.xml; do
  status=$(curl -o /dev/null -s -w "%{http_code}" https://example.com/$file)
  echo "$file -> $status"
done

# Git泄露检测
git-dumper https://example.com/.git/ git_repo/
```

### 5. CORS配置检测

```bash
# 检查CORS配置
curl -s -H "Origin: https://evil.com" -I https://api.example.com | grep -i "access-control-allow-origin"

# 手动测试
curl -s -H "Origin: https://evil.com" -H "Referer: https://evil.com" https://api.example.com/endpoint
```

### 6. 登录页面安全检测

```bash
# 检测登录页面
def find_login_pages():
    paths = ['/login', '/admin', '/wp-admin', '/admin.php', '/login.php', 
             '/signin', '/auth', '/user/login', '/administrator']
    for path in paths:
        r = requests.get(f"https://example.com{path}")
        if r.status_code == 200:
            print(f"Found: {path}")

# 弱密码测试
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"
```

## 常见漏洞检测指标

| 漏洞类型 | 检测方法 | 关键指标 |
|:---|:---|:---|
| SQL注入 | 单引号测试 | 500错误/数据库错误信息 |
| XSS | `<script>alert(1)</script>` | 脚本执行/HTML注入 |
| 目录遍历 | `../../../etc/passwd` | 文件内容泄露 |
| CSRF | 检查Token | 缺少Token/Token可预测 |
| SSRF | 外部服务器监听 | 收到回调请求 |
| 命令注入 | `;id` / `|whoami` | 命令执行结果 |
| 文件上传 | 上传webshell | 文件可访问/执行 |

## 常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Nikto | Web服务器扫描 | https://github.com/sullo/nikto |
| WPScan | WordPress扫描 | https://github.com/wpscanteam/wpscan |
| ffuf | 快速模糊测试 | https://github.com/ffuf/ffuf |
| Gobuster | 目录/子域名爆破 | https://github.com/OJ/gobuster |
| Arjun | HTTP参数发现 | https://github.com/s0md3v/Arjun |
| Nuclei | 模板化漏洞扫描 | https://github.com/projectdiscovery/nuclei |

## 参考资源
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
