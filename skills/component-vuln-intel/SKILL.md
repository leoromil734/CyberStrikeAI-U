---
name: component-vuln-intel
description: >-
  已识别具体框架、组件或版本后收集公告、CVE、补丁和 PoC 线索，并标记版本适用性。
  没有目标指纹时不使用；全部输出保持 tentative，必须在目标侧验证后才能记录漏洞。
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 联网情报收集（识别组件→立即全网搜；结果=线索/tentative，验证前不是 confirmed Fact）

已接入 `web-search` 时，优先按 `references/web-research.md` 使用 `research_plan` → `web_search` → `web_fetch` / `github_readme`。平台工具名为 `web-search__工具名`（配置/角色键为 `web-search::工具名`）。多引擎结果须核对原始公告与补丁，不能把摘要当作 PoC 正文；需要代理优先 `proxy_get` 获取项目共享住宅代理，不向模型或终端命令暴露上游凭据。未挂载工具时才用下面的浏览器/终端路径。

**出口纪律**：本 skill 结束时应得到「候选 CVE/PoC 链接 + 建议验证步骤」，并 `upsert_project_fact`（confidence=tentative）。**禁止**在本 skill 内直接 `record_vulnerability`。验证交给 `web-attack-methods` / penetration 与 `pentest-verification`。

```
🔴一识别出框架/组件/版本 → 必须停本地扫描立即联网(不搜就利用=盲打=违反铁律)。
🔴以下序列全部执行(不是选做),用{C}=组件名 {V}=版本替换。每步都用browser_navigate或terminal实际访问:

1.CVE漏洞库(必做,找已知漏洞):
  terminal: searchsploit {C} {V}
  terminal: curl -s "https://cve.circl.lu/api/search/{C}/{V}" | python3 -c "import sys,json;[print(x['id'],x.get('summary','')[:80]) for x in json.load(sys.stdin)[:10]]"
  browser_navigate: https://github.com/advisories?query={C}+{V}
  browser_navigate: https://www.cvedetails.com/google-search-results.php?q={C}+{V}&sa=Search

2.搜索引擎(至少执行3个,找漏洞分析+PoC):
  browser_navigate: https://www.google.com/search?q={C}+{V}+exploit+PoC+RCE+site:github.com
  browser_navigate: https://www.google.com/search?q={C}+{V}+漏洞+利用+复现
  browser_navigate: https://www.baidu.com/s?wd={C}+{V}+漏洞+利用+poc+getshell
  browser_navigate: https://www.bing.com/search?q={C}+{V}+CVE+exploit+poc
  browser_navigate: https://duckduckgo.com/?q={C}+{V}+vulnerability+exploit

3.中文安全社区(必做,中文首发多且深度分析好):
  browser_navigate: https://xz.aliyun.com/search?keyword={C}+漏洞
  browser_navigate: https://www.seebug.org/search/?keywords={C}
  browser_navigate: https://paper.seebug.org/search/?keyword={C}
  browser_navigate: https://www.freebuf.com/search?search={C}+{V}
  browser_navigate: https://ti.qianxin.com/vulnerability?keyword={C}
  browser_navigate: https://www.anquanke.com/search?s={C}

4.GitHub搜PoC/exploit代码(必做,最直接拿利用代码):
  terminal: curl -s "https://api.github.com/search/repositories?q={C}+{V}+exploit+OR+poc+OR+CVE&sort=updated&per_page=10" | python3 -c "import sys,json;d=json.load(sys.stdin);[print(x['full_name'],x['html_url'],x.get('description','')[:60]) for x in d.get('items',[])]"
  terminal: curl -s "https://api.github.com/search/code?q={C}+RCE+OR+shell+OR+exploit+language:python&per_page=5" | python3 -c "import sys,json;d=json.load(sys.stdin);[print(x['html_url']) for x in d.get('items',[])]"
  terminal: curl -s "https://api.github.com/search/repositories?q={C}+CVE&sort=stars&per_page=5" | python3 -c "import sys,json;d=json.load(sys.stdin);[print(x['full_name'],x['stargazers_count'],'★',x.get('description','')[:50]) for x in d.get('items',[])]"
  找到仓库后: curl -s "https://api.github.com/repos/{owner}/{repo}/readme" | python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin)['content']).decode())"

5.资产引擎(找同类目标/暴露面):
  browser_navigate: https://fofa.info/result?qbase64=$(echo -n 'app="{C}"' | base64)
  browser_navigate: https://www.shodan.io/search?query={C}+{V}
  browser_navigate: https://www.zoomeye.org/searchResult?q={C}
  browser_navigate: https://search.censys.io/search?resource=hosts&q=services.software.product:{C}

6.即时情报(最新0day/在野利用):
  browser_navigate: https://x.com/search?q={C}+CVE+OR+0day+OR+exploit&f=live
  browser_navigate: https://www.reddit.com/r/netsec/search/?q={C}&sort=new&t=month
  browser_navigate: https://www.exploit-db.com/search?q={C}

7.依赖深化: 有清单/锁文件/构建或镜像产物时读 references/dependency-reachability.md，固定版本与漏洞库时间，回溯直接/间接引入链，再选择适用公告和受影响符号。not_imported不等于安全，grep不等于调用图；不对每个依赖重复全渠道搜索，不自动安装/更新库/pull镜像，所有结果仍tentative。

🔴搜索受阻处理序列(碰到403/验证码/空结果/超时→按序执行不放弃):
  ①换UA: curl -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "{URL}"
  ②Jina读取器: browser_navigate: https://r.jina.ai/{原始URL}
  ③来源已失效时跳过 Google Cache（服务已关闭），直接查官方引用/补丁或下面的公开历史快照，并记录时间
  ④Archive: browser_navigate: https://web.archive.org/web/{URL}
  ⑤GitHub API替代(GitHub页面拦但API不拦): 用上面第4步的curl命令
  ⑥换引擎: Google拦→执行Bing/DuckDuckGo/百度; 百度拦→执行Google/Bing
  ⑦走代理: 优先按 `proxy-tool-bootstrap` 使用项目 `proxy_get`；仅连接类故障有界重试，407/597检查代理凭据，429先等待/降速，登录/验证码/JS需求交浏览器，不无限换出口
  全部受阻→写blocked Fact，保留查询/时间/失败分类/替代路径，不能声明“无公开漏洞”。可达但没有命中→只记录本轮检索范围内未找到证据，按需要继续其他方法。
```

