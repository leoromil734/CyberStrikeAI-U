---
name: source-code-hunting
description: >-
  在公开源码泄露、前端 bundle、仓库历史、密钥或混淆产物中寻找安全线索。用于源码获取与静态线索发现；
  已有完整源码并要做路由/数据流/鉴权到动态 PoC 时，改用 source-aware-whitebox。
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 源码狩猎

```
=== 源码狩猎 ===
.git泄露: git-dumper → git log -p --all(已删敏感文件) | .svn/.DS_Store/composer.lock
危险函数grep: exec/system/eval/unserialize/pickle.loads/render/curl_exec + 硬编码密钥(sk-/ghp_/BEGIN RSA)
JS混淆破解(RC4+base64字符串数组模式): 1)提取字符串数组(var a0G=[...]) 2)找解码函数(a0m(idx,key)→RC4解密+base64) 3)找rotation IIFE(目标偏移量) 4)Node.js重建解码器批量解码全部字符串→得到明文变量名/API路径/配置
  UniApp特征: app-service.js(业务逻辑,常800KB+混淆) + zlsioh.dat(加密配置,native .so解密) + dcloud_uniplugins.json(插件清单)
静态扫描: semgrep --config=auto 快扫 / CodeQL建库写query (taint求解+变体分析方法论见 `zero-day-discovery`)
Secrets深挖: trufflehog/gitleaks 扫git全历史+docker镜像层+npm/PyPI tarball+前端bundle(--only-verified区分死活密钥)
框架Patch Diff: clone前后版本 diff → 修了什么=漏洞在哪 | 依赖链: composer.json/npm audit/pip-audit
供应链/CI: 依赖混淆(内部包名抢注公共registry) | GHA命令注入${{github.event.issue.title}} | self-hosted runner接管 | .npmrc/.pypirc凭据
```
