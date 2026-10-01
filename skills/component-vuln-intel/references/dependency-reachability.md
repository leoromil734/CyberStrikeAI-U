# 依赖图、公告条件与可达性

## 触发

已有 manifest/lockfile/构建产物或镜像固定版本，需判断特定公告适用性时读取。

## 执行顺序

1. 记录源码/构建、生态、包身份、锁文件与实际运行版本。
2. 固定扫描器、漏洞库更新时间和查询来源；外部查询/上传按数据许可执行。
3. 回溯 direct/transitive 引入链、多版本、开发/运行/可选依赖及平台分支。
4. 按 CVE/公告记录受影响符号、参数、模式、配置、修复版本和可信依据。
5. 区分 installed/imported/symbol-used/call-graph/target-effect；每级附证据与局限。
6. not_imported 不等于安全；grep 命中不等于调用图；调用图也不替代真实部署。
7. 高信号候选交白盒/目标验证；本 skill 所有输出保持 tentative，禁止直接 record_vulnerability。

## 反例与工具

旧镜像层、有风险包但功能未启用、vendor backport、非目标构建需独立分析。
trivy 有实际工具配置，但不代表当前环境可用；govulncheck/Syft 为可选依赖。
sg-code-search 不是 ast-grep；supply-chain-collect 是 FOFA 资产关联，不是 SCA。
缺 lockfile、图或库版本记证明缺口；不安装、不更新库、不 pull 镜像或执行未知 PoC。

## 修复与复测

说明哪个直接依赖引入风险、可信升级/backport 和兼容性；正常业务/配置/最小复现分别验证。
公告评级与目标实际影响分开，扫描等级不等于漏洞等级。

## 来源与补充

Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`，`strix/skills/custom/dependency_cve_scanning.md`，Apache-2.0；中文改编，根 LICENSE。
完整原理：`knowledge_base/Source-Code-Audit/Dependency-Reachability.md`。
