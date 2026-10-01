# 三项目知识与 Skills 增量记录

## 本轮交付范围

2026-10-01，以本项目提交 `d6cbed5` 为去重基线，仅整合知识与 skills。
新增 31 篇知识、31 份按需执行参考及 4 个独立技能入口；保留原 32 个入口。
这是内容与使用方法增量，不代表发现率已经提高，也不代表工具依赖安装或知识服务已启用。
其他设计优点、架构备选、运行引擎、全局提示、自动算法与现网部署均按用户要求排除。
`manifest.json` 保存逐项能力、既有锚点、来源路径、目标文件、正反案例和中英文检索问题。

## 新增与深化

- 框架：Next.js、NestJS、FastAPI、Django 的对象、动作、通道、缓存和依赖边界。
- 托管后端：Supabase/Firebase 的项目 key、用户、数据库/规则、存储与高权限代理差分。
- 产品平台：Vault、消息缓存、可观测性、SCM/CI、IaC state/plan、IdP 和 CMS/LMS/电商对象权限。
- 方法与证据：具体反证、证明缺口、OOB 协议分级/来源、变更/修复复测、影响分级、跨解析语义、无 Shell 参数、包执行器、依赖可达性、API 契约、幂等与支付回调、浏览器状态。
- 制品与 AI：iOS、移动保护、Electron IPC、OCI/SBOM、n8n/插件定义和 MCP 精确审批。

AD、Android/UniApp/Flutter、固件、多云/K8s、通用 Web/API 和一般 AI/RAG 已有方法复用，不因外源文件更多重复建入口。覆盖情况见 manifest 的 covered；明确拒绝项见 nonadopt。

## 加载与状态

继续采用一个扫描深度 + 一个领域 + 验证；新专题替换当前领域，而非全量叠载。
SRC 起点先 `src-hunting`，保留 CORS、缺安全头、低价值结果与泛 LLM 越狱教材排除。
知识是独立原理与验证资料，reference 是短可直接读取的流程；知识服务关闭仍可使用文件。
现有路由接入新内容，不改角色、运行契约、数据库模型或调度引擎。
静态链、版本/CVE/扫描命中、关键词与模型投票不能直接 confirmed。
管理员正常功能、已失陷身份原权限不重复计洞；正式记录仍要求真实新增权限、完整 POC 和 validation。
proof gap 和 reproduced/changed/gone/unverifiable 为说明/复测字段，不新增现有机器状态枚举。

## 来源与许可

本轮文档均为中文改编/重组，修改日期为 2026-10-01；各文件保留具体上游路径和原许可。

- Strix：`https://github.com/usestrix/strix`，`007ed1a94e7dbf7b096c81e5b0354533ce94e0db`，Apache-2.0。原归属 `Copyright 2025 OmniSecure Inc.`；完整 Apache 文本见根 `LICENSE`。不以许可附录示例替代来源归属。
- NeuroSploit：`https://github.com/JoasASantos/NeuroSploit`，`5d4e7e0347219ceae22735ec6af3d8cdd0561ded`，MIT；`Copyright (c) 2026 Joas A Santos & Red Team Leaders`。完整文本见 `licenses/NeuroSploit-MIT.txt`。
- Dark-Moon：`https://github.com/ASCIT31/Dark-Moon`，`cb0d9b83e745034c8bcff90daee9668b834d1508`，原 GPLv3。用户于 2026-10-01 自述原作者并允许其自有内容改编，故不列为许可待确认、不阻止整合；本批相应文档保留 `GPL-3.0-only` 标注与 `licenses/Dark-Moon-GPL-3.0.txt`，第三方原许可继续保留，根 `LICENSE` 未改。

本记录不声称翻译/改名可以去除许可义务，也不声称整个项目已换许可证。
官方参考链接用于匹配实际产品/协议版本；本轮未逐个联网验证链接当前页面或最新版本。
参考克隆位于忽略目录，不是 CI 或文档使用的运行依赖；离线测试只依赖本项目交付文件。

## 离线验收与限制

- 格式/引用/来源、旧入口保留、新工具声明和入口字符预算。
- 关键正反案例的文档契约检查，避免取消 SRC 排除项或新增错误确认判据。
- 在临时 SQLite 数据库和临时知识目录测试分类、标题、全文、重复扫描不重复及修改后待索引 ID。
- manifest 内检索问题只是未来召回评估夹具；离线检查不能等同语义召回、动态漏洞验证或真实效果评测。
- 本轮不调用 embedding、不重建现网索引、不安装依赖、不运行参考项目、不测试目标、不部署、不提交。

本次仅新增验收测试代码，没有修改生产 Go 代码。

### 本轮实际结果

- `go test -count=1 -p 4`：coverage、projectprompt、skillpackage、agents、vulnquality、database、agentfinalizer、handler、multiagent、project、knowledge、app 共 12 个包全部通过。
- `go build ./...`：通过；`git diff --check`：通过。
- 新增三份测试文件：`internal/skillpackage/knowledge_integration_test.go`、`internal/skillpackage/integration_routing_test.go`、`internal/knowledge/integration_scan_test.go`。
- Windows SQLite 测试临时使用已有 Zig 编译器配置，仅对该次命令设置 CC；没有安装编译器或持久修改环境。
- 初次检查发现路由入口预算、引用路径识别和临时知识库 schema 设置问题，已修正并重新运行相关测试；最终上述结果为修正后结果。
