# OCI 镜像 SBOM、公告匹配与真实可达性

## 适用范围与状态
- 适用于获授权的本地 OCI 镜像归档、镜像配置、层、已有 SBOM 与扫描输出。
- Open Container Initiative（OCI）定义镜像结构；Software Bill of Materials（SBOM）记录软件组件库存。
- SBOM 是库存交付，不是漏洞利用证据，也不代表供应链安全检查全部通过。
- `tentative` 表示公告/扫描候选，`confirmed` 表示被证实的具体边界影响，`blocked` 表示依赖或范围不足。
- 本流程不自动拉取镜像、不执行镜像、不更新联网漏洞库、不推送或修改 registry。
- 需要在线操作时必须独立获得授权，离线输入不足就报告局限。

## 不可变版本、身份与输入
- 记录 image reference、registry、仓库、tag、manifest digest 和取得时间。
- Tag 可变，不能作为不同扫描结果相同制品的唯一依据。
- 多架构 image index digest 与所选平台 manifest digest 分别记录。
- 记录 OS、架构、config digest、有序 layer digest 与本地归档哈希。
- 压缩 blob digest 与解压层 diff ID 不同，关联证据时注明所用类型。
- 若只提供 Dockerfile，记录提交/文件哈希；它是构建意图，不是最终镜像库存。
- 记录扫描器版本、规则版本、数据库版本/更新时间、扫描时间与过滤项。
- 记录漏洞数据库是否离线、缺失或过期，不能把下载失败当“零漏洞”。
- 记录 registry 身份、运行工作负载身份、用户权限与环境，库存不推断运行权限。
- 本流程无需模型调用；模型辅助应固定 provider/model，输入仅为获准脱敏库存，模型评级不是可达性证据。

## SBOM 标准与覆盖
- SPDX 与 CycloneDX 分别保留文档格式版本、生成器、时间、主体与组件标识。
- 两种格式的属性和关系表达不同，不能要求字段逐字相同或强行一对一转换。
- 保留 package 名称、版本、生态、架构、路径、许可证和可用 purl/CPE。
- 记录 OS 软件包、语言依赖、静态链接、自带二进制与打包资源的覆盖缺口。
- 扫描器未识别的组件必须写入局限；无法识别不是组件不存在。
- 双格式库存独立归档并留哈希，摘要与原始文件关联到相同镜像主体。
- 只有已有工具支持时生成双格式；缺格式导出依赖时记 `blocked`，不伪造文件。
- 即使无 CVE 仍交付库存，说明“在指定数据库与覆盖范围内未发现”，不写全局安全。
- SBOM 未覆盖签名、构建者身份、来源真实性、更新链、密钥与运行配置等全部问题。

## 镜像层与有效文件系统
- 对命中记录 layer digest、文件路径及其在有效根文件系统中的状态。
- Whiteout 或上层覆盖能移除运行时可见文件，但旧层 blob 可能仍被持有镜像者读取。
- 构建阶段依赖不一定进入最终镜像；只看 Dockerfile 安装列表可能误判运行库存。
- 最终层中可执行文件存在不等于应用实际加载或攻击者可达。
- 压缩归档、vendored 依赖、native 扩展与动态下载的运行依赖分别列出。
- 检查 image config/history 的敏感残留，报告使用脱敏摘要与准确位置。
- 发现秘密样式字符串先判断用途；不得为验证 liveness 自动登录供应商。
- 已删除秘密仍在可获取层中可构成制品泄露事实，但权限与活性影响需另证。

## 公告匹配与可达性原理
- 用实际生态、发行版、package release 和供应商公告核对 CVE，不只比上游版本号。
- 发行版安全回补可能保留旧主版本，需用发行版修复状态解释扫描候选。
- fixed-in 记录公告来源与条件；未提供修复版本不等于永远无法修复。
- KEV 或已知利用状态影响优先级，不证明当前镜像已满足利用条件。
- 基础镜像 EOL 是维护风险，不能自动当成可达 CVE 或系统接管。
- 可达性需要入口、数据控制、调用/加载路径、配置及触发前提。
- 区分包安装、进程加载、易受影响函数执行与攻击者控制输入到达函数。
- 静态链接和裁剪组件需核对真实二进制，包元数据不足时保留候选。
- 网络入口关闭、特性禁用、权限限制与参数校验可阻断特定攻击路径。
- 环境防护不是库存修复；报告保留未修依赖及当前路径不可达的两个事实。

## 离线优先工作流
1. 固定输入归档、manifest、config、层和平台，检查所有库存指向同一 digest。
2. 读取或使用现有可用工具生成 SBOM，记录格式版本与组件覆盖。
3. 对扫描 JSON 逐条提取 package@version、路径、公告、fixed-in 与数据库时间。
4. 关联组件到层、有效文件系统和应用加载/调用路径。
5. 使用已提供供应商公告或本地资料核对回补、发行版与架构，不自动联网查最新。
6. 将每个候选列出必要输入、功能开关、身份、配置和缺失证据。
7. 动态影响验证需另获测试环境授权；本流程不启动容器、不提交利用请求。
8. 分别交付库存、公告候选、可达性证据、无法验证项及修复建议。

## 基线与具体证据
- 基线包括原始镜像 digest、组件库存、扫描器/数据库时间和未修改运行配置材料。
- 允许对照是应用正常业务路径加载目标组件的已有追踪或获批测试记录。
- 拒绝对照是特性禁用、参数校验或无权限身份下相同合成输入无法到达目标。
- 单变量比较仅改变组件修复状态、功能开关或身份之一，避免混用重建镜像。
- 同一 tag 的不同 digest 必须视为不同制品，不能直接宣称漏洞自行消失。
- 具体证据：公告编号、组件完整版本、purl/CPE、层/路径、数据库元数据与输出哈希。
- 可达性证据补充调用栈/源码位置、功能配置、入口身份与目标结果。
- 扫描器 HIGH 标签是公告或匹配层级，影响严重度需说明真实部署前提。
- 漏洞确认要求合成数据上的明确边界失效；仅版本匹配仍 `tentative`。

## 反证、停止与清理
- 公告不适用当前发行版或有可信回补证据，应记录不受影响原因。
- 组件只在构建阶段且不进入最终镜像，是运行时可达性的反证。
- 无外部可控输入或相关功能禁用，需收窄当前利用结论，不删除库存问题。
- 数据库失效、镜像平台不明、层缺失或私有 registry 未获授权时记 `blocked`。
- 只有 Dockerfile 或 SBOM 且不能绑定主体时，不猜最终运行镜像。
- 遇到镜像初始化、生命周期脚本、自动 pull/数据库更新或秘密外发要求即停止。
- 清理获批产生的临时解包和缓存，保留脱敏 SBOM、输出哈希与依赖缺口。
- 不删除远端镜像、不主动撤销生产凭据、不替用户更换基础镜像。

## 工具映射与修复
- 已注册 `trivy` 是库存/扫描映射；核对实际版本、离线模式与 format 支持后才可选用。
- 配置注册不证明工具已安装、数据库可用或支持 SPDX/CycloneDX 双格式。
- Syft、Grype、registry 客户端是未在本篇新增的依赖，缺失记 `blocked`，不安装。
- 提供已生成 SBOM 可继续离线审阅；不会为了双格式调用未注册工具。
- 修复采用受支持基础镜像与依赖版本，重新构建并记录新 digest 与库存差异。
- 若秘密进入层，删除文件不足；按批准流程轮换秘密、重建并处理旧制品可获取性。
- 使用构建秘密机制、最小运行依赖与制品真实性验证，避免把 SBOM 当唯一控制。
- 复测固定相同公告口径，同时说明数据库变化与制品变化，避免混淆效果。

## 可测正反例
- 正例：固定 digest 中目标组件被运行路径加载，获批合成输入实际跨越指定授权边界。
- 反例：只出现 scanner CVE 命中，函数未加载或供应商回补证明已修复。
- 正例：合成秘密仍可从旧层读取，证明制品残留；活性与下游权限仍另记。
- 反例：两份 SBOM 均存在、扫描为零，但数据库过期；供应链结论不能判通过。

## 来源、版本与改编说明
- 改编来源：NeuroSploit `5d4e7e0`（本地标注 4.2.1），`agents_md/container/image_sbom_generate.md`、`agents_md/container/image_vuln_scan.md`、`agents_md/container/image_secret_scan.md`。
- 原归属 Joas A Santos & Red Team Leaders；上游：https://github.com/JoasASantos/NeuroSploit/tree/5d4e7e0/agents_md/container 。
- 中文重组双格式归档与层关联方法，补充 digest/数据库/真实可达性；移除自动安装、pull、liveness 探测与扫描即确认要求。
- 官方参考（按目标格式/工具版本核对，本文未联网查最新）：https://github.com/opencontainers/image-spec ；https://spdx.dev/specifications/ ；https://cyclonedx.org/specification/overview/ ；https://trivy.dev/ ；https://www.cisa.gov/known-exploited-vulnerabilities-catalog 。
- 上游 MIT 许可随本篇保留如下。

> MIT License
> Copyright (c) 2026 Joas A Santos & Red Team Leaders
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
