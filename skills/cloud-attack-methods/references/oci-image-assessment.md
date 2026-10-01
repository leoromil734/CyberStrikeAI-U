# OCI 镜像库存、层与公告可达性核验

## 适用、版本与身份
- 只读审阅获授权本地镜像归档、层/config、SBOM 与扫描 JSON，不拉镜像、不运行容器。
- 固定归档哈希、index/平台 manifest/config/layer digest、OS/架构及取得时间；tag 不是不可变版本。
- 记录扫描器、数据库版本/更新时间、扫描时间、过滤与覆盖缺口。
- 记录 registry 与运行工作负载身份、权限和环境；安装组件不证明已被运行身份使用。
- SPDX/CycloneDX 的格式版本和生成器分别记录，不能只写“已生成 SBOM”。
- 无模型调用需求；模型辅助只用获准脱敏库存，记录 provider/model 与数据范围。
- 详见 [OCI SBOM 与可达性](../../../knowledge_base/Cloud-Container-Attack/OCI-SBOM-Reachability.md)。

## 短执行流程
1. 固定实际平台与 digest，确认 SBOM/扫描结果都指向相同镜像主体。
2. 读取已有或以已注册且可用工具离线生成 SPDX/CycloneDX，保存原件及哈希；双格式能力不足记依赖缺口。
3. 对 package@version 记录生态、发行版 release、purl/CPE、路径与有序 layer digest。
4. 区分有效根文件系统、上层覆盖/whiteout、构建阶段和旧层残留。
5. 将每条公告关联组件、fixed-in、数据库时间与供应商回补信息，KEV 只用于优先级。
6. 追踪入口→可控输入→加载/调用→受影响函数→配置/权限条件，未知环节保留候选。
7. 对层/历史中的秘密只保存脱敏位置与摘要，不主动检验 liveness 或登录下游服务。
8. 分开交付库存、公告命中、可达性与影响；本流程不通过启动容器补证。

## 基线、证据与状态
- 基线：不可变镜像、相同平台与配置、原始库存和数据库元数据。
- 对照：可信发行版回补说明、构建阶段不入最终镜像、相关特性关闭或无权输入被拒绝。
- 单变量比较记录修复前后 digest；数据库变化与镜像变化分别说明。
- 最小证据含组件全版本、公告来源、fixed-in、层/路径、数据库时间与输出哈希。
- 可达性需源码/调用记录、入口身份、配置和真实目标结果，不用“可执行文件存在”替代。
- `tentative`：scanner hit 或版本匹配；`confirmed`：独立证实的具体边界影响；`blocked`：授权/依赖不足。
- 无 CVE 仍可交付库存，但只能说在指定覆盖与数据库下未发现，不能判供应链全部通过。

## 反证、停止与清理
- 正例：实际加载受影响函数且获批合成输入造成明确越界，相关 audit/readback 可关联。
- 反例：CVE 命中但存在可信回补，或组件仅在不进入最终镜像的构建阶段。
- 正例：合成秘密可从旧层读取，证明制品残留；活性和下游权限仍另记。
- 反例：SBOM 存在而数据库过期/缺失，不能据零命中断言安全。
- 缺平台、层、绑定主体、有效数据库或私库授权时停止相关分支并记 `blocked`。
- 拒绝自动 pull、联网 DB 更新、执行镜像/构建脚本、秘密外发与生产 registry 修改。
- 清理获批临时解包/缓存，保留脱敏 SBOM 与证据哈希，不删除远端镜像。

## 工具映射与修复
- 已注册 `trivy` 映射镜像/库存扫描，先核对安装版本、离线模式与实际格式支持。
- 注册配置不证明双格式导出可用；Syft、Grype、registry 客户端缺失记 `blocked`，不新增/安装。
- 可继续审阅已有 SBOM，不能为满足双格式伪造字段或调用未注册客户端。
- 使用受支持基础镜像与修复依赖重建，记录新 digest、库存变化与公告口径。
- 层秘密按批准流程轮换并处理旧制品；仅在新层删除文件不消除旧层泄露。
- 制品签名、来源与构建链验证另列，SBOM 不替代真实性与运行权限控制。

## 来源、改编与许可
- NeuroSploit `5d4e7e0`（本地标注 4.2.1），`agents_md/container/image_sbom_generate.md`、`agents_md/container/image_vuln_scan.md`、`agents_md/container/image_secret_scan.md`；原归属 Joas A Santos & Red Team Leaders。
- 来源：https://github.com/JoasASantos/NeuroSploit/tree/5d4e7e0/agents_md/container 。
- 中文重组双格式/层关联并补充不可变主体、回补与证据状态；删除自动安装/pull 和扫描即确认要求。
- 官方资料按目标版本核对，未联网查最新：https://github.com/opencontainers/image-spec ；https://spdx.dev/specifications/ ；https://cyclonedx.org/specification/overview/ ；https://trivy.dev/ 。
- 上游 MIT 许可保留如下。

> MIT License
> Copyright (c) 2026 Joas A Santos & Red Team Leaders
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
