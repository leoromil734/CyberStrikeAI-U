---
name: security-regression-testing
description: >-
  对获准读取的 diff、提交范围、补丁或历史 PoC 做安全变更审查、修复验收和复测。
  用于检查新可达性、删除 guard、共享 helper、正常业务与等价输入回归；不是第四个
  扫描深度，不自动改产品、运行陌生项目、安装或部署。SRC/赏金先 src-hunting 定界，
  到具体修复/变更阶段再切换，不常驻叠载；静态候选不直接 confirmed，无法复测不等于已修复。
license: Apache-2.0
metadata:
  tags: [security-regression, diff-review, fix-verification, retest]
  source: Strix/NeuroSploit；各 reference 保留原许可
allowed-tools: exec upsert_project_fact get_project_fact list_project_facts list_vulnerabilities get_vulnerability record_vulnerability
---

# 安全变更与复测

只在输入为批准变更或历史发现时使用。需要在线复测先确认范围、目标版本、身份、对象、预算、写入及恢复许可。工具或配置存在不等于当前可用。

## 按需流程

读 `references/change-review-and-fix.md`；普通新候选验证使用 `pentest-verification`，不全量预读其他领域。

1. 固定 base/head、构建/部署、配置、原发现和原始证据。无关旧问题不归给当前变更。
2. 沿入口→变换→guard→效果比较新增/删除分支、默认值、失败回退与共享 helper 兄弟调用。
3. 静态链保持 tentative；缺运行环境/部署/身份记 blocked，只阻断对应单元。
4. 获准执行时验证正常基线、原 PoC、等价输入/方法/Content-Type、替代入口和异步消费者；保存每次输出。
5. 仅可恢复受控副本且明确获准才撤销补丁反测，随后恢复验收；没执行明确标注。
6. 另记 reproduced/changed/gone/unverifiable 复测字段并关联历史，不覆盖原结论、不改账本枚举。
7. confirmed 仍需实际目标侧新增权限、完整 POC 与 validation；正常行为损坏不是修复成功。

## 系统工具补全

| 场景 | 工具 | 边界 |
| --- | --- | --- |
| 获准本地 diff/测试 | `exec` | 仅可信且批准的项目/命令，不自动安装或联网 |
| 历史事实 | `get_project_fact` / `list_project_facts` | 区分轮次、版本、身份与原件 |
| 历史发现 | `list_vulnerabilities` / `get_vulnerability` | 原发现保留，新建复测关联 |
| 保存复测 | `upsert_project_fact` | 未执行、缺口和限定负结果真实记录 |
| 正式发现 | `record_vulnerability` | 只限独立边界动态闭环，不把静态报告升级 |

达到预算、非预期副作用、健康异常或回滚失败停止对应单元。同组合三次无新证据换路；保留本项目低价值排除、身份预算和清理验收要求。发布、迁移与部署另行批准。

## 来源

中文改编自 Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db` 的 `strix/skills/scan_modes/diff.md`、`analysis/fix_verification.md`（Apache-2.0），及 NeuroSploit `5d4e7e0347219ceae22735ec6af3d8cdd0561ded` 的 `neurosploit-rs/crates/harness/src/poc.rs`（MIT；Copyright (c) 2026 Joas A Santos & Red Team Leaders）。许可见根 LICENSE 与 `docs/knowledge-skill-integration/licenses/NeuroSploit-MIT.txt`；未移植外源运行引擎。
