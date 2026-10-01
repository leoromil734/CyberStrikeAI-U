# 变更与修复的窄范围验收

## 前提

固定批准 diff 的 base/head、构建/部署、配置、历史 PoC、身份、对象、预算和恢复方式。
静态审阅不授予运行陌生项目、修改产品、安装依赖、部署或执行目标的权限。

## 变更审查

1. 定位新增入口/可达性、被删 guard、默认值/错误回退变化。
2. 沿共享 helper 检查直接/兄弟调用、异步/重试消费者与实际安全效果。
3. 分开新引入、新暴露、受影响旧风险和无关旧问题，保存变更前后依据。
4. 静态候选保持 tentative；缺部署/身份/运行环境记 blocked，不判安全。

## 修复验收

1. 正常成功基线 + 原 PoC + 相同前提下目标状态读回。
2. 相关替代输入/编码/方法/Content-Type 和兄弟路径。
3. 获准且可恢复副本才撤销补丁反测，确认断言会失败，然后恢复验收。
4. 保存每次原件和执行关联，注明动态/静态/未执行；不只保留最后响应。
5. 新建复测字段 reproduced/changed/gone/unverifiable，关联原结论，不改账本枚举。
6. 正常行为损坏不叫修复；无法复测不等于已修复；正式漏洞仍需真实新增能力。

## 停止与修复

健康异常、非预期副作用、缺范围或回滚失败停止；同组合三次无新证据换路。
优先共享权限/语义边界修复，失败关闭，覆盖合法行为和等价输入，非只挡单一 payload。

## 来源与补充

Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`，`strix/skills/scan_modes/diff.md`、`strix/skills/analysis/fix_verification.md`，Apache-2.0。
NeuroSploit `5d4e7e0347219ceae22735ec6af3d8cdd0561ded`，`neurosploit-rs/crates/harness/src/poc.rs`，MIT；Copyright (c) 2026 Joas A Santos & Red Team Leaders。
中文重组；许可见根 LICENSE 与 NeuroSploit 独立许可文本；完整原理：`knowledge_base/Security-Verification/Change-Review-and-Retest.md`。
