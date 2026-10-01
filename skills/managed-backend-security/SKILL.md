---
name: managed-backend-security
description: 对授权的 Supabase/Firebase 托管后端，检查 RLS/RPC、Realtime/Storage、Firestore/Realtime Database Rules、GCS IAM/ACL、Functions 与用户/租户权限的跨入口差异。适用于项目 key、匿名用户、签名 URL、Admin SDK/高权限客户端候选；SRC 先用 src-hunting 定界再切换本技能，不常驻叠载。public key、规则文件缺失、关闭平台 JWT 检查或静态宽松配置仅是线索，须以目标侧新增权限确认；禁止批量提取或未经许可写入。
license: Apache-2.0
compatibility: 需要授权项目和合成对象；工具按当前注册状态使用，不要求知识服务启用。
metadata:
  tags: supabase,firebase,rls,storage,functions,authorization
  source: usestrix/strix@007ed1a94e7dbf7b096c81e5b0354533ce94e0db
allowed-tools: http-framework-test httpx exec upsert_project_fact record_vulnerability
---

# 托管后端安全测试

## 最小加载与边界

继承用户项目、环境、排除项、身份与动作许可；第三方后端地址不自动构成授权。SRC 先读 `skills/src-hunting/SKILL.md` 定界，确认产品后切换本技能，只读对应 reference。

- Supabase key/JWT、RLS/RPC、GraphQL、Realtime、Functions、Storage：`skills/managed-backend-security/references/supabase-authorization.md`。
- Firebase 配置、Rules、GCS IAM/ACL、Functions：`skills/managed-backend-security/references/firebase-authorization.md`。

完整中文资料位于 reference 指明的根目录 `knowledge_base/`，直接读文件即可。一般 API 越权按需切换 `skills/api-security-testing/SKILL.md`，云 IAM 广域任务切换 `skills/cloud-attack-methods/SKILL.md`，不常驻叠载。本技能仅处理已定界后端的授权引擎差分。

## 执行顺序

1. 对齐项目标识、实际请求、部署、SDK/后端版本与生效规则。记录凭据类型并脱敏；本地规则/锁文件不等于线上状态，未知版本标 unverified。
2. 区分未认证、匿名登录、用户 A/B、管理员/服务身份。public key 与 App Check 不是所有权；合法令牌执行本来允许的操作不是新增权限。
3. 建立“资源 × 读/列举/创建/更新/删除/签名/订阅 × 身份 × 租户 × 入口”矩阵。只测授权路径、已知合成对象和少量标记字段；禁止根读取、全表、通配列表和递归分页。
4. 保存所有者成功、非所有者/未认证拒绝、无效对象负对照；固定版本与请求，一次只改变身份、对象或入口之一。写入、签名和订阅副作用另需许可。
5. 确认最终授权引擎及高权限代理：Supabase 区分项目 key/用户/数据库角色；Firebase 区分 Rules/GCS IAM/ACL/Admin SDK 的业务校验。一侧 403 不反证其他入口。
6. 证明读取私有合成标记、受控写入回查或越权订阅合成事件的新增能力。签名 URL 预期持有者访问、public bucket 预期公开、配置弱项与静态链不直接 confirmed。
7. 按 `skills/pentest-verification/SKILL.md` 保存实际请求/输出、起始权限、业务边界、反证、影响、清理与复测；仅独立边界已动态闭环的条目记录漏洞。

## 系统工具补全

- `httpx`：仅探活允许入口，不扩大项目、bucket 或数据库列表。
- `http-framework-test`：已知合成对象 REST/Functions 差分，保存状态、Content-Type、最终 URL、有界输出；长度或空列表不足以下结论。
- `exec`：专用工具缺失时，仅用已安装可信客户端做获批 SDK/Realtime 对照或只读分析；不安装、启动陌生项目、部署规则或执行未经许可触发器。
- `upsert_project_fact`：保存版本、权限矩阵、tentative/negated/blocked、排除项、Do-Not-Repeat；须实际注册且项目绑定。
- `record_vulnerability`：只提交动态新增权限证据，核对当前 schema。工具定义存在不保证启用、依赖安装或项目权限。

## 停止、反证与修复

缺第二身份仅阻断对应单元；对象归属不明、真实数据、配额告警、外部通知、预算耗尽或清理不可靠时停止相关操作并标 blocked。具体控制在消费前覆盖已测路径且目标拒绝，才形成限定 negated；规则 IaC 缺失只记部署证据缺口。

修复覆盖各实际入口、操作、字段、租户和高权限路径。撤销 key 或调整 Rules/RLS 后，复测原反例、替代入口与合法操作；未执行标“未验收”。

## 来源与改编

改编自 [Strix technologies](https://github.com/usestrix/strix/tree/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/technologies) 的 `supabase.md`、`firebase.md`，原路径 `others/strix/strix/skills/technologies/`，原作 [Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。中文重写，修正“DEFINER 必然绕 RLS”“缺规则 IaC 即漏洞”泛化，加入动态门禁与受控数据。官方链接见 reference，实际版本另核对。
