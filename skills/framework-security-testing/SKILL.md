---
name: framework-security-testing
description: 对已确认使用 Next.js、NestJS、FastAPI/Starlette 或 Django/DRF/Channels 的授权目标，检查跨路由、运行时、认证依赖、对象操作、缓存与异步通道的安全边界。适用于 Server Actions 越权、Guard/Pipe 差异、Depends/令牌提取误用、ViewSet 动作权限等候选；SRC 任务先用 src-hunting 定界，再按具体框架切换本技能，不常驻叠载。仅指纹、静态链、配置弱项和版本命中不能确认漏洞；通用注入与组件情报分别交给既有领域技能。
license: Apache-2.0
compatibility: 需要授权目标和可用身份；工具需按本会话实际注册状态使用，不要求知识库服务启用。
metadata:
  tags: framework,nextjs,nestjs,fastapi,django,authorization
  source: usestrix/strix@007ed1a94e7dbf7b096c81e5b0354533ce94e0db
allowed-tools: http-framework-test httpx exec upsert_project_fact record_vulnerability
---

# 框架安全边界测试

## 使用边界与按需读取

继承用户目标、环境、排除项、动作许可、请求预算和停止条件，不扩大范围。SRC 起点先读 `skills/src-hunting/SKILL.md`；命中具体框架后切换本技能，只读取对应 reference，不同时载入四个专题。

- Next.js App/Pages Router、Server Actions、RSC 或个性化缓存：`skills/framework-security-testing/references/nextjs-boundaries.md`。
- NestJS Guard、Reflector、Pipe、HTTP/WS/RPC 差异：`skills/framework-security-testing/references/nestjs-boundaries.md`。
- FastAPI/Starlette 依赖、挂载应用、HTTP/WS/作业权限：`skills/framework-security-testing/references/fastapi-boundaries.md`。
- Django/DRF ViewSet、对象权限、序列化、Channels：`skills/framework-security-testing/references/django-boundaries.md`。

详细中文资料位于 reference 指明的根目录 `knowledge_base/`，可直接读取；服务不可用不影响执行。通用漏洞候选按需切换 `skills/web-attack-methods/SKILL.md` 或 `skills/api-security-testing/SKILL.md`；有源码时按需读 `skills/source-aware-whitebox/SKILL.md`，避免常驻叠载。

## 执行顺序

1. 确认真实部署版本、依赖版本、构建、适配器和暴露通道。锁文件只代表源码候选；版本不明标 unverified，不套用来源中的新 CVE 或默认行为。
2. 用允许的入口建立“身份 × 租户 × 对象 × 操作 × 通道”矩阵。以授权测试账号 A/B 和合成对象为准，缺身份只阻断相关单元；按用户排除项标 excluded。
3. 保留对象所有者的成功基线、未认证/非所有者的拒绝基线、无效对象负对照。固定部署、方法、正文、会话与对象，仅改变一个权限变量。
4. 沿入口→解析/转换→认证→对象/动作校验→业务效果定位差异；确认共享缓存、后台任务和替代通道消费的是哪个身份与对象。静态链仅产生 tentative 候选。
5. 用最少请求验证目标侧新增能力。200、重定向、文档公开、装饰器缺失、额外字段被接受均非充分证据；读取应是非公开受控标记，写入必须另有许可并回查、清理。
6. 按 `skills/pentest-verification/SKILL.md` 闭合基线、实际请求与输出、起始权限、业务规则、新增权限、控制级反证、影响和清理。仅 confirmed 且独立跨越安全边界时记录漏洞；其他状态保存事实与未覆盖单元。

## 系统工具补全

- `httpx`：仅对已授权少量入口探活/指纹；不能证明鉴权或替代浏览器语义。
- `http-framework-test`：HTTP 身份/对象/方法差分，先确认状态、Content-Type、最终 URL 和有界正文；不批量抓取数据。
- `exec`：专用工具不支持的已批准 WS/流式检查或本地只读分析。仅使用已安装可信工具，先核对参数；不自动安装 SDK、不运行陌生项目、不执行生产触发器。
- `upsert_project_fact`：保存版本依据、矩阵、tentative/negated/blocked、排除项、反证与 Do-Not-Repeat；须已注册且项目绑定有效。
- `record_vulnerability`：只提交完成动态验证与新增权限证据的条目；调用前核对实际 schema。工具定义存在不代表当前已注册或依赖已安装。

## 停止与修复验收

达到预算、异常负载、接触非测试数据、身份/对象归属不明、写入许可不足时停止对应操作，标 blocked 并说明所缺条件；不能据此宣布全目标安全。已有具体校验在消费前覆盖所有已测路径且目标拒绝时，记录限定范围的 negated。

修复落在最终业务入口与对象/动作权限，不依赖 UI、文档隐藏或单一中间件。验收须重放原最小反例、同业务替代通道和正常所有者操作；未执行的修复建议标“未验收”。

## 来源与改编

改编自 [Strix frameworks](https://github.com/usestrix/strix/tree/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/frameworks) 的 `nextjs.md`、`nestjs.md`、`fastapi.md`、`django.md`；原文件本地路径为 `others/strix/strix/skills/frameworks/`。原作 [Apache-2.0 许可](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)，本入口为中文重写，新增宿主工具映射、动态确认门禁、受控数据与停止条件，未复制特定 CVE/版本断言。官方文档与版本核对链接见各 reference。
