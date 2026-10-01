# Django 边界：精简检查流程

## 触发与前提

命中 Django/DRF ViewSet、serializer、对象权限、Channels 或异步任务时读取。核对部署 Django、DRF、Channels、认证扩展与 ASGI/WSGI；permission 默认值、middleware 顺序、session backend 和 serializer 依真实版本。保留用户排除项，准备 A/B 身份、合成对象和许可动作。

## 执行顺序

1. 依据允许流量、schema/urls/router 映射 list/retrieve/create/update/partial_update/destroy 与自定义 action；注明真实 HTTP method、authenticator、permission、queryset、serializer 和 service 校验。
2. 建立所有者 A 成功、B/未认证拒绝、无效对象负对照。固定对象/方法，只替换身份，区分认证、staff/model permission 与对象权限。
3. 检查自定义 `get_object` 是否调用对象权限；列表不假定逐对象调用，创建阶段核对 owner/tenant 分配及关联对象授权。服务层校验可能构成有效反证。
4. 只在许可合成对象测试 writable owner/tenant/role 或嵌套关联；`fields='__all__'` 和字段可见不自动越权，须证明权限字段生效或非公开字段泄漏。
5. session 认证的状态变更需浏览器 CSRF/Origin 实验；token 路径独立比较。csrf_exempt、cookie flag 或 admin 路径可见不直接确认漏洞，不爆破。
6. Channels 分别查握手身份、Origin、group 加入/发布/每消息对象权限；HTTP 拒绝不代表 WS 拒绝。Celery/后台 task 的创建、执行、结果读取均绑定原身份与租户。
7. 若有 proxy 注入身份头，核对真实 ASGI/代理规范化；只做无害单变量。不要诱发 debug 500、大查询或生产状态触发器。

## 反证、停止与修复

- 可测反例：宽 queryset 但所有 detail/custom action 都有对象校验，list 另有 tenant 过滤；serializer 敏感字段只读且关系写入被拒；WS 握手成功但跨租户 group 加入被拒。
- 单个安全 action、自动转义、DEBUG=False 或配置默认值只覆盖对应路径；框架 ORM 并非所有拼接都安全，源码危险调用仍仅候选。
- 缺角色/第二身份、浏览器会话、后台任务许可、版本或规则信息标相关 blocked；预算、异常负载、非测试数据或无法清理时停止，不外推全站。
- 修复按 action 统一权限并在 service 中绑定对象/租户；列表限定 queryset，创建/更新限制字段和关联，Channels/任务重用等价业务规则，明确 session CSRF。
- 验收原反例、兄弟 action、替代通道及合法 A 流程；按 `skills/pentest-verification/SKILL.md` 以动态新增权限确认，未执行修复验收标明。

## 补充资料与来源

完整正文：根路径 `knowledge_base/Framework-Security/Django-Security-Boundaries.md`，无需知识服务。
原路径 `others/strix/strix/skills/frameworks/django.md`，改编自 [Strix 007ed1a](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/frameworks/django.md)，[Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。中文重写，收紧配置/静态链证据，补充动作、创建与列表权限差异；未复制新 CVE 或 session RCE 泛化。
官方核对：[DRF permissions](https://www.django-rest-framework.org/api-guide/permissions/)、[Serializers](https://www.django-rest-framework.org/api-guide/serializers/)、[Django security](https://docs.djangoproject.com/en/stable/topics/security/)、[Channels authentication](https://channels.readthedocs.io/en/stable/topics/authentication.html)、[Channels security](https://channels.readthedocs.io/en/stable/topics/security.html)。
