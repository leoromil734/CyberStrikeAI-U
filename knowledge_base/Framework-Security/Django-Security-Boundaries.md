# Django 安全边界：动作权限、序列化与异步通道

## 1. 触发与授权范围

适用于 Django/DRF ViewSet 的 action 权限、queryset/serializer、Channels、后台任务与 session 认证候选。
核心增量是同一对象在 list/retrieve/create/update/custom action 与替代通道中的有效控制。
SRC 先通过 `skills/src-hunting/SKILL.md` 定义边界，再切换本框架场景，不常驻叠载。
继承用户全部排除项，只使用已授权环境、账号与合成对象；公开 admin 路径不是爆破许可。
读取限少量测试标记，不批量导出列表、文件、debug 信息或个人数据。
创建/删除、角色字段、Channels 事件、Celery 任务与 CSRF 状态改变都需明确动作许可。

## 2. 真实版本与部署前提

记录部署 Django、DRF、Channels、session/JWT 扩展、ASGI/WSGI server 的版本与构建依据。
源码/锁文件和线上应对齐；老 debug 页面、cookie 名称或 header 不证明准确版本。
核对 REST_FRAMEWORK 的认证/权限默认值、view/action 覆盖与 middleware 顺序。
核对 session backend/serializer、CSRF 配置、proxy 信任和实际 Origin/Host 处理。
签名 cookie、session key 与 password reset token 机制不能混为一谈，JSON session 不意味着 pickle RCE。
Django/DRF/Channels 各自的安全默认值只覆盖实际使用的路径，不替代自定义 view/service 逻辑。
不复制来源中新 CVE、ASGI header 或 GeoDjango 版本断言；真实适用性按部署分支核对。
版本或生产 Rules/permission 无法取得时标 unverified，保留实际行为而非虚构默认安全。

## 3. 基线和动作矩阵

选 A 所有的非公开合成对象，定义 tenant、owner、role 和具体可执行动作。
保存 A 成功、B/未认证拒绝和无效 ID 负对照，固定 method、对象、正文与部署。
矩阵逐项列 list/retrieve/create/update/partial_update/destroy 与每个自定义 `@action`。
记录 action 的 URL/method、authenticator、permission、queryset、serializer、service 和业务效果。
区分 authentication、staff/model permission 与对象权限，不把用户已登录当成 owner。
普通用户/staff/admin 仅使用用户提供的合法测试身份，不自行创建/提升角色。
一次只改身份、对象或入口，记录状态、Content-Type、响应标记/状态回查与实际差分。
缺账号 B/特定角色只阻断相应单元，排除与未测项独立保存。

## 4. DRF 权限实际调用位置

检查 `get_permissions()`、permission_classes、默认策略及按 action 分支的最终结果。
一个 action 安全不能外推其他 action；不同 serializer、authenticator 与 version 也可能改变路径。
通用 detail `get_object()` 常执行对象权限，重写或自定义加载可能省略，需核对真正调用。
list 通常不会为每个返回对象自动运行对象权限，应查 queryset/filter 中的用户与 tenant 限制。
create 尚无原对象，不应依赖既有对象权限检查；需限制 owner/tenant 分配及关联目标。
update/delete/detail/custom action 均需绑定调用者和最终消费对象，query 与 body ID 不能错位。
权限发生在最终业务动作前，提前校验后另一个 service 使用不同对象需记录生命周期差异。
宽 queryset 本身不必然越权，service/detail 权限可构成反证；但 list 必须单独取得证据。
admin 的 staff 入口、model/action/object 权限与 DRF 是独立策略，不能由 API 安全推定 admin 安全。

## 5. Serializer 与嵌套写入

明确读取字段、写入字段、read_only_fields、自定义 create/update 及 nested relation 的最终消费。
`fields='__all__'` 是审查线索，字段可见或可输入不等于权限字段实际被更新。
在许可合成对象加入无害标记，验证 role/owner/tenant 及关联 ID 是否被拒绝/忽略/实际保存。
更新须同时校验旧对象权限和新关联/新租户权限，避免仅验证修改前 owner。
列表/导出/详情的 serializer 可不同，敏感字段应逐入口验证，不批量抓真实实体。
公开 ID、元数据、debug 字段需业务保密依据；“前端未展示”不自动等价泄漏。
模型约束、serializer validation 与 service 校验可能拦截越权，保留实际拒绝位置和输出。
ORM/filter API 的参数化与 raw/动态拼接是不同路径，静态危险调用交通用技能并保持 tentative。

## 6. Session、CSRF 与代理身份

session authentication 的 unsafe 方法需要按真实浏览器 cookie/Origin/CSRF 行为验证。
DRF SessionAuthentication、token/JWT 和混合 authenticator 分别记录，不能用某一路安全覆盖其他。
仅 `csrf_exempt`、宽 CSRF_TRUSTED_ORIGINS 或 cookie flag 缺失不能直接 confirmed。
授权浏览器实验只操作合成可回滚对象，保留 baseline、跨源实际请求及目标状态变化。
curl 能比较服务响应，不能替代浏览器会话自动附带、SameSite/Origin 与真实 CSRF 效果。
Host/proxy 身份头候选需确认实际注入/规范化和消费；不要根据下划线/连字符名称推定绕过。
DEBUG/SECRET_KEY/settings 候选只被动检查已允许内容，不诱发未授权 500 或主动窃取真实凭据。
有效凭据/签名材料验证仍需最小额外能力证据，合法身份本来拥有的能力不是独立漏洞。

## 7. Channels 与后台任务

Channels 分别核对 auth middleware、握手 Origin、consumer、group join/publish 和每消息对象授权。
AuthMiddlewareStack 提供用户上下文不代表每个 channel/topic 自动受对象权限保护。
由请求输入拼 group 名称时，必须绑定可信 user/tenant/member relation，不能仅信名称格式。
握手成功而跨租户 join 被拒是有效限定反证；HTTP 拒绝不能直接反证 WS 路径。
只订阅测试房间与合成事件，连接结束及时退出，不能监听真实业务通知流。
Celery/异步操作分别检查触发参数、可信身份存储、执行上下文、状态/结果读取与取消。
job ID 或任务名不等于授权，B 不应读取 A 的私有合成结果或借 Admin 服务写入其他租户。
成员资格/撤销在执行时是否复核需明确业务规则，不把所有异步时间窗自动判成漏洞。
触发真实邮件、支付、外部 webhook 或不可逆任务时停止，未许可的执行只做静态候选分析。

## 8. 误报、反证与可测反例

反例一：宽 queryset 的 detail 都有对象权限，而 list 有有效 tenant 过滤，B 无新增能力。
反例二：serializer 声明敏感字段但只读/被 service 忽略，受控回查无权限变更。
反例三：consumer 可连接，但每次 group/message 都检查 membership 并拒绝 B。
反例四：session API 对跨源 unsafe 请求有有效 CSRF 验证，公开 admin/docs 不产生越权。
安全 sibling、DEBUG=False 或默认自动转义仅反证对应路径，不能代替所有操作的控制审查。
有效反证应注明具体控制、消费前时序、已覆盖动作与目标拒绝输出。
静态链、配置弱项、版本命中仅 tentative；confirmed 需实际目标动态证明新增权限和独立边界。

## 9. blocked 与停止条件

缺版本、第二身份、浏览器会话、合成对象、WS 客户端或后台任务许可时标对应 blocked。
达到预算、异常负载/配额、非测试数据、外部通知或清理不可靠时停止对应动作。
不爆破 admin、不扫描无授权环境、不批量查询/导出、不执行陌生项目或安装依赖。
证据保存实际身份、动作映射、对象/tenant、请求/输出、反证、清理、排除项和 Do-Not-Repeat。
`http-framework-test` 用于已授权 HTTP 对照；WS/浏览器选实际可用可信工具，缺工具明确记录缺口。
按 `skills/pentest-verification/SKILL.md` 闭合动态与新增权限，只将已确认独立条目提交漏洞记录。

## 10. 修复与验收

每个 action 明确 permission，最终 service 绑定 user/tenant/object/action，未知动作默认拒绝。
list 限定 queryset，create 固定可信 owner，update/nested write 验证关联和新旧租户/字段。
Channels 与后台任务复用等价业务策略，session 路径正确 CSRF，proxy 身份限定可信来源。
验收原反例、兄弟 action、HTTP/WS/任务的实际替代入口与合法所有者流程。
配置 diff 与源码修复只算建议；没有实际复测输出必须标“未验收”。

## 11. 来源与改编

原路径 `others/strix/strix/skills/frameworks/django.md`，Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`。
[固定版本原文](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/frameworks/django.md)；原作 [Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。
本篇中文重写，补充列表/创建/自定义 action 权限与 Channels/任务边界，收紧配置/静态证据，不复制新 CVE/版本断言。
官方核对：[DRF permissions](https://www.django-rest-framework.org/api-guide/permissions/)、[Serializers](https://www.django-rest-framework.org/api-guide/serializers/)、[Django security](https://docs.djangoproject.com/en/stable/topics/security/)、[Channels auth](https://channels.readthedocs.io/en/stable/topics/authentication.html)、[Channels security](https://channels.readthedocs.io/en/stable/topics/security.html)。
入口 `skills/framework-security-testing/SKILL.md`；短流程 `skills/framework-security-testing/references/django-boundaries.md`。本文件可直接读取，无需知识服务。
