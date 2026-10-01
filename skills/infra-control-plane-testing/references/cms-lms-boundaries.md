# CMS/LMS/电商对象权限工作流

仅在WordPress插件版本/REST namespace/AJAX action、Moodle course/context/文件区或WooCommerce/Magento订单及角色证据明确时触发。favicon、非404与插件目录猜测不能单独dispatch；SRC先使用 `src-hunting`。

1. WordPress映射anonymous/subscriber/author/editor/admin → post/media/plugin action → capability；REST permission_callback、AJAX nopriv与nonce检查分别核对，nonce不是对象授权。
2. Moodle映射guest/student/teacher/manager → course/enrolment/group/context → grade/submission/pluginfile操作；预期权限按context和capability确认，不按userid是否可见推断。
3. WooCommerce/Magento映射customer/shop manager/admin/integration → cart/order/refund/download/store → read/update；订单key、guest token与store范围是否属于授权材料必须说明。
4. 用受控A/B账号各自测试对象建立合法读取与拒绝基线；固定请求仅换owner/object/role一项。课程群组规则、公开文章和共享下载作为对照。
5. 默认只读限量；另行获准写测试仅修改自建测试对象，独立会话回读及目标审计确认持久化，再验证恢复。禁止他人成绩/订单修改、真支付退款、批量导出、账户或插件植入。
6. 管理员正常编辑、教师课程授权评分、有效订单key合法下载、公开内容可读均不是独立漏洞。版本命中/扫描报告仅候选；缺身份、私有测试对象或写授权记blocked/tentative。

工具：仓库启用定义 `http-framework-test` 仅在当前会话已注册且依赖可用时做身份隔离和有限对照；`httpx`只提供指纹线索；`wpscan`仅已确认WordPress且范围允许的低影响枚举，禁密码破解与默认广扫。核对当前工具/依赖，禁运行时安装，脱敏cookie/nonce/order key。

记录：产品/插件版本、主体/角色、对象owner/context/store、允许操作、基线/未授权对照、内容标记、回读与审计引用、新增权限、反例和未验证持久化；沿用项目低价值排除与独立边界quality。

完整知识：[CMS-LMS-Commerce-Authority](../../../knowledge_base/Web-Product-Security/CMS-LMS-Commerce-Authority.md)。
改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
来源：`others/Dark-Moon/conf/agents/{wordpress,moodle,magento}.md`，提交 `cb0d9b8`，原GPLv3；本文GPL-3.0-only。用户2026-10-01自述作者授权自有内容改编；第三方许可保留，不改根LICENSE。
官方参考：https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/ ；https://moodledev.io/docs/apis/subsystems/access ；https://developer.woocommerce.com/docs/apis/rest-api/ 。
