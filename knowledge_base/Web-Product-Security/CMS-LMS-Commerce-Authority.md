# CMS/LMS/电商：产品对象权限证据

## 适用条件
- 已确认WordPress插件/REST action、Moodle course/context或WooCommerce/Magento对象与角色。
- 有插件版本、请求样本、提供凭据或源码产物，而非仅favicon、端口或非404。
- SRC先使用 `src-hunting`；本篇细化角色×对象×操作，保留低价值排除与独立边界quality。
- 不以产品名称、版本匹配或扫描候选代替实际未授权能力。

## 身份 → 对象 → 允许操作
- WordPress主体分anonymous/subscriber/contributor/author/editor/admin与multisite角色。
- 对象分post/media/user/plugin settings/action；capability与对象owner同时核对。
- Moodle主体分guest/student/teacher/manager，权限按context、enrolment和capability计算。
- 对象分course/activity/group/submission/grade/file context，不用角色名代替对象授权。
- WooCommerce主体分customer/shop manager/admin/API key，记录key对应user与read/write模式。
- Magento主体分customer/admin/integration，记录ACL resource、store与具体API对象。
- 对象分cart/order/refund/address/download/store；管理后台看得到菜单不是API授权证据。
- 租户/站点Admin只在正常范围内操作不计洞；跨站点/平台或额外资源仍需对照。

## 产品确认与对象库存
- WordPress核心/插件/主题版本来自获准资产、源码或多项可核验信号，单路径不是证明。
- REST namespace、schema、真实action和wp_localize_script输出关联具体插件，不穷举全目录。
- AJAX `action`、nonce来源、认证条件与最终capability检查分开记录。
- Moodle记录course、contextid、component、filearea、itemid和group模式，不全站枚举ID。
- WooCommerce/Magento记录订单owner、guest令牌/订单key、store scope和下载授权材料。
- 插件/模块inactive、历史静态缓存与实际加载差异说明，不把文件存在当可调用版本。

## 基线与未授权对照
1. 使用A/B受控账号，各自创建无业务秘密的测试内容/课程对象/模拟订单。
2. A读A对象建立允许基线；A读B私有对象建立预期拒绝基线。
3. 固定同一会话和请求只换对象，或固定对象只换会话；不混用cookie、nonce和tenant。
4. 记录谁创建/持有对象、是否公开/共享、允许角色与实际context/store。
5. 服务端返回必须包含B受保护内容/操作效果，200/长度差分不自动确认。
6. 自有对象可读、公开文章/产品可读是基线，不作为独立漏洞。
7. 缺第二身份或私有受控对象时tentative/blocked，不改他人真实内容补证据。

## WordPress 与 WooCommerce
- REST `permission_callback`是否检查capability与对象owner分开看，缺函数只是静态候选。
- AJAX `wp_ajax_nopriv_*`允许匿名是路由设计；需核对实际操作是否应公开。
- nonce是请求来源/动作约束，不等于用户或对象授权，也不因获得nonce自动确认越权。
- subscriber可访问author/editor动作需比角色预期与私有对象返回，禁管理员功能正常计洞。
- post/media status与visibility核对：published内容可公开，private/draft不能按URL猜授权。
- multisite site admin与network admin对象分开，不能把single-site后台能力当network权限。
- WooCommerce REST API key按关联user与permission判断，不以key存在当shop接管。
- 订单ID与 `wc_order_*` key/guest访问结合核对；提供正确key可能本来是授权链接。
- 下载权限关联order/product/customer/expiry，验证只用自己创建的测试材料。
- 默认不做支付、退款、库存竞态、真实优惠/订单改写或webhook真实发送。

## Moodle：课程、成绩、提交与文件
- enrolment状态、course visibility、guest access与活动条件共同确定读取基线。
- student对自己grade/submission的合法读取与其他学生私有内容读取分开。
- teacher在自己课程有评分权并非漏洞；跨课程/被拒context操作才是候选边界。
- Web service函数的 `userid`参数需检查返回对象owner，参数接受不证明越权。
- `pluginfile.php`路径由context/component/filearea/itemid决定，不能只改数字猜任意文件。
- group submission可能合法共享组成员文件；separate/visible group模式与成员关系记录。
- enrolment操作、LTI注册/身份映射、grade override分别是边界，不能一成功就全面计洞。
- 默认只读成绩与无敏感测试文件；禁止他人成绩、截止时间、提交状态或账户改写。
- 不导出全course backup/gradebook、不restore包或植入插件，不重复计正常teacher能力。

## Magento：customer、integration 与store
- `/rest/<store>/V1/...`等实际API按版本核对，store code不一定独立租户授权域。
- `acl.xml`的resource与webapi route权限关联，区分anonymous/self/integration/admin。
- customer的 `mine`路径是自有对象基线，直接ID路径是否限制owner需实际对照。
- guest cart masked ID本身是能力材料；能用合法受控ID不等于任意他人cart可读。
- integration访问批准订单是本职能力，不以admin token成功调用判独立漏洞。
- GraphQL与REST对同对象要核政策一致性，不从introspection自动确认订单泄露。
- 缺业务敏感字段、只见公开catalog/title按项目低价值排除，不升级影响。

## 目标侧证据与持久效果
- 保存脱敏实际请求、测试内容标记、object owner、context/store与完整控制变量。
- 用服务器审计、后台对象记录或独立owner会话回读关联实际执行，不只看UI通知。
- 写测试仅额外授权、自建测试对象，记录before/after、异步完成及恢复结果。
- POST成功可能只提交任务，必须核对目标实际保存；readonly不推断持久写入。
- 没做写入标“持久化未验证”；不能把read泄露写成退款/改成绩/账号接管。
- 不触发logout/revoke、真实资损、插件账户持久化、DoS或无限扫描。

## 可核验反例
- author编辑自己的文章，B draft被拒：正常owner分权。
- 公开WordPress post可匿名读，private post拒绝：非未授权敏感内容。
- 有nonce但capability拒绝subscriber修改settings：nonce可得不等于提权。
- Moodle teacher只读/评分本课程，其他课程拒绝：正常职责。
- 小组成员按批准group submission规则读共同文件：合法共享。
- WooCommerce订单key获准持有者读相应订单，缺key拒绝：授权链接基线。
- Magento customer `mine`只返回自有cart，B cart被拒：条件边界有效。
- integration按批准ACL管理订单：正常权限；泄露token的既有能力不重复计洞。

## 缺口、记录与敏感值
- 记录起始角色、凭据来源、产品/插件版本、context/store、object owner与允许操作。
- 记录允许/未授权单变量对照、返回敏感类型/测试标记、目标证据与额外能力。
- 记录公开/共享/guest key规则、反证、采样预算和未覆盖操作，不以一例结束全部域。
- 空结果、401/403、nonce过期、错误context、timeout分别记录，不机械否定整个产品。
- 订单key、cookie、nonce、学号、成绩、地址脱敏，原始敏感正文不打印普通日志。
- demo/sample账号不免责，但其当前权限/业务信任必须实证；版本命中仅tentative。

## 工具边界
- `http-framework-test`当前注册/依赖需核对，用独立凭据和限量请求，关闭请求概览。
- `httpx`仅指纹线索；`wpscan`需确认WordPress、范围允许且低影响枚举，禁密码破解。
- WPScan数据库/API联网行为先核授权；离线没有资料写缺口，不自动安装或更新。
- `exec`不意味着WP/Moodle/Magento CLI可用，不执行来源命令或创建业务对象补环境。
- 响应过滤/截断不是脱敏；缺能力blocked，不绕工具限制。

## 来源、改编与许可
- 改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。
- 作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
- 源：`others/Dark-Moon/conf/agents/{wordpress,moodle,magento}.md`，https://github.com/ASCIT31/Dark-Moon 。
- WooCommerce知识来自wordpress提示中的专节，无独立woocommerce源文件。
- 快照 `cb0d9b8`（`cb0d9b83e745034c8bcff90daee9668b834d1508`），原GPLv3；本文GPL-3.0-only。
- 用户2026-10-01自述作者并授权自有内容改编；第三方原许可保留，根LICENSE不变。
- 改编去除遍历他人数据、真实成绩/订单修改与固定severity，补context/owner反证。
- 官方：https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/ ；https://developer.wordpress.org/plugins/security/nonces/ 。
- 官方：https://moodledev.io/docs/apis/subsystems/access ；https://moodledev.io/docs/apis/subsystems/files 。
- 官方：https://developer.woocommerce.com/docs/apis/rest-api/ ；https://developer.adobe.com/commerce/webapi/get-started/authentication/ 。
