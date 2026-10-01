# Next.js 安全边界：路由、动作、序列化与缓存

## 1. 触发场景与边界

适用于已确认的 Next.js 目标：App/Pages Router 共存、Server Actions、RSC、预览或用户相关缓存。
核心问题是同一业务规则是否在页面、数据、动作与缓存消费入口一致执行，而非泛用载荷枚举。
SRC 任务先通过 `skills/src-hunting/SKILL.md` 定义范围，再按本场景切换框架技能，不常驻叠载。
用户排除的域名、环境、账号、动作与组件继续排除；构建中出现第三方地址不产生授权。
仅使用授权测试身份 A/B 和合成对象；禁止批量抓取 props、真实记录、token 或缓存内容。
任何写入、重验证、预览状态变更和共享缓存失效都需动作许可，不因可访问就执行。

## 2. 真实部署与版本前提

记录 Next.js、React 与 `react-server-dom-*` 的实际安装/部署依据，不能只看仓库 package.json。
对齐 commit/build ID、锁文件、容器/托管发布与线上流量；旧 source map 或 manifest 仅代表候选。
分别确认 App Router、Pages Router、Route Handler、API route、Action 是否真正暴露。
确认 hosting、CDN、反向代理、Node/Edge runtime 和源站外部可达性，不探测未授权源站。
`middleware.ts`/`proxy.ts` 名称、runtime 能力与缓存默认值按目标版本官方文档核对。
不能把某版本 GET/fetch 默认值或历史补丁结论套到另一分支；版本不明标 unverified。
RSC 路径与普通 client-only React 不同，组件名/头部只证明线索，不直接证明漏洞适用。
官方公告可用于决定候选，但特定 CVE、受影响版本、hosting 防护必须另行核实。

## 3. 建立可复现基线

为每个业务对象记录 owner、tenant、可执行动作及公开/私有字段的业务依据。
选一个 A 所有的私有合成对象，内容带唯一无敏感标记；保留 A 的合法成功请求。
用 B 和未认证请求形成拒绝基线；无效对象用于排除静态模板、默认页与通用错误。
固定构建、对象、方法、正文、语言和请求顺序；一次只改变身份、对象或入口之一。
保存状态、最终 URL、Content-Type、重定向链、必要响应字段与服务端效果，不只截取 200。
认证过期、浏览器旧数据、预览 cookie、feature flag 和租户切换需在比较前对齐。
文档/manifest 发现的路径必须确认部署；404 与登录页不能作为受保护数据访问成功。
将缺第二身份、缺对象或版本冲突写入相应矩阵单元，不阻断其他允许的单元。

## 4. 对象与操作权限路径

按“页面 → RSC/数据请求 → Action/Route Handler → 数据访问 → 业务效果”拆出实际路径。
页面布局、客户端按钮、导航重定向与 middleware 只能是前置控制，最终数据入口仍需授权。
Server Component 在服务器运行不代表输出自动保密，传给客户端的 props/流可被浏览器读取。
Server Action ID 是调用定位信息，不是对象所有权；需重验 session、role、tenant、object、action。
Action 请求必须来自已观察的合法测试流程，保留框架要求的头/正文，不猜造大批 Action 调用。
对读取、更新、删除、导出和签名分别检查；安全读取不能反证未经测试的写路径。
对象 ID 与 tenant 选择器来自请求时，必须和可信用户上下文结合，而不是沿用客户端声明。
App/Pages Router 共存时比较等价业务操作；同 URL 名称不代表执行相同 handler 或配置。
只比较真实部署的 Node/Edge 路径，不能声称可在运行时随意切换同一路由。
路径/头差分需证明请求最终进入不同控制路径并获得新增能力，重定向变化不够。

## 5. 序列化与字段泄漏

检查 HTML、`__NEXT_DATA__`、RSC stream、客户端组件 props 及允许 API 响应中的字段。
“DOM 未展示”不代表秘密，需说明字段为何对当前身份非公开，并证明目标实际返回。
完整用户实体、嵌套关系、调试字段只选少量受控样本，避免输出真实个人信息。
比较 A/B 请求，确认 B 获得 A 的私有标记；公开 slug、路由名、内部 ID 单独可见不自动成漏洞。
`NEXT_PUBLIC_*` 本来可被打包公开；键名或疑似 token 仅是线索，不自动报告有效凭据泄漏。
密钥候选仅在许可内验证最小额外能力，不能用其批量读库或取得身份本来就有的权限。
输出字段应在数据访问/DTO 边界收敛；“只不渲染”无法阻止序列化输出。

## 6. 共享缓存与状态差分

先识别 browser cache、客户端导航状态、框架缓存、CDN 与后端缓存，避免把会话污染当泄漏。
用私有合成对象低频执行 A→B→未认证→新会话对照，记录相同 URL 和实际非公开标记。
Age、ETag、cache header 与 HIT/MISS 是辅助证据；相同 ETag 或 200 本身不证明越权。
缓存 key、arguments/closed-over values、tenant、cookie/token 使用与失效范围需结合真实配置。
敏感数据是否进入共享缓存是核心；缺 `no-store` 但有有效身份隔离不直接构成漏洞。
缓存标签和重验证也可能跨 tenant 影响，检查作用域但不在生产批量失效或制造污染。
公开内容与只存在同浏览器缓存的旧内容是重要负对照；需排除 A/B 实际使用同一会话。
若共享缓存内容没有身份标记或无法识别层级，标 tentative/blocked，不推定跨用户。
预览/草稿模式的秘密 URL、cookie 与授权分开检查，只访问合成草稿；内部图片解码等另定范围。

## 7. 误报、反证与可测反例

可测反例一：页面未加载但 Action 也因对象权限拒绝 B，说明入口差异未产生新增能力。
可测反例二：`fetch` 没有 `no-store`，但实际 key 绑定 user/tenant，B 从未获得 A 的私有标记。
可测反例三：RSC 返回与 HTML 不同字段，但全部属于公开测试资料，不能作为敏感数据泄漏。
可测反例四：路径变体改变 307/404，却没有受保护数据或真实状态变化，不能确认绕过。
静态找到缺鉴权 Action、版本命中、source map、配置宽松均为 tentative 候选。
有效反证应注明控制位置、在消费前的时序、覆盖的路径和目标拒绝输出；安全兄弟入口不覆盖全部。
confirmed 只在实际目标证据证明独立安全边界与新增权限后成立，沿用 `skills/pentest-verification/SKILL.md`。

## 8. blocked、停止与证据保存

缺部署版本、账号 B、缓存控制信息、可回滚对象或动作许可时，仅标相关单元 blocked。
达到请求/时间预算、出现非测试数据、共享负载异常、外部通知或无法清理时停止对应动作。
不执行大 RSC/图片/表单、递归路径、资源耗尽或陌生项目，必要时只给隔离实验室验证前提。
保存起始身份、业务规则、实际请求/输出、差分、反证、未测/排除项和 Do-Not-Repeat。
HTTP 证据可用 `http-framework-test`；探活 `httpx` 不能替代对象权限与浏览器流程证明。
项目事实工具实际可用时保存状态；只有动态闭环的条目使用 `record_vulnerability`，无工具则保留证据。

## 9. 修复与验收

在最终数据访问/Action/service 绑定可信身份、对象、tenant、动作，前置 middleware 做附加防线。
限制传给客户端的字段；按部署版本显式配置敏感数据缓存、身份 key 和失效范围。
修复缓存泄漏后处理历史共享内容，避免只修未来请求；清除共享内容必须获得许可。
验收原最小反例、真实替代入口、A/B 合法请求、预览与缓存状态，不靠配置 diff 宣称有效。
若仅给出建议或无法执行复测，标“未验收”，不得表述为已动态修复。

## 10. 来源、许可与改编

原作：`others/strix/strix/skills/frameworks/nextjs.md`，Strix commit `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`。
[固定版本原文](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/frameworks/nextjs.md)；[Apache-2.0 许可](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。
本篇为中文改编与重写，保留来源归属；新增用户排除项、动态确认、新增权限、合成数据、缓存反证和停止条件。
未复制特定新 CVE/版本断言，也未沿用“版本/配置命中即漏洞”的推断。
官方核对：[认证](https://nextjs.org/docs/app/guides/authentication)、[Server Actions](https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations)、[缓存](https://nextjs.org/docs/app/guides/caching)、[升级](https://nextjs.org/docs/app/guides/upgrading)。
执行入口：`skills/framework-security-testing/SKILL.md`；短流程：`skills/framework-security-testing/references/nextjs-boundaries.md`。无需知识服务，可直接读本文件。
