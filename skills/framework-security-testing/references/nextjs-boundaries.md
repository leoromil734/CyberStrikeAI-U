# Next.js 边界：精简检查流程

## 触发与前提

命中 App/Pages Router、Server Actions、RSC、预览或个性化缓存时读取。先继承用户排除项，取得 A/B 测试身份、合成对象和动作预算。核对部署 Next.js、React/RSC 包、构建、hosting、路由与 Node/Edge；缓存默认值、middleware/proxy 文件名按实际版本核对，指纹与旧构建产物仅是线索。

## 执行顺序

1. 仅根据授权 UI 流量、公开构建资料和源码定位入口，确认线上可达；记录页面、Route Handler/API route、Action、RSC 是否访问同一业务对象。
2. 以 A 所有的非公开合成标记建立正常响应，保存未认证、B 和无效对象基线。固定部署与请求，只换一个身份/对象变量。
3. 比较页面保护与最终数据/操作入口：Action 标识不替代权限；服务端须重新验证用户、租户、对象与动作。middleware 重定向或 UI 不显示不能证明业务拒绝。
4. 对真实部署的路由/运行时检查守卫一致性，不尝试把同一路由强行改成另一运行时。路径或头差分只有实际越过业务边界才升级候选。
5. 检查 HTML、RSC、`__NEXT_DATA__` 和客户端 props 的允许字段；序列化内容公开且无需保密时不是泄漏。
6. 缓存使用 A→B→未认证→新会话的低频对照，固定对象与内容标记；结合 Age/ETag/回源或日志区分共享缓存、浏览器旧状态与公共内容。缓存标签、失效与 key 均须隔离身份/租户。
7. 已允许的写操作用可回滚合成对象，回查真实状态、清理；缓存清除/预览/重验证可能影响其他用户，未许可时只读分析并标 blocked。

## 反证、停止与修复

- 可测反例：未认证页面被重定向，但直接 Action/数据入口也拒绝；缺少 `no-store`，仍因显式身份 key 隔离；B 的相似页面没有 A 的非公开标记。这些限制各自候选，不外推全站。
- 200 登录页、空 RSC、Action ID 可见、公开构建/环境变量、版本命中和静态缺守卫均不能 confirmed。
- 缺账号/可识别缓存层/线上版本，相关单元 blocked；达到预算、非测试数据出现或共享失效副作用停止。保留用户排除项与未覆盖入口。
- 修复在数据访问/Action 内绑定身份、租户、对象和动作，减少序列化字段，按版本显式配置敏感数据缓存与失效。验收原反例、替代入口、合法 A/B 正常流程。
- 按 `skills/pentest-verification/SKILL.md` 记录实际目标请求/输出和新增权限；静态链与配置不直接记录漏洞。

## 补充资料与来源

完整正文：根路径 `knowledge_base/Framework-Security/Nextjs-Security-Boundaries.md`，可直接文件读取。
改编原路径：`others/strix/strix/skills/frameworks/nextjs.md`，来自 [Strix 007ed1a](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/skills/frameworks/nextjs.md)，[Apache-2.0](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/LICENSE)。中文重写并加入动态确认、受控缓存和反证约束，未沿用特定新 CVE/版本断言。
官方核对：[认证](https://nextjs.org/docs/app/guides/authentication)、[Server Actions](https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations)、[缓存](https://nextjs.org/docs/app/guides/caching)、[升级](https://nextjs.org/docs/app/guides/upgrading)。
