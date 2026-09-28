# 前端 JS 分析与密钥/接口发现

> 现代 SPA 把大量"服务端逻辑"搬到了浏览器：**接口清单、参数、内网域名、有时还有密钥**。看 JS 往往比扫描器更快找到漏洞面。

## 一、抓取与分析

```bash
katana -u https://target -jc -d 5 -o urls.txt          # 含 JS 渲染
gau --subs target.com | grep -Ei '\.js($|\?)' >> js.txt
# sourcemap 还原
unwebpack-sourcemap / sourcemapper / restringer
```

重点文件：

- 打包产物 `*.js`、`chunk-*.js`、`runtime-*.js`
- `*.js.map`（sourcemap）→ 可还原原始 TypeScript 源码与注释
- `manifest.json`、`sw.js`（Service Worker 常含缓存路由与接口）
- `asset-manifest.json`、`webpack.stats.json`
- 移动端 APK/IPA 内的 bundle（见 `../Mobile-Security/README.md`）

## 二、接口与参数发现

在 JS 中 grep：

```text
/api/  /v1/  /v2/  /graphql  /internal  /admin  /debug  /actuator
fetch(  axios.  $.ajax  useQuery  apollo  gql`
token  apiKey  apikey  secret  bearer  Basic
Authorization  X-Api-Key  X-Internal
```

手段：

- 路由表字符串常量（`path:`、`routes = [`、`createBrowserRouter`）。
- 前端"权限判断"的接口（`isAdmin`、`canApprove`）→ 对应后端接口的授权测试。
- 被注释/已下线但仍可访问的接口（版本切换 `v1`/`v2`）。
- GraphQL 的 query 片段 → 直接还原 schema 与字段。

## 三、密钥与配置泄漏

常见位置：

- 硬编码在该打包产物里的第三方 key（Mapbox、Google Maps、Stripe `pk_`、Firebase config）。
- `.env` 被误打包（`process.env.X` 被内联后的字面量）。
- 内网地址：`10.*`、`192.168.*`、`*.internal`、`*.corp`、`*.local`。
- 调试开关：`debug=true`、`mockApi`、`devToken`。
- 遗留账号：`test@`、`admin@` 与对应口令（很少见但存在）。

> 密钥要**验证其有效性与权限**再定性：只读的公开 key（如 Maps key）通常只是配置问题；能写数据或调用管理 API 的才是高危。

## 四、其他线索

- `robots.txt` / `sitemap.xml` 中的隐藏路径。
- `/.well-known/`（openid-configuration → OAuth 端点；security.txt → 联系人）。
- 错误堆栈里的框架版本（旧版前端库 → 已知 gadget，见 `../Browser-Side-Bypass/CSP-Bypass.md`）。
- `postMessage` 监听器（`addEventListener("message"`）与 `origin` 校验缺失。
- DOM sink：`innerHTML`、`eval`、`Function(`、`srcdoc`、`document.write`。

## 五、Git 与代码托管泄漏

- `/.git/HEAD`、`/.git/config`、`/wp-content/*.bak`、`*.swp`、`*.orig`。
- 公开仓库：`github.com/search`（组织名 + `password`/`secret`）、GitHub Dork、`gitleaks`/`trufflehog`。
- 提交历史中的已删除密钥（仍可检出）。
- CI 配置文件中的明文变量与 OIDC 配置（见 `../Cloud-Container-Attack/CI-CD-Supply-Chain.md`）。

## 六、验证（最小证据）

1. 给出**文件与代码行**（或 sourcemap 还原后的原始位置）。
2. 接口：请求与响应原文，说明是否需要鉴权、返回了什么敏感字段。
3. 密钥：给出**最小有效性证明**（如调用只读接口返回账号信息；不执行破坏性操作）。
4. 内网域名：仅作为线索记录，不直接访问目标内网。

## 七、常见误报

- 前端可见的接口但后端已下线（404/410）。
- 密钥已失效（返回 401/403）→ 记 `revoked`，不要记高危。
- 公共可公开的 key（`pk_`、公开地图 key）——定性为配置卫生问题。
- 前端权限判断（隐藏按钮）但后端正确校验。

## 八、修复

- 构建时剔除 sourcemap 或限制访问；不要把 `.env` 内联进产物。
- 前端不放置任何可写/管理级密钥；密钥由后端代理或短期令牌。
- 后端对所有接口做**独立**鉴权（不依赖前端隐藏）。
- Service Worker 缓存策略避免缓存私有响应。

## 参考

- OWASP WSTG-CONF、OWASP ASVS V14（配置）
- `katana`、`gau`、`trufflehog`、`gitleaks`、`unwebpack-sourcemap`
