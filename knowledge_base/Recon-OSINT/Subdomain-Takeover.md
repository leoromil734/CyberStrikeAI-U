# 子域与域接管（Takeover）

> 接管成立的条件是"**悬空引用 + 第三方可注册**"。只看到 404/CNAME 不等于可接管，必须实际证明能控制解析目标。

## 一、子域接管

典型场景：CNAME 指向已释放的第三方服务账号（Heroku、GitHub Pages、S3、Azure、Netlify、Vercel、Fastly、Shopify、Zendesk…）。

```text
sub.example.com  CNAME  something.herokuapp.com   ← 该 heroku 应用已删除
```

流程：

1. 枚举 CNAME/NS/MX 目标（`subfinder` + `dnsx -cname`，或 `nuclei -t takeovers`）。
2. 对目标服务查询**"不可用"特征响应**（各家错误页字符串不同，如 "No such app"、"There isn't a GitHub Pages site here"）。
3. 在对应平台尝试注册该名称（**仅在授权范围内且不得实际占用生产域名**；通常以"可注册"证据替代）。
4. 影响评估：该子域能否读取 Cookie（`Domain=.example.com` 的 Cookie 会发送给子域）、是否在白名单（CORS/redirect_uri/SPF）、是否被 CDN 缓存。

高影响组合：

- 子域在 `script-src`/`connect-src` 白名单 → CSP 失效。
- 子域在 CORS `Access-Control-Allow-Origin` 白名单 → 跨域读数据。
- 子域在 OAuth `redirect_uri` 白名单 → 令牌窃取。
- 子域是 SPF 的 `include` → 可发可信邮件。

## 二、域接管

组织放弃某域名但仍在使用（邮件、链接、品牌）→ 注册该域即可：

- 邮件：注册后即可收信（密码重置、邀请链接）。
- 链接：站点内引用该域的 JS/CSS → 供应链 XSS。
- 品牌：冒充官方域实施钓鱼。

发现途径：反向 whois、WHOIS 到期监控、页面死链、历史证书。

## 三、SSRF 场景下的 DNS 接管

SSRF 校验"域名必须解析到公网"，而该域名的 DNS 由攻击者控制时，可用 **DNS rebinding** 先返回公网 IP 通过校验、再返回内网 IP（TTL=0）。见 `../SSRF/SSRF-Bypass-Techniques.md`。

## 四、"被动接管"（IP 复用）

悬空的 A 记录在云厂商重新分配该 IP 后变为可达（研究演示了"开一台实例并关联被动 DNS"的流程）。属于同一类问题的变体，测试同样需要授权。

## 五、验证（最小证据）

1. 引用关系：`dig`/`dnsx` 输出的 CNAME 链。
2. 目标服务的"未注册/已释放"特征响应（原始响应片段）。
3. 归属证据：该服务上的资源名可注册（例如登录平台查询可用性，**不实际注册**，或以测试账号在授权子域上完成）。
4. 影响证据：Cookie 作用域、白名单引用位置（配置/响应头原文）。

## 六、常见误报

- CNAME 指向 CDN（属于共享基础设施，非可注册）。
- 404 但服务仍在运行（只是路径不存在）。
- 服务需要验证域名所有权（如尝试添加域时会要求 TXT 校验）→ 不可接管。
- 记录已被清理但被动 DNS 仍显示。

## 七、修复

- CI/CMDB 中登记所有 DNS 记录与负责人；删除资源前先摘除记录。
- 定期用 `nuclei -t http/takeovers`、`dnsx` 巡检团队域名。
- 对第三方服务使用需验证所有权的方式；避免长期不用的记录。
- Cookie 降低作用域（不用 `.example.com`），敏感白名单只含自有且受控域。
- SPF/DMARC 收紧（`-all`、`p=reject`）。

## 参考

- HackTricks：Domain/Subdomain takeover；Can I Take Over XYZ（服务特征表）
- OWASP WSTG-CONF（DNS 配置）
