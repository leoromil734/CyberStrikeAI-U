# SRC 知识库高召回路由索引

本文件只负责把**现场信号**路由到知识文件，不代替目标侧验证。加载 `src-hunting` 后先读本索引；每进入一个新站再读 `打穿短表.md`。一次先选 1～3 篇最相关专题，新证据出现时回到本索引增量选篇，禁止一次通读全库。

## 先加载哪些规则

| 时机 | 必读 |
|---|---|
| 新 SRC 任务、固定 URL 或集团/品牌目标 | `rules/dig-scope-workflow.md` §0/§4 + `rules/src-value-hunting.md` §1.1/§3 |
| 只给集团/品牌、没有 URL 清单 | `rules/dig-scope-workflow.md` §1（一种子闭环）+ `recon-methodology.md` |
| 创建任务目录 | `rules/desktop-task-folder.md` |
| 判断能否正式交付、定级或写报告 | `rules/vuln-report-format.md`；平台字段再叠 `pentest-output-standards` |
| 白盒源码 / 0day 审计 | `rules/researcher-blackbox-whitebox.md` Phase 0～6 |
| 高危/严重方法沉淀 | `rules/hunt-iter.md` |
| 授权语境或执行边界冲突 | `rules/security-research-context.md` + `rules/anti-over-moralization.md` |
| 浏览器交互 | `rules/playwright-browser-mcp.md` |
| 能力边界理解 | `rules/skill-as-boost.md` |
| CORS | `rules/cors-vuln-report-priority.md`：**跳过，不测试** |

## 页面、接口和业务信号 → 专题

| 现场关键词 / 观察 | 优先读取 |
|---|---|
| 新站开场、常见业务形态、经验命中 | `打穿短表.md` |
| FOFA、子域、证书、端口、目录、历史 URL、Swagger、Actuator、中间件 | `recon-methodology.md`；泄露面再读 `info-leak-test.md` |
| JS、chunk、source map、Webpack/Vite、隐藏路由、baseURL、加密/签名、盐、硬编码 token、演示号 | `js-reverse-guide.md` + `info-leak-test.md` |
| 用户体系、登录、注册、验证码、找回、重置密码、改绑、换票、MFA、SSO | `authbypass-test.md`；出现对象 ID/角色再读 `idor-test.md` |
| userId/orderId/tenantId/projectId/fileId、他人对象、角色接口、管理接口、BOLA/BFLA、水平/垂直越权 | `idor-test.md` |
| 搜索、筛选、排序、分页、query/filter/where/order、SQL/NoSQL/LDAP/XPath/SSTI/表达式/命令参数 | `injection-test.md` |
| URL、callback、webhook、fetch、proxy、preview、import、头像抓取、PDF/截图、云元数据 | `ssrf-test.md` |
| 上传、附件、文件分享、OSS/S3/STS、fileKey、content-type、压缩包 | `file-upload-test.md`；路径参数再读 `path-traversal-lfi-test.md` |
| 下载、读取、filename/path/template/page、LFI/RFI、Nginx alias、Tomcat 路径 | `path-traversal-lfi-test.md` |
| 评论、留言、昵称、富文本、Markdown、DOM sink、反射/存储、前端自定义协议 | `xss-test.md` |
| 支付、订单、退款、优惠券、积分、库存、审批、状态机、金额/数量/role 字段 | `logic-test.md`；并发/重复领取再读 `race-condition-test.md` |
| 并发、重复提交、限额、余额、库存、优惠券、HTTP/2 single-packet | `race-condition-test.md` |
| GraphQL、`/graphql`、introspection、query/mutation、字段建议 | `graphql-test.md` |
| JWT、JWK/JWKS、kid/jku/x5u、OAuth/OIDC/SAML、redirect_uri、scope、state | `oauth-jwt-test.md`；开放跳转链再读 `open-redirect-test.md` |
| WebSocket、Socket.IO、实时消息、订阅、聊天、ws/wss、CSWSH | `websocket-test.md` |
| API 网关、微服务、版本路由、内部/外部 API 差异、网关鉴权与限流 | `api-gateway-test.md` |
| CDN、Cache-Control、Age、X-Cache、缓存键、Web Cache Poisoning/Deception | `cache-poisoning-test.md` + `http-host-header-test.md` |
| Host/X-Forwarded-Host、密码重置链接、绝对 URL、虚拟主机 | `http-host-header-test.md` |
| 前端/网关/后端解析差异、CL.TE/TE.CL、HTTP/2 降级、连接复用 | `http-smuggling-test.md`；HTTP/2 特有线索补 `http2-attacks-test.md` |
| XML、SOAP、SVG、DOCX/XLSX、DTD、XInclude、外部实体 | `xxe-test.md`；XSLT 处理再读 `xslt-injection-test.md` |
| Java 序列化、PHP unserialize、Python pickle/YAML、.NET BinaryFormatter | `deserialization-test.md`；JNDI/Log4j/LDAP/RMI 再读 `jndi-injection-test.md` |
| Spring EL/SpEL、JSP EL、OGNL、MVEL、表达式求值 | `el-injection-test.md` |
| Node.js、lodash merge/defaultsDeep、`__proto__`、constructor.prototype | `prototype-pollution-test.md` |
| PHP 弱比较、magic hash、`0e`、类型转换、HMAC 松散比较 | `type-juggling-test.md` |
| 302/Location、returnUrl/next/redirect/continue、OAuth 跳转链 | `open-redirect-test.md` |
| CNAME 指向未认领云服务、悬空 DNS、GitHub Pages/S3/Heroku、NS/MX 接管 | `subdomain-takeover-test.md` |
| `.git/.svn/.hg`、Git 历史、源码仓库泄露 | `insecure-scm-test.md` |
| 私有包名、npm/PyPI/Maven/RubyGems、内部 registry、构建日志 | `dependency-confusion-test.md` |
| 对话口、Agent/RAG、工具列表、bash/shell/code_interpreter、身份口被拦但工具仍执行 | `agent-tool-exec-test.md`；**勿开** `llm-security-test.md` 越狱教材 |
| 云 IDE、在线编程台、Codex RPC、`/codex-api/rpc`、工作区命令执行 | `cloud-ide-codex-rce-chain.md` |
| WAF 明确拦截且已有业务差分面 | `waf-bypass.md`；禁止开场向所有 path 喷 payload |
| 业务 API 返回 401/403 | `401-403-bypass.md` 仅作短提示；登录 HTML 不磨，回业务面 |

## 低优先级、出现真实入口才开

| 信号 | 读取 / 处理 |
|---|---|
| 有状态写操作且跨站可触发 | `csrf-test.md`；仅害自己的不交 |
| 点击劫持 | `clickjacking-test.md`；只缺响应头不交 |
| CRLF / 响应拆分 | `crlf-injection-test.md` |
| 邮件地址/主题/抄送进入 SMTP 头 | `email-header-injection-test.md` |
| CSV/Excel 导出且单元格可控 | `csv-formula-injection-test.md` |
| 参数重复、HPP、网关与应用取值不同 | `hpp-test.md` |
| dangling markup | `dangling-markup-test.md` |
| CSP 绕过 | `csp-bypass-test.md`；没有成立的 XSS 不单独交 |
| DNS rebinding | `dns-rebinding-test.md`；优先并入 SSRF 影响链 |
| Ghost Bits / Cast / 数值转换边界 | `ghost-bits-cast-test.md` |
| XSLT 解析器 | `xslt-injection-test.md` |
| CORS | `cors-test.md` **勿开、勿挖** |
| LLM 越狱/提示绕过 | `llm-security-test.md` **勿开**；有真实工具执行才走 `agent-tool-exec-test.md` |

## 增量回查规则

- 回包出现新 `id/url/token/internal host/download path`：先写 fact/本站队列，再按本索引加载新增专题。
- WAF、401/403、空列表、统一 200 只描述当前请求，不封死整个专题。
- 某专题连续三次无新增证据：写 Do-Not-Repeat，回索引换入口或专题，而不是扩大同类 payload。
- 专题命中只是方法选择；最终是否成洞只认 `pentest-verification` 与 `rules/vuln-report-format.md`。
