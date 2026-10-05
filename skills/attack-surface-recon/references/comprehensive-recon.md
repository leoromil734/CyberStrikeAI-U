# 全面侦察、资产分级与前端接口提取

用于用户明确要求“全面、完整、深度、包含品牌子资产”的 Web/API 评估。目标不是堆工具调用，而是让独立来源互相补缺，并用覆盖账本证明哪些面已经处理。

## 1. 资产来源账本

| 类别 | Deep 最小动作 | 记录字段 |
| --- | --- | --- |
| 被动子域 | `subfinder` + `oneforall`；可用时补 `amass` | raw、去重后、相对前序增量、错误 |
| 证书/历史 | CT、历史 URL、DNS 历史或公开搜索至少一类 | 来源、首次/末次观察、候选域名 |
| 品牌关联 | 官网链接、证书 SAN、注册主体、favicon/标题、共享分析标识，以及范围内页面/JS/接口带出的下游 host | 关联依据、置信度；有关联证据的 probable 下游进入浅测，仅名称相似或参股主体只记录 |
| 首步测绘（必调） | `fofa_search` 实际调用，所有线上范围必需；其他引擎仅补缺 | query、范围、时间、raw/unique/incremental、执行/原件、失败与替代证据 |
| DNS 验证 | `dnsx` + 随机标签通配基线 | A/AAAA/CNAME、解析链、wildcard |

初始收集先 FOFA，再补子域/DNS/HTTP；锁面只查当前host/IP、自由跳只查当前一种子，详细规则见根路径 `skills/recon-osint-playbook/references/fofa-first.md`。上游本轮同范围真实证据可复用，离线审阅不新开查询。缺依赖、额度、网络或平台限制时写真实 `blocked` 并补异构来源；FOFA不能因此写covered或N/A。成功零结果保存原件与零计数，不等于不存在资产。

## 2. 资产价值评分

对去重存活资产按以下维度各记 `0–3`，保留理由而非只给总分：

```text
value = business_criticality + auth_or_admin + data_sensitivity
      + input_capability + boundary_reach + exposure_confidence
```

优先级示例：管理/控制台、API 网关、账号与支付、上传/导入/回调、代理或远程访问服务、高权限异步任务。共享 IP 或默认证书只增加关联置信度，不单独作为入池依据。

**疑似下游入池**：已确认范围内页面、JS、接口响应、跳转参数或证书 SAN 带出的 host（`baseURL`/`apiHost`、回调、`redirect_uri`、登录后业务 host、同证书/同主体业务子域）记为 probable。先确认它在任务允许的品牌关联扩展边界内，再做存活确认、指纹和入口枚举，不因归属未最终坐实而跳过。固定 URL/资产清单任务中的范围外候选只记录，不主动测。排除：仅凭名称相似或「获投资/关联企业」名录、CDN/图床/第三方库域、已坐实参股或非全资主体。

### 2.1 解析 IP 与品牌扩测（必须分类）

- 每个 A/AAAA 地址记录 `ip, source_hosts, scope_basis, cname_chain, asn/provider, cdn_status, classification_evidence, service_status, expansion_status`；`cdn_status` 只用 `confirmed/non-cdn/unknown`，保留判断时间和来源。
- Cloudflare/Akamai 等只有结合解析链、可信公开边缘地址段或 CDN 指纹证明**当前 IP 是边缘节点**，才记 `confirmed`，排除该裸 IP 的端口/同 IP 品牌扩测。域名经 CDN 代理不排除域名业务、JS/API 或另外发现的授权源站。单个 `cf-ray` 只能证明请求链路有边缘层，不能据此把历史/源站 IP 全部排除。
- **Hetzner、OVH、AWS、Azure 等云/托管商不是 CDN 排除理由**；供应商 ASN 不等于边缘节点。任务范围内 `non-cdn` IP 必须作为独立资产做服务/重点端口、HTTP/证书/虚拟主机入口补充与品牌关联检索，不仅测原域名的 80/443。
- `unknown` 用 CNAME、公开网段/测绘、证书与服务证据继续分类；无法确认时留 `gap/blocked`，不默认为 CDN，不直接扫身份不明或未授权的 IP。
- 同 IP/同 ASN 不自动证明品牌归属；旁站先被动关联，只有明确任务范围与品牌/主体证据支持的 host 才主动验证。共享 IP 上仅探测经范围确认的服务/虚拟主机；IP 级端口扫描须 IP 本身在范围内，不扩供应商网段、不扫描无关租户。
- 去重按 IP + 服务端口 + 虚拟主机/认证域保留映射；多个品牌域名共享源站可以复用端口发现，不能用一个域名的负结果替代其它业务/身份边界。每 IP 的分类及范围内扩测必须有终态与证据。


## 3. 服务与入口账本

- 先对主机批量 `httpx` 和重点端口发现，再按资产价值选择 `nmap -sCV` 或长尾端口策略。
- 对每个 Web 资产记录真实状态、标题、hash、长度、重定向、技术栈和边缘层；随机不存在路径建立 catch-all/SPA shell 基线。
- 状态码相同但 body hash、标题或最终路由一致的 SPA fallback 不计为多个有效入口。
- 非 HTTP 服务记录协议证据、认证要求和暴露风险；未验证弱口令时不得把“端口开放”升级成认证缺陷。
- 范围内 Web/管理面、SSH、数据库、SMTP/IMAP/POP3 密码入口交接 `credential-stuffing` 做一轮简单弱口令，不能仅以“不爆破”跳过。每账号≤8、每入口≤5账号/40组合/5分钟，并发1、间隔≥3秒；命中/验证码/MFA/锁定/429/异常即停。产品默认对和简单口令共用预算；协议无密码能力须证据 N/A，缺身份或策略阻断记 blocked。逐项保存实际次数、字典/hash、停止原因；未测不能记 covered。字典与详细方法见根路径 `skills/credential-stuffing/references/lite-wordlists.md`。


### 3.1 目录、文件与扩展名覆盖

本节适用于任务范围内的 Web 攻击面发现，不把离线审阅、非 HTTP 目标或单接口验证扩展成全站扫描。

- **分工与触发**：目录、文件和扩展名枚举优先 `dirsearch`；参数、虚拟主机和自定义请求模糊测试优先 `ffuf`。爬取/JS 之外的未链接路径尚未覆盖，或发现需继续枚举的目录时，必须执行有界目录发现，或记录具体 `blocked`/`not-applicable` 理由及证据。仅爬取/JS 提取不能证明未链接目录和文件已覆盖。
- **证据复用**：同一 origin（协议/主机/端口）、路径范围、认证态、字典/扩展名及过滤条件已有充分且仍有效的扫描证据时，引用原 `execution_id`/工件并说明适用范围，可复用 `ffuf` 等价目录扫描，不为调用次数重复运行 `dirsearch`。不同部署、认证态、新目录或未完成候选集不能继承覆盖，只补实际缺口。
- **基线与过滤**：先以同一认证态请求 2–3 个随机不存在路径，保存状态、长度、正文特征/hash 与重定向。确认统一页后按实测 `exclude_sizes`、`exclude_text`、`exclude_regex` 或 `exclude_response` 过滤；后者是已验证不存在页面的站内路径，不是本地文件。不猜过滤值，不一概排除 401/403/405/500，不能用 SPA shell 批量否定 JS 真实接口。
- **有界执行**：选定小字典与技术栈相关扩展名，明确并发、速率、单请求超时、总时限和递归深度。`dirsearch` 默认 20 线程、50 请求/秒、单请求 10 秒、总时限 300 秒、不递归；需要递归时深度默认 2。用户更严预算优先；429、持续挑战或健康异常停止该轮。`extensions` 默认仅替换 `%EXT%`，没有占位符的小字典确需补扩展名时才显式 `force_extensions`。首选工具不可用时，在角色工具范围内用等价工具并记录原因。
- **覆盖记录**：使用 `recon/source/{assessment_id}/{tool}/{target_id}`（未绑定项目时在交付中列出同等记录），保留目标/路径/认证态、实际字典路径及 hash/候选数、扩展名、基线、过滤、预算、实际进度、停止原因、原始结果和执行引用。`covered` 只表示完成所选候选集，不表示所有目录存在性已穷尽；完整跑完且零新增可以是该范围负结果。
- **未完成与交接**：超时、限流、中断或缺依赖导致候选集未完成时留 `gap/blocked` 和剩余范围，即使进程返回成功也不能写全覆盖。`not-applicable` 必须有任务范围或协议/能力证据，已有很多接口、单次 404、统一页面不构成理由。先验证已有就绪候选，再补独立目录缺口；续跑只补剩余候选，不重复相同批次。缺口复核前，每个适用 Web 范围均须有执行、复用或具体阻断/不适用证据。

## 4. JS 与 API 清单

1. 从入口 HTML、manifest、preload/prefetch、动态 import、worker/service worker 收集所有脚本，维护 `queued → fetched → analyzed → references-expanded` 状态；递归跟进新增 chunk，直到队列为空或每个失败项有原始 blocked 证据。
2. 保存 URL、hash、来源页面、抓取状态；探测同名 `.map`，解析 source map/sourceRoot/sourcesContent，但不把未下载文件写成已审计。
3. **必须双通道**：先用 `katana`/`gau` 发现范围内 JS URL，再按授权下载保存源码（保留 URL、抓取状态和 hash）。第一路用 `jsluice` 静态分析这些本地文件，传 `file` 与实际 `source_url`；后者仅为元数据，不发请求。读取绑定执行目录中的 `manifest.json`、`source.js`、`raw.jsonl` 和 `urls.jsonl`/`secrets.jsonl` 原件，stdout 计数不是端点清单。保留 method、relativeURL、参数名及 EXPR 占位，不按 JS 目录猜运行时 baseURL。第二路实际用 `grep/rg` 检索同批原始 JS/chunk/worker 与 source map 提取出的 `sourcesContent` 文件。第二路不是工具故障时才做；工具零结果也必须执行。source map 的 `.ts/.tsx/.jsx` 原源码与 HTML 内联脚本保存为本地源码后同样检索，不能只读 JSON 外壳。
   `jsluice` 不执行 JS、不爬取、不验证可达性；secrets 始终 tentative，原始秘密值仅在受限原件，不直接 `record_vulnerability`。旧 `jsapiscan` 默认停用、保留显式兼容和历史 CSV 读入，不自动回退在线爬取。缺依赖/原件/受界限截断时留 gap/blocked。
4. 命令检索覆盖绝对 HTTP/WebSocket URL、相对路径（不限 `/api/`）、fetch/axios/XHR/GraphQL、共享客户端的 `baseURL/urlPrefix` 与调用点、模板字符串/拼接/转义和环境配置。逐个展开方法/前缀/参数，未能解析的动态项保留 `gap/blocked` 与具体表达式，不把 `MainClient/*` 当完整端点。
5. 对两路原件分别记录命令、源文件清单/hash、raw/unique/incremental 和错误；合并去重保留所有来源/调用上下文。不得对**输入源码**使用 `head` 或只抽代表 chunk 以宣称全覆盖；可以对输出做短预览，但完整命中保存工件。
6. 解混淆只服务于恢复路由与数据流；保留变换方法和输入 hash。正则和静态工具都无法保证完全恢复动态接口；字符串只是 tentative，结合必要的运行时调用确认方法、参数与可达性。
7. 端点表至少包含 `host, method, path, params, auth_hint, source_js, extraction_sources, runtime_status, value_reason`，并 upsert 为 `recon/endpoint/*`（字段见 `recon-fact-schema.md`）。不要只报告“发现 MainClient 路由表”而不展开每个方法和参数。

### 源码命令检索示例（文件目录必须来自已抓取清单）

下面是候选提取和调用上下文两步；它们补充静态工具，不替代语义/运行时验证。GNU grep 返回 1 表示零匹配，可保存零计数；返回 2 才是执行失败，需要修正后重跑或记录 blocked。

```bash
# js_dir 包含全部已下载脚本、内联脚本和 source map 展开的源码。
js_dir=/path/to/assessment/js-sources
cat > js-url-patterns.txt <<'REGEX'
(https?|wss?)://[^"'`[:space:]<>\\]+
["'`](/{1,2}|\./|\.\./)[[:alnum:]_$?&=./%:#{},+@~-]+["'`]
REGEX
# 保留文件名/行号；全部结果落盘，不把大 minified bundle 全塞进上下文。
grep -rnoHE --include='*.js' --include='*.mjs' --include='*.cjs' \
  --include='*.ts' --include='*.tsx' --include='*.jsx' \
  -f js-url-patterns.txt "$js_dir" > js-strings.raw.txt
# 捕获客户端/相对前缀/动态构造；再按命中位置读取上下文恢复真实请求。
grep -rnHE --include='*.js' --include='*.mjs' --include='*.cjs' \
  --include='*.ts' --include='*.tsx' --include='*.jsx' \
  '(fetch[[:space:]]*\(|axios|XMLHttpRequest|\.open[[:space:]]*\(|\.(get|post|put|patch|delete|request)[[:space:]]*\(|baseURL|apiHost|urlPrefix|WebSocket|graphql|import[[:space:]]*\()' \
  "$js_dir" > js-calls.raw.txt
```

可用 `rg -n -o` 对等替代，失败时改 Python/其它本地检索需保留理由，不能悄悄删掉第二路门禁。URL 字符串无匹配但有调用点时，应继续追前缀/变量/模板；只有两路实际执行并且动态缺口被处理或逐项 blocked 才闭合 JS 资源。


## 5. 认证态与业务流入口

若自助注册属于范围，按 `pentest-scan-deep` §4 的低成本 A/B 身份准备预算执行：最多新建两个受控测试账号、每个注册步骤一次提交、网络故障最多一次同条件重试、最多 5 分钟；验证码/滑块、费用、邀请/实名、人工审批、锁定/限流立即阻断该身份线，不磨挑战、不无限注册。保护用户现有账户，不登出/注销/吊销、不改密/改绑/触发找回；生命周期只登记未执行入口及原因。

匿名与认证态分别爬取并比较导航、API、对象字段和功能入口。测试完成后仅清理自己新建的测试数据；缺少第二身份只将依赖 A/B 的单元记为 `blocked`，不记安全、否定或 N/A，继续正常可达的匿名/单身份及其它独立单元。

## 6. 阶段账本与队列终态

全面任务维护一个可恢复的 `phase_ledger`，不能只维护自然语言待办：

```text
recon_sources  → asset_ranking → frontend_api → auth_workflows
              → risk_matrix   → gap_review

phase.status ∈ pending | active | passed | blocked
```

阶段通过条件：

| 阶段 | `passed` 的最低证据 |
| --- | --- |
| recon_sources | 强制工具与异构来源的状态、raw/unique/incremental 计数、DNS 通配基线 |
| asset_ranking | 所有确认范围内存活资产均有维度分与价值理由；每个解析 IP 有 CDN 分类/范围证据，范围内非 CDN IP 已独立扩测或具体 blocked |
| frontend_api | 资源队列无未处理项；全部已下载源码有工具 + grep/rg 两路证据与增量统计，动态项已闭合或 blocked；端点保留来源 JS；适用目录/文件覆盖有完成、复用或具体 blocked/N/A 证据（§3.1） |
| auth_workflows | 注册/登录入口均分类；允许时完成匿名/账号 A/可行账号 B；Web/SSH/数据库/邮件密码入口均有简单弱口令次数、停止原因与终态，或逐项证据阻断 |
| risk_matrix | 每个高价值端点有适用风险族，候选进入 confirmed/negated/blocked 终态 |
| gap_review | 无当前授权和工具能力内可执行的高价值 `gap/tentative` |

资源和端点也使用显式状态，避免“已提取”等同于“已测试”：

```text
resource: queued → fetched → analyzed → expanded
endpoint: discovered → extracted → baselined → risk-mapped → verified | negated | blocked
```

只要阶段仍为 `pending/active`，或队列中存在可执行项，本轮输出就是进度更新。协调者应继续路由，不能生成最终渗透总结。

## 7. 覆盖状态

每个矩阵单元只能是：

- `covered`：有工具/请求/文件证据和产出计数。
- `blocked`：有原始失败原因，且已尝试合理替代来源。
- `gap`：尚未处理；全面任务不得在仍有高价值 `gap` 时结案。
- `not-applicable`：有证据证明该面不存在或不在范围，不是主观判断。

最终交接同时输出资产价值排序、JS 资源清单、API 清单、身份状态、工具增量和 Remaining Gaps。