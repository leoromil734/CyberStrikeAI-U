# 全面侦察、资产分级与前端接口提取

用于用户明确要求“全面、完整、深度、包含品牌子资产”的 Web/API 评估。目标不是堆工具调用，而是让独立来源互相补缺，并用覆盖账本证明哪些面已经处理。

## 1. 资产来源账本

| 类别 | Deep 最小动作 | 记录字段 |
| --- | --- | --- |
| 被动子域 | `subfinder` + `oneforall`；可用时补 `amass` | raw、去重后、相对前序增量、错误 |
| 证书/历史 | CT、历史 URL、DNS 历史或公开搜索至少一类 | 来源、首次/末次观察、候选域名 |
| 品牌关联 | 官网链接、证书 SAN、注册主体、favicon/标题、共享分析标识 | 关联依据、置信度、是否获准主动测试 |
| 空间测绘 | FOFA/ZoomEye/Quake/Shodan/VirusTotal 中可用来源 | 查询、命中、与品牌/域名的关联证据 |
| DNS 验证 | `dnsx` + 随机标签通配基线 | A/AAAA/CNAME、解析链、wildcard |

同类工具可因缺依赖、额度、网络或平台限制而失败；失败写 `blocked` 并使用异构替代来源。只有工具成功但增量为 0 才能记录“无新增”，不能把空结果解释为不存在资产。

## 2. 资产价值评分

对去重存活资产按以下维度各记 `0–3`，保留理由而非只给总分：

```text
value = business_criticality + auth_or_admin + data_sensitivity
      + input_capability + boundary_reach + exposure_confidence
```

优先级示例：管理/控制台、API 网关、账号与支付、上传/导入/回调、代理或远程访问服务、高权限异步任务。共享 IP 或默认证书只增加关联置信度，不自动证明品牌归属或测试授权。

## 3. 服务与入口账本

- 先对主机批量 `httpx` 和重点端口发现，再按资产价值选择 `nmap -sCV` 或长尾端口策略。
- 对每个 Web 资产记录真实状态、标题、hash、长度、重定向、技术栈和边缘层；随机不存在路径建立 catch-all/SPA shell 基线。
- 状态码相同但 body hash、标题或最终路由一致的 SPA fallback 不计为多个有效入口。
- 非 HTTP 服务记录协议证据、认证要求和暴露风险；未验证弱口令时不得把“端口开放”升级成认证缺陷。

## 4. JS 与 API 清单

1. 从入口 HTML、manifest、preload/prefetch、动态 import、worker/service worker 收集所有脚本，维护 `queued → fetched → analyzed → references-expanded` 状态；递归跟进新增 chunk，直到队列为空或每个失败项有原始 blocked 证据。
2. 保存 URL、hash、来源页面、抓取状态；探测同名 `.map`，解析 source map/sourceRoot/sourcesContent，但不把未下载文件写成已审计。
3. 逐文件提取 API base URL、HTTP method/path、query/body/header 字段、WebSocket、GraphQL、上传、下载、回调、认证/刷新、feature flag 和环境名；对共享客户端或路由前缀展开每个调用点，不能只保留 `MainClient/*` 等模块名。
4. 解混淆只服务于恢复路由与数据流；保留变换方法和输入 hash。字符串只是 tentative，必须对目标侧可达性做去重验证。
5. 端点表至少包含 `host, method, path, params, auth_hint, source_js, runtime_status, value_reason`。不要只报告“发现 MainClient 路由表”而不展开每个方法和参数。

## 5. 认证态与业务流入口

若自助注册属于范围且不会触发付费、邀请滥用、短信/邮件轰炸或真实用户影响，可创建最少测试账号并记录注册、激活、登录、刷新、登出和找回流程。授权差分需要时创建两个独立测试主体和各自对象；验证码只能使用测试方实际收到的值，不绕过第三方或批量触发。

匿名与认证态分别爬取并比较导航、API、对象字段和功能入口。测试完成后按能力清理测试数据；无法注册、需要人工激活或缺少第二身份时记为 `blocked`，不得据此宣称授权安全。

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
| asset_ranking | 所有确认范围内存活资产均有维度分与价值理由 |
| frontend_api | 资源队列无未处理项；每个端点处于 `baselined/blocked` 并保留来源 JS |
| auth_workflows | 注册/登录入口均分类；允许时完成匿名/账号 A/可行账号 B，或记录逐项阻断 |
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