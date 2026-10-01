# 侦察 Fact 与端点表 Schema（P0 闸门）

全面/Deep 侦察与「信息收集」角色在交接或结案前，必须用稳定 `fact_key` 落库。协调者只认这些 key 前缀作为覆盖证据；自然语言“已全覆盖”无效。

## 1. fact_key 前缀

| 前缀 | 用途 | 同一 key 语义 |
| --- | --- | --- |
| `recon/source/{tool}/{target_slug}` | 单一来源/工具一轮结果 | 覆盖更新；换目标换 slug |
| `recon/phase/{phase}` | phase_ledger 阶段状态 | phase ∈ recon_sources, asset_ranking, frontend_api, auth_workflows, risk_matrix, gap_review |
| `recon/asset/{asset_slug}` | 确认范围内资产 | 含价值分与归属置信度 |
| `recon/js/{resource_slug}` | 前端资源队列项 | 状态 queued→fetched→analyzed→expanded |
| `recon/endpoint/{host_slug}/{endpoint_id}` | 逐端点 API/入口 | 方法前缀 + 完整 origin/method/大小写保真 path 的稳定摘要；不可小写或截断路径生成唯一标识 |

`target_slug` / `host_slug` 只作可读前缀，不能代替唯一 origin；body 保留协议、主机与有效端口。绑定项目的全面任务以 `pentest-blackboard/references/coverage-contract.md` 的 v2 结构为准：先建 assessment manifest，本轮事实带 assessment_id，端点明确关联 risk_units；旧结构用于兼容笔记，不冒充 v2 覆盖。

## 2. `recon/source/*` body 必填字段

写入 `upsert_project_fact` 时 body 须可解析出下列键（Markdown 列表或 YAML 均可）：

```text
status: covered | blocked | gap | not-applicable
raw: <整数，工具原始行数/命中数>
unique: <整数，去重后>
incremental: <整数，相对前序来源新增>
error: <失败原文；成功可写 none>
alt_tried: <已尝试替代来源列表；无则 []>
tool: <工具名>
target: <根域/主机/URL>
```

summary 示例：

```text
subfinder example.com: raw=120 unique=98 incremental=98 status=covered
```

规则：

- 工具成功但增量为 0 → `status=covered`，`incremental=0`（不是 gap）。
- 工具失败/未装 → `status=blocked`，`error` 非空，且 `alt_tried` 至少一项或说明无可用替代。
- 尚未执行 → 不得写 covered；保持 gap 或不写该 key。

### FOFA 必经来源

初始线上信息收集先实际调用 `fofa_search`；所有范围（含固定URL/IP/资产清单）都需本轮FOFA来源，其他引擎只能补缺。规则见根路径 `skills/recon-osint-playbook/references/fofa-first.md`。完整query、目标范围、采集时间和本次执行/原件在evidence中关联；raw按实际返回条目计，不把远端total写成已获取量。

成功零结果用covered与零计数；未调用为gap。缺工具/key/配额、权限/网络/限流失败用blocked并附原始原因/替代证据，不伪造执行，不用not-applicable跳过，不写“FOFA已完成”。绑定v2轮次时用 `recon/source/{assessment_id}/fofa_search/{target_id}`；旧key只兼容笔记。锁面不出圈，上游本轮同范围真实证据可复用。

## 3. `recon/endpoint/*` body 必填字段

```text
host: <主机>
method: <GET|POST|...>
path: </api/...>
params: <参数名列表或 none>
auth_hint: <anonymous|cookie|bearer|unknown>
source_js: <来源 JS URL 或 local path；HTML 入口可写 page>
runtime_status: discovered | extracted | baselined | risk-mapped | verified | negated | blocked
value_reason: <为何进入 Top-N 或保留>
evidence: <状态码/长度/hash 或 blocked 原因>
```

SPA catch-all 只能把**猜测路径**标 negated，不能批量把同 shell 的 JS 真实接口标 negated。

## 4. `recon/phase/*` body

```text
status: pending | active | passed | blocked
evidence: <覆盖对象 + 计数 + 证据位置>
blockers: <原始错误与替代路径；无则 none>
```

所有线上范围交接前先存在本轮 `fofa_search` 来源（covered或有证据blocked，不能N/A替代）；Deep根域的 `recon/phase/recon_sources` 标 `passed` 前还需：

- `recon/source/subfinder/*`（covered 或 blocked+alt）
- `recon/source/oneforall/*` 或等价异构子域来源的 blocked 记录
- `recon/source/dnsx/*`（covered 或 blocked+alt）

且 `frontend_api` 标 `passed` 前：资源队列无 `queued/fetched` 未处理项，端点均有 `runtime_status`。

## 5. 信息收集角色退出门禁

交付前自检：

1. 输出 **Source Coverage** 表（与 `recon/source/*` 一致）。
2. 绑定项目时已 upsert 上述 fact；未绑定时在交付末尾给出待落库条目。
3. **禁止** `record_vulnerability`；nuclei/组件命中只写 `tentative` fact 或 `note/*`。
4. 缺 Source Coverage 或 Deep 缺强制 source fact → 本轮只能算进度，不得结案话术。