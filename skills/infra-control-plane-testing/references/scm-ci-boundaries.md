# SCM/CI 信任边界工作流

仅在范围内具体 GitHub/GitLab 仓库、Jenkins job、提供的token或已授权流水线配置时触发；公开代码可先做本地产物审阅，不推定API写授权。SRC 先读 `src-hunting`，不全量加载领域库。

1. 记录 token 种类、主体、仓库/项目/组织、实际权限和有效期；GitHub scope 响应头不覆盖所有令牌类型，不将 /user 失败等同无权限。
2. 画出不可信输入/代码 commit → checkout/build → job 权限 → secret/environment/runner → 制品发布；区分拉取请求来源与实际运行代码来源。
3. GitHub 核对 pull_request_target/workflow_run 的 checkout ref、受信任 gate、GITHUB_TOKEN job权限、environment审批；OIDC核对 issuer/audience/subject 与下游 role trust。
4. GitLab 核对 protected ref、变量保护/掩码、fork/MR pipeline上下文与 CI_JOB_TOKEN allowlist；Jenkins 核对 folder/job/node/credential scope，受信任脚本配置权与读取权分开。
5. 默认静态/只读验证；实际运行只能用另行批准的隔离测试 job 和无效标记，关联 commit、run ID、审批/runner审计。无下游权限证据的宽OIDC配置是候选，不是接管。
6. Maintainer正常执行pipeline、Admin使用自己授权凭据、列表secret名称不等于读值；masked变量不等于隔离。禁止外传秘密、改真实workflow、创建长期token或触发生产部署。

工具：仓库启用定义 `http-framework-test`，仅在当前会话已注册且依赖可用时用于有限元数据对照；已有 `checkov`/`trivy` 等离线分析只产生候选。`exec` 不意味着 gh/glab/jenkins CLI 或依赖可用，禁止安装或联网拉全历史。缺低权限身份/安全job则 tentative 或 blocked。

记录：起始权限、代码来源/ref、信任条件、token/job/env/runner/object、基线/对照、run与目标审计、新增权限、反例及未做动态/持久化验证。

完整知识：[SCM-CI-Trust-Boundaries](../../../knowledge_base/DevOps-Security/SCM-CI-Trust-Boundaries.md)。
改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
来源：`others/Dark-Moon/conf/agents/{github,gitlab,jenkins}.md`，提交 `cb0d9b8`，原 GPLv3；本文 GPL-3.0-only。用户 2026-10-01 自述作者授权自有内容改编，第三方许可保留，根 LICENSE 不变。
官方参考：https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions ；https://docs.gitlab.com/ci/jobs/ci_job_token/ ；https://www.jenkins.io/doc/book/security/ 。
