# IaC source/state/plan 证据工作流

仅在具体 Terraform/Terragrunt source、tfstate、plan或已核验backend/workspace对象时触发；文件名/公开bucket域名不是暴露确认。SRC先使用 `src-hunting`。

1. 对每份产物记录来源、哈希/时间、commit、workspace、backend对象key、lineage/serial和解析格式；state是历史快照，不视为实时部署事实。
2. 从source解析provider/module版本、变量来源和backend；不执行terraform init/plan/refresh，不下载模块。已有plan JSON与raw state/schema可能不同，分开处理。
3. 将资源地址 → 实例索引 → 属性路径 → sensitive标记 → 预期访问主体关联；比较source意图、plan变更、state快照与授权实时只读数据，不能只grep密码就confirmed。
4. backend读权只对已知授权对象进行单变量身份对照，保留owner允许与非owner拒绝基线；署名下载URL本身含授权，不当作匿名公开链接。
5. 只读取最少样本并脱敏；秘密在受控state中可能是正常存储，额外权限要证明不获准主体可读敏感字段或资源。历史secret无需猜可用，不登录外部系统验证。
6. 无实时权限则结论限定为静态配置/历史快照候选；无安全解析器则blocked。禁止apply/destroy/import/state修改、backend写/锁操作及远程动态data source执行。

工具：`checkov`/`terrascan`/`trivy` 在当前注册、已有依赖、离线配置成立时审阅提供的本地目录；先核对参数，不假设包装器支持全部CLI子命令。`http-framework-test`可有限验证已授权HTTP backend。`exec`只使用已具备的受控本地解析器，禁止运行时安装。

记录：artifact出处/时间/格式、主体、workspace/key、资源地址/属性路径、基线与未授权对照、目标侧读取日志/对象版本、现网映射缺口、反证、敏感值处理；不得以扫描severity替代项目quality。

完整知识：[IaC-State-Plan-Evidence](../../../knowledge_base/DevOps-Security/IaC-State-Plan-Evidence.md)。
改编日期：2026-10-01。完整许可：[`docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt`](../../../docs/knowledge-skill-integration/licenses/Dark-Moon-GPL-3.0.txt)。作者身份与授权仅记录用户自述，不从GPL通用文本推定，也不据此重许可第三方素材。
来源：`others/Dark-Moon/conf/agents/terraform.md`，提交 `cb0d9b8`，原 GPLv3；本文 GPL-3.0-only。用户2026-10-01自述作者授权自有内容改编；第三方许可保留，不改根LICENSE。
官方参考：https://developer.hashicorp.com/terraform/language/state/sensitive-data ；https://developer.hashicorp.com/terraform/internals/json-format ；https://terragrunt.gruntwork.io/docs/reference/hcl/blocks/ 。
