# 云 IAM 提权路径

> 云环境的提权不是"内核漏洞"，而是**权限组合**：某个操作权限 + 某个对象的可控性 = 更高的权限。发现后的验证必须**只读**（如 `GetCallerIdentity`），不要实际创建长期凭据。

## 一、AWS：常见的提权"权限原子"

| 权限 | 利用方式 |
|---|---|
| `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` | 把自己的策略改成 `*` → 立即提权 |
| `iam:AttachUserPolicy` / `AttachGroupPolicy` / `AttachRolePolicy` | 挂上 `AdministratorAccess` |
| `iam:PutUserPolicy` / `PutRolePolicy` / `PutGroupPolicy` | 直接写入允许 `*` 的内联策略 |
| `iam:CreateAccessKey` | 为其他（更高权限）用户创建密钥 |
| `iam:CreateLoginProfile` / `UpdateLoginProfile` | 给任意用户设置控制台口令 |
| `iam:UpdateAssumeRolePolicy` | 改信任策略，让任何人可承担自己的角色 |
| `sts:AssumeRole` + 宽信任策略 | 横向到其他账号/角色 |
| `iam:PassRole` + `ec2:RunInstances` / `lambda:CreateFunction` / `glue`/`sagemaker` | 用高权限角色运行自己的代码 |
| `lambda:UpdateFunctionCode` + `InvokeFunction` | 把代码注入已挂高权角色的函数 |
| `ec2:RunInstances`（含 UserData） + 目标实例 profile | 在该角色下执行代码 |
| `ssm:SendCommand` / `ssm:StartSession` | 在实例上以实例角色执行命令 |
| `ecs:RegisterTaskDefinition` + `RunTask` + `PassRole` | 容器内以高权角色运行 |
| `codepipeline`/`codebuild` + `iam:PassRole` | 构建环境执行任意代码 |
| `secretsmanager:GetSecretValue` / `ssm:GetParameter*` | 直接读取凭据 |
| `kms:Decrypt` + 可访问的密文 | 解密受保护数据 |
| `s3:GetObject` 对配置桶 | 读取 `tfstate`、`.env`、备份 |

验证流程（只读）：

```bash
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <me>
aws iam list-user-policies --user-name <me>
aws iam simulate-principal-policy --policy-source-arn <arn> --action-names iam:CreatePolicyVersion
aws iam get-account-authorization-details       # 需要权限，可一次性看清全貌
```

> 具备 `iam:Get*`/`list*` 权限时，用 `enumerate-iam`、`Pacu`（`iam__enum_permissions`、`iam__privesc_scan`）快速建档。

## 二、Azure（Entra ID + ARM）

| 权限 | 利用方式 |
|---|---|
| `Microsoft.Authorization/roleAssignments/write` | 给自己/服务主体授予 Owner |
| `Microsoft.Authorization/*/write`（如 `roleDefinitions/write`） | 自定义角色含 `*` |
| 应用/服务主体的 `credentials` 写权限 | 添加密码/证书凭据 → 以该主体访问 |
| `AppRoleAssignment` 写 + 高权 API 权限 | 为恶意应用授予 Graph 权限（需管理员同意） |
| 订阅级 `Contributor` + `User Access Administrator` | 组合即等价 Owner |
| 托管身份（Managed Identity）可达 IMDS | 直接取令牌（见 `../SSRF/Cloud-Metadata-Access.md`） |
| Azure DevOps Service Connection | 通过 pipeline 使用连接凭据 |
| 存储账户 `listKeys` + 防火墙规则可改 | 读写数据面（绕过 RBAC） |
| `runAs`/`managedBy` 属性可写 | 借高权托管身份执行 |

工具：`roadtools`（`roadrecon`/`roadtx`）、`AzureHound`、`MicroBurst`。

## 三、GCP

| 权限 | 利用方式 |
|---|---|
| `iam.serviceAccountKeys.create` | 为高权 SA 生成长期密钥 |
| `iam.serviceAccounts.actAs` + `compute.instances.create` | 以该 SA 运行实例 |
| `iam.serviceAccounts.getAccessToken` | **直接取 SA 令牌**（最直接） |
| `iam.roles.update` / `setIamPolicy` | 给自己加 `roles/owner` |
| `cloudfunctions.deploy` / `run.services.update` | 在已有 SA 上部署代码 |
| GKE `container.clusters.getCredentials` | 拿集群凭据 |
| `compute.instances.setMetadata` + SA 无范围限制 | 在实例上执行（metadata SSH key） |
| Cloud Build / Cloud Scheduler | 以高权 SA 执行 |

工具：`gcloud`（`iam policy`、`auth print-access-token`）、`gcp_scanner`。

## 四、跨云与身份联邦

- **信任链**：CI OIDC → 云角色（`sts:AssumeRoleWithWebIdentity`）；若 subject 条件宽松（`repo:*` 或 `pull_request`），可被 PR 利用（见 `CI-CD-Supply-Chain.md`）。
- **SAML/OIDC 联邦**：IdP 侧管理员 → 云侧管理员（Golden SAML 见 `../Authentication-Bypass/SAML-XSW-Bypass.md`）。
- **外部账号**：`AWS Organization` 的 `AssumeRole` 跨账号、Azure B2B 访客、GCP 域委派。

## 五、验证（最小证据）

1. 身份与权限：`get-caller-identity`、`simulate-principal-policy` 或角色分配列表。
2. 提权可行性：证明"该权限组合存在"（例如 `list-attached-user-policies` 显示可附加策略），**不必实际执行提权**。
3. 若客户同意验证到底：用**临时、可回滚**的方式（如创建后立即删除一个测试角色），并在报告中标注时间与清理证据。
4. 影响：可访问的资源类型（不导出业务数据）。

## 六、常见误报

- 权限存在但被 SCP/权限边界（Permissions Boundary）限制。
- 条件（`Condition`）要求 MFA/来源 IP，实际无法满足。
- 服务控制策略（AWS Organizations SCP）、Azure Policy、GCP 组织策略阻断。
- 拿到的令牌只有只读范围（`ReadOnlyAccess`）。

## 七、修复

- 最小权限 + 权限边界；禁止 `iam:*`/`*:*` 通配。
- 禁止长期 Access Key；使用短期角色/OIDC；定期 `get-account-authorization-details` 巡检。
- 保护 `iam:PassRole`（限定可传递的角色）；限制 `iam:CreatePolicyVersion`。
- 云上开启 CloudTrail/GuardDuty/Defender for Cloud 并对高危 API 告警（`CreatePolicyVersion`、`AttachUserPolicy`、`CreateAccessKey`、`roleAssignments/write`）。
- 对 SA 密钥与托管身份做定期轮换与清点；GKE 限制 `actAs`。

## 参考

- Rhino Security Labs：AWS IAM Privilege Escalation 研究（原始 21 种路径 + 后续补充）
- HackTricks：云安全章节；Rhino `Pacu`、`enumerate-iam`
- roadtools、AzureHound、MicroBurst；GCP IAM 文档
- MITRE ATT&CK：T1078.004（Cloud Accounts）、T1098（Account Manipulation）
