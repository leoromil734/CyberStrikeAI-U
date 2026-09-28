# 剧本：云内横向（Cloud Lateral Movement）

> **起点**：一个云上受信身份 —— 可能来自 SSRF 拿到的 IMDS 凭据、容器内的 SA token、CI 的 OIDC 令牌，或一个泄漏的长期 AccessKey。
> **终点**：证明"这个入口能触达哪些跨服务/跨账号的数据与权限"。
> **原则**：先建图、再横向；只读优先；临时凭据先榨干；跨账户需另行授权。

## 阶段 0：范围与前置

| 项 | 要确认的内容 |
|---|---|
| 云与边界 | AWS / Azure / GCP / 阿里云 / 腾讯云 / 私有云；账号、订阅、项目 ID；区域 |
| 授权范围 | 是否包含跨账号/跨订阅；是否允许读取生产数据（通常只允许证明可达）；是否允许写操作 |
| 时间窗 | 临时凭据有效期、客户允许的测试时段、是否有蓝队值守 |
| 联系人 | 触发告警或造成影响的升级路径 |

**侦查阶段产出**（见 `../Recon-OSINT/Cloud-Asset-Enumeration.md`、`../Edge-Appliance-Attack/README.md`）：公网可达的管理面、对象存储、SaaS 集成、CI/CD、边界设备 —— 这些是"进入云内"的候选入口。

## 阶段 1：进入（拿到第一个受信身份）

按可得性选择路径，**每条路径的产出都是一个"身份"**（不是"一个漏洞"）：

| 路径 | 入口 | 产出 | 关联文档 |
|---|---|---|---|
| A. SSRF → 元数据 | URL/导入/webhook/文档渲染 | IMDS/托管标识的临时凭据 | `../SSRF/Cloud-Metadata-Access.md` |
| B. 应用 RCE | 命令注入/上传/反序列化 | 容器内的环境变量、挂载文件、SA token | `../Command-Injection/`、`../File-Upload/`、`../Deserialization/` |
| C. CI/CD | PR/issue 提示注入、工作流配置、依赖投毒 | OIDC 令牌或 Runner 的长期 secret | `../Cloud-Container-Attack/CI-CD-Supply-Chain.md` |
| D. 有效凭据 | 泄漏、喷洒、钓鱼会话 | 长期/短期云凭据 | `../Credential-Attack/`、`../Initial-Access/` |
| E. 边缘设备 | VPN/网关/虚拟化平台 | 内网访问 + 设备内的凭据库 | `../Edge-Appliance-Attack/README.md` |
| F. 容器/K8s | 应用漏洞进入任意 Pod | SA token、节点身份 | `../Cloud-Container-Attack/Kubernetes-Attack.md` |

**判据（进入成功）**：能以某个身份成功调用一次云 API，且返回的身份信息与我们持有的凭据一致。

**证据**：凭据来源（文件路径/请求/环境变量名）、一次成功的身份查询输出、凭据类型与有效期。

**常见失败与回退**：

- IMDSv2 强制 + hop limit=1 → 从容器内拿不到宿主机凭据，转 B/C/F 路径或寻找 ECS `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`。
- 环境变量里有 key 但已被撤销 → 先验证有效性，别在死凭据上花时间。
- CI 只能拿到只读 token → 评估该 token 能否读仓库 secret/制品（供应链侧价值可能更高）。

## 阶段 2：身份建图（Identity Mapping）

**子阶段 2.1：我是谁、我在哪**

```bash
aws sts get-caller-identity
aws configure list                      # 凭据来源与 profile
az account show; az account list -o table
gcloud auth list; gcloud config list
# 容器/编排位置
cat /proc/1/cgroup; ls -la /.dockerenv; env | grep -Ei 'aws_|azure_|google_|kube|serviceaccount'
# K8s SA
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

**子阶段 2.2：我有什么（只读枚举）**

```bash
aws iam list-attached-role-policies --role-name <role>
aws iam list-role-policies --role-name <role>
aws iam get-account-authorization-details        # 一次看清全貌（需权限）
aws iam simulate-principal-policy --policy-source-arn <arn> --action-names <a,b,c>
gcloud projects get-iam-policy <project> --flatten="bindings[].members" --filter="bindings.members:<sa>"
az role assignment list --assignee <objectId> -o table
```

工具：`enumerate-iam`、`Pacu`（`iam__enum_permissions`、`iam__privesc_scan`）、`ScoutSuite`/`Prowler`（只读配置审计）、`roadtools`（Azure）、`gcp_scanner`。

**子阶段 2.3：关键判定（决定后续路线）**

| 问题 | 影响 |
|---|---|
| 凭据是**临时**（STS/托管身份/OIDC）还是**长期 key**？ | 临时凭据必须优先做高价值只读动作 |
| 有效期还剩多久？ | < 10 分钟 → 只做一次身份确认 + 一次关键读取 |
| 身份绑定的计算资源是什么？ | EC2/Lambda/ECS/EKS/App Service/Cloud Run/GCE → 决定能否用该平台能力提权 |
| 是否跨账号可承担其他角色？ | 决定阶段 4 的可行性 |
| 是否有 `iam:PassRole` / `actAs` / 角色分配写权限？ | 提权捷径（见 `../Cloud-Container-Attack/Cloud-IAM-Privilege-Escalation.md`） |

**判据（建图完成）**：能列出"当前身份可直接调用的高危 API 清单"与"必须借助其他主体才能做的动作清单"。

**证据**：权限清单输出（脱敏）、身份来源、可承担角色列表。

## 阶段 3：同账号内的横向

按"成本从低到高"排列，优先取只读且高价值的证据：

### 3.1 凭据与配置库（最高性价比）

- AWS：Secrets Manager `get-secret-value`、SSM `get-parameter(s)`（含 `/prod/*`）、S3 中的 `tfstate`/`.env`/备份。
- Azure：Key Vault secrets/certificates（若权限允许）、App Configuration、存储账户 `listKeys`。
- GCP：Secret Manager `versions access`、Cloud Storage 中的配置与备份。

这些位置常含**其他系统的凭据**（数据库、SaaS、内网 API），是横向的最短路径。

### 3.2 数据面

- 对象存储：列举 → 挑一个非敏感对象读片段证明可达（`../Recon-OSINT/Cloud-Asset-Enumeration.md` 的判定纪律同样适用）。
- 数据库/缓存：优先看"网络是否可达"，而非直接爆破；托管服务的连接串常在 3.1 中找到。
- 数据仓库/消息：Athena/Glue、Synapse/Fabric、BigQuery；SQS/SNS/EventBridge、Service Bus、Pub/Sub —— 消息里常有下游系统的 token。

### 3.3 计算面（用"平台能力"代替"提权漏洞"）

| 动作 | 需要的权限 | 效果 |
|---|---|---|
| 在实例上执行命令 | `ssm:SendCommand`（AWS）、Run Command（Azure）、OS Config（GCP） | 以实例角色身份执行（可能比当前身份权限更高） |
| 起一台实例并指定角色 | `ec2:RunInstances` + `iam:PassRole` | 以目标角色运行代码 |
| 改函数代码并调用 | `lambda:UpdateFunctionCode` + `InvokeFunction` | 使用函数已有角色 |
| 改容器任务定义 | `ecs:RegisterTaskDefinition` + `RunTask` + `PassRole` | 同上 |
| 改构建/部署流程 | CodeBuild/CodePipeline、DevOps Pipeline、Cloud Build | 使用部署身份 |
| 改应用配置 | App Service 的 Kudu/`/api/settings`、Cloud Run/Functions 的环境变量 | 注入代码或读出配置 |

### 3.4 快照、备份与版本

- EBS 快照共享（`modify-snapshot-attribute`）、RDS 快照恢复、S3 版本/复制、Azure 快照/托管磁盘导出、GCP 磁盘快照。
- 价值：绕过运行时的访问控制，直接读"另一个时间点"的数据（也常用于离线分析凭据）。

### 3.5 注册表与供应链

- 私有镜像仓库（ECR/ACR/GAR/`imagePullSecrets`）→ 拉取镜像分析其中的凭据与下游地址。
- 可变标签（`:latest`）→ 覆盖即供应链投毒（需授权）。

### 3.6 日志与监控（常被忽略的凭据来源）

- CloudWatch Logs / Log Analytics / Cloud Logging：应用日志常打印连接串、token、内部 URL。
- 审计日志本身也是资产：能看到"谁在何时做了什么"、内部工具与角色名。

**判据（同账号横向成功）**：从当前身份读到了**本不该能读**的资源内容，或通过平台能力获得了更高权限的执行上下文。

**证据**：每一步的 API 调用与响应（敏感值掩码）、身份链（当前身份 → 新身份）。

**常见失败与回退**：

- 权限被 SCP/Permissions Boundary/Azure Policy/组织策略限制 → 记录"策略存在"，转向有权限的分支。
- 数据面只有 `list` 无 `get` → 用元数据（大小、时间、键名）间接证明。
- 计算面权限受限 → 走 CI/CD 或 K8s（阶段 4）。

## 阶段 4：K8s / 容器面横向

进入任意 Pod 或拿到集群凭据后：

1. **SA token 权限**：`kubectl auth can-i --list`；关注 `secrets`、`pods/exec`、`pods/create`、`serviceaccounts/token`、`clusterrolebindings`。
2. **Secret 读取**：默认 base64（除启用 etcd 加密）→ 读到即等效明文。
3. **TokenRequest 提权**：为高权 SA 申请令牌。
4. **节点级身份**：`hostPath`/`privileged`/`hostNetwork` → 逃逸后常直接拿到**节点实例角色**（通常比 Pod 身份权限更大）。
5. **控制面与外围**：Ingress Controller / Admission Webhook 的配置注入（如 CVE-2025-1974，见 `../Cloud-Container-Attack/Kubernetes-Attack.md`）。
6. **网格内部信任**：默认 allow-all、`PERMISSIVE` mTLS、XFCC 伪造、sidecar 绕过与出网策略缺失（`../API-Gateway-Service-Mesh/Mesh-Internal-Trust-Abuse.md`）。
7. **镜像与标签**：见 3.5。

**判据**：以新身份访问到其他命名空间/服务的受保护资源，或拿到节点/云侧身份。

**证据**：`can-i` 输出、读到的 Secret 名（值掩码）、逃逸前后身份对比（`whoami`/`get-caller-identity`）。

## 阶段 5：跨账号 / 跨订阅 / 跨项目

**把"信任关系"当成图上的边**：每个可被承担的角色、每个联邦信任、每个服务主体授权都是一条边。

```bash
# AWS：找出可承担的跨账号角色
aws iam list-roles --query "Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS]].[RoleName,Arn]"
# 观察信任策略的宽松模式
aws iam get-role --role-name <role> --query "Role.AssumeRolePolicyDocument"
# 实际尝试（授权范围内）
aws sts assume-role --role-arn <arn> --role-session-name assess
```

高风险信任模式（发现即记录为高危配置）：

- `Principal: "*"` 或整个账号根（`arn:aws:iam::<id>:root`）无 `ExternalId`、无 `Condition`。
- `Condition` 仅限制 `sts:ExternalId` 但 ExternalId 在客户端代码/日志中泄漏。
- 联邦/OIDC 信任的 `sub` 条件过宽（例如 `repo:org/*:*`、任意分支、任意 PR）→ CI 侧可提权（`../Cloud-Container-Attack/CI-CD-Supply-Chain.md`）。
- 角色链（role chaining）超过单次会话上限被滥用为长期访问。
- Azure：管理组/订阅级 `Owner`/`User Access Administrator`、B2B 访客的高权角色、PIM 可激活的常驻资格、多租户应用的 `adminconsent`。
- GCP：跨项目 `roles/iam.serviceAccountTokenCreator`、域委派管理员、Shared VPC 的服务项目权限。

**判据**：以**另一个账号/项目**的身份成功调用一次 API（`get-caller-identity`/`az account show` 显示新主体）。

**证据**：信任策略原文（哪条边）、AssumeRole/令牌获取请求、新身份确认输出、影响范围（新身份能读什么）。

**停止条件**：跨到客户未授权的账号 → 立即停止并报告，不要继续探查。

## 阶段 6：数据面（按分类证明）

按敏感性分级取证，**每级只取最小必要证明**：

| 级别 | 例子 | 建议证据 |
|---|---|---|
| 公开 | 静态站点资源 | 可略 |
| 内部 | 文档、架构图、日志 | 键名 + 一个对象的前若干字节（掩码） |
| 敏感 | 备份、导出、配置 | 仅证明可列举与可读，不回传内容 |
| 凭据 | 密钥库、Secret 内容 | 只证明"可获取"，不记录凭据本体 |
| 客户数据 | PII/业务数据 | **不读取**；以权限路径 + 少量元数据证明可达 |

跨租户验证（SaaS 集成、共享资源）参考 `../IDOR-BOLA/README.md` 的两身份对照法。

## 阶段 7：持久化（仅授权明确时）

云上的持久化选择"**事件驱动**"通常比"新建长期 key"更贴近真实攻击且更少破坏性：

- AWS：EventBridge 规则 → Lambda；S3 事件通知；IAM 角色信任条件调整。
- Azure：Event Grid → Function；自动化账户 Runbook；应用的服务主体凭据。
- GCP：Pub/Sub → Cloud Function；Cloud Scheduler；SA 的 `actAs` 授权。
- K8s：CronJob、admission webhook、SA token、镜像标签。
- CI：工作流触发器、OIDC 信任条件。

**纪律**：不做（默认）；做则必须①书面授权②记录创建物③演练后立即删除并验证④在报告中单列。

## 阶段 8：证据、清理与报告

1. **凭据链图**：入口 → 每个身份 → 获取方式 → 有效期 → 能做什么（一张图胜过十段文字）。
2. **影响矩阵**：能读的资源类型、能写的范围、跨账号数量、是否触达 PII。
3. **时间线**：每一步的时间戳（与客户日志对齐，用于验证检测覆盖）。
4. **清理清单**：临时实例/函数/规则、上传的测试对象、创建的 SA/凭据、缓存的凭据文件（`~/.aws`、ccache、`az` token cache）。
5. **未验证项**：标注"理论可达但未执行"的路径，方便客户按风险自评。

## 附：常见误报与收敛判据

- 凭据有效但**所有高危动作被策略拒绝** → 结论是"权限边界有效"，不是"横向成功"。
- 只拿到 `list` 权限 → 用元数据证明，但不要称"读取了数据"。
- 跨账号 `AssumeRole` 报 `AccessDenied` ≠ 该角色不可承担（可能需要 `ExternalId` 或 MFA 条件）。
- 环境变量里的 key 属于**另一个已退役**环境 → 验证账号/项目 ID 是否在范围内。
- 从节点角色拿到的是**只读**实例配置文件 → 影响降级。

## 参考

- 关联域：`../Cloud-Container-Attack/README.md`、`../Cloud-Container-Attack/Cloud-IAM-Privilege-Escalation.md`、`../Cloud-Container-Attack/Kubernetes-Attack.md`、`../Cloud-Container-Attack/CI-CD-Supply-Chain.md`、`../SSRF/Cloud-Metadata-Access.md`
- 检测映射：`Cloud-Detection-Mapping.md`；噪声控制：`../OPSEC-and-Evasion/README.md`
- 工具：Pacu、enumerate-iam、ScoutSuite/Prowler、roadtools、gcp_scanner、kubeaudit
- MITRE ATT&CK：T1078.004（Cloud Accounts）、T1098（Account Manipulation）、T1530（Data from Cloud Storage）、T1552（Unsecured Credentials）
