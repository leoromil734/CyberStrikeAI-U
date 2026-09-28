# 剧本：云内横向 · 检测映射（红蓝对照）

> 用法：红队用它做**可见性验证**（我这一步在客户那边能不能被看到）；蓝队用它做**覆盖度评估**（哪些阶段目前是盲区）。
> 配套文档：`Cloud-Lateral-Movement.md`（同一阶段的动作）。

## 一、日志源清单（先确认"有没有、留多久、送到哪"）

| 云/层 | 关键日志 | 常见缺口 |
|---|---|---|
| AWS | CloudTrail（Management **和 Data Events**）、GuardDuty、Config、VPC Flow Logs、EKS audit、S3 access logs、IAM Access Analyzer | 未开 Data Events（看不到读对象）；未多区域；日志桶可被写方删除；EKS audit 未开 |
| Azure | Entra ID 登录/审计日志、Activity Log、Defender for Cloud / for Identity、Key Vault 日志、存储日志、AKS audit | Entra 日志未导出/保留期短；Key Vault 日志未开；AKS audit 未开 |
| GCP | Cloud Audit Logs（**Admin Activity + Data Access**）、SCC、VPC Flow Logs、GKE audit、Access Transparency | Data Access 默认关闭；GKE audit 未开；日志桶权限过宽 |
| K8s | kube-apiserver audit（策略级别）、admission webhook 日志、节点 auditd、运行时（Falco/Tetragon） | audit 未开或级别过低（只记 `Metadata`）；无运行时检测；kubelet 日志缺失 |
| CI/CD | GitHub/GitLab 审计日志、Actions 运行日志、OIDC 令牌签发、制品仓库 | 日志短期、未集中；OIDC 签发无审计；自托管 Runner 无日志 |
| 网络 | VPC Flow / NSG Flow / Firewall logs、DNS 查询日志、TLS SNI（若可解） | DNS 日志未开（出网与 C2 难查） |

## 二、阶段 → 检测点

| 阶段 | 动作（见主剧本） | 关键日志与事件 | 高信号组合 |
|---|---|---|---|
| 1 进入 | IMDS/容器凭据访问、CI OIDC 签发、边缘设备登录 | GuardDuty `InstanceCredentialExfiltration`/`UnauthorizedAccess`、ECS 容器凭据异常、CI 审计中的 OIDC 事件、VPN/SSO 登录异常 | 新 IP 首次出现 + 立即调用云 API；CI OIDC `sub` 与仓库/分支不匹配 |
| 2 建图 | `list*`/`get*` 大量枚举、`SimulatePrincipalPolicy`、Graph/API 枚举 | CloudTrail `Discovery` 类调用、Entra 图形枚举、GCP `getIamPolicy` 突增 | `SimulatePrincipalPolicy` 后紧跟高危调用；同一新主体在 1 分钟内遍历 5+ 服务 |
| 3 同账号横向 | Secrets/Parameter 读取、对象存储读取、`ssm:SendCommand`、`RunInstances`+`PassRole`、`UpdateFunctionCode`、快照共享、`listKeys` | `GetSecretValue`/`GetParameters`、S3/Blob/GCS 数据事件、`SendCommand`、`RunInstances`、`RegisterTaskDefinition`、`ModifySnapshotAttribute`、`listKeys` | 短窗口内批量读 secret + 紧接着读对象存储；`RunInstances` 与 `PassRole` 成对出现且实例角色为高权 |
| 4 K8s 横向 | `secrets get`、`pods/exec`、TokenRequest、`create pods` 带 hostPath/privileged、改 webhook/SA 绑定 | K8s audit（`create pods`、`get secrets`、`pods/exec`、`tokenrequest`）、运行时告警、`clusterrolebinding` 创建 | `create pods` + `hostPath:/` + 随后使用节点实例角色；TokenRequest 指向高权 SA |
| 5 跨账号 | AssumeRole、改信任策略、服务主体加凭据、同意授权、`serviceAccountKeys.create` | `AssumeRole`（新 source ARN）、`UpdateAssumeRolePolicy`、Entra 同意与凭据新增、GCP `actAs`/key 创建 | 角色信任策略变更 **后** 立即出现来自新 IP 的会话；跨账号会话出现在非工作时间 |
| 6 数据面 | 数据导出、批量读取、跨区域访问 | 数据事件、导出任务（`StartExportTask`/`ExportToS3`…）、异常 egress | 单主体在短时间读取多个"业务不相关"的数据集；从计算区域之外读取 |
| 7 持久化 | EventBridge/Event Grid/Pub Sub 触发器、函数新建或改码、CI 触发器、CronJob | 资源创建事件（rule/function/schedule）、`UpdateFunctionCode`、工作流文件变更、K8s CronJob | 新建触发器 + 立即调用一次（测试行为）；函数代码哈希变化但 CI 无对应构建记录 |

## 三、降低误报的判据

单一事件几乎都会误报（自动化、运维脚本、IaC 部署都会产生类似调用）。建议按"**主体 + 时间 + 上下文**"组合判断：

1. **主体新不新**：该 IAM 主体/服务主体是否首次出现（尤其是首次做敏感调用）。
2. **来源是否合理**：调用来自计算资源（预期）还是外部 IP / 数据中心 IP（异常）。
3. **序列是否成链**：枚举 → 读凭据 → 提权 的连续序列比单点更可信。
4. **是否与变更流程对应**：IaC/CI 部署应有对应的提交与运行记录；没有对应记录的资源变更就是强信号。
5. **基线**：同类主体每天的正常调用量；偏离基线 5-10 倍才有意义。

## 四、红队可见性验证流程（推荐产出）

1. 与客户约定**动作清单**（例如：读 1 个 secret、列 1 个桶、执行 1 次 `SendCommand`、创建 1 个测试配置对象）。
2. 执行后核对：是否有告警、延迟多久、告警内容是否包含主体与资源。
3. 输出**覆盖矩阵**：阶段 × 动作 × 数据源 × 是否命中 × 告警质量（精确/模糊/无）。
4. 把未命中的动作列为**检测缺口**（比"我们拿到了凭据"对客户更有价值）。
5. 若客户允许，做一次**清理验证**：删除临时资源后再确认是否产生告警（防"只监控创建不监控删除"）。

## 五、常见覆盖盲区（按经验排序）

1. **数据事件未开**：对象存储的读取完全不可见（而读取正是横向的核心动作）。
2. **容器运行时无检测**：K8s 内 `exec`、凭据读取、逃逸行为无可见性。
3. **CI 的 OIDC 签发不可见**：跨云提权的关键一步没有集中日志。
4. **日志可被写方删除**：同账号内的攻击者能清掉自己留下的痕迹（应送到独立账号 + 不可变存储/Object Lock）。
5. **只有"创建"类告警**：删除、修改、读取类动作没有规则。
6. **保留期过短**：横向常在数小时到数天内完成，日志保留 7 天难以复盘。

## 六、修复与建设建议

- **日志**：CloudTrail 多区域 + Data Events（至少对敏感桶）；Entra/GCP 审计日志导出到集中 SIEM 并设置保留 ≥ 90-180 天；EKS/AKS/GKE audit 开启并设置合适级别（`RequestResponse` 对敏感资源）。
- **不可变**：审计日志写到**独立账号/订阅/项目** + Object Lock/不可变保留策略；限制写方删除权限。
- **检测规则**：按上表建立规则，优先做"高信号组合"而非单点；用 Sigma 的云规则（AWS/Azure/GCP）作为起点，结合本地基线调参。
- **响应**：凭据撤销为先（停用 Access Key/会话、轮换 secret）、再清理持久化、最后复盘（顺序反了会被对手继续利用）。
- **演练**：定期用本剧本 + 主剧本做红蓝对抗，验证"检测 + 响应"闭环，而不只是漏洞发现。

## 七、参考

- 各云厂商的检测与响应文档（GuardDuty / Defender for Cloud / SCC）、CISA 云日志指南
- MITRE ATT&CK：Detection Strategies（Cloud）、T1078.004 / T1530 / T1552 / T1098
- 主剧本：`Cloud-Lateral-Movement.md`；噪声控制：`../OPSEC-and-Evasion/README.md`
