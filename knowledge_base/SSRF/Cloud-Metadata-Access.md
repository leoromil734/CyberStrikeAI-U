# 云元数据访问（SSRF → 凭据）

> SSRF 的最高价值出口是云元数据服务（IMDS）。本篇给出跨云判定矩阵、IMDSv2 障碍与绕过思路、以及"拿到凭据之后"的边界纪律。

## 授权边界

仅在授权范围内访问元数据。取到凭据后**不得**用它访问客户云账号做任何超出范围的操作；只记录"可获得哪类权限"的证据即可。

## 各云元数据端点

| 云 | 端点 | 必需 Header |
|---|---|---|
| AWS EC2 | `http://169.254.169.254/latest/meta-data/` | IMDSv1 无需；IMDSv2 需 token |
| AWS ECS/EKS 容器 | `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` | 依赖环境变量 |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `Metadata: true` |
| Azure（托管标识） | `.../metadata/identity/oauth2/token?resource=...` | `Metadata: true` |
| Alibaba Cloud | `http://100.100.100.200/latest/meta-data/` | 无 |
| Tencent Cloud | `http://metadata.tencentyun.com/latest/meta-data/` | 无 |
| DigitalOcean | `http://169.254.169.254/metadata/v1.json` | 无 |
| Oracle OCI | `http://169.254.169.254/opc/v2/instance/` | `Authorization: Bearer Oracle` |
| Kubernetes（Pod 内） | 见 SA token 路径 | - |

AWS 关键路径：

```text
/latest/meta-data/iam/security-credentials/            # 角色名
/latest/meta-data/iam/security-credentials/<role>      # AccessKeyId/SecretAccessKey/Token
/latest/user-data                                       # 常含引导脚本与密钥
/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance
```

## IMDSv2 障碍

IMDSv2 需先执行：

```http
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
```

若 SSRF 只能发 GET，常见尝试：

1. 目标应用是否支持自定义方法与 Header（`PUT` + Header 注入、CRLF 注入）。
2 . 应用是否允许 `gopher://` —— 可手写完整 PUT 请求并串联取回 token 与凭据（注意 gopher 单包响应处理）。
3. 反向代理/中间件是否把 `X-HTTP-Method-Override: PUT` 传给上游。
4. IPv6 端点 `fd00:ec2::254`，以及 IMDS 未启用或 hop-limit 配置错误时回退 v1。
5. 容器场景优先看 `AWS_CONTAINER_CREDENTIALS_FULL_URI` / ECS 相对路径，限制通常更弱。

> hop limit 已被加固为 1 时，容器内 SSRF 往往拿不到宿主机 IMDS —— 这属于"已验证不可达"，要如实记录。

## 验证（最小证据）

1. 一次受控输入导致服务端访问元数据端点。
2. 回显内容足以证明是元数据（如 `ami-id`、`instance-id`、`project-id`、角色名）。
3. 若取到凭据，只证明**可用性**：例如 `sts:GetCallerIdentity` 返回的账号/角色；不执行越权写操作。

## 常见误报

- 应用自己代理了元数据但不返回任何内容 → 记为 possible，不给结论。
- 回显的"实例 ID"来自请求参数或缓存 → 交叉验证唯一性。
- 出网被 VPC 端点策略阻断，但应用层 200 → 不要记成功。

## 修复

- 强制 IMDSv2 + `HttpTokens=required` + `HttpPutResponseHopLimit=1`。
- 元数据端点通过 egress 规则从工作负载侧显式拒绝（除必要代理）。
- 应用层 SSRF 防护按 `SSRF-Bypass-Techniques.md` 执行；容器避免挂载长期凭据，改用短期 IRSA/Workload Identity。

## 工具

`interactsh-client`（带外确认）、`execute-python-script`（自定义 Header/方法）、`nuclei` 元数据模板（仅线索）。

## 参考

- AWS IMDS 文档、Google/Azure 元数据文档
- HackTricks：云元数据；OWASP SSRF 与 API7:2023
