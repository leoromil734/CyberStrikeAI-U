# 云与容器攻击面总览

> 云环境的攻击链通常是"**一个应用层瑕疵 → 一个凭据 → 一片权限**"。判定重点是**边界**：当前能读什么、能写什么、能否跨账号/跨租户。

## 一、链路模型

```text
应用漏洞(SSRF/RCE/上传)
   ↓ 拿到环境凭据
云元数据 / 环境变量 / 挂载文件 / K8s SA token
   ↓ 权限枚举
IAM / STS / 服务账号 / 工作负载身份
   ↓ 横向
对象存储 / 数据库 / 密钥管理 / 容器编排 / CI
```

## 二、常见凭据位置

| 位置 | 说明 |
|---|---|
| IMDS | 见 `../SSRF/Cloud-Metadata-Access.md` |
| 环境变量 | `AWS_*`、`AZURE_*`、`GOOGLE_*`、`KUBERNETES_*`、数据库 DSN |
| 挂载文件 | `/var/run/secrets/kubernetes.io/serviceaccount/token`、`.aws/credentials`、`/etc/kubernetes/*` |
| 应用配置 | `.env`、`config.php`、`application.yml`、`appsettings.json` |
| 容器与编排 | Docker socket `/var/run/docker.sock`、containerd socket |
| CI/CD | Runner 环境变量、OIDC token（见 `CI-CD-Supply-Chain.md`） |

## 三、权限枚举（只读、低噪声）

- AWS：`sts get-caller-identity` → `iam list-attached-*-policies`/`get-policy-version`/`simulate-principal-policy`（若允许）→ 对象存储 `s3 ls`。
- GCP：`gcloud auth list`、`gcloud projects get-iam-policy`、`gcloud auth print-access-token`。
- Azure：`az account show`、`az role assignment list`。
- K8s：`kubectl auth can-i --list`、`kubectl get secrets`、`kubectl get pods -A`。

纪律：**只读优先**；不做破坏性操作（删除、扩权、创建长期凭据）。取到的证据只用于评估影响。

## 四、容器与 Kubernetes 常见风险

- `hostPath` 挂载 `/`、`/var/run/docker.sock`、`/proc` → 逃逸。
- `privileged: true`、`CAP_SYS_ADMIN`、`securityContext.runAsUser: 0`。
- 默认 SA `automountServiceAccountToken: true` + 过宽 RBAC（`*` 权限）。
- 只有 `create pods` 权限时可通过 Pod 创建挂载 hostPath 逃逸。
- 元数据未加固（IMDSv1）、网络策略缺失（Pod 之间可任意访问）。
- 加密的 Secret 只是 base64（`etcd` 未加密）。
- 已知漏洞链例：**IngressNightmare（CVE-2025-1974）** —— 未认证的 admission webhook → NGINX 配置注入 → 结合 client-body 缓冲与 ProcFS fd 复用加载临时共享库 → 容器内 RCE。

## 五、对象存储与数据面

- 桶策略过宽（`s3:GetObject` 对 `*`）、`list` 可枚举、预签名 URL 长期有效。
- ACL 与 Bucket Policy 冲突、CDN 源站回源到私有桶导致间接公开。
- 静态站点桶可写 → 前端 JS 供应链投毒。
- 数据库/缓存暴露公网（5432/6379/9200/27017）+ 弱口令。

## 六、验证（最小证据）

1. 从应用层漏洞到凭据的完整链（每一步请求/命令与输出）。
2. 凭据可用性的**最小证明**（如 `get-caller-identity` 返回的账号/角色，或读到的一个非敏感对象）。
3. 影响评估：能读哪些敏感位置、能否写、能否跨账号/跨租户。**不实际执行**破坏性动作。
4. 记录凭据有效期与来源，便于客户轮换。

## 七、常见误报

- 拿到的是"已被撤销"的凭据（先验证有效性）。
- 环境变量里有 key 但无权限（枚举结果为空）。
- 内网可达但需要 mTLS/额外令牌。
- 容器内是只读文件系统，逃逸路径不可用。

## 八、修复（要点）

- IMDSv2 强制 + hop limit 1；工作负载用短期身份（IRSA/Workload Identity），禁止长期静态密钥。
- 容器：非 root、只读根 FS、drop all capabilities、不挂载 docker.sock/hostPath。
- K8s：RBAC 最小化、禁用默认 SA token 自动挂载、网络策略默认拒绝、etcd 加密。
- CI/CD：使用 OIDC 短期凭据替代长期 secret（见 `CI-CD-Supply-Chain.md`）。
- 对象存储：默认私有 + 明确策略 + 访问日志；禁止对 `*` 授权。

## 参考

- Wiz：IngressNightmare（CVE-2025-1974，2025）
- 各云厂商 IMDS 与最小权限文档
- 上游 `../SSRF/Cloud-Metadata-Access.md`、`../tools/`、skill `cloud-attack-methods`
