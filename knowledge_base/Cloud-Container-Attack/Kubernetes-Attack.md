# Kubernetes 攻击与逃逸要点

> K8s 的攻击面 = **API Server + 工作负载 + 网络 + 镜像供应链**。授权范围内只做只读枚举与最小验证，不执行破坏性操作。

## 一、信息收集（从 Pod 内部出发）

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
env | grep -i kubernetes
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces
kubectl --token=$TOKEN --server=https://kubernetes.default.svc auth can-i --list
```

- `can-i --list` 是最快判断"这个 SA 能干什么"的方式。
- 关注：`secrets`、`pods/exec`、`pods/create`、`clusterrolebindings`、`serviceaccounts/token`、`nodes`。

## 二、凭据与 Secret

- `secrets` 默认只是 base64（除非启用 etcd 加密）→ 读到即等同明文。
- `serviceaccounts/token`（TokenRequest）权限 → 为任意 SA 申请令牌 → 权限提升。
- `pods/exec` → 进入其他 Pod，横向。
- Env 注入：有 `pods/create` 且能指定 `envFrom: secretRef` 时，可把任意 Secret 读到自己容器。

## 三、逃逸路径

| 路径 | 条件 | 说明 |
|---|---|---|
| `hostPath: /` | Pod 定义可控或已有特权 Pod | 读写宿主文件系统；`/etc/cron.d`、`/root/.ssh`、容器 runtime socket |
| `hostPath: /var/run/docker.sock` | 同上 | `docker run -v /:/host --privileged` 直接逃逸 |
| `hostPath: /var/run/containerd/containerd.sock` | 同上 | 类似 |
| `privileged: true` | 同上 | `nsenter -t 1 -m -u -i -n -p sh` |
| `CAP_SYS_ADMIN` | 能力授权 | 挂载与 namespace 操作 |
| `CAP_SYS_PTRACE` | 能力授权 | 注入宿主进程 |
| 内核漏洞 / 容器运行时漏洞 | 版本 | 谨慎，风险高 |
| 只读 `/proc` 或 `hostPID` | `hostPID: true` | 读宿主进程内存/环境变量 |

## 四、网络面

- 无 NetworkPolicy → 可从任一 Pod 访问集群内所有服务（数据库、Prometheus、Admission webhook、Kubelet）。
- Kubelet 10250（未认证）→ `pods/exec` 等价能力；10255 只读。
- API Server 匿名/宽松 RBAC → 直接枚举。
- 元数据/IMDS 可达 → 云侧提权（见 `README.md`）。
- Ingress Controller 与 admission webhook 是外围高价值目标（IngressNightmare 类）。

## 五、镜像与供应链

- 私有镜像仓库凭据（`imagePullSecrets`、`~/.docker/config.json`）→ 拉取/推送镜像 → 植入后门。
- 镜像标签可变（`:latest`）→ 覆盖即供应链投毒。
- 无镜像签名验证（cosign/Notation）。
- Helm/Operator 的 CRD 可被低权用户创建 → 触发高权控制器行为。

## 六、验证（最小证据）

1. 当前工作负载身份与权限（`can-i --list` 输出）。
2. 能达到的边界（读到哪些 Secret 名/对象，不导出敏感值；必要时掩码）。
3. 逃逸链每一步的命令与输出（若客户要求不做逃逸，则只证明"可达条件"，如挂载项与权限位）。
4. 影响评估：能否访问宿主、其他命名空间、云凭据。

## 七、常见误报

- SA token 无实际权限（`can-i` 全 no）。
- 有 `hostPath` 但路径为空/不存在。
- `privileged` 但缺少必要宿主机二进制或 seccomp 限制。
- 只读 token（`automountServiceAccountToken=false` 但 env 中仍残留旧变量）。

## 八、修复（要点）

- RBAC 最小权限；避免 `cluster-admin` 绑定给 SA；禁用默认 SA token 自动挂载。
- Pod Security Standards（restricted/baseline）；禁止 privileged、hostPath、hostNetwork、hostPID。
- 启用 etcd 加密 + KMS；Secret 使用外部密钥管理（Vault/Secrets Store CSI）。
- 默认拒绝 NetworkPolicy；Kubelet 强制认证鉴权。
- 镜像固定 digest + 签名验证；仓库凭据最小化。
- Ingress Controller / admission webhook 及时升级（IngressNightmare 类）。

## 参考

- Wiz：IngressNightmare（CVE-2025-1974，2025）
- NSA/CISA Kubernetes Hardening Guidance
- Skill：`cloud-attack-methods`、`post-exploitation`
