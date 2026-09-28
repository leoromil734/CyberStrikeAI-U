# 云与 SaaS 资产枚举

> 云资产的常见问题是**"配置错误的存储/数据库直接暴露在公网"**。枚举的目标是找出属于目标组织的存储桶、数据库与 SaaS 实例，并**只做只读验证**。

## 一、对象存储桶

命名规律：`<org>`、`<org>-backup`、`<org>-dev`、`<org>-assets`、`<org>-logs`、`<org><env><region>`。

```bash
# S3（AWS）
aws s3 ls s3://<bucket> --no-sign-request          # 列出（需桶允许）
aws s3 cp s3://<bucket>/<key> - --no-sign-request  # 只读取一个对象

# Azure Blob
https://<account>.blob.core.windows.net/<container>?restype=container&comp=list

# GCP
gsutil ls gs://<bucket>
https://storage.googleapis.com/storage/v1/b/<bucket>/o
```

常见的可读/可写判定：

- 列出成功 → 可枚举内容（`ListBucket`）。
- 单项 GET 成功 → 可读对象。
- PUT 成功 → **高危**（可投毒前端资源/覆盖数据）。仅在授权范围内做**一次**最小写验证（写一个随机名空对象后立即删除），否则只记录"策略允许写"的间接证据。

**接管**：桶名已被释放但仍被引用（`<org>-cdn.s3.amazonaws.com`）→ 见 `Subdomain-Takeover.md`。

## 二、数据库与中间件暴露

公网可达的 `3306/5432/6379/27017/9200/11211/5672/15672`：

- 无认证：Elasticsearch `/_cat/indices`、`/index/_search`；Redis `INFO`；MongoDB `db.stats()`；Memcached `stats`。
- 弱口令：只在授权范围内做**低频**尝试，并记录是否触发锁定。
- Kibana/Grafana/Prometheus/Consul/etcd：`/api/v1/status`、`/metrics`、`/v1/kv/`。
- 注意：这些往往是"影子资产"（运维临时暴露），需要与客户确认归属。

## 三、SaaS 与 PaaS 实例

- **Firebase**：`https://<project>.firebaseio.com/.json`、`/users.json`；RTDB 规则宽松时可直接读写。检查 `google-services.json`/前端 config 中的 `databaseURL` 与 `apiKey`。
- **Supabase**：`https://<ref>.supabase.co/rest/v1/<table>`（anon key + RLS 缺失 → 全量读写）。
- **Vercel/Netlify** 预览部署：`*.vercel.app`、`*-git-*.vercel.app` 常绕过主站访问控制或暴露未发布内容。
- **Jenkins/GitLab/Jira/Confluence** 实例：`/script`（Groovy）、`/-/metrics`、默认口令。
- **Kubernetes Dashboard / API**：`/api/v1/namespaces`、`/healthz`（见 `../Cloud-Container-Attack/Kubernetes-Attack.md`）。
- **CI/CD**：`<org>.github.io`、Actions artifacts 的公开链接。

## 四、云元数据与凭据（从应用漏洞侧）

见 `../SSRF/Cloud-Metadata-Access.md` 与 `../Cloud-Container-Attack/README.md`。

## 五、验证（最小证据）

1. 桶/实例的服务端响应（列出结果、对象内容片段、数据库版本信息）。
2. 归属证据：组织名出现在桶内容、证书、页面、或响应头中。
3. 只读优先；写操作仅在授权明确时做一次最小化验证并恢复。
4. 敏感性分级：公开静态资源 < 内部文档 < 备份/日志 < 凭据导出。

## 六、常见误报

- 桶允许列出但只有无害静态资源（常见于公共 CDN 桶）。
- 响应 403 但存在桶（`AccessDenied` 不等于不存在，也不等于可读）。
- 数据库端口开放但要求客户端证书/TLS 双向认证。
- SaaS 子域属于该平台公共基础设施（不是目标实例）。

## 七、修复

- 桶默认私有并启用"Block Public Access"；使用策略明确授权而非 ACL。
- 禁用匿名访问；开启访问日志与异常告警。
- 数据库/中间件不出公网（安全组 + 私有子网 + VPN/堡垒机）。
- Firebase/Supabase 规则必须按用户隔离（`request.auth.uid == resource.data.owner`）。
- 预览部署需要认证（Vercel/Netlify 开启 Deployment Protection）。

## 参考

- HackTricks：Buckets、Firebase、云安全章节；各云厂商存储安全文档
- Rhino Security Labs：云资产枚举思路
