# 反序列化攻击

> 反序列化的判定链是：**可控字节 → 进入 unserialize/readObject/ObjectInputStream → 触发 gadget 链 → 达成效果（RCE/SSRF/文件操作）**。缺少任何一环都不成立。

## 一、各语言入口与指纹

| 语言 | 入口 | 指纹 |
|---|---|---|
| Java | `ObjectInputStream.readObject`、`XStream`、`Fastjson`、`Jackson`(默认类型)、`SnakeYAML`、`Hessian`、`Kryo`、`JNDI` | `rO0AB`(base64)、`\xac\xed\x00\x05`、`Hessian` 头 |
| PHP | `unserialize()`、session 反序列化、`phar://` | `O:8:"ClassName":2:{...}`、`a:2:{...}` |
| .NET | `BinaryFormatter`、`LosFormatter`、`ObjectStateFormatter`、`JavaScriptSerializer`+`TypeNameHandling`、ViewState | `AAEAAAD/////`、ViewState 中的 `__VIEWSTATE` |
| Python | `pickle`、`yaml.load`(非 safe)、`torch.load` | `\x80\x04`、`!!python/object`、`!!python/object/apply` |
| Node | `node-serialize` 的 `_$$ND_FUNC$$_`、`serialize-javascript`+`eval` | |
| Ruby | `Marshal.load`、YAML(unsafe_load) | `\x04\x08` |

## 二、Java gadget 链（概要）

- 触发点：`readObject` → `Transformer` 链 → `TemplatesImpl`/`InvokerTransformer` → 反射调用 `Runtime.exec`。
- 常用链（取决于依赖）：CommonsCollections 1-x、CommonsBeanutils、Spring、Groovy、C3P0、ROME、JDK7u21、Jdk8u20、URLDNS（探测用）。
- **JNDI 注入**（Log4Shell 家族）：`${jndi:ldap://...}` → 远程加载 object factory → 老 JDK 可 RCE；新 JDK 需配合本地 gadget（如 Tomcat BeanFactory、`org.apache.naming.factory.BeanFactory` + EL）。
- 探测先用 **URLDNS**（只发 DNS，无副作用，安全）。
- 生成：`ysoserial`；检测：`ysoserial` 的 `URLDNS` + Interactsh。

### 2025 相关

- **SharePoint ToolShell（CVE-2025-53770）**：referrer 认证绕过 + ToolPane 调用 + 泛型 wrapper 类型混淆绕过 `DataSetSurrogateSelector` 白名单 → 反序列化 pre-auth RCE。
- **SOAPwn**：.NET 从攻击者提供的 WSDL 生成 SOAP 代理，可设置非 HTTP scheme → 任意文件写 + NTLM 中继 → webshell（2025）。
- ASP.NET 视图引擎：任意文件写（含穿越）落到视图搜索路径 → Razor 编译执行（2025）。
- 加密/序列化 API 误用：AEAD tag 截断导致可暴力破解短 tag → nonce 重用 → 伪造密文（OpenSSL 绑定，2025）。

## 三、PHP 反序列化

- `unserialize()` 直接入口；`phar://` 可在**文件操作**时触发（无需显式 unserialize）。
- `__wakeup`/`__destruct`/`__toString`/`__invoke`/`__call` 作为起点。
- POP 链：框架/库（Laravel、Symfony、Yii、ThinkPHP、Monolog、Guzzle）中寻找 `__destruct` → 文件写/命令执行。
- 绕过 `__wakeup` 校验：属性数量伪造（`C:` 序列化自定义对象、`O:+N` 使 wakeup 失败但仍反序列化）。
- 生成/利用：`phpggc`。

## 四、Python

- `pickle`：`__reduce__` 返回 `(os.system, ('id',))`。
- `yaml.load` 未用 `SafeLoader`：`!!python/object/apply:os.system ["id"]`。
- `torch.load`（默认 pickle）、`joblib`、`dill`。
- 场景：ML 模型文件、缓存文件、Celery/Redis 任务、队列消息。

## 五、.NET

- `BinaryFormatter`/`LosFormatter`/`ObjectStateFormatter`：ViewState 未启用 MAC → 直接构造（工具 `ysoserial.net`）。
- `TypeNameHandling=All` 的 JSON.NET：`$type` 指定 gadget。
- ViewState MAC 密钥泄漏（`machineKey` 在 `web.config` 泄漏）→ 伪造 ViewState。

## 六、验证（最小证据）

1. 可控字节确实进入反序列化（源码引用或行为指纹：如 `URLDNS` 触发 DNS）。
2. 可复现的 gadget 链与完整 payload（base64 或原始字节）。
3. 效果证据：命令回显/带外命中/文件落地/SSRF 回调。
4. 记录 JDK/库版本（决定链是否可用）。

## 七、常见误报

- 传入 `rO0AB...` 后返回 500（解析失败，未执行）。
- URLDNS 命中但来自其他组件的探测（校验来源 IP）。
- 目标已升级且白名单过滤（如 `ObjectInputFilter`），仍被视为可用。
- 只证明"存在某依赖库"而未证明可达触发点。

## 八、修复

- 不使用原生反序列化传输数据；改用 JSON/Protobuf 等无类型绑定的格式。
- Java：配置 `ObjectInputFilter` 白名单；禁止外部 JNDI/LDAP；升级 JDK。
- PHP：不使用 `unserialize` 处理用户输入；禁用 `phar` 包装器；`allowed_classes` 限制。
- Python：只 `yaml.safe_load`；不 `pickle.load` 不可信数据；模型文件校验签名。
- .NET：禁用 `BinaryFormatter`（已废弃）；ViewState 启用 MAC 并轮换 `machineKey`。
- 网络层：限制出网（阻断 JNDI/HTTP 回调）。

## 参考

- ysoserial / ysoserial.net / phpggc
- PortSwigger、HackTricks 反序列化章节
- Viettel：SharePoint ToolShell（2025）、Watchtowr：SOAPwn（2025）
