### 多层域名轮换CDN防封系统 → S3 STS凭据升级攻击链
```
架构识别: 入口域名 → JS跳转层1(随机子域+通配符DNS) → 跳转层2 → 真实业务站(静态Landing)
  CDN特征: Server: Xcdn | "Please access via the domain name" | 987dns.com 国内DNS调度(海外返0.0.0.0)
  关键突破点:
    ①真实业务站HTML内联JS中暴露mainDomains列表(层层递进)+base64编码的子站跳转配置
    ②最深层Landing页引用CDN外源站资源(ug458.com/idcpc8.com等)→ 绕过CDN直接打源站
    ③源站是S3(AmazonS3 header/ListBucket公开) → 暴露bucket名
    ④同站提供APK下载 → 逆向提取API域名+AES密钥+STS获取路径
    ⑤注册→登录→JWT→/BBS/GetSTSToken → AWS STS临时凭据(PutObject权限)
    ⑥S3写入 = CDN源站篡改 = 全用户JS注入(等效RCE)
  
  技术细节:
    AES-CBC加密API通信: 密钥在前端JS(lazyDecryptImg.js)和APK(.so strings)双重暴露
    ASP.NET后端: 从validation错误格式+traceId判断 | form-urlencoded优先(JSON可能415)
    注册无验证: 无SMS/无验证码/任意手机号 → 批量注册可能
    STS过度授权: 普通用户角色获得s3:PutObject → 覆盖CDN源站文件
    S3 bucket ListBucket公开: prefix参数无效(CDN缓存), 但直连S3域名可全量枚举
  证据要求: 保留每层跳转、源站归属、STS 权限与对象写入的单变量对照
```
