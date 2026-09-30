---
name: specialized-attack-playbooks
description: >-
  GoEdge、特定 CDN、宝塔/UniApp、OCS/MinIO 等已命中特定技术栈时使用的专题索引。
  不用于常规 Web/API 测试；仅加载与已确认产品和版本对应的 playbook。
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

# 专题路由与升级前提

仅在已确认产品/版本或场景、且授权覆盖当前操作时按下列路由读取**一个专题文件**。这些文件完整保留原内联正文；加载一个专题无需读取其他专题。只在出现新的产品/场景证据时再加载对应专题，缺前提只阻断对应方向，不能视为安全结论。

## 逐专题路由

- **GoEdge CDN(8002端口)私钥批量导出** → `references/goedge-cdn.md`。前提：GoEdge API 指纹、已获授权的管理员 AK/SK；先认证取 token，再按证书范围检查 `sslCertJSON`/`keyData`。确认跨范围私钥证据后才评估 MITM、凭据复用与边缘节点影响，其他实例仍须单独授权。
- **灰产CDN后渗透取证** → `references/cdn-post-access-forensics.md`。前提：已取得 CDN 管理/证书访问权限；全量证书含过期/禁用 → 关键词初分类 → 跟随重定向核对最终 title/meta/h1/JS跳转 → 真实内容重新分类 → A/B/C 高价值标注。不能只信证书域名。
- **ARP MITM同L2窃取SSH密码** → `references/arp-l2-mitm.md`。前提：目标同L2（同Hyper-V宿主/同VLAN）、有已控跳板机、目标SSH密码未知；MAC 解析问题先核查 → 部署/抓包 → 进程与流量验证 → 日志有新内容才通知 → 清理。原文的持久化仅在授权覆盖时适用。
- **多层域名轮换CDN防封 → S3 STS凭据升级链** → `references/cdn-antiblock-s3.md`。前提：已确认随机子域/多层JS跳转、真实Landing；逐层跳转 → CDN外源站资源 → S3归属/bucket → 同站APK/API/AES → JWT/STS → 权限与对象写入单变量对照。只有归属、STS权限及写入证据闭合后才升级源站影响。
- **宝塔面板(BT Panel)渗透** → `references/bt-panel.md`。前提：端口与404 Set-Cookie（32位MD5 + `_ssl`）等面板指纹；先核对安全入口和版本，旧版CVE-2023-38038仅<=7.7。入口枚举、同IP弱站横向须独立满足授权；随机8位不可推导，2024+无已知通用绕过。
- **UniApp/DCloud APK逆向** → `references/uniapp-dcloud.md`。前提：已取得APK且确认dcloud_uniplugins/assets/apps/uni-jsframework结构；manifest版本/权限 → config/env API → 页面JS业务/IDOR；保留认证凭据、加密/签名和WebSocket方向，再凭实际后端证据升级验证。
- **橙子建站(ChengZi/d3504.cn) SDK解密** → `references/chengzi-sdk.md`。前提：ChengZi APP分发/邀请/跳转及init3响应；URL-safe base64 → XOR 0x96 → fu/ph/fm → 实际APK/阿里云FC下载线索 → 后端API分析。正文的历史脚本名不是可调用文件。
- **AI IDE API反代/key泄露目录** → `references/ai-ide-api-proxy.md`。前提：正在评估AI编程工具反代/模型接口与凭据暴露；仓库搜索 → README → 最新issue核对状态 → 区分可用、已废与流量研究辅助方案。正文中的时间与模型可用性是原文记录，不替代当前证据。
- **OCS在线客服系统 + MinIO对象存储** → `references/ocs-minio.md`。前提：OCS客服链接/SPA真实API及visitor token；init → 签名/上传 → 静态对象核验 → dir/bucket权限与MinIO版本 → CDN响应大小/挑战、nginx方法/路径ACL、Spring路径差分、宝塔入口和Longteng证书关联。对象内容可访问不等于Tomcat执行；需webroot/执行证据才升级RCE，挑战通过不等于路径ACL通过。

## 保真与历史素材

完整原始 frontmatter、全部专题正文及原支持文件索引见 `references/original-skill.md`，仅用于保真审计或必要时完整取回，不作为默认上下文，不默认加载。

原支持文件索引是**历史未附带素材**：原文提及的额外 references 和 scripts 并未附带，索引只保留在原文归档，不把它们当可调用文件，也不补造脚本。当前有效路由只有上述实际存在的九个专题文件。

原索引中的其他探索线索仍保留：发卡系统、PHPCMS V9、Spring Boot/Actuator、CDN/WAF、WebSocket/SockJS/STOMP、nginx/PHP-FPM/PATH_INFO 与 APK 逆向。遇到对应现场信号时按需读取原文归档中的索引，区分已有方法和未附带材料；不能因缺参考文件而把该方向写成已测或已排除。
