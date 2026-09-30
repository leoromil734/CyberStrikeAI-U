### 灰产CDN后渗透取证(拿下CDN后摸清它在运营什么)
```
五步: ①全量枚举证书(ID 1-500,过期/禁用的也含私钥,揭示历史运营) ②关键词初分类 ③真实访问验证(关键!不能只信证书域名,
      requests跟随重定向看最终落地页title/meta/h1/JS跳转) ④按真实内容重新分类 ⑤标注高价值目标
关键词矩阵(dnsNames分类): 钱包钓鱼 tokenpocket/tokenpoket(字母置换抢注)/metamask/trust | 支付诈骗 paypal/wxpay/bayspay/147pay
  成人付费站群 xiuren/xrw/sood/laikantu/tuhaokan/kantu | 盗版影视 7she/acgzy/yiyiyi/dilige/80sjdy/mogudong
  VPN翻墙 futo-on/xyou/gogocloud/douyinjiasu/tudoujiasu | 泛站群SEO 0x000/tc7/vn00/fc000/ikkk(程序化泛解析跳转链) | 彩票诈骗 0149/dh49/999pian(pian=骗)
高价值标注: A级有效期内钱包/支付私钥→MITM/HTTPS钓鱼绿锁 | B级ACME自动续期证书可持续监控 | C级AK/SK凭据复用+WHOIS关联运营者其他资产
识别特征(🔴极高): 同服务器混部正常+涉黄+盗版 | 大量泛站群通配符证书 | 品牌域名+仿冒域名同CDN(内部人运营钓鱼) | 唯一管理员key可导全部私钥(GoEdge默认无隔离)
```
