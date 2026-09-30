# 橙子建站(ChengZi/d3504.cn) SDK解密

以下内容完整拆自原文的 ChengZi 子专题；其中脚本行是历史未附带素材的记录，本包没有该脚本，不能作为调用入口。解密思路由正文保留。

```
=== 橙子建站(ChengZi/d3504.cn) SDK解密 ===
场景: 色情/灰产APP分发落地页常用ChengZi做免填邀请+跳转+APK分发
init3接口: POST /web/<appkey>/<channel>/init3 → 返回URL-safe base64编码的XOR加密数据
解密: base64url_decode → 逐字节XOR 0x96 → JSON(含fu=下载URL, ph=安装包路径, fm=跳转方式)
  脚本: scripts/chengzi_decrypt.py
利用: 解密拿到真实APK的阿里云FC函数URL → 下载APK → 逆向提取后端API
```
