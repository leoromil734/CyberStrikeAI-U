# UniApp/DCloud APK逆向

以下内容完整拆自原文的 UniApp/DCloud 子专题。

```
=== UniApp/DCloud APK逆向(极高效) ===
识别: assets/dcloud_uniplugins.json + assets/apps/<appid>/ + uni-jsframework.js
核心: 业务逻辑全在 assets/apps/<appid>/www/ 目录的JS/Vue文件中(无需jadx反编译Java)
  API提取: grep -r 'https\?://' assets/apps/ | 过滤baseURL/apiUrl/request配置
  认证: 搜索token/key/secret/Authorization → 硬编码凭据常见于config.js/env.js/manifest.json
  加密: 搜索aes/encrypt/decrypt/sign → 前端加密=明文(密钥必在JS中)
  WebSocket: 搜索wss://ws:// → 实时通信后端地址
优先级: manifest.json(appid/版本/权限) → config或env相关JS(API地址) → 页面JS(业务逻辑/IDOR)
```
