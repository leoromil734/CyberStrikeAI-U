# 浏览器消息、窗口与 Worker 状态边界

## 适用与触发

实际页面使用 postMessage、命名窗口、opener、iframe、worker 或 cache 时使用。
深化已有 XSS/CSRF 方法，关注 origin/source 与对象生命周期，而非缺安全头清单。
仅有 DOM 修改、配置弱项或弹窗存在不代表真实目标漏洞。

## 前提与版本

固定浏览器版本、页面 origin、登录身份、对象、导航和隔离配置。
使用批准的专用测试 context、自有测试对象和无害标记。
记录实际 origin、frame、window 引用、session 和存储状态。
不重置用户/其他任务的 cookie、缓存或账户，不依赖 shell curl 代替浏览器证明。

## 状态图

- message sender → 接收 frame → origin/source 检查 → schema → 受保护操作。
- opener → 命名 browsing context → 导航/复用 → 返回消息与窗口引用。
- 页面 → worker/service worker → cache/key → 最终内容或请求消费者。
- 登录、租户切换、redirect、销毁/重建对象会改变状态，逐段记录。
COOP、noopener 和浏览器策略按实际部署分析，不由 header 缺失单独报洞。

## 单变量验证

1. 正常业务流建立合法窗口、消息、身份和操作基线。
2. 一次只变 origin、source/frame、消息字段或生命周期事件。
3. URL 解析后的 origin 校验与 source 引用校验分别检查。
4. 可预测 window.open target name 仅是候选，确认实际复用组、opener 链和时序。
5. 比较导航前后、frame 替换、注销/租户切换时旧引用是否仍被接受。
6. worker/cache 消费值与页面决策值分别观察，不能从页面日志推断 worker 效果。
7. 若是侧信道，用无敏感合成状态、随机重复对照及噪声记录，不扩大敏感数据采集。
8. 只有实际浏览器触发受保护数据访问/状态变化才升级验证结论。

## 证据

保存页面/iframe URL、origin、source、窗口生命周期、消息 schema 和真实处理路径。
关联真实交互、网络请求、DOM/运行时现象及后续目标状态。
console 输出、弹窗或本地 wrapper 只能说明观测，不能单独证明目标副作用。
HTTP 请求原件和浏览器 context 关联到当前身份、时间和执行记录。
对他人会话的影响按既有政策判断；仅害自己不纳入本项目正式发现。

## 反证与缺口

消息被接收但 schema/对象授权在 handler 拒绝，不证明越权。
不同来源能发消息是平台功能，缺 origin 检查仍需真实危险效果。
命名窗口预测成功但未复用、失去 opener 或无法调用能力，链未闭合。
截图出现字符串不证明脚本执行或服务端状态改变。
curl/手工 DOM 修改不能证明浏览器 origin/source 或正常投递路径。
cache 差分来自版本、登录态或扩展时，先对齐条件。
缺真实浏览器、测试页面或授权身份时记 blocked，不装替代浏览器绕过限制。

## 停止与清理

有界处理窗口，三次同组合无新证据只关闭该组合。
禁止创建钓鱼部署、扩展外部目标、滥发消息或资源耗尽。
撤销仅本任务临时 wrapper、worker、cache 和测试对象，保留清理证据。
不能删除共享 worker/cache 或登出用户现有账户。
正式 confirmed 仍需真实目标侧新增权限、稳定复现与 validation。

## 修复与复测

精确校验解析后 origin、预期 source、消息 schema 和对象授权。
将批准/业务动作绑定到正确窗口、会话与生命周期，过期引用失败关闭。
不必要的 opener 关系断开，窗口命名及 worker/cache 按身份和环境隔离。
复测合法消息、无效来源、frame 替换、导航、会话变化与异步消费者。
既有 CORS、缺安全头和低价值排除不被本篇覆盖。

## 来源与改编

- Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`，`strix/skills/vulnerabilities/browser_security.md`，Apache-2.0。
- 来源：https://github.com/usestrix/strix 。中文改编，保留真实浏览器与权限门槛；许可见根 `LICENSE`。
- 官方参考：https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage 、https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API 。按实际浏览器版本核对。
