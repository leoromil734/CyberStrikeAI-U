# 浏览器窗口、消息与 Worker 状态

## 触发

真实页面有 postMessage、opener、命名窗口、iframe、worker/cache，且有实际受保护操作时读取。

## 执行顺序

1. 固定真实浏览器版本/context、origin、身份、对象、导航与隔离状态。
2. 建立正常业务基线；画 sender → frame → origin/source → schema → effect 状态链。
3. 一次只变 origin/source、frame、消息字段、导航或会话/租户生命周期。
4. 命名窗口预测需证明实际复用组、opener 与时序，缺 header 不独立计洞。
5. 比较 worker/cache 消费与页面决策，保留实际网络和受保护状态证据。
6. console/截图/手工 DOM 修改不是目标副作用；curl 不能证明浏览器状态边界。
7. 真实新增权限且稳定复现才 confirmed；仅害自己或缺安全头仍按既有排除。

## 反证与停止

接收消息但 handler/schema/对象授权拒绝，不证明越权；origin 可发消息是平台正常能力。
缺真实浏览器/身份记 blocked，不自行安装替代客户端或创建钓鱼部署。
同组合三次无新证据换路，不做洪泛/耗尽。

## 清理与修复

仅恢复本任务 wrapper/worker/cache/对象，不重置用户或其他任务的存储和账户。
精确验证解析后 origin、source、schema 和对象权限，将动作绑定窗口/会话/有效期，复测正常行为。

## 来源与补充

Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`，`strix/skills/vulnerabilities/browser_security.md`，Apache-2.0；中文改编，根 LICENSE。
完整原理：`knowledge_base/Browser-Security/Browser-Context-State-Boundaries.md`。
