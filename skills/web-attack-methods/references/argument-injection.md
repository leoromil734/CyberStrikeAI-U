# 无 Shell 参数与二次解析验证

## 触发

用户字段进入子进程数组、客户端选项、响应文件、配置或嵌套语言时使用。

## 最小流程

1. 固定执行 API、平台/运行时、目标二进制/版本、cwd、环境、身份与实际部署。
2. 区分 Shell 分词、argv 边界、目标 option parser 和二次解析。
3. 找可控参数位置及校验，观察最终子 argv，不从空格拼接日志猜参数。
4. Windows 核查数组序列化和子程序 parser；POSIX 一个元素内空格不自动变多个元素。
5. 正常成功基线后只改变一个选项/表示，使用自有受控对象和无害效果。
6. 证明目标实际解释和相对起始权限的新增能力，动态闭合后才 confirmed。

## 反例与停止

程序有危险选项、输入被识别为选项或本地 recorder 成功均不足以证明目标洞。
Shell payload 被挡不否定二次解析，反之亦然；'--' 是否有效按实际 parser 确认。
缺二进制/argv/部署前提记 tentative/blocked，不安装软件、运行陌生项目或使用破坏性选项。
同组合三次无新证据换路；清理仅本任务临时对象并验收。

## 修复

优先语义 API、固定可执行路径、参数允许集合和目标确认支持的数据位置。
消费前统一验证，涵盖响应文件、配置和 Windows 解析，保留合法行为回归。

## 来源与补充

Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`，`strix/skills/vulnerabilities/argument_injection.md`，Apache-2.0；中文改编，根 LICENSE。
完整原理：`knowledge_base/Command-Injection/Argument-and-Secondary-Parser-Injection.md`。
