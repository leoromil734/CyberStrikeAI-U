# 包执行器的身份与回退审阅

## 触发与前提

构建/CI/MCP stdio/插件配置实际调用 npx/npm exec/bunx/dlx 等时使用。
固定 runner 版本、完整调用、cwd/workspace、lockfile、registry、缓存和继承权限。

## 只读顺序

1. 分开包名/scope、bin 名、发布者、registry 和本地程序身份。
2. 读现有依赖树/.bin/PATH/锁文件，核查本地命中与缺失回退。
3. 确认配置实际被目标运行，不由注释或文档示例推断执行。
4. 标注可控制内容、选中 package/version/bin、执行过渡与起始权限。
5. 只有另批的隔离副本可用合成包/registry 和无害标记验证；演示不自动证明目标。
6. 真实目标侧新增能力才 confirmed，404 仅说明当时缺失，不证明可认领/安装/执行。

## 必须避免的误判

npm ci 会改依赖树/执行生命周期脚本；npx --no 可能执行本地程序，均不是纯只读检查。
列 stdio MCP 工具前可能先启动程序，不能将列举当作无副作用动作。
本地固定可信依赖满足时，公共缺失名不一定进入实际链。
不注册争议包名、不运行陌生包、不自动下载或安装依赖。

## 停止与修复

未知脚本、未批准 registry 查询、缺 cwd/构建前提时停止对应单元并记缺口。
固定可信依赖和本地执行路径，明确 package/bin/版本，关闭非预期回退并最小化继承凭据。

## 来源与补充

Strix `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`，`strix/skills/custom/npx_confusion.md`，Apache-2.0；中文改编，根 LICENSE。
完整原理：`knowledge_base/Source-Code-Audit/Package-Executor-Identity.md`；SRC 默认排除/现场触发规则继续有效。
