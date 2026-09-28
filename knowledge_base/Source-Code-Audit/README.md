# 源码审计（白盒）方法论

> 白盒的价值在于**可证明的数据流**：从外部输入（source）到危险操作（sink）的完整路径。审计报告要能给出"文件:行号 + 数据流 + 可达性论证"。

## 一、审计前置

1. 明确范围：哪些仓库/分支/提交在范围内（记录 commit hash）。
2. 建立"信任边界清单"：谁是不可信输入（HTTP 参数、Header、上传文件、WebSocket 消息、队列消息、第三方回调、DB 内容、AI 输出）。
3. 建立"资产清单"：鉴权中间件、ORM 层、模板引擎、序列化入口、命令执行封装、密钥管理。
4. **不要先看漏洞清单**：先理解业务与权限模型，再找实现偏差。

## 二、Source → Sink 映射

| Sink | 典型危险 API |
|---|---|
| SQL | 字符串拼接进 `query`/`execute`、`ORDER BY` 拼接、动态表名 |
| 命令 | `exec`/`system`/`popen`/`subprocess(shell=True)`/`Runtime.exec`/`child_process.exec` |
| 文件 | 路径拼接（读/写/删除）、`include`/`require`、模板加载路径、解压目标路径 |
| 模板 | `render_template_string`、`Template().render(user_input)`、Handlebars 编译、Thymeleaf 预处理 |
| 反序列化 | `unserialize`/`pickle.loads`/`ObjectInputStream`/`BinaryFormatter`/`yaml.load` |
| SSRF | HTTP 客户端取用户 URL、webhook、图片代理、PDF/文档渲染 |
| XML | 未禁用外部实体的解析器（`DocumentBuilderFactory`、`libxml`、`lxml`） |
| 重定向 | `redirect(user_input)`、`Location` 拼接 |
| 认证 | JWT 校验、会话生成、密码重置 token、权限判定函数 |

在高危 sink 上回溯数据流：参数是否经过白名单/参数化/编码？是否存在"看起来过滤了但可绕过"的路径（见 `../WAF-Bypass/README.md`）。

## 三、按语言的高危模式

- **Java**：`ObjectInputStream`、`XStream`、`Fastjson`（`autoType`）、`SnakeYAML`、SpEL/OGNL 表达式、`ProcessBuilder`、`File` 路径拼接、`URL.openConnection`。
- **PHP**：`unserialize`、`include $x`、`system/exec/shell_exec`、`preg_replace /e`、`create_function`、`$variable()` 动态调用、`phar`。
- **Python**：`eval/exec`、`pickle`、`yaml.load`、`os.system`、`subprocess(shell=True)`、`jinja2` 非沙箱渲染、`requests.get(user_url)`。
- **Node/TS**：`child_process.exec`、`eval`/`new Function`、`fs` 路径拼接、原型污染（`merge`/`extend`）、`vm` 模块、模板引擎动态编译。
- **Go**：`os/exec`（`sh -c`）、`text/template`（非 `html/template`）、`filepath.Join` 与用户输入、`http.Get` 任意 URL、`encoding/json` 大小写不敏感与重复键（见 `../WAF-Bypass/Parser-Confusion-Bypass.md`）。
- **C#**：`BinaryFormatter`、`Process.Start`、`Path.Combine` 逃逸、`XmlReader` 未禁用 DTD、Razor 运行时编译。

## 四、鉴权与逻辑审计要点

- 每个路由/处理器是否都经过鉴权中间件？找出**未挂载中间件**的路由（历史遗留、内部接口、调试接口）。
- 对象级授权：资源查询是否带 `owner_id`/`tenant_id` 条件？找"只按 id 查询"的语句。
- 属性级授权：DTO 是否白名单？是否存在 `Object.assign(model, req.body)`。
- 状态机：状态转换是否有前置条件校验（能否从任意状态跳到终态）。
- 多租户：`tenant_id` 从 token 取还是从请求体取（后者可越权）。
- 竞态：`SELECT ... 然后 UPDATE` 模式（无事务/无唯一约束）→ 见 `../Race-Condition/README.md`。

## 五、工具与流程

```bash
# 静态扫描（线索）
semgrep --config=p/owasp-top-ten --config=p/security-audit .
codeql database create db --language=java && codeql database analyze ...
gitleaks detect --source . --report-format sarif   # 密钥
# 依赖与配置
trivy fs . ; npm audit ; pip-audit ; osv-scanner -r .
```

流程建议：

1. 自动化扫描产出**候选清单**（不是结论）。
2. 人工按"可达性 + 影响"排序，逐个构造 PoC。
3. 每个候选都要回答：**输入可控吗？过滤可绕吗？能到达 sink 吗？有实际影响吗？**

## 六、验证（最小证据）

1. 代码位置（`文件:行号`）与完整数据流。
2. 运行验证：在测试环境用最小 payload 触发，附请求/响应或堆栈。
3. 精确性与可利用性论证（否则应降级为"代码异味/潜在风险"）。
4. 给出修复建议对应的具体代码修改点。

## 七、常见误报

- 上游有框架级防护（自动转义、ORM 参数化）但被忽略。
- sink 参数实际来自常量或内网可信来源。
- 需要不可达的权限（该函数只由管理员内部的另一步调用）。
- 已废弃代码路径（未被路由引用）。

## 八、参考

- OWASP Code Review Guide、OWASP ASVS
- Semgrep/CodeQL 规则库；CWE Top 25
- Skill：`source-code-hunting`、`source-aware-whitebox`、`zero-day-discovery`
