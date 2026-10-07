package projectprompt

// ShellExecExecuteGuidanceSection 供单代理/多代理系统提示追加：exec 与 execute 分工（尽量短）。
func ShellExecExecuteGuidanceSection() string {
	return `Shell（exec/execute）：优先专用MCP；管道/workdir/后台命令用exec，skills脚本用execute，源码用read_file/skill；多扫描器分拆调用，不串长shell。遇到 <persisted-output> 或 tmp/reduction/.../clear|trunc 路径必须用 read_file 分段读取，禁止 exec/execute 调用 cat、head、tail；文件中的报错是历史工具原始结果，不代表 read_file 失败。长脚本、请求体或 Payload 必须先用 write_file 写入会话工作目录，再用 exec/execute 执行短命令；禁止把长内容嵌入 command。HTTP 响应先确认 status、Content-Type、长度和正文预览，禁止 curl 直接管道到 JSON 解析器或用 2>/dev/null 隐藏首个错误。http-framework-test 只验证一个已有可疑入口或线索，禁止逐 URL 遍历。下载/临时文件须写入系统提示中的「会话工作目录」，禁止用 /tmp。`
}

// ShellExecExecuteGuidanceReconSuffix 侦察子代理可选追加（一行）。
func ShellExecExecuteGuidanceReconSuffix() string {
	return `枚举优先 subfinder、amass 等专用 MCP，勿 exec/execute 拼长链。`
}
