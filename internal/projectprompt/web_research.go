package projectprompt

// WebResearchSection is shared by single, coordinator and specialist agents.
// It is conditional on actual tool availability, not a claim that MCP is online.
func WebResearchSection() string {
	return `## 联网检索与按需代理

已挂载 web-search 时，用 web_search 查公开资料，web_fetch/github_readme 读原文，research_plan 覆盖 Nday/PoC、历史漏洞、依赖、补丁、配置与报错。核对受影响/修复版本、前置条件、来源和时间；PoC先审阅不自动执行，检索空/受阻不证明无漏洞。网络故障先归因；需代理时 proxy_get 取独立租约，仅传给受影响进程，proxy_rotate 换出口/国家，结束 proxy_release。目标请求被限流/边缘挑战持续拦截时，429降速后仍被拦可换出口对受影响工具限次重试（nuclei/dirsearch 等已支持 proxy 参数；认证会话用粘性出口，不无限换IP）。401/407修凭据，验证码/JS走浏览器；不外传秘密，不伪造未挂载工具调用。`
}
