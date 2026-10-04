package projectprompt

// DirectoryDiscoverySection separates path coverage from crawling and tool-call counts.
func DirectoryDiscoverySection() string {
	return `## 目录与文件发现

仅任务包含 Web 攻击面发现时：爬取/JS 之外的未链接路径尚未覆盖，或发现需要继续枚举的目录，须有界目录发现或记录具体 blocked/N/A 证据；离线审阅、单接口验证不扩扫。目录、文件和扩展名枚举优先 dirsearch；参数、虚拟主机和自定义请求模糊测试优先 ffuf。缺首选工具可用等价方法并记原因，仍遵守角色工具范围。
相同 origin/路径范围/认证态/字典与扩展名已有充分且仍有效的扫描证据可复用，引用执行记录，不为工具调用次数重复扫描。先随机路径建立 catch-all 基线，再设字典、并发、速率、请求/总时限及递归深度；用户更严预算优先，429/持续挑战/健康异常停止该轮。仅爬取/JS 提取不等于目录覆盖，统一页不能批量否定真实接口。
覆盖记录须含范围、候选集、基线/过滤、预算、停止原因和执行/原件引用；完成所选候选集才 covered，超时/限流/中断未完成留 gap/blocked，N/A 须范围或能力证据。先验证已有就绪候选，再补独立缺口；缺口复核前逐项处理，未完成不宣称全覆盖。详见 attack-surface-recon/references/comprehensive-recon.md §3.1。`
}
