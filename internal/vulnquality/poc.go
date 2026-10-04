package vulnquality

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const minEvidenceRunes = 50

var (
	sqlWriteStartRe  = regexp.MustCompile(`(?is)\b(?:INSERT|REPLACE)\s+INTO\b`)
	sqlUpdateRe      = regexp.MustCompile(`(?is)\bUPDATE\b[\s\S]{0,240}\bSET\b`)
	ellipsisRe       = regexp.MustCompile(`(?:\.{3}|…|……)`)
	sqlOmittedColsRe = regexp.MustCompile(`(?is)\b(?:INSERT|REPLACE)\s+INTO\b[\s\S]{0,180}\(\s*(?:\.{3}|…|\.{2,}\s*)\)`)
	sqlOmittedValsRe = regexp.MustCompile(`(?is)\bVALUES\s*\([^;]{0,800}(?:\.{3}|…)`)
	evidenceFileRe   = regexp.MustCompile(`(?i)\b[\w.-]+(?:_out|_poc|_evidence)\.(?:txt|log|sql|py|sh|out|js)\b|\b(?:poc|exploit|r\d+_[a-z0-9_]+)\.(?:py|sh|sql|txt|js|rb|php)\b`)
	omissionPhraseRe = regexp.MustCompile(`详见[^\n]{0,80}(?:\.txt|\.log|\.py|\.sql)|完整输出见|见附件|此处省略|关键部分省略|输出已省略|命令已省略`)

	// Common transcript headings may include numbering, Markdown emphasis or
	// an annotation. Match the whole heading, never prose claiming success.
	outputHeadingRe   = regexp.MustCompile(`(?im)^[ \t#]*(?:\*\*)?(?:(?:该|本|此)脚本的)?(?:本次)?(?:原始(?:执行)?输出|实际(?:执行)?输出|执行输出|输出|Output|stdout|stderr|响应|Response|Console|控制台)(?:[ \t]*[0-9]+)?(?:[ \t]*[（(][^\n()（）]{1,100}[）)])?(?:\*\*)?[ \t]*[:：]?[ \t]*(?:\*\*)?[ \t]*$`)
	curlFileInputRe   = regexp.MustCompile(`(?i)(?:--data(?:-raw|-binary|-ascii|-urlencode)?|--header|-d|-H)(?:[= \t]+)['"]?@[^ \t\n]+|(?:--upload-file|--config|-T|-K)[= \t]+[^ \t\n]+`)
	httpHeaderLineRe  = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9a-zA-Z-]+:[ \t]*[^\n]*$`)
	fenceLineRe       = regexp.MustCompile("^[ \\t]*(`{3,}|~{3,})([^\\n]*)$")
	httpRequestRe     = regexp.MustCompile(`(?m)^[ \t]*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)[ \t]+(?:/[^ \t\n]*|https?://[^ \t\n]+|[^ \t\n]+:[0-9]+)[ \t]+HTTP/[0-9.]+[ \t]*\n`)
	httpHostRe        = regexp.MustCompile(`(?im)^[ \t]*(?:Host|:authority):[ \t]*[^ \t\n]+`)
	httpResponseRe    = regexp.MustCompile(`(?m)^[ \t]*HTTP/[0-9.]+[ \t]+[1-5][0-9]{2}(?:[ \t]+[^\n]*)?\n`)
	curlCommandRe     = regexp.MustCompile(`(?m)^[ \t]*(?:[$#][ \t]+)?curl(?:\.exe)?[ \t]+[^\n]*https?://[^ \t\n'"<>]+`)
	scriptSyntaxRe    = regexp.MustCompile(`(?m)^[ \t]*(?:import[ \t]+[a-zA-Z_]|from[ \t]+[a-zA-Z_]|(?:const|let|var)[ \t]+[a-zA-Z_]|[a-zA-Z_][\w.]*[ \t]*=|(?:async[ \t]+)?(?:def|function)[ \t]+[a-zA-Z_]|package[ \t]+[a-zA-Z_]|<\?php)`)
	scriptActionRe    = regexp.MustCompile(`(?i)(?:\.(?:get|post|put|patch|delete|request|do|execute|executemany|connect|send|sendall|recv|query|run|popen|getelementbyid|queryselector)\s*\(|\b(?:fetch|curl_exec|file_get_contents|XMLHttpRequest)\s*\()`)
	commandPromptRe   = regexp.MustCompile(`(?m)^[ \t]*(?:[$#][ \t]+|PS[ \t]+[^\n>]*>[ \t]*)([a-zA-Z_][\w./-]*(?:[ \t]+[^\n]+)?)`)
	scriptRunnerRe    = regexp.MustCompile(`(?i)^(?:python[0-9.]*|node|ruby|php|perl|bash|sh|powershell|pwsh|cmd|go)[ \t]+`)
	protocolClientRe  = regexp.MustCompile(`(?im)^[ \t]*(?:C:|Client:|>>>|send:)[ \t]+[^\n]+`)
	protocolServerRe  = regexp.MustCompile(`(?im)^[ \t]*(?:S:|Server:|<<<|recv:)[ \t]+(?:[0-9]{3}\b|[0-9a-f]{2}[ \t]+[0-9a-f]{2}\b|\{)[^\n]*`)
	protocolTargetRe  = regexp.MustCompile(`(?i)\b(?:[a-z][a-z0-9+.-]*://[^\s<>]+|[a-z0-9.-]+:[0-9]{1,5})`)
	resultValueRe     = regexp.MustCompile(`(?m)^[ \t]*(?:uid=[0-9]+[^\n]*|(?:status(?:_code)?|exit_code|inserted_rows|new_id)[ \t]*[=:][ \t]*[0-9]+[^\n]*)$`)
	sqlResultHeaderRe = regexp.MustCompile(`(?im)^[ \t|]*(?:new_id[ \t|]+inserted_rows|inserted_rows[ \t|]+new_id|ID[ \t|]+user_login|rows affected)[^\n]*$`)
	sqlResultRowRe    = regexp.MustCompile(`(?m)^[ \t|]*[0-9]+[ \t|]+[^\n]+$`)
	oobTimeRe         = regexp.MustCompile(`\b[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}`)
	oobQueryRe        = regexp.MustCompile(`(?im)^[^\n]*\b(?:query|qname|hostname)[=:][ \t]*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})[^\n]*\b(?:type|qtype|protocol)[=:][ \t]*(?:A|AAAA|TXT|CNAME|DNS|HTTP)\b`)
	placeholderRe     = regexp.MustCompile(`(?im)(?:^|[ \t])\.{3}(?:[ \t]|$)|^[ \t]*(?:#|//)?[ \t]*(?:TODO\b[^\n]*|…|pass)[ \t]*$|<(?:target|host|payload|token)>|\b(?:YOUR|REPLACE)_(?:TARGET|HOST|PAYLOAD|TOKEN)\b|\([ \t]*\.{3}[ \t]*\)`)
)

// HasValidPOC 与落库校验共用同一标准；围栏、关键词或文件名本身不是证据。
func HasValidPOC(evidence string) bool {
	return ValidateEvidencePOC(evidence) == nil
}

// ValidateEvidencePOC 只做静态完整性校验，不执行脚本或访问目标，也不能替代独立安全边界验证。
// evidence 必须同时包含可复现的输入和原始结果，支持脚本、HTTP、协议和 OOB 证据。
func ValidateEvidencePOC(evidence string) error {
	trimmed := strings.TrimSpace(evidence)
	if utf8.RuneCountInString(trimmed) < minEvidenceRunes {
		return fmt.Errorf("evidence 过短，不能作为 POC；请贴完整可运行脚本或原始请求，以及原始响应/执行输出")
	}
	if reason := omittedCriticalEvidence(trimmed); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	// 保留原文落库，只在校验时归一换行。HTTP 的空行也是完整请求/响应的一部分。
	normalized := strings.ReplaceAll(strings.ReplaceAll(evidence, "\r\n", "\n"), "\r", "\n")
	segments, err := evidenceSegments(normalized)
	if err != nil {
		return err
	}
	if !hasReproducibleEvidence(segments) {
		if evidenceFileRe.MatchString(trimmed) {
			return fmt.Errorf("evidence 只引用了证据/POC 文件名，或缺少文件内的完整脚本/请求与原始结果；请直接粘贴文件内容，不能以文件名代替")
		}
		return fmt.Errorf("evidence 缺少完整可复核的输入与原始结果。须粘贴完整脚本/curl + 实际输出、完整 HTTP 请求/响应、带目标的协议收发原文，或触发请求 + 含时间戳和关联域名的 DNSLog/OOB 原始记录；脚本与结果请用独立闭合围栏或明确的“实际输出：”标题分开。纯摘要、空/假代码围栏、仅脚本无输出或仅结果均无效；只需补录已取得的原文，不要为录入重新执行测试")
	}
	return nil
}

type evidenceSegment struct {
	text   string
	code   bool
	output bool
}

// evidenceSegments 仅提取闭合围栏的正文，避免把 ``` 或语言标签当成证据。
func evidenceSegments(evidence string) ([]evidenceSegment, error) {
	var segments []evidenceSegment
	var body strings.Builder
	fence := ""
	output := false
	flush := func(code bool) {
		if strings.TrimSpace(body.String()) != "" {
			segments = append(segments, evidenceSegment{text: body.String(), code: code, output: output})
			output = false
		}
		body.Reset()
	}
	for _, line := range strings.SplitAfter(evidence, "\n") {
		if fence == "" && outputHeadingRe.MatchString(strings.TrimSuffix(line, "\n")) {
			flush(false)
			output = true
			continue
		}
		match := fenceLineRe.FindStringSubmatch(strings.TrimSuffix(line, "\n"))
		if fence == "" && match != nil {
			flush(false)
			fence = match[1]
			continue
		}
		if fence != "" && match != nil && match[1][0] == fence[0] && len(match[1]) >= len(fence) && strings.TrimSpace(match[2]) == "" {
			flush(true)
			fence = ""
			continue
		}
		body.WriteString(line)
	}
	if fence != "" {
		return nil, fmt.Errorf("evidence 的代码围栏未闭合，可能缺少脚本或输出；请粘贴完整内容并闭合围栏")
	}
	flush(false)
	return segments, nil
}

func hasReproducibleEvidence(segments []evidenceSegment) bool {
	var inputs []string
	hasResult := false
	var oobDomains []string
	for _, segment := range segments {
		text := segment.text
		script := scriptSyntaxRe.MatchString(text) && scriptActionRe.MatchString(text)
		curlText := strings.ReplaceAll(strings.ReplaceAll(text, "\\\n", " "), "`\n", " ")
		input := script || hasHTTPRequest(text) || (curlCommandRe.MatchString(curlText) && !curlFileInputRe.MatchString(curlText)) ||
			(sqlWriteStartRe.MatchString(text) && strings.Contains(strings.ToUpper(text), "VALUES")) || sqlUpdateRe.MatchString(text) ||
			(protocolClientRe.MatchString(text) && protocolTargetRe.MatchString(text))
		if command := commandPromptRe.FindStringSubmatch(text); command != nil && !scriptRunnerRe.MatchString(command[1]) && !strings.HasPrefix(strings.ToLower(command[1]), "curl") {
			input = true
		}
		if input && !placeholderRe.MatchString(text) {
			inputText := text
			if !script {
				// 同一段落里的响应/回连日志不应反过来满足触发输入的关联域名。
				if loc := httpResponseRe.FindStringIndex(inputText); loc != nil {
					inputText = inputText[:loc[0]]
				}
				if loc := oobQueryRe.FindStringIndex(inputText); loc != nil {
					inputText = inputText[:loc[0]]
				}
			}
			inputs = append(inputs, inputText)
		}
		// 脚本中的字符串常量、print 等不能冒充执行输出。
		if script {
			continue
		}
		result := strings.TrimSpace(text)
		// 明确标注且与输入分离的原始 stdout 不限定为 JSON/HTTP/固定键名。
		// 这里只判断文本完整性，不证明执行真实性；空输出、占位或仅文件名仍不算结果。
		independentOutput := segment.output && !input && result != "" && !placeholderRe.MatchString(text) && evidenceFileRe.FindString(result) != result && !descriptiveOnlyPOCOutput(result)
		if independentOutput || hasHTTPResponse(text) || protocolServerRe.MatchString(text) || resultValueRe.MatchString(text) ||
			(sqlResultHeaderRe.MatchString(text) && sqlResultRowRe.MatchString(text)) ||
			(json.Valid([]byte(result)) && len(result) > 2 && (strings.HasPrefix(result, "{") || strings.HasPrefix(result, "["))) {
			hasResult = true
		}
		if oobTimeRe.MatchString(text) {
			for _, match := range oobQueryRe.FindAllStringSubmatch(text, -1) {
				oobDomains = append(oobDomains, strings.ToLower(match[1]))
			}
		}
	}
	if len(inputs) == 0 {
		return false
	}
	if hasResult {
		return true
	}
	// OOB 的关联域名须同时出现在触发输入中；只有回连结论或孤立日志不能复现。
	for _, input := range inputs {
		for _, domain := range oobDomains {
			if strings.Contains(strings.ToLower(input), domain) {
				return true
			}
		}
	}
	return false
}

func hasHTTPRequest(text string) bool {
	for _, loc := range httpRequestRe.FindAllStringIndex(text, -1) {
		if headers, ok := httpHeaders(text[loc[1]:]); ok {
			requestLine := text[loc[0]:loc[1]]
			if httpHostRe.MatchString(headers) || strings.Contains(requestLine, "http://") || strings.Contains(requestLine, "https://") {
				return true
			}
		}
	}
	return false
}

func hasHTTPResponse(text string) bool {
	for _, loc := range httpResponseRe.FindAllStringIndex(text, -1) {
		if _, ok := httpHeaders(text[loc[1]:]); ok {
			return true
		}
	}
	return false
}

// httpHeaders 要求完整头部和结束空行；避免把后续摘要或响应拼成未完成的请求。
func httpHeaders(text string) (string, bool) {
	if strings.HasPrefix(text, "\n") {
		return "", true
	}
	end := strings.Index(text, "\n\n")
	if end < 0 {
		return "", false
	}
	headers := text[:end]
	for _, line := range strings.Split(headers, "\n") {
		if !httpHeaderLineRe.MatchString(line) {
			return "", false
		}
	}
	return headers, true
}

func omittedCriticalEvidence(evidence string) string {
	if sqlOmittedColsRe.MatchString(evidence) || sqlOmittedValsRe.MatchString(evidence) {
		return "evidence 省略了受控写入的关键 SQL。禁止 INSERT INTO table(...) / VALUES('x',...); 这类裁剪。必须贴完整列名、完整 VALUES，以及 inserted_rows/new_id 和回查结果"
	}
	if (sqlWriteStartRe.MatchString(evidence) || sqlUpdateRe.MatchString(evidence)) && ellipsisRe.MatchString(evidence) {
		return "evidence 中的 SQL 写入语句含省略号。受控写入必须保留完整语句和执行输出，不能用 ... / … 代替列、取值或回查字段"
	}
	if omissionPhraseRe.MatchString(evidence) {
		return "evidence 把关键输出指到外部文件或写了“省略”。请把 POC 脚本和原始执行输出直接贴进本字段，不要写“详见 xxx.txt”"
	}
	return ""
}

// EvidencePOCFieldDescription 供 record_vulnerability.evidence 的工具 schema 复用。
func EvidencePOCFieldDescription() string {
	return "证据 / POC（必需）：必须让未参与对话的人只靠本记录复核。能脚本化时贴完整可运行 POC 脚本（语言不限，Python/curl 均可），含目标、入口、参数、payload、认证头和关键 SQL/body；紧贴本次已取得的实际执行输出原文；脚本与输出分段，输出可用“实际输出：”“响应 1（原文）：”或“该脚本的实际执行输出（终端逐字原文）：”等标题标识，也可使用独立闭合代码围栏。浏览器、协议或 OOB 场景也可用完整原始请求/响应、带目标的协议收发记录、触发输入 + 含时间戳和关联域名的 DNSLog/OOB 原始记录，不强制 Python。受控写入必须贴完整 INSERT/UPDATE、inserted_rows/new_id 和回查结果。禁止纯摘要、仅脚本无输出、仅结果、空/假/未闭合代码围栏、文件名引用及 ... 占位。利用链的前置权限、执行顺序、每步输入与输出依赖写入 preconditions/reproduction_steps；已保存证据不足时应补录现有原文，不得编造输出或为录入自动执行脚本。"
}
