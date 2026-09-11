package vulnquality

import (
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
	evidenceFileRe   = regexp.MustCompile(`(?i)\b[\w.-]+(?:_out|_poc|_evidence)\.(?:txt|log|sql|py|sh|out)\b|\b(?:poc|exploit|r\d+_[a-z0-9_]+)\.(?:py|sh|sql|txt)\b`)
	omissionPhraseRe = regexp.MustCompile(`详见[^\n]{0,80}(?:\.txt|\.log|\.py|\.sql)|完整输出见|见附件|此处省略|关键部分省略|输出已省略|命令已省略`)
)

// HasValidPOC 判断 evidence 是否包含可复核的技术证据特征。
func HasValidPOC(evidence string) bool {
	if utf8.RuneCountInString(strings.TrimSpace(evidence)) < minEvidenceRunes {
		return false
	}

	hasCodeBlock := strings.Contains(evidence, "```")
	hasHTTPRequest := strings.Contains(evidence, "POST ") || strings.Contains(evidence, "GET ") ||
		strings.Contains(evidence, "PUT ") || strings.Contains(evidence, "PATCH ") ||
		strings.Contains(evidence, "HTTP/") || strings.Contains(evidence, "Host:")
	hasCurlCommand := strings.Contains(evidence, "curl ")
	hasDNSLog := (strings.Contains(evidence, "dnslog") || strings.Contains(evidence, "ceye") ||
		strings.Contains(evidence, "interactsh") || strings.Contains(evidence, "burpcollaborator")) &&
		(strings.Contains(evidence, "202") || strings.Contains(evidence, "时间"))
	hasCommandOutput := strings.Contains(evidence, "$ ") || strings.Contains(evidence, "# ") ||
		strings.Contains(evidence, "root@") || strings.Contains(evidence, "C:\\")
	hasPythonScript := strings.Contains(evidence, "import ") &&
		(strings.Contains(evidence, "requests") || strings.Contains(evidence, "urllib") ||
			strings.Contains(evidence, "http.client") || strings.Contains(evidence, "pymysql") ||
			strings.Contains(evidence, "mysql.connector") || strings.Contains(evidence, "psycopg"))
	hasSQLWrite := sqlWriteStartRe.MatchString(evidence) && strings.Contains(strings.ToUpper(evidence), "VALUES")
	hasPayload := strings.Contains(evidence, "payload") || strings.Contains(evidence, "<script") ||
		strings.Contains(evidence, "' or ") || strings.Contains(evidence, "union select")

	strongEvidence := hasCodeBlock || hasHTTPRequest || hasCurlCommand || hasDNSLog ||
		hasCommandOutput || hasPythonScript || hasSQLWrite
	weakEvidence := hasPayload
	return strongEvidence || (weakEvidence && utf8.RuneCountInString(evidence) > 200)
}

// ValidateEvidencePOC 拒绝描述性空话、文件名占位和被裁剪的关键写入/查询证据。
func ValidateEvidencePOC(evidence string) error {
	trimmed := strings.TrimSpace(evidence)
	if utf8.RuneCountInString(trimmed) < minEvidenceRunes {
		return fmt.Errorf("evidence 过短，不能作为 POC；请贴完整可运行脚本或原始请求/响应/命令输出")
	}
	if !HasValidPOC(trimmed) {
		return fmt.Errorf("evidence 缺少可复核技术证据。须包含完整 HTTP 请求/响应、curl/脚本+输出、DNSLog/OOB 记录，或数据库写入/回查原文；仅写“存在漏洞/成功执行”无效")
	}
	if reason := omittedCriticalEvidence(trimmed); reason != "" {
		return fmt.Errorf("%s", reason)
	}
	return nil
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
	if loc := evidenceFileRe.FindStringIndex(evidence); loc != nil {
		if !embeddedFilePayload(evidence, loc[0], loc[1]) {
			return "evidence 只引用了证据/POC 文件名（如 r3_insert_redhouse_out.txt），未粘贴文件内的脚本或输出。受控写入必须包含完整 INSERT/UPDATE、inserted_rows 和回查行，不能只写文件名"
		}
	}
	return ""
}

func embeddedFilePayload(evidence string, start, end int) bool {
	window := evidence
	if start >= 0 && end <= len(evidence) {
		from := start - 400
		if from < 0 {
			from = 0
		}
		to := end + 1200
		if to > len(evidence) {
			to = len(evidence)
		}
		window = evidence[from:to]
	}
	hasSQL := sqlWriteStartRe.MatchString(window) && strings.Contains(strings.ToUpper(window), "VALUES") && !ellipsisRe.MatchString(window)
	hasHTTP := strings.Contains(window, "HTTP/") || strings.Contains(window, "Host:") || strings.Contains(window, "curl ")
	hasScript := strings.Contains(window, "import ") || strings.Contains(window, "#!/") || strings.Contains(window, "def ")
	hasResult := strings.Contains(window, "inserted_rows") || strings.Contains(window, "new_id") ||
		strings.Contains(window, "user_login") || strings.Contains(window, "uid=") ||
		strings.Contains(strings.ToLower(window), "rows affected")
	return (hasSQL || hasHTTP || hasScript) && (hasResult || utf8.RuneCountInString(window) > 280)
}

// EvidencePOCFieldDescription 供 record_vulnerability.evidence 的工具 schema 复用。
func EvidencePOCFieldDescription() string {
	return "证据 / POC（必需）：必须让未参与对话的人只靠本字段复现。能脚本化时必须生成完整可运行 POC 脚本（优先 Python；HTTP 也可用完整 curl），脚本含目标、入口、参数、payload、认证头和关键 SQL/body，禁止用 ... 省略。同时必须粘贴本次实际执行输出原文。若存在受控写入（如 r3_insert_redhouse_out.txt），禁止只写文件名，必须贴完整 INSERT/UPDATE 语句、inserted_rows/new_id，以及回查结果（user_login、capabilities 等）。还可补充完整 HTTP 请求/响应、curl 命令+输出、截图说明、DNSLog/OOB（含时间戳）或读文件/命令输出。仅描述性文字（“成功执行”“存在漏洞”）无效。"
}
