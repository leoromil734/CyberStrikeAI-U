package coverage

// This module only reads registered local originals. It never executes a command
// or makes a request. An observation establishes an HTTP exchange, not a finding
// or a negative security test for an arbitrary risk family.
import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"cyberstrike-ai/internal/evidence"
)

const MaxHTTPOriginalBytes int64 = 16 << 20

type OriginalBinding struct {
	evidence.Access
	AssessmentID string
	ScopeID      string
}

// HTTPObservation is intentionally opaque: callers cannot turn model fields or
// parsed source metadata into a verified observation by constructing a struct.
type HTTPObservation struct {
	binding                                               OriginalBinding
	executionID, inputID, outputID, inputHash, outputHash string
	url, method, tool                                     string
	status                                                int
}

func (o HTTPObservation) Tool() string             { return o.tool }
func (o HTTPObservation) ExecutionID() string      { return o.executionID }
func (o HTTPObservation) OutputArtifactID() string { return o.outputID }
func (o HTTPObservation) Matches(rawURL, method string) bool {
	a, err := exactHTTPIdentity(rawURL, method)
	b, other := exactHTTPIdentity(o.url, o.method)
	return o.executionID != "" && err == nil && other == nil && a == b
}
func (o HTTPObservation) Binding() OriginalBinding { return o.binding }
func (o HTTPObservation) EvidenceRef() string {
	return fmt.Sprintf("execution:%s input_artifact:%s input_sha256:%s output_artifact:%s output_sha256:%s", o.executionID, o.inputID, o.inputHash, o.outputID, o.outputHash)
}
func (o HTTPObservation) StatusCode() int { return o.status }

func exactHTTPIdentity(raw, method string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || !oneOf(u.Scheme, "http", "https") || u.Fragment != "" || strings.ContainsAny(raw, "\r\n\t ") || !httpMethod.MatchString(method) {
		return "", fmt.Errorf("invalid exact HTTP identity")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	// Preserve all query values, ordering, percent escapes and an empty trailing ?.
	return u.Scheme + "\n" + host + ":" + port + "\n" + method + "\n" + path + "\n" + u.RawQuery + "\n" + strconv.FormatBool(u.ForceQuery), nil
}

var httpMethod = regexp.MustCompile(`^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$`)
var httpStatus = regexp.MustCompile(`^HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?) ([2-5][0-9]{2})(?: [^\r\n]*)?$`)
var headerName = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)

func ReadCompleteOriginal(ctx context.Context, registry *evidence.Registry, e evidence.Execution, id string, input bool) ([]byte, evidence.Artifact, error) {
	if registry == nil {
		return nil, evidence.Artifact{}, evidence.ErrDenied
	}
	a, err := registry.Metadata(ctx, id)
	if err != nil {
		return nil, a, err
	}
	if a.ExecutionID != e.ID || a.Access != e.Access || a.Completion != evidence.Complete || (a.Kind == "input") != input || a.Size <= 0 || a.Size > MaxHTTPOriginalBytes {
		return nil, a, evidence.ErrDenied
	}
	// Output must be the captured output, not a tool-created arbitrary file.
	if !input && a.Kind != "stdout" && a.Kind != "output" {
		return nil, a, evidence.ErrDenied
	}
	f, checked, err := registry.OpenVerified(ctx, id)
	if err != nil {
		return nil, a, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxHTTPOriginalBytes+1))
	if err != nil || int64(len(data)) != a.Size {
		return nil, a, evidence.ErrChanged
	}
	if err = registry.CheckUnchanged(ctx, f, checked); err != nil {
		return nil, a, err
	}
	return data, a, nil
}

func VerifyHTTPOriginal(ctx context.Context, registry *evidence.Registry, binding OriginalBinding, executionID, inputID, outputID string) (HTTPObservation, error) {
	empty := HTTPObservation{}
	if registry == nil || binding.ProjectID == "" || binding.Owner == "" || binding.ConversationID == "" || binding.AssessmentID == "" || binding.ScopeID == "" || inputID == outputID {
		return empty, evidence.ErrDenied
	}
	e, err := registry.Execution(ctx, executionID)
	if err != nil {
		return empty, err
	}
	if e.Access != binding.Access || e.AssessmentID != binding.AssessmentID || e.ScopeID != binding.ScopeID || e.Status != "completed" || e.Completion != evidence.Complete || e.TimedOut || e.Capped || e.StartedAt.IsZero() || e.FinishedAt.Before(e.StartedAt) {
		return empty, evidence.ErrDenied
	}
	input, in, err := ReadCompleteOriginal(ctx, registry, e, inputID, true)
	if err != nil {
		return empty, err
	}
	output, out, err := ReadCompleteOriginal(ctx, registry, e, outputID, false)
	if err != nil {
		return empty, err
	}
	if e.OutputBytes != out.Size {
		return empty, evidence.ErrDenied
	}
	latest, latestErr := registry.Execution(ctx, executionID)
	latestIn, inputErr := registry.Metadata(ctx, inputID)
	latestOut, outputErr := registry.Metadata(ctx, outputID)
	if latestErr != nil || inputErr != nil || outputErr != nil || latest != e || latestIn != in || latestOut != out {
		return empty, evidence.ErrChanged
	}
	raw, method, status, err := parseHTTPOriginal(e.Tool, input, output)
	if err != nil {
		return empty, err
	}
	return HTTPObservation{binding: binding, executionID: e.ID, inputID: in.ID, outputID: out.ID, inputHash: in.SHA256, outputHash: out.SHA256, url: raw, method: method, tool: e.Tool, status: status}, nil
}

func parseHTTPOriginal(tool string, input, output []byte) (string, string, int, error) {
	var args map[string]any
	if err := json.Unmarshal(input, &args); err != nil {
		return "", "", 0, fmt.Errorf("invalid original input")
	}
	switch tool {
	case "http-framework-test":
		return parseFrameworkExchange(args, string(output))
	case "exec", "execute", "curl":
		return parseCurlExchange(tool, args, string(output))
	default:
		return "", "", 0, fmt.Errorf("tool is not a supported independent HTTP exchange")
	}
}

func responseStatus(block string) (int, bool) {
	lines := strings.Split(strings.ReplaceAll(block, "\r\n", "\n"), "\n")
	if len(lines) < 3 {
		return 0, false
	}
	match := httpStatus.FindStringSubmatch(lines[0])
	if match == nil || strings.Contains(strings.ToLower(lines[0]), "connection established") {
		return 0, false
	}
	headers := 0
	for _, line := range lines[1:] {
		if line == "" {
			n, _ := strconv.Atoi(match[1])
			return n, headers > 0
		}
		key, _, ok := strings.Cut(line, ":")
		if !ok || !headerName.MatchString(key) {
			return 0, false
		}
		headers++
	}
	return 0, false
}

func parseFrameworkExchange(args map[string]any, output string) (string, string, int, error) {
	fail := func() (string, string, int, error) {
		return "", "", 0, fmt.Errorf("framework output lacks an unambiguous bound request/response")
	}
	raw, _ := args["url"].(string)
	method, _ := args["method"].(string)
	if method == "" {
		method = "GET"
	}
	method = strings.ToUpper(method)
	if _, err := exactHTTPIdentity(raw, method); err != nil {
		return fail()
	}
	// Redirects, repeated exchanges and response filtering cannot prove that the
	// observed response belongs to this exact request. Keep them unresolved.
	for _, key := range []string{"follow_redirects", "download", "response_filter", "additional_options"} {
		if v, ok := args[key]; ok && v != nil && v != false && v != "false" && v != "" {
			return fail()
		}
	}
	if v, ok := args["repeat"]; ok && fmt.Sprint(v) != "1" {
		return fail()
	}
	output = strings.ReplaceAll(output, "\r\n", "\n")
	marker := "===== Prepared Request =====\n"
	if strings.Count(output, marker) != 1 || strings.Count(output, "===== Response #") != 1 {
		return fail()
	}
	_, prepared, _ := strings.Cut(output, marker)
	request, rest, ok := strings.Cut(prepared, "\n===== Response #1 =====\n")
	if !ok {
		return fail()
	}
	lines := strings.Split(request, "\n")
	if len(lines) < 4 || lines[0] != "Method: "+method || lines[1] != "URL: "+raw {
		return fail()
	}
	hasHeaders, hasBody, hasHost := false, false, false
	requestURL, _ := url.Parse(raw)
	for _, line := range lines[2:] {
		if strings.HasPrefix(line, "Wire request-target: ") {
			wire := strings.TrimPrefix(line, "Wire request-target: ")
			path := requestURL.EscapedPath()
			if path == "" {
				path = "/"
			}
			if requestURL.RawQuery != "" || requestURL.ForceQuery {
				path += "?" + requestURL.RawQuery
			}
			if wire != path && wire != raw {
				return fail()
			}
		}
		if strings.HasPrefix(line, "  ") {
			name, value, found := strings.Cut(strings.TrimSpace(line), ":")
			if found && strings.EqualFold(name, "host") {
				if hasHost || !strings.EqualFold(strings.TrimSpace(value), requestURL.Host) {
					return fail()
				}
				hasHost = true
			}
		}
		if strings.HasPrefix(line, "Headers (") && strings.HasSuffix(line, " total):") {
			hasHeaders = true
		}
		if strings.HasPrefix(line, "Body: ") {
			hasBody = true
		}
	}
	if !hasHeaders || !hasBody {
		return fail()
	}
	response, meta, ok := strings.Cut(rest, "\n----- Meta #1 -----\n")
	if !ok || !strings.Contains(meta, "Wall Time (client): ") || !strings.Contains(meta, "Encoding Used: ") {
		return fail()
	}
	if strings.Contains(meta, "Redirects:") && !regexp.MustCompile(`(?m)^Redirects: 0$`).MatchString(meta) {
		return fail()
	}
	status, ok := responseStatus(response)
	if !ok {
		return fail()
	}
	return raw, method, status, nil
}

// shellWords is deliberately not a shell interpreter. A single direct argv is
// allowed; substitutions, redirections, pipelines and script wrappers are not.
func shellWords(command string) ([]string, bool) {
	var words []string
	var word strings.Builder
	quote := rune(0)
	started := false
	for _, c := range command {
		if c == '\n' || c == '\r' || c == 0 || c == '`' || c == '$' || c == '\\' {
			return nil, false
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteRune(c)
			}
			started = true
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			started = true
			continue
		}
		if strings.ContainsRune(";|&<>(){}", c) {
			return nil, false
		}
		if c == ' ' || c == '\t' {
			if started {
				words = append(words, word.String())
				word.Reset()
				started = false
			}
			continue
		}
		word.WriteRune(c)
		started = true
	}
	if quote != 0 {
		return nil, false
	}
	if started {
		words = append(words, word.String())
	}
	return words, len(words) > 0
}

func parseCurlExchange(tool string, args map[string]any, output string) (string, string, int, error) {
	fail := func() (string, string, int, error) {
		return "", "", 0, fmt.Errorf("not a provable direct curl request/response")
	}
	command, _ := args["command"].(string)
	words, ok := shellWords(command)
	if !ok || len(words) < 3 || !oneOf(words[0], "curl", "/usr/bin/curl", "/bin/curl") || !oneOf(words[1], "-q", "--disable") {
		// Disable implicit curlrc options before any other flag; otherwise a
		// config file could add another URL, redirect, or fabricated --write-out.
		return fail()
	}
	method, raw := "GET", ""
	include, head, explicitMethod, data, pathAsIs := false, false, false, false, false
	for i := 1; i < len(words); i++ {
		w := words[i]
		switch w {
		case "-X", "--request":
			i++
			if i >= len(words) {
				return fail()
			}
			method = words[i]
			explicitMethod = true
		case "--url":
			i++
			if i >= len(words) || raw != "" {
				return fail()
			}
			raw = words[i]
		case "-H", "--header":
			i++
			if i >= len(words) || strings.HasPrefix(words[i], "@") || strings.ContainsAny(words[i], "\r\n") {
				return fail()
			}
			k, _, found := strings.Cut(words[i], ":")
			if !found || !headerName.MatchString(k) || strings.EqualFold(k, "host") {
				return fail()
			}
		case "--max-time", "--connect-timeout":
			i++
			if i >= len(words) {
				return fail()
			}
			if _, err := strconv.ParseFloat(words[i], 64); err != nil {
				return fail()
			}
		case "-d", "--data", "--data-raw", "--data-binary":
			i++
			if i >= len(words) || strings.HasPrefix(words[i], "@") {
				return fail()
			}
			data = true
		case "--path-as-is":
			pathAsIs = true
		case "--include":
			include = true
		case "--head":
			head = true
			include = true
		case "--silent", "--show-error", "--insecure", "--disable", "--globoff":
		default:
			if strings.HasPrefix(w, "-") {
				for _, c := range strings.TrimPrefix(w, "-") {
					switch c {
					case 'i':
						include = true
					case 'I':
						head = true
						include = true
					case 's', 'S', 'k', 'q', 'g':
					default:
						return fail()
					}
				}
			} else {
				if raw != "" {
					return fail()
				}
				raw = w
			}
		}
	}
	if data && !explicitMethod {
		method = "POST"
	}
	if head {
		if data || (explicitMethod && method != "HEAD") {
			return fail()
		}
		method = "HEAD"
	}
	if !include || strings.ContainsAny(raw, "{}[]") {
		return fail()
	}
	if _, err := exactHTTPIdentity(raw, method); err != nil {
		return fail()
	}
	parsedURL, _ := url.Parse(raw)
	if !pathAsIs {
		for _, part := range strings.Split(parsedURL.EscapedPath(), "/") {
			if part == "." || part == ".." {
				return fail()
			}
		}
	}
	status, ok := responseStatus(strings.TrimLeft(output, "\r\n"))
	if !ok {
		return fail()
	}
	return raw, method, status, nil
}
