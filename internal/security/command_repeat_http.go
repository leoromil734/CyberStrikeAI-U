package security

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// HTTP identity deliberately retains the escaped path and the entire raw query:
// no numeric/nonce/query stripping, sorting, path cleaning or percent decoding.
func repeatURLIdentity(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Opaque != "" || strings.ContainsAny(raw, "\r\n\t ") {
		return ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	u.Host = strings.ToLower(u.Host)
	u.Fragment, u.RawFragment = "", ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

func repeatHTTPRequests(toolName string, args map[string]interface{}) (map[string]int, error) {
	if index := strings.LastIndex(toolName, "::"); index >= 0 {
		toolName = toolName[index+2:]
	}
	switch toolName {
	case "http-framework-test":
		if extra, ok := args["additional_args"].(string); ok && strings.TrimSpace(extra) != "" {
			// The generic executor appends these as raw argv; argparse can then
			// override --url/--repeat (including abbreviated option names).
			return nil, fmt.Errorf("http-framework-test 请使用明确的 url/repeat 参数及 httpx_options，禁止 additional_args 覆盖目标或次数")
		}
		raw, _ := args["url"].(string)
		identity := repeatURLIdentity(raw)
		if identity == "" {
			return nil, nil
		}
		cost := 1
		if value, ok := args["repeat"]; ok && value != nil {
			n, parseErr := strconv.Atoi(fmt.Sprint(value))
			if parseErr != nil || n > httpRepeatLimit {
				return nil, fmt.Errorf("http-framework-test repeat 必须是最多 %d 次的整数；%s", httpRepeatLimit, repeatGuardGuidance)
			}
			if n > 1 {
				cost = int(n)
			}
		}
		// Framework methods share the URL allowance by design. Curl uses a
		// separate namespace with an independent allowance for each method.
		return map[string]int{repeatHash("framework\x00" + identity): cost}, nil
	case "exec", "execute", "curl":
		command, _ := args["command"].(string)
		return repeatCurlRequests(command), nil
	}
	return nil, nil
}

func repeatGuardedHTTP(toolName string, args map[string]interface{}) bool {
	requests, err := repeatHTTPRequests(toolName, args)
	return err != nil || len(requests) > 0
}

func repeatCurlRequests(command string) map[string]int {
	// Eino's streaming wrapper prepends exactly this trusted non-buffering
	// export before calling the native shell. It does not change curl's target.
	command = strings.TrimPrefix(command, "export PYTHONUNBUFFERED=1\n")
	command = strings.TrimSpace(command)
	if strings.HasSuffix(command, "&") && !strings.HasSuffix(command, "&&") {
		command = strings.TrimSuffix(command, "&")
	}
	normalized, ok := simpleRepeatCommand(command)
	if !ok {
		return nil // Never guess at scripts, substitutions or shell pipelines.
	}
	// Reuse the executor's argv parser after proving its literal subset. Shell
	// mode additionally retains empty quoted words and literal single-quote escapes.
	words := parseLiteralToolArgs(normalized, true)
	if len(words) < 2 {
		return nil
	}
	switch words[0] {
	case "curl", "curl.exe", "/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl":
	default:
		return nil
	}
	var urls, data []string
	method := ""
	head, get, post, upload, globoff := false, false, false, false, false
	consume := func(name, value string) bool {
		switch name {
		case "X", "request":
			if value == "" || strings.ContainsAny(value, " \t\r\n") {
				return false
			}
			method = value // HTTP method tokens are case-sensitive, including -X.
		case "url":
			urls = append(urls, value)
		case "d", "data", "data-ascii", "data-binary", "data-raw", "data-urlencode", "json":
			post = true
			if name != "data-raw" && strings.HasPrefix(value, "@") {
				data = append(data, "\x00") // File data is unknowable for -G.
			} else if name == "data-urlencode" {
				if strings.Contains(value, "@") && !strings.Contains(value, "=") {
					data = append(data, "\x00")
				} else if key, val, found := strings.Cut(value, "="); found {
					encoded := strings.ReplaceAll(url.QueryEscape(val), "+", "%20")
					if key != "" {
						encoded = key + "=" + encoded
					}
					data = append(data, encoded)
				} else {
					data = append(data, strings.ReplaceAll(url.QueryEscape(value), "+", "%20"))
				}
			} else {
				data = append(data, value)
			}
		case "F", "form", "form-string":
			post = true
			data = append(data, "\x00")
		case "T", "upload-file":
			upload = true
		case "H", "header", "A", "user-agent", "b", "cookie", "c", "cookie-jar", "e", "referer",
			"u", "user", "x", "proxy", "U", "proxy-user", "o", "output", "D", "dump-header", "w", "write-out",
			"m", "max-time", "connect-timeout", "retry", "retry-delay", "retry-max-time", "cacert", "cert", "key", "resolve", "connect-to", "max-redirs":
			// Do not scan option values for URLs (header/proxy/body are not targets).
		default:
			return false
		}
		return true
	}
	flag := func(name string) bool {
		switch name {
		case "I", "head":
			head = true
		case "G", "get":
			get = true
		case "g", "globoff":
			globoff = true
		case "q", "disable", "s", "silent", "S", "show-error", "k", "insecure", "i", "include", "L", "location",
			"f", "fail", "fail-with-body", "v", "verbose", "N", "no-buffer", "4", "ipv4", "6", "ipv6",
			"O", "remote-name", "J", "remote-header-name", "path-as-is", "compressed", "http1.0", "http1.1", "http2", "http3":
		default:
			return false
		}
		return true
	}
	for i := 1; i < len(words); i++ {
		word := words[i]
		if word == "--" {
			urls = append(urls, words[i+1:]...)
			break
		}
		if strings.HasPrefix(word, "--") {
			name, value, equals := strings.Cut(word[2:], "=")
			if !equals && flag(name) {
				continue
			}
			if !equals {
				i++
				if i == len(words) {
					return nil
				}
				value = words[i]
			}
			if !consume(name, value) {
				return nil
			}
		} else if strings.HasPrefix(word, "-") {
			for j := 1; j < len(word); j++ {
				name := word[j : j+1]
				if flag(name) {
					continue
				}
				value := word[j+1:]
				if value == "" {
					i++
					if i == len(words) {
						return nil
					}
					value = words[i]
				}
				if !consume(name, value) {
					return nil
				}
				break
			}
		} else {
			urls = append(urls, word)
		}
	}
	if method == "" {
		switch {
		case head:
			method = "HEAD"
		case get:
			method = "GET"
		case upload:
			method = "PUT"
		case post:
			method = "POST"
		default:
			method = "GET"
		}
	}
	requests := make(map[string]int)
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || (!globoff && strings.ContainsAny(u.Path+u.RawQuery, "{}[]")) {
			return nil
		}
		if get && len(data) > 0 {
			query := strings.Join(data, "&")
			if strings.ContainsRune(query, 0) {
				return nil
			}
			if u.RawQuery != "" {
				u.RawQuery += "&" + query
			} else {
				u.RawQuery = query
			}
			raw = u.String()
		}
		identity := repeatURLIdentity(raw)
		if identity == "" {
			return nil
		}
		requests[repeatHash("curl\x00"+method+"\x00"+identity)]++
	}
	return requests
}
