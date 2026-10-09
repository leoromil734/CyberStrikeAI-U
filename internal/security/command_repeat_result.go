package security

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"net/textproto"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

var repeatHTTPStatus = regexp.MustCompile(`^HTTP/(?:1\.[01]|2|3) ([1-5][0-9]{2})(?:[^\r\n]*)\r?\n`)
var repeatHTMLNonce = regexp.MustCompile(`(?i)^(\s+nonce\s*=\s*)("[^"]*"|'[^']*')`)

// Hash all available bytes. Persisted previews are not full results and cannot
// establish stability. HTTP headers are parsed with the standard MIME parser;
// only known per-request metadata is ignored, not arbitrary digits/parameters.
func commandResultFingerprintOf(text string) string {
	if strings.Contains(text, "<persisted-output>") || strings.Contains(text, "[原件落盘失败；输出仅为部分预览") {
		return ""
	}
	return repeatHash(normalizeRepeatResponse(text))
}

func normalizeRepeatResponse(text string) string {
	response := strings.TrimLeft(text, "\r\n")
	match := repeatHTTPStatus.FindStringSubmatchIndex(response)
	if match == nil {
		return "output:" + normalizeRepeatBody(text)
	}
	reader := bufio.NewReader(strings.NewReader(response[match[1]:]))
	headers, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil {
		return "raw:" + text // Incomplete/malformed exchanges retain every byte.
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return text
	}
	for _, key := range []string{"Date", "Age", "X-Request-Id", "X-Correlation-Id", "Traceparent", "Tracestate", "Server-Timing", "Cf-Ray", "Content-Length"} {
		// Preserve the presence of a header. Content-Length is redundant with
		// the complete body and may change solely due to nonce length.
		if _, ok := headers[key]; ok {
			headers[key] = []string{"<volatile>"}
		}
	}
	canonicalHeaders, _ := json.Marshal(headers)
	return "http:" + response[match[2]:match[3]] + "\n" + string(canonicalHeaders) + "\n" + normalizeRepeatBody(string(body))
}

// Only top-level response metadata (and explicitly named meta/metadata objects)
// is normalized. Timestamps in business records, IDs, counts, prices, error codes,
// URLs and string whitespace remain meaningful. UseNumber avoids float rounding.
func normalizeRepeatBody(body string) string {
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	value, err := repeatJSONValue(decoder)
	if err == nil {
		if _, err = decoder.Token(); err == io.EOF {
			if object, ok := value.(map[string]interface{}); ok {
				normalizeRepeatMetadata(object)
			}
			if canonical, err := json.Marshal(value); err == nil {
				return "json:" + string(canonical)
			}
		}
	}
	// CSP nonces are recognized only on actual HTML start tags, never in
	// arbitrary text, URL query strings, script text or JSON business values.
	return "text:" + normalizeRepeatHTMLNonce(body)
}

func normalizeRepeatMetadata(object map[string]interface{}) {
	for key, value := range object {
		switch strings.ToLower(key) {
		case "timestamp", "nonce", "request_id", "requestid", "trace_id", "traceid":
			switch value.(type) {
			case string, json.Number:
				object[key] = "<volatile>"
			}
		case "meta", "metadata":
			if nested, ok := value.(map[string]interface{}); ok {
				normalizeRepeatMetadata(nested)
			}
		}
	}
}

// Detect duplicate JSON keys rather than silently dropping their earlier values.
func repeatJSONValue(decoder *json.Decoder) (interface{}, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	if delim == '{' {
		object := make(map[string]interface{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, io.ErrUnexpectedEOF
			}
			if _, duplicate := object[name]; duplicate {
				return nil, io.ErrUnexpectedEOF
			}
			value, err := repeatJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		_, err := decoder.Token()
		return object, err
	}
	if delim == '[' {
		array := make([]interface{}, 0)
		for decoder.More() {
			value, err := repeatJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		_, err := decoder.Token()
		return array, err
	}
	return nil, io.ErrUnexpectedEOF
}

func normalizeRepeatHTMLNonce(body string) string {
	if !strings.Contains(body, "<") {
		return body
	}
	// Tokenize for context, but retain Raw rather than re-serialize HTML. This
	// preserves malformed markup, scripts, comments and whitespace verbatim.
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	var result strings.Builder
	for {
		kind := tokenizer.Next()
		raw := string(tokenizer.Raw())
		if kind == html.ErrorToken {
			result.WriteString(raw)
			return result.String()
		}
		if kind == html.StartTagToken || kind == html.SelfClosingTagToken {
			name, _ := tokenizer.TagName()
			if string(name) == "script" || string(name) == "style" {
				raw = normalizeRepeatNonceAttribute(raw)
			}
		}
		result.WriteString(raw)
	}
}

func normalizeRepeatNonceAttribute(tag string) string {
	var result strings.Builder
	var quote byte
	for i := 0; i < len(tag); {
		c := tag[i]
		if quote == 0 {
			if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				if match := repeatHTMLNonce.FindStringSubmatchIndex(tag[i:]); match != nil {
					result.WriteString(tag[i+match[2] : i+match[3]])
					result.WriteString(`"<volatile>"`)
					i += match[1]
					continue
				}
			}
			if c == '\'' || c == '"' {
				quote = c
			}
		} else if c == quote {
			quote = 0
		}
		result.WriteByte(c)
		i++
	}
	return result.String()
}

const repeatResultBufferBytes = 1024 * 1024

// Native execute streams may exceed the in-memory output limit. Normalize small
// complete responses, otherwise retain a full streaming SHA256, never a prefix.
// The caller serializes writes (foreground shell's merged chunk channel).
type commandRepeatOutput struct {
	buffer bytes.Buffer
	digest hash.Hash
	large  bool
}

func (o *commandRepeatOutput) Write(p []byte) (int, error) {
	if o.digest == nil {
		o.digest = sha256.New()
	}
	_, _ = o.digest.Write(p)
	if !o.large && o.buffer.Len()+len(p) <= repeatResultBufferBytes {
		_, _ = o.buffer.Write(p)
	} else {
		o.large = true
		o.buffer.Reset()
	}
	return len(p), nil
}

func (o *commandRepeatOutput) record(ctxCommand func(string, string)) {
	if o.large {
		ctxCommand(hex.EncodeToString(o.digest.Sum(nil)), "（大结果：使用完整流摘要）")
		return
	}
	text := o.buffer.String()
	ctxCommand(commandResultFingerprintOf(text), text)
}
