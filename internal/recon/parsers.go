package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"cyberstrike-ai/internal/evidence"
)

var errRecordLimit = errors.New("record_limit")
var errFormat = errors.New("invalid_format")
var errUnsupported = errors.New("unsupported_format")

type ParsedOutput struct {
	Records []Record
	Stats   evidence.Stats
	State   string
	Reason  string
	Partial bool
}

type collector struct {
	result ParsedOutput
	limits Limits
}

func (c *collector) add(records []Record, loc Location) error {
	for _, r := range records {
		if len(c.result.Records) >= c.limits.MaxRecords {
			return errRecordLimit
		}
		r.Location = loc
		r.ScopeState = UnknownScope
		r.CandidateOnly = true
		if err := r.Validate(); err != nil {
			c.result.Stats.Rejected++
			continue
		}
		c.result.Records = append(c.result.Records, r)
		c.result.Stats.Records++
		switch r.Kind {
		case Host:
			c.result.Stats.Hosts++
		case Service:
			c.result.Stats.Services++
		case Endpoint:
			c.result.Stats.Endpoints++
		case JS:
			c.result.Stats.JS++
		case Candidate:
			c.result.Stats.Candidates++
		}
	}
	return nil
}

func CanonicalTool(tool string) string {
	tool = strings.ToLower(strings.TrimSpace(tool))
	switch tool {
	case "fofa_search", "fofa_query":
		return "fofa"
	case "one_for_all", "oneforall_run":
		return "oneforall"
	case "jsapiscan_run", "jsapiscan_scan":
		return "jsapiscan"
	}
	return tool
}

// Parse accepts only declared supported machine/plain formats. It does not
// inspect a preview or extract arbitrary URLs from human-readable logs/HTML.
// Every parser is offline and bounded by bytes, line/record size and row count.
func Parse(ctx context.Context, tool, format string, reader io.Reader, limits Limits) (ParsedOutput, error) {
	limits = limits.normalized()
	tool = CanonicalTool(tool)
	format = strings.ToLower(format)
	c := &collector{limits: limits, result: ParsedOutput{State: evidence.Parsed}}
	limited := &io.LimitedReader{R: cancelReader{ctx, reader}, N: limits.MaxBytes + 1}
	var err error
	switch {
	case tool == "nmap" && format == "xml":
		err = parseNmap(ctx, limited, c)
	case tool == "fofa" && format == "json":
		err = parseFOFA(limited, c)
	case (tool == "fofa" || tool == "oneforall" || tool == "jsapiscan") && format == "csv":
		err = parseCSV(tool, limited, c)
	case supportsLines(tool, format):
		err = parseLines(tool, format, limited, c)
	default:
		err = errUnsupported
	}
	if ctx.Err() != nil {
		return ParsedOutput{}, ctx.Err()
	}
	if limited.N <= 0 {
		c.result.Partial = true
		c.result.Reason = "byte_limit"
	}
	if errors.Is(err, errUnsupported) {
		// Never publish guessed rows when the document's envelope is unsupported.
		return ParsedOutput{State: evidence.Unsupported, Reason: "unsupported_format"}, nil
	}
	if errors.Is(err, errRecordLimit) {
		c.result.Partial = true
		c.result.Reason = "record_limit"
	} else if err != nil {
		c.result.Partial = true
		if c.result.Reason == "" {
			c.result.Reason = "invalid_format"
		}
		if len(c.result.Records) == 0 {
			c.result.State = evidence.Invalid
		}
	}
	if c.result.Stats.Rejected > 0 {
		c.result.Partial = true
		if c.result.Reason == "" {
			c.result.Reason = "rejected_records"
		}
		if len(c.result.Records) == 0 {
			c.result.State = evidence.Invalid
		}
	}
	if c.result.Partial && c.result.State == evidence.Parsed {
		c.result.State = evidence.Partial
	}
	return c.result, nil
}

type cancelReader struct {
	ctx context.Context
	io.Reader
}

func (r cancelReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func supportsLines(tool, format string) bool {
	if format == "jsonl" || format == "ndjson" {
		switch tool {
		case "subfinder", "dnsx", "httpx", "naabu", "gau", "katana", "nuclei", "jsapiscan", "oneforall":
			return true
		}
	}
	if format == "text" || format == "txt" {
		switch tool {
		case "subfinder", "dnsx", "httpx", "naabu", "gau", "katana":
			return true
		}
	}
	return false
}

func originalLine(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i+1], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func parseLines(tool, format string, reader io.Reader, c *collector) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), c.limits.MaxLineBytes+1)
	scanner.Split(originalLine)
	var offset, line int64
	for scanner.Scan() {
		raw := scanner.Bytes()
		loc := Location{Offset: offset, Length: int64(len(raw)), Line: line + 1}
		offset += int64(len(raw))
		line++
		if offset > c.limits.MaxBytes {
			return errors.New("byte_limit")
		}
		text := strings.TrimSpace(strings.TrimPrefix(string(raw), "\ufeff"))
		if text == "" {
			continue
		}
		if !utf8.Valid(raw) || strings.IndexByte(text, 0) >= 0 {
			c.result.Stats.Rejected++
			continue
		}
		var records []Record
		var err error
		if format == "jsonl" || format == "ndjson" {
			records, err = parseJSONLine(tool, []byte(text))
		} else {
			records, err = parseTextLine(tool, text)
		}
		if err != nil || len(records) == 0 {
			c.result.Stats.Rejected++
			continue
		}
		if err = c.add(records, loc); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, errFormat
	}
	return obj, nil
}
func str(obj map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		value := obj[key]
		if len(value) == 0 {
			continue
		}
		var s string
		if json.Unmarshal(value, &s) == nil {
			return s
		}
		var n json.Number
		if json.Unmarshal(value, &n) == nil {
			return n.String()
		}
	}
	return ""
}
func objAt(obj map[string]json.RawMessage, key string) map[string]json.RawMessage {
	nested, _ := decodeObject(obj[key])
	return nested
}
func portNumber(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, errFormat
	}
	return n, nil
}

var hostPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\.?$`)

func hostRecord(raw string) (Record, error) {
	if raw == "" || strings.ContainsAny(raw, " \t\r\n/\\:@") || len(raw) > 253 {
		return Record{}, errFormat
	}
	host := strings.TrimSuffix(strings.ToLower(raw), ".")
	ip := net.ParseIP(raw)
	if ip == nil && (!hostPattern.MatchString(raw) || strings.Contains(host, "..")) {
		return Record{}, errFormat
	}
	r := Record{Kind: Host, Host: host, RawHost: raw}
	if ip != nil {
		r.IP = ip.String()
		r.Host = ip.String()
	}
	return r, nil
}

func serviceRecords(rawHost, rawPort, protocol string) ([]Record, error) {
	// IPv6 raw hosts are represented without brackets after SplitHostPort.
	h, err := hostRecord(rawHost)
	if err != nil && net.ParseIP(rawHost) != nil {
		h = Record{Kind: Host, Host: net.ParseIP(rawHost).String(), RawHost: rawHost, IP: net.ParseIP(rawHost).String()}
		err = nil
	}
	if err != nil {
		return nil, err
	}
	port, err := portNumber(rawPort)
	if err != nil {
		return nil, err
	}
	s := h
	s.Kind = Service
	s.Port = port
	s.RawPort = rawPort
	s.Protocol = strings.ToLower(protocol)
	if s.Protocol == "" {
		s.Protocol = "tcp"
	}
	return []Record{h, s}, nil
}

func urlRecords(raw, method string) ([]Record, error) {
	if raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, " \r\n\t\x00") {
		return nil, errFormat
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errFormat
	}
	host := u.Hostname()
	h, err := hostRecord(host)
	if err != nil && net.ParseIP(host) != nil {
		h = Record{Kind: Host, Host: net.ParseIP(host).String(), RawHost: host, IP: net.ParseIP(host).String()}
		err = nil
	}
	if err != nil {
		return nil, err
	}
	rawPort := u.Port()
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if rawPort != "" {
		port, err = portNumber(rawPort)
		if err != nil {
			return nil, err
		}
	}
	s := h
	s.Kind = Service
	s.Port = port
	s.RawPort = rawPort
	s.Protocol = u.Scheme
	s.ServiceName = u.Scheme
	endpoint := s
	endpoint.Kind = Endpoint
	endpoint.RawURL = raw
	endpoint.RawPath = u.EscapedPath()
	if u.RawQuery != "" || u.ForceQuery {
		endpoint.RawPath += "?" + u.RawQuery
	}
	endpoint.Method = strings.ToUpper(method)
	if endpoint.Method == "" {
		endpoint.Method = "GET"
	}
	if len(endpoint.Method) > 16 || strings.ContainsAny(endpoint.Method, " \r\n\t") {
		return nil, errFormat
	}
	records := []Record{h, s, endpoint}
	if ext := strings.ToLower(path.Ext(u.Path)); ext == ".js" || ext == ".mjs" || ext == ".cjs" {
		js := endpoint
		js.Kind = JS
		records = append(records, js)
	}
	return records, nil
}

func parseTextLine(tool, text string) ([]Record, error) {
	switch tool {
	case "subfinder":
		h, err := hostRecord(text)
		return []Record{h}, err
	case "dnsx":
		fields := strings.Fields(text)
		if len(fields) == 0 {
			return nil, errFormat
		}
		h, err := hostRecord(fields[0])
		if err != nil {
			return nil, err
		}
		records := []Record{h}
		for _, field := range fields[1:] {
			ip := strings.Trim(field, "[]")
			if net.ParseIP(ip) != nil {
				r, _ := hostRecord(ip)
				if r.Host == "" {
					r = Record{Kind: Host, Host: net.ParseIP(ip).String(), RawHost: ip, IP: net.ParseIP(ip).String()}
				}
				records = append(records, r)
			}
		}
		return records, nil
	case "naabu":
		host, port, err := net.SplitHostPort(text)
		if err != nil {
			return nil, errFormat
		}
		return serviceRecords(host, port, "tcp")
	case "httpx":
		fields := strings.Fields(text)
		if len(fields) == 0 {
			return nil, errFormat
		}
		return urlRecords(fields[0], "GET")
	case "gau", "katana":
		return urlRecords(text, "GET")
	}
	return nil, errUnsupported
}

func parseJSONLine(tool string, data []byte) ([]Record, error) {
	obj, err := decodeObject(data)
	if err != nil {
		return nil, err
	}
	switch tool {
	case "subfinder", "oneforall":
		h, err := hostRecord(str(obj, "host", "domain", "subdomain"))
		return []Record{h}, err
	case "dnsx":
		h, err := hostRecord(str(obj, "host", "name"))
		if err != nil {
			return nil, err
		}
		records := []Record{h}
		for _, key := range []string{"a", "aaaa"} {
			var ips []string
			_ = json.Unmarshal(obj[key], &ips)
			for _, ip := range ips {
				if parsed := net.ParseIP(ip); parsed != nil {
					records = append(records, Record{Kind: Host, Host: parsed.String(), RawHost: ip, IP: parsed.String()})
				}
			}
		}
		return records, nil
	case "httpx":
		return urlRecords(str(obj, "url", "input"), str(obj, "method"))
	case "naabu":
		return serviceRecords(str(obj, "host", "ip"), str(obj, "port"), str(obj, "protocol"))
	case "gau":
		return urlRecords(str(obj, "url"), str(obj, "method"))
	case "katana":
		request := objAt(obj, "request")
		if request != nil {
			return urlRecords(str(request, "endpoint", "url"), str(request, "method"))
		}
		return urlRecords(str(obj, "url", "endpoint"), str(obj, "method"))
	case "jsapiscan":
		return urlRecords(str(obj, "url", "URL"), str(obj, "method", "Method"))
	case "nuclei":
		target := str(obj, "matched-at", "matched_at", "host")
		template := str(obj, "template-id", "template_id")
		if template == "" {
			return nil, errFormat
		}
		var r Record
		if endpoints, err := urlRecords(target, str(obj, "method")); err == nil {
			r = endpoints[2]
		} else {
			host, port, splitErr := net.SplitHostPort(target)
			if splitErr == nil {
				services, err := serviceRecords(host, port, "tcp")
				if err != nil {
					return nil, err
				}
				r = services[1]
			} else {
				var err error
				r, err = hostRecord(target)
				if err != nil {
					return nil, err
				}
			}
		}
		r.Kind = Candidate
		r.TemplateID = template
		r.Severity = str(objAt(obj, "info"), "severity")
		return []Record{r}, nil
	}
	return nil, errUnsupported
}

func parseCSV(tool string, reader io.Reader, c *collector) error {
	r := csv.NewReader(reader)
	r.ReuseRecord = true
	header, err := r.Read()
	if err != nil {
		return errFormat
	}
	if r.InputOffset() > int64(c.limits.MaxLineBytes) {
		return errFormat
	}
	columns := map[string]int{}
	for i, name := range header {
		columns[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "\ufeff")))] = i
	}
	get := func(row []string, keys ...string) string {
		for _, key := range keys {
			if index, ok := columns[key]; ok && index < len(row) {
				return row[index]
			}
		}
		return ""
	}
	switch tool {
	case "fofa":
		if _, ok := columns["host"]; !ok {
			return errUnsupported
		}
	case "oneforall":
		if _, ok := columns["subdomain"]; !ok {
			if _, ok = columns["domain"]; !ok {
				return errUnsupported
			}
		}
	case "jsapiscan":
		if _, ok := columns["url"]; !ok {
			return errUnsupported
		}
		if _, ok := columns["method"]; !ok {
			return errUnsupported
		}
	}
	var line int64 = 1
	for {
		start := r.InputOffset()
		row, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errFormat
		}
		line++
		end := r.InputOffset()
		if end > c.limits.MaxBytes || end-start > int64(c.limits.MaxLineBytes) {
			return errFormat
		}
		var records []Record
		switch tool {
		case "oneforall":
			h, e := hostRecord(get(row, "subdomain", "domain"))
			err = e
			records = []Record{h}
		case "jsapiscan":
			records, err = urlRecords(get(row, "url"), get(row, "method"))
		case "fofa":
			records, err = fofaRow(get(row, "host"), get(row, "ip"), get(row, "port"), get(row, "protocol"))
		}
		if err != nil {
			c.result.Stats.Rejected++
			continue
		}
		if err = c.add(records, Location{Offset: start, Length: end - start, Line: line}); err != nil {
			return err
		}
	}
}

func fofaRow(host, ip, port, protocol string) ([]Record, error) {
	var records []Record
	var err error
	switch {
	case strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://"):
		records, err = urlRecords(host, "GET")
	case port != "":
		if h, p, e := net.SplitHostPort(host); e == nil {
			if p != port {
				return nil, errFormat
			}
			host = h
		}
		records, err = serviceRecords(host, port, protocol)
	default:
		if h, p, e := net.SplitHostPort(host); e == nil {
			records, err = serviceRecords(h, p, protocol)
		} else {
			var h Record
			h, err = hostRecord(host)
			records = []Record{h}
		}
	}
	if err != nil {
		return nil, err
	}
	if ip != "" {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return nil, errFormat
		}
		records = append(records, Record{Kind: Host, Host: parsed.String(), RawHost: ip, IP: parsed.String()})
	}
	return records, nil
}

// FOFA JSON uses a declared fields array followed by results/data rows. Large
// row arrays are decoded one at a time; unknown envelope fields are skipped.
func parseFOFA(reader io.Reader, c *collector) error {
	d := json.NewDecoder(reader)
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return errFormat
	}
	var fields []string
	seenResults := false
	for d.More() {
		keyToken, err := d.Token()
		if err != nil {
			return errFormat
		}
		key, ok := keyToken.(string)
		if !ok {
			return errFormat
		}
		switch key {
		case "fields":
			if err = d.Decode(&fields); err != nil || len(fields) > 128 {
				return errFormat
			}
		case "error":
			var failed bool
			if err = d.Decode(&failed); err != nil || failed {
				return errFormat
			}
		case "results", "data":
			if len(fields) == 0 {
				return errUnsupported
			}
			index := map[string]int{}
			for i, field := range fields {
				index[strings.ToLower(field)] = i
			}
			if _, ok := index["host"]; !ok {
				return errUnsupported
			}
			token, err = d.Token()
			if err != nil || token != json.Delim('[') {
				return errFormat
			}
			seenResults = true
			for d.More() {
				start := d.InputOffset()
				var row []json.RawMessage
				if err = d.Decode(&row); err != nil {
					return errFormat
				}
				end := d.InputOffset()
				if end-start > int64(c.limits.MaxLineBytes) || end > c.limits.MaxBytes {
					return errFormat
				}
				get := func(key string) string {
					i, ok := index[key]
					if !ok || i >= len(row) {
						return ""
					}
					var text string
					if json.Unmarshal(row[i], &text) == nil {
						return text
					}
					var n json.Number
					if json.Unmarshal(row[i], &n) == nil {
						return n.String()
					}
					return ""
				}
				records, err := fofaRow(get("host"), get("ip"), get("port"), get("protocol"))
				if err != nil {
					c.result.Stats.Rejected++
					continue
				}
				if err = c.add(records, Location{Offset: start, Length: end - start}); err != nil {
					return err
				}
			}
			if _, err = d.Token(); err != nil {
				return errFormat
			}
		default:
			if err = skipJSON(d); err != nil {
				return errFormat
			}
		}
	}
	if _, err = d.Token(); err != nil || !seenResults {
		return errFormat
	}
	if _, err = d.Token(); err != io.EOF {
		return errFormat
	}
	return nil
}
func skipJSON(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errFormat
	}
	depth := 1
	for depth > 0 {
		token, err = d.Token()
		if err != nil {
			return err
		}
		if ch, ok := token.(json.Delim); ok {
			if ch == '{' || ch == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

type nmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Address string `xml:"addr,attr"`
		Type    string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		ID       string `xml:"portid,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name string `xml:"name,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
}

func parseNmap(ctx context.Context, reader io.Reader, c *collector) error {
	d := xml.NewDecoder(reader)
	rootSeen := false
	finished := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := d.InputOffset()
		token, err := d.Token()
		if err == io.EOF {
			if !rootSeen || !finished {
				return errFormat
			}
			return nil
		}
		if err != nil {
			return errFormat
		}
		switch value := token.(type) {
		case xml.Directive:
			if strings.TrimSpace(string(value)) != "DOCTYPE nmaprun" {
				return errUnsupported
			} // Never resolve external entities.
		case xml.StartElement:
			if !rootSeen {
				if value.Name.Local != "nmaprun" {
					return errUnsupported
				}
				rootSeen = true
			}
			if value.Name.Local != "host" {
				continue
			}
			var host nmapHost
			if err = d.DecodeElement(&host, &value); err != nil {
				return errFormat
			}
			end := d.InputOffset()
			if end-start > int64(c.limits.MaxLineBytes) || end > c.limits.MaxBytes {
				return errFormat
			}
			if host.Status.State != "up" {
				continue
			}
			names := []string{}
			for _, a := range host.Addresses {
				if a.Type == "ipv4" || a.Type == "ipv6" {
					names = append(names, a.Address)
				}
			}
			for _, h := range host.Hostnames {
				names = append(names, h.Name)
			}
			records := []Record{}
			for _, name := range names {
				h, err := hostRecord(name)
				if err != nil && net.ParseIP(name) != nil {
					h = Record{Kind: Host, Host: net.ParseIP(name).String(), RawHost: name, IP: net.ParseIP(name).String()}
					err = nil
				}
				if err != nil {
					c.result.Stats.Rejected++
					continue
				}
				records = append(records, h)
				for _, port := range host.Ports {
					if port.State.State != "open" {
						continue
					}
					services, err := serviceRecords(name, port.ID, port.Protocol)
					if err != nil {
						c.result.Stats.Rejected++
						continue
					}
					services[1].ServiceName = port.Service.Name
					records = append(records, services[1])
				}
			}
			if err = c.add(records, Location{Offset: start, Length: end - start}); err != nil {
				return err
			}
		case xml.EndElement:
			if value.Name.Local == "nmaprun" {
				finished = true
			}
		}
	}
}
