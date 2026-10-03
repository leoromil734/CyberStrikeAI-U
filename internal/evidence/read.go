package evidence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaxEvidenceBytes = 64 * 1024
const DefaultEvidenceBytes = 8 * 1024

type Region struct {
	ArtifactID string `json:"artifact_id"`
	Offset     int64  `json:"offset"`
	Length     int    `json:"length"`
}

type Snippet struct {
	ExecutionID string `json:"execution_id"`
	ArtifactID  string `json:"artifact_id"`
	SHA256      string `json:"sha256"`
	Kind        string `json:"kind"`
	Completion  string `json:"completion"`
	Offset      int64  `json:"offset"`
	Bytes       int    `json:"bytes"`
	Truncated   bool   `json:"truncated"`
	Redacted    bool   `json:"redacted"`
	Text        string `json:"text"`
}

// ReadRegion enforces execution binding as well as ID-based lookup. UTF-8
// conversion and redaction are explicitly reported; snippets are observations,
// not a verification result. Locations refer to original byte offsets.
func (r *Registry) ReadRegion(ctx context.Context, executionID string, region Region) (Snippet, error) {
	if region.Offset < 0 || region.Length < 0 || region.Length > MaxEvidenceBytes {
		return Snippet{}, ErrLimit
	}
	if region.Length == 0 {
		region.Length = DefaultEvidenceBytes
	}
	a, err := r.Metadata(ctx, region.ArtifactID)
	if err != nil {
		return Snippet{}, err
	}
	if a.ExecutionID != executionID {
		return Snippet{}, ErrDenied
	}
	if region.Offset > a.Size {
		return Snippet{}, ErrLimit
	}
	f, a, err := r.OpenVerified(ctx, region.ArtifactID)
	if err != nil {
		return Snippet{}, err
	}
	defer f.Close()
	if _, err = f.Seek(region.Offset, io.SeekStart); err != nil {
		return Snippet{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(region.Length)))
	if err != nil {
		return Snippet{}, errors.New("evidence read failed")
	}
	if err = r.CheckUnchanged(ctx, f, a); err != nil {
		return Snippet{}, err
	}
	text := strings.ToValidUTF8(string(data), "�")
	// Normalize NUL/control bytes instead of forwarding terminal control codes.
	text = strings.Map(func(ch rune) rune {
		if ch < 32 && ch != '\n' && ch != '\r' && ch != '\t' {
			return '�'
		}
		return ch
	}, text)
	clean := Redact(text)
	return Snippet{ExecutionID: executionID, ArtifactID: a.ID, SHA256: a.SHA256, Kind: a.Kind, Completion: a.Completion, Offset: region.Offset, Bytes: len(data), Truncated: region.Offset+int64(len(data)) < a.Size, Redacted: clean != text, Text: clip(clean, region.Length)}, nil
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?im)(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+`),
	regexp.MustCompile(`(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_.=~-]+`),
	regexp.MustCompile(`(?i)(?:"|\b)(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|token)(?:"|\b)\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s&,;\r\n]+)`),
	regexp.MustCompile(`(?i)https?://[^/@\s]+:[^/@\s]+@`),
}

// Redact is defense-in-depth, not a promise to detect arbitrary secrets. No
// evidence package method logs originals or snippets; callers must not log them.
func Redact(text string) string {
	for _, pattern := range secretPatterns {
		text = pattern.ReplaceAllString(text, "[REDACTED]")
	}
	return text
}

func clip(text string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(text) <= n {
		return text
	}
	for n > 0 && !utf8.RuneStart(text[n]) {
		n--
	}
	return text[:n]
}

type MinimalEvidence struct {
	ExecutionID  string  `json:"execution_id"`
	Input        Snippet `json:"input"`
	Output       Snippet `json:"output"`
	Verification string  `json:"verification"`
	Text         string  `json:"text"`
}

// Assemble requires a registered input original and a distinct actual output
// original. It never executes content or declares that a finding is validated.
func (r *Registry) Assemble(ctx context.Context, executionID string, input, output Region) (MinimalEvidence, error) {
	if input.Length <= 0 {
		input.Length = DefaultEvidenceBytes / 2
	}
	if output.Length <= 0 {
		output.Length = DefaultEvidenceBytes / 2
	}
	if input.Length+output.Length > MaxEvidenceBytes-1024 {
		return MinimalEvidence{}, ErrLimit
	}
	in, err := r.ReadRegion(ctx, executionID, input)
	if err != nil {
		return MinimalEvidence{}, err
	}
	out, err := r.ReadRegion(ctx, executionID, output)
	if err != nil {
		return MinimalEvidence{}, err
	}
	if in.Kind != "input" || out.Kind == "input" || in.ArtifactID == out.ArtifactID {
		return MinimalEvidence{}, ErrDenied
	}
	text := fmt.Sprintf("Evidence observation only; verification=unverified. Redacted ranges may be incomplete.\nOriginal input (artifact=%s, sha256=%s, offset=%d):\n%s\nActual output (artifact=%s, sha256=%s, offset=%d, completion=%s):\n%s", in.ArtifactID, in.SHA256, in.Offset, in.Text, out.ArtifactID, out.SHA256, out.Offset, out.Completion, out.Text)
	return MinimalEvidence{ExecutionID: executionID, Input: in, Output: out, Verification: "unverified", Text: clip(text, MaxEvidenceBytes)}, nil
}
