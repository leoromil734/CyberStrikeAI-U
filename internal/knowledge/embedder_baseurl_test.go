package knowledge

import "testing"

func TestNormalizeOpenAICompatibleBaseURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://api.openai.com/v1", "https://api.openai.com/v1"},
		{"https://api.openai.com/v1/", "https://api.openai.com/v1"},
		{"https://api.openai.com", "https://api.openai.com/v1"},
		{"https://dashscope.aliyuncs.com/compatible-mode/v1", "https://dashscope.aliyuncs.com/compatible-mode/v1"},
		{"https://dashscope.aliyuncs.com/compatible-mode", "https://dashscope.aliyuncs.com/compatible-mode/v1"},
		{"https://dashscope.aliyuncs.com/compatible-mode/", "https://dashscope.aliyuncs.com/compatible-mode/v1"},
	}
	for _, c := range cases {
		got := normalizeOpenAICompatibleBaseURL(c.in)
		if got != c.want {
			t.Fatalf("in=%q got=%q want=%q", c.in, got, c.want)
		}
	}
}