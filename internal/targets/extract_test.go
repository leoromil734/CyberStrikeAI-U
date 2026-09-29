package targets

import (
	"reflect"
	"testing"
)

func TestExtractStandardTaskSentence(t *testing.T) {
	t.Parallel()
	msg := "对 hfm.com 做全面 完整 深度的渗透测试 漏洞挖掘，包括品牌资产 子资产 子域名 IP等"
	got := Extract(msg)
	want := []string{"hfm.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Extract(%q) = %v, want %v", msg, got, want)
	}
}

func TestExtractWithoutSpacesAroundChinese(t *testing.T) {
	t.Parallel()
	got := Extract("对hfm.com做全面渗透测试")
	want := []string{"hfm.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractMultipleTargetsKeepsOrderAndDedupes(t *testing.T) {
	t.Parallel()
	got := Extract("先测 b.co.uk，再测 a.com，最后重复 HFM.COM 与 hfm.com")
	want := []string{"b.co.uk", "a.com", "hfm.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractSkipsIPAddresses(t *testing.T) {
	t.Parallel()
	if got := Extract("对 136.110.39.163 做端口扫描"); len(got) != 0 {
		t.Fatalf("IP 不应被当成目标域名: %v", got)
	}
}

func TestExtractSkipsFileNames(t *testing.T) {
	t.Parallel()
	cases := []string{
		"python3 poc.py 2>&1 | tee poc_reg.out",
		"bash probe_b7.sh 输出到 results.json",
		"curl -o resp_ssrf.txt",
		"cat www_wpjson.body",
	}
	for _, c := range cases {
		if got := Extract(c); len(got) != 0 {
			t.Fatalf("%q 里的文件名不应被当成目标: %v", c, got)
		}
	}
}

func TestExtractKeepsHyphenatedAndMultiLabelDomains(t *testing.T) {
	t.Parallel()
	got := Extract("测试 相似注册域(careers-hfm.com、webterminal-hfm.com、e-hfm.com)；另有 scalable.capital 与 finanzen.net")
	want := []string{"careers-hfm.com", "webterminal-hfm.com", "e-hfm.com", "scalable.capital", "finanzen.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractHandlesUrlsPortsAndTrailingPunctuation(t *testing.T) {
	t.Parallel()
	got := Extract("https://www.Example.com/login?next=/x 以及 hfm.com:8443。")
	want := []string{"example.com", "hfm.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNormalize(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"  HFM.com ":                    "hfm.com",
		"www.hfm.com":                   "hfm.com",
		"http://hfm.com/a/b":            "hfm.com",
		"https://user:pw@hfm.com:8443/": "hfm.com",
		"hfm.com.":                      "hfm.com",
		"hfm.com:443":                   "hfm.com",
		"136.110.39.163":                "",
		"poc.py":                        "",
		"":                              "",
		"localhost":                     "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Fatalf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeAllAcceptsPlainText(t *testing.T) {
	t.Parallel()
	got := NormalizeAll([]string{"对 orbex.com 做全面 完整 深度的渗透测试", "WWW.HFM.com", "hfm.com"})
	want := []string{"orbex.com", "hfm.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestExtractIgnoresNonTargetChineseInput(t *testing.T) {
	t.Parallel()
	if got := Extract("只做一件事：调用 fofa_search 工具一次，参数 query 为 ip=\"136.110.39.163\""); len(got) != 0 {
		t.Fatalf("工具类输入不应产生目标: %v", got)
	}
}
