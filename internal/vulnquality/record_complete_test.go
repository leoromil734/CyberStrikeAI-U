package vulnquality

import "testing"

func TestCompleteRecordArgsFillsAnonymousPhpinfoGaps(t *testing.T) {
	args := map[string]interface{}{
		"title":       "www.example.test 匿名暴露 phpinfo",
		"severity":    "medium",
		"target":      "https://www.example.test/phpinfo.php",
		"description": "匿名 GET /phpinfo.php 返回完整 phpinfo。随机路径是站点 404。",
		"impact":      "匿名即可读取生产 PHP 配置与绝对路径。",
		"evidence":    "```http\nGET /phpinfo.php HTTP/1.1\nHost: www.example.test\n```\n\n实际输出：\n\nHTTP/1.1 200 OK\n\nphpinfo()",
		"preconditions": "无需登录。",
	}
	CompleteRecordArgs(args)
	for _, key := range []string{"reproduction_steps", "vulnerability_type", "recommendation", "attacker_starting_state", "security_boundary_crossed", "control_comparison"} {
		if _, ok := args[key].(string); !ok || args[key] == "" {
			t.Fatalf("missing completed field %s: %#v", key, args[key])
		}
	}
	if args["credential_compromise_required"] != false || args["additional_authority_proven"] != true {
		t.Fatalf("boundary flags not completed: %#v", args)
	}
	_, missing := ParseBoundaryValidation(args)
	if len(missing) != 0 {
		t.Fatalf("completed anonymous record still missing boundary: %v", missing)
	}
}

func TestCompleteRecordArgsFillsTitleFromDescription(t *testing.T) {
	args := map[string]interface{}{
		"severity":      "medium",
		"target":        "https://www.example.test/phpinfo.php",
		"description":   "匿名 GET /phpinfo.php 返回完整 phpinfo。随机路径是站点 404。",
		"impact":        "匿名即可读取生产 PHP 配置与绝对路径。",
		"evidence":      "```http\nGET /phpinfo.php HTTP/1.1\nHost: www.example.test\n```\n\n实际输出：\n\nHTTP/1.1 200 OK\n\nphpinfo()",
		"preconditions": "无需登录。",
	}
	CompleteRecordArgs(args)
	if args["title"] != "匿名 GET /phpinfo.php 返回完整 phpinfo" {
		t.Fatalf("title not taken from description: %#v", args["title"])
	}
}

func TestCompleteRecordArgsDoesNotInventEvidence(t *testing.T) {
	args := map[string]interface{}{"title": "只写了标题", "description": "匿名页面"}
	CompleteRecordArgs(args)
	if _, ok := args["reproduction_steps"]; ok {
		t.Fatal("short or missing evidence must not be expanded into a record")
	}
}
