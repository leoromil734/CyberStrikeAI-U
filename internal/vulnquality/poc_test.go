package vulnquality

import "testing"

func TestHasValidPOCRejectsShortOrNarrativeOnly(t *testing.T) {
	if HasValidPOC("存在SQL注入漏洞") {
		t.Fatal("narrative-only evidence should be invalid")
	}
	if HasValidPOC("成功执行") {
		t.Fatal("too short evidence should be invalid")
	}
}

func TestHasValidPOCAcceptsHTTPAndScript(t *testing.T) {
	httpEvidence := "```\nPOST /login HTTP/1.1\nHost: example.com\n\nusername=admin' OR '1'='1\n```\nHTTP/1.1 302 Found"
	if !HasValidPOC(httpEvidence) {
		t.Fatal("HTTP request/response should be valid POC")
	}
	scriptEvidence := "```python\nimport requests\nr = requests.get('http://example.com/x', params={'id': '1 OR 1=1'})\nprint(r.text)\n```"
	if !HasValidPOC(scriptEvidence) {
		t.Fatal("python requests script should be valid POC")
	}
}

func TestValidateEvidencePOCRejectsTruncatedSQLWrite(t *testing.T) {
	truncated := "受控写入（r3_insert_redhouse_out.txt）\n```\nINSERT INTO wp_redhouse.dog_users(...) VALUES('sdta_audit_c9d4b2','$P$BaxSHok.BvH1h5GtTjEm0wO.N3iOvH.',...);\nnew_id  inserted_rows\n3       1\n```"
	if err := ValidateEvidencePOC(truncated); err == nil {
		t.Fatal("truncated INSERT should be rejected")
	}
}

func TestValidateEvidencePOCRejectsFilenameOnlyWrite(t *testing.T) {
	filenameOnly := "已完成受控写入，证据见 r3_insert_redhouse_out.txt，管理员账号创建成功，inserted 1 行。"
	if err := ValidateEvidencePOC(filenameOnly); err == nil {
		t.Fatal("filename-only controlled write should be rejected")
	}
}

func TestValidateEvidencePOCAcceptsCompleteWriteAndScript(t *testing.T) {
	complete := "```python\nimport pymysql\nconn = pymysql.connect(host='127.0.0.1', user='audit', password='x', db='wp_redhouse')\ncur = conn.cursor()\nsql = (\"INSERT INTO wp_redhouse.dog_users\"\n       \"(user_login,user_pass,user_nicename,user_email,user_url,user_registered,user_activation_key,user_status,display_name) \"\n       \"VALUES('sdta_audit_c9d4b2','$P$BaxSHok.BvH1h5GtTjEm0wO.N3iOvH.','sdta_audit_c9d4b2','sdta.audit.r3@example.com','',NOW(),'',0,'sdta_audit_c9d4b2')\")\ncur.execute(sql)\nprint('new_id', cur.lastrowid, 'inserted_rows', cur.rowcount)\nconn.commit()\n```\n受控写入（r3_insert_redhouse_out.txt）\n```\nINSERT INTO wp_redhouse.dog_users(user_login,user_pass,user_nicename,user_email,user_url,user_registered,user_activation_key,user_status,display_name) VALUES('sdta_audit_c9d4b2','$P$BaxSHok.BvH1h5GtTjEm0wO.N3iOvH.','sdta_audit_c9d4b2','sdta.audit.r3@example.com','','2026-09-09 00:00:00','',0,'sdta_audit_c9d4b2');\nnew_id  inserted_rows\n3       1\nmeta_inserted\n3\nID  user_login        user_email\n3   sdta_audit_c9d4b2 sdta.audit.r3@example.com\nuser_id  meta_key          meta_value\n3        dog_capabilities  a:1:{s:13:\"administrator\";b:1;}\n3        dog_user_level    10\n3        dog_nickname      sdta_audit_c9d4b2\n```"
	if err := ValidateEvidencePOC(complete); err != nil {
		t.Fatalf("complete write+script should pass: %v", err)
	}
}
