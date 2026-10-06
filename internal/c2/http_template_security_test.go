package c2

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
	"text/template"
)

// Validate the authentication-only template changes without compiling or
// executing generated client code and without opening a network connection.
func TestHTTPBeaconSessionCredentialTemplateSyntax(t *testing.T) {
	raw, err := os.ReadFile("payload_templates/beacon.go.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("beacon").Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, map[string]string{
		"Transport": "http", "ServerURL": "http://127.0.0.1:12345", "TCPDialAddr": "",
		"TransportMetadata": "http_beacon", "SleepSeconds": "5", "JitterPercent": "0",
		"ImplantToken": "test-only-token", "AESKeyB64": "test-only-key",
		"CheckInPath": "/check_in", "TasksPath": "/tasks", "ResultPath": "/result",
		"UploadPath": "/upload", "FilePath": "/file/", "UserAgent": "test-only",
	}); err != nil {
		t.Fatal(err)
	}
	source, err := parser.ParseFile(token.NewFileSet(), "beacon.go", rendered.Bytes(), parser.AllErrors)
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{"checkIn": false, "fetchTasks": false, "reportResult": false, "fetchC2FileByID": false}
	for _, decl := range source.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if _, ok := required[fn.Name.Name]; !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Set" {
				return true
			}
			key, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				return true
			}
			name, err := strconv.Unquote(key.Value)
			value, ok := call.Args[1].(*ast.Ident)
			if err == nil && name == "X-Session-Token" && ok && value.Name == "sessionToken" {
				required[fn.Name.Name] = true
			}
			return true
		})
	}
	for name, authenticated := range required {
		if !authenticated {
			t.Errorf("%s lacks session credential header", name)
		}
	}
	if !strings.Contains(rendered.String(), "rand.Read(tokenBytes)") || !strings.Contains(rendered.String(), "sha256.Sum256(tokenBytes)") || strings.Contains(rendered.String(), "sessionToken[:") {
		t.Fatal("credential generation or derived identity leaks a credential prefix")
	}
}
