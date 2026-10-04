package handler

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"
)

// These source-level regression checks cover the real single/deep streaming and
// JSON call sites without adding a replaceable production model runner. Runtime
// rebind/cancellation/HITL behavior is covered in eino_run_deadline_test.go.
func TestEinoRunDeadlineWiring(t *testing.T) {
	for _, tc := range []struct {
		file, handler, runner string
		stream                bool
	}{
		{"eino_single_agent.go", "EinoSingleAgentLoopStream", "RunEinoSingleChatModelAgent", true},
		{"multi_agent.go", "MultiAgentLoopStream", "RunDeepAgent", true},
		{"eino_single_agent.go", "EinoSingleAgentLoop", "RunEinoSingleChatModelAgent", false},
		{"multi_agent.go", "MultiAgentLoop", "RunDeepAgent", false},
	} {
		t.Run(tc.handler, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, tc.file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			text := func(node ast.Node) string {
				var out bytes.Buffer
				if err := printer.Fprint(&out, fset, node); err != nil {
					t.Fatal(err)
				}
				return out.String()
			}
			var fn *ast.FuncDecl
			for _, decl := range file.Decls {
				if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == tc.handler {
					fn = f
				}
			}
			if fn == nil {
				t.Fatal("request entry point missing")
			}
			roots, segments, rebinds, runners, guarded, hitl := 0, 0, 0, 0, 0, 0
			var rootPos, loopPos token.Pos
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if loop, ok := node.(*ast.ForStmt); ok && loopPos == 0 {
					loopPos = loop.Pos()
				}
				if call, ok := node.(*ast.CallExpr); ok {
					switch name := text(call.Fun); name {
					case "newAgentRunDeadline":
						roots++
						rootPos = call.Pos()
						wantParent := "c.Request.Context()"
						if tc.stream {
							wantParent = "detachedAgentContext(" + wantParent + ")"
						}
						if text(call.Args[0]) != wantParent {
							t.Fatal("changed SSE/non-stream request cancellation policy")
						}
					case "runDeadline.newEinoSegment":
						segments++
					case "h.rebindEinoRunningTask":
						rebinds++
						if text(call.Args[0]) != "runDeadline" || text(call.Args[2]) != "segmentCancel" {
							t.Fatal("continuation must use the unchanged request root and retire the old segment")
						}
					case "multiagent." + tc.runner:
						runners++
						wantCtx := "taskCtx"
						if tc.stream {
							wantCtx = "taskCtxLoop"
						}
						if text(call.Args[0]) != wantCtx {
							t.Fatal("runner bypassed the bounded segment context")
						}
					case "multiagent.WithHITLToolInterceptor":
						hitl++
					case "context.WithTimeout", "context.WithDeadline", "context.WithoutCancel":
						t.Fatalf("%s bypasses the request deadline owner", name)
					}
				}
				// Every actual runner call must be under a guard that was set
				// immediately before it, including iterations after rebind.
				if block, ok := node.(*ast.BlockStmt); ok {
					for i, stmt := range block.List {
						guard, ok := stmt.(*ast.IfStmt)
						if !ok || text(guard.Cond) != "runErr == nil" {
							continue
						}
						found := false
						ast.Inspect(guard.Body, func(n ast.Node) bool {
							if call, ok := n.(*ast.CallExpr); ok && text(call.Fun) == "multiagent."+tc.runner {
								found = true
							}
							return true
						})
						if found {
							if i == 0 || text(block.List[i-1]) != "runErr = agentRunContextError(taskCtx)" {
								t.Fatal("runner can execute after its absolute deadline or cancellation")
							}
							guarded++
						}
					}
				}
				return true
			})
			wantRebinds := 0
			if tc.stream {
				wantRebinds = 3 // Empty response, finalization, interrupt-and-continue.
			}
			if roots != 1 || segments != 1 || rebinds != wantRebinds || runners != 1 || guarded != 1 || hitl != 1 || loopPos == 0 || rootPos > loopPos {
				t.Fatalf("deadline wiring drift: roots=%d segments=%d rebinds=%d runners=%d guarded=%d hitl=%d", roots, segments, rebinds, runners, guarded, hitl)
			}
		})
	}
}
