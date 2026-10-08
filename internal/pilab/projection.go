package pilab

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// projectEvent accepts only bounded, typed UI state. There is intentionally no
// promotion into production assets, confirmed vulnerabilities or attack chains.
func projectEvent(run *Run, event Event) error {
	invalid := fmt.Errorf("PI 事件字段无效或投影预算已耗尽")
	nodeCap, edgeCap, findingCap := 256, 512, 128
	if run.Mode == ModePlatform {
		nodeCap, edgeCap, findingCap = 4096, 8192, 512
	}
	switch event.Type {
	case "agent_start":
		var agent Agent
		if json.Unmarshal(event.Data, &agent) != nil || event.AgentID == "" {
			return invalid
		}
		agent.ID, agent.Status = event.AgentID, "running"
		if textLength(agent.Task) > 16384 || textLength(agent.Role) > 256 || textLength(agent.ParentID) > 128 {
			return invalid
		}
		for i := range run.Agents {
			if run.Agents[i].ID == agent.ID {
				return invalid
			}
		}
		if len(run.Agents) >= run.Limits.MaxAgents+1 {
			return invalid
		}
		run.Agents = append(run.Agents, agent)
	case "agent_end":
		var end struct {
			Status  string `json:"status"`
			Summary string `json:"summary"`
		}
		if json.Unmarshal(event.Data, &end) != nil || textLength(end.Summary) > 32768 {
			return invalid
		}
		switch end.Status {
		case "completed", "partial", "failed", "cancelled", "interrupted":
		default:
			return invalid
		}
		for i := range run.Agents {
			if run.Agents[i].ID == event.AgentID {
				run.Agents[i].Status, run.Agents[i].Summary = end.Status, end.Summary
				return nil
			}
		}
		return invalid
	case "node":
		var node Node
		if json.Unmarshal(event.Data, &node) != nil || !validID(node.ID) || textLength(node.Label) > 1024 || textLength(node.Detail) > 16384 || textLength(node.URL) > 4096 || textLength(node.ParentID) > 128 {
			return invalid
		}
		for i := range run.Nodes {
			if run.Nodes[i].ID == node.ID {
				run.Nodes[i] = node
				return nil
			}
		}
		if len(run.Nodes) >= nodeCap {
			return invalid
		}
		run.Nodes = append(run.Nodes, node)
	case "edge":
		var edge Edge
		if json.Unmarshal(event.Data, &edge) != nil || !validID(edge.ID) || !validID(edge.Source) || !validID(edge.Target) || textLength(edge.Label) > 1024 {
			return invalid
		}
		for i := range run.Edges {
			if run.Edges[i].ID == edge.ID {
				run.Edges[i] = edge
				return nil
			}
		}
		if len(run.Edges) >= edgeCap {
			return invalid
		}
		run.Edges = append(run.Edges, edge)
	case "finding":
		var finding Finding
		if json.Unmarshal(event.Data, &finding) != nil || !validID(finding.ID) || textLength(finding.Title) > 1024 || textLength(finding.URL) > 4096 || textLength(finding.Evidence) > 16384 || textLength(finding.Remediation) > 8192 {
			return invalid
		}
		if finding.Status != "hypothesis" && finding.Status != "observed" {
			return invalid
		}
		switch finding.Severity {
		case "info", "low", "medium", "high", "critical":
		default:
			return invalid
		}
		for i := range run.Findings {
			if run.Findings[i].ID == finding.ID {
				run.Findings[i] = finding
				return nil
			}
		}
		if len(run.Findings) >= findingCap {
			return invalid
		}
		run.Findings = append(run.Findings, finding)
	case "report":
		var report struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(event.Data, &report) != nil || textLength(report.Text) > 65536 {
			return invalid
		}
		run.Report = report.Text
	case "error":
		// Arbitrary SDK/provider exception messages are not suitable for publication.
		run.Error = "PI 报告了运行错误；该试验不能视为完整成功"
	case "complete", "message", "tool_start", "tool_end":
		if len(event.Data) == 0 || event.Data[0] != '{' {
			return invalid
		}
	default:
		return fmt.Errorf("PI 返回了不支持的事件类型")
	}
	return nil
}

func textLength(s string) int { return utf8.RuneCountInString(s) }
func validID(s string) bool   { return strings.TrimSpace(s) != "" && len(s) <= 128 }
