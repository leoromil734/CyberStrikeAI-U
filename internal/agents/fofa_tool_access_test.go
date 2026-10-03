package agents

import (
	"slices"
	"testing"
)

// The shared online-recon contract asks these roles to use fofa_search. Merely
// mentioning the tool in the prompt/skill does not put it in a role's toolset.
func TestBundledOnlineRolesDeclareFOFAPrerequisite(t *testing.T) {
	load, err := LoadMarkdownAgentsDir(bundledAgentsRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"recon", "intel-collection", "penetration"} {
		t.Run(id, func(t *testing.T) {
			for _, sub := range load.SubAgents {
				if sub.ID == id {
					if !slices.Contains(sub.RoleTools, "fofa_search") {
						t.Fatalf("%s requires FOFA but filters fofa_search out before tool_search is built", id)
					}
					return
				}
			}
			t.Fatalf("bundled role %q was not loaded", id)
		})
	}
}

func TestExplicitRoleToolListIsNotImplicitlyExpanded(t *testing.T) {
	sub, err := ParseMarkdownSubAgent("limited.md", "---\nid: limited\nname: Limited\ntools:\n  - httpx\n---\nOnly the declared tool is permitted.")
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.RoleTools) != 1 || sub.RoleTools[0] != "httpx" {
		t.Fatalf("fix must not bypass custom role tool restrictions: %v", sub.RoleTools)
	}
}
