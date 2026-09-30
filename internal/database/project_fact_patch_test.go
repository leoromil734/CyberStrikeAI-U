package database

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestUpsertProjectFactPatchOptionalFields(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "fact-patch.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	proj, err := db.CreateProject(&Project{Name: "fact-patch"})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		fields     ProjectFactPatchFields
		body       string
		category   string
		confidence string
		pinned     bool
		related    string
	}{
		{name: "summary-only", pinned: true, related: "vuln-1"},
		{name: "empty-text-fields", body: " \n", category: " \t", confidence: " \n", pinned: true, related: "vuln-1"},
		{name: "explicit-unpin", fields: ProjectFactPatchFields{PinnedSet: true}, related: "vuln-1"},
		{name: "explicit-clear-related", fields: ProjectFactPatchFields{RelatedVulnerabilityIDSet: true}, pinned: true},
		{name: "explicit-clear-both", fields: ProjectFactPatchFields{PinnedSet: true, RelatedVulnerabilityIDSet: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := "note/" + tc.name
			original, err := db.UpsertProjectFact(&ProjectFact{
				ProjectID: proj.ID, FactKey: key, Summary: "before", Body: "preserved details",
				Category: "recon", Confidence: "confirmed", Pinned: true, RelatedVulnerabilityID: "vuln-1",
			})
			if err != nil {
				t.Fatal(err)
			}
			updated, err := db.UpsertProjectFactPatch(&ProjectFact{
				ProjectID: proj.ID, FactKey: key, Summary: "after", Body: tc.body,
				Category: tc.category, Confidence: tc.confidence,
			}, tc.fields)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := db.GetProjectFactByKey(proj.ID, key)
			if err != nil {
				t.Fatal(err)
			}
			for _, fact := range []*ProjectFact{updated, stored} {
				if fact.ID != original.ID || fact.Summary != "after" || fact.Body != "preserved details" ||
					fact.Category != "recon" || fact.Confidence != "confirmed" || fact.Pinned != tc.pinned ||
					fact.RelatedVulnerabilityID != tc.related {
					t.Fatalf("partial update lost fields: %#v", fact)
				}
			}
		})
	}
}

func TestUpsertProjectFactLegacyExplicitZeroValues(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "fact-legacy.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	proj, err := db.CreateProject(&Project{Name: "fact-legacy"})
	if err != nil {
		t.Fatal(err)
	}

	for _, loaded := range []bool{false, true} {
		name := "fresh-input"
		if loaded {
			name = "loaded-input"
		}
		t.Run(name, func(t *testing.T) {
			key := "note/" + name
			_, err := db.UpsertProjectFact(&ProjectFact{
				ProjectID: proj.ID, FactKey: key, Summary: "before", Body: "details",
				Category: "recon", Confidence: "confirmed", Pinned: true, RelatedVulnerabilityID: "vuln-1",
			})
			if err != nil {
				t.Fatal(err)
			}
			input := &ProjectFact{ProjectID: proj.ID, FactKey: key}
			if loaded {
				input, err = db.GetProjectFactByKey(proj.ID, key)
				if err != nil {
					t.Fatal(err)
				}
			}
			input.Summary = "after"
			input.Pinned = false
			input.RelatedVulnerabilityID = ""
			if _, err := db.UpsertProjectFact(input); err != nil {
				t.Fatal(err)
			}
			stored, err := db.GetProjectFactByKey(proj.ID, key)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Summary != "after" || stored.Body != "details" || stored.Category != "recon" ||
				stored.Confidence != "confirmed" || stored.Pinned || stored.RelatedVulnerabilityID != "" {
				t.Fatalf("legacy update did not retain explicit zero-value behavior: %#v", stored)
			}
		})
	}
}

func TestUpsertProjectFactCreationDefaults(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "fact-defaults.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	proj, err := db.CreateProject(&Project{Name: "fact-defaults"})
	if err != nil {
		t.Fatal(err)
	}

	for name, upsert := range map[string]func(*ProjectFact) (*ProjectFact, error){
		"legacy": db.UpsertProjectFact,
		"patch": func(f *ProjectFact) (*ProjectFact, error) {
			return db.UpsertProjectFactPatch(f, ProjectFactPatchFields{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, category := range []string{"", " \t"} {
				key := "note/" + name + "/empty"
				if category != "" {
					key = "note/" + name + "/whitespace"
				}
				created, err := upsert(&ProjectFact{
					ProjectID: proj.ID, FactKey: key, Summary: "created", Category: category, Confidence: category,
				})
				if err != nil {
					t.Fatal(err)
				}
				stored, err := db.GetProjectFactByKey(proj.ID, key)
				if err != nil {
					t.Fatal(err)
				}
				for _, fact := range []*ProjectFact{created, stored} {
					if fact.Category != "note" || fact.Confidence != "tentative" || fact.Pinned || fact.RelatedVulnerabilityID != "" {
						t.Fatalf("unexpected creation defaults: %#v", fact)
					}
				}
			}
		})
	}
}
