package agentfinalizer

import (
	"regexp"
	"strings"

	"cyberstrike-ai/internal/coverage"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/evidence"
	"cyberstrike-ai/internal/recon"
)

// MaxAutomaticCoverageRepairGroups bounds bookkeeping repair, not inventory or
// assessment scope. Larger unresolved candidate sets need an auditable scope,
// freshness and business-template review before any automatic continuation.
const MaxAutomaticCoverageRepairGroups = 100

// CoverageProgress describes independent inventory and actual source executions,
// never the number of model-written facts. Known is false when the assessment
// was not checked or any inventory/source read was incomplete. In that case the
// counts are observations only, not a claim of zero remaining work.
//
// MappedGroups means source-backed terminal ledger mappings, NOT confirmed safe
// business test units. An N/A-only risk ledger cannot dispose of a raw candidate.
// InventoryGroups always includes unresolved candidates; filtering a model's
// manifest or limiting displayed diagnostics does not reduce this count.
type CoverageProgress struct {
	// Known requires a persisted assessment, successful uncapped inventory and
	// source reads, and no pending/failed original ingestion. It does not mean
	// the ledger, sources, or assessment passed the delivery gate.
	Known bool
	// When Known, InventoryGroups = MappedGroups + UnresolvedGroups, using
	// every stored independent endpoint/JS group, not manifest declarations.
	InventoryGroups  int
	UnresolvedGroups int
	MappedGroups     int
	// Distinct current-assessment execution IDs with at least one supported,
	// parsed, complete, non-expired actual recon_source; multiple originals
	// for one execution count once. This is not a count of fact/tool rows.
	EvidenceExecutions int
	// RepairBlocked prevents automatic bookkeeping repair when progress is
	// unknown or UnresolvedGroups > MaxAutomaticCoverageRepairGroups. It is
	// never a waiver of missing checks or permission to finalize with gaps.
	RepairBlocked bool
}

// Explicit references are token-matched: execution:scan-1 must not match
// execution:scan-10. Free prose, file reads and project_fact references do not
// establish an execution. Structured IDs, when supplied, must also match.
var coverageEvidenceReference = regexp.MustCompile(`\b(mcp_execution|execution|execution_id|source|source_id):([A-Za-z0-9._-]+)`)

type coverageSourceIndex struct {
	sources     map[string]database.AssessmentSourceMetadata
	byExecution map[string][]string
	http        map[string][]coverage.HTTPObservation
	binding     coverage.OriginalBinding
}

func completeCoverageSources(sources []database.AssessmentSourceMetadata, nowMS int64) coverageSourceIndex {
	index := coverageSourceIndex{sources: map[string]database.AssessmentSourceMetadata{}, byExecution: map[string][]string{}}
	for _, source := range sources {
		if source.ID == "" || source.ExecutionID == "" || source.State != evidence.Parsed || source.Completion != evidence.Complete || (source.ExpiresAtMS != 0 && source.ExpiresAtMS <= nowMS) {
			continue
		}
		// Only parsers for real reconnaissance tools may establish progress.
		// A completed fact-write/read-file execution is never evidence progress.
		switch recon.CanonicalTool(source.Tool) {
		case "fofa", "subfinder", "oneforall", "dnsx", "httpx", "naabu", "nmap", "gau", "katana", "jsapiscan", "jsluice", "nuclei":
		default:
			continue
		}
		index.sources[source.ID] = source
		index.byExecution[source.ExecutionID] = append(index.byExecution[source.ExecutionID], source.ID)
	}
	return index
}

func (index coverageSourceIndex) corroborates(fields map[string]any) bool {
	executionID, sourceID := fieldText(fields, "execution_id"), fieldText(fields, "source_id")
	matches := func(source database.AssessmentSourceMetadata) bool {
		if (executionID != "" && source.ExecutionID != executionID) || (sourceID != "" && source.ID != sourceID) {
			return false
		}
		for _, observation := range index.http[source.ExecutionID] {
			if tool := fieldText(fields, "http_tool"); tool != "" && tool != observation.Tool() {
				continue
			}
			if observation.Matches(fieldText(fields, "endpoint_url"), fieldText(fields, "method")) {
				return true
			}
		}
		return false
	}
	matchExecution := func(id string) bool {
		for _, sourceID := range index.byExecution[id] {
			if matches(index.sources[sourceID]) {
				return true
			}
		}
		return false
	}
	if sourceID != "" {
		source, ok := index.sources[sourceID]
		return ok && matches(source)
	}
	if executionID != "" {
		return matchExecution(executionID)
	}
	for _, ref := range coverageEvidenceReference.FindAllStringSubmatch(fieldText(fields, "evidence"), -1) {
		if ref[1] == "source" || ref[1] == "source_id" {
			if source, ok := index.sources[ref[2]]; ok && matches(source) {
				return true
			}
		} else if matchExecution(ref[2]) {
			return true
		}
	}
	return false
}

// inventoryDispositionFacts is intentionally stricter than merely matching a
// URL. Keep the existing ledger validator and actual-source gate; additionally,
// a discovered candidate needs a terminal, source-backed disposition to count
// as mapped. N/A may describe individual inapplicable risk families, but an
// all-N/A endpoint says nothing about the disposition of the raw candidate.
func inventoryDispositionFacts(facts []coverage.Fact, assessmentID string, sources coverageSourceIndex) []coverage.Fact {
	type entry struct {
		fact   coverage.Fact
		fields map[string]any
	}
	entries := make(map[string]entry, len(facts))
	for _, fact := range facts {
		fields, err := coverage.ParseLedgerBody(fact.Body)
		if err != nil || fieldText(fields, "assessment_id") != assessmentID || coverage.ValidateLedgerFact(fact.Key, fact.Body) != nil {
			continue
		}
		entries[fact.Key] = entry{fact: fact, fields: fields}
	}
	out := make([]coverage.Fact, 0)
	for key, e := range entries {
		if !strings.HasPrefix(key, "recon/endpoint/") && !strings.HasPrefix(key, "recon/js/") {
			continue
		}
		if !sources.corroborates(e.fields) {
			continue
		}
		if strings.HasPrefix(key, "recon/js/") {
			if status := fieldText(e.fields, "status"); status == "expanded" || status == "blocked" {
				out = append(out, e.fact)
			}
			continue
		}
		status := fieldText(e.fields, "runtime_status")
		if status == "blocked" {
			out = append(out, e.fact)
			continue
		}
		if status != "risk-mapped" {
			continue
		}
		units, _ := e.fields["risk_units"].([]any)
		valid, substantive := len(units) > 0, false
		for _, raw := range units {
			unit, ok := raw.(string)
			risk, exists := entries[strings.TrimSpace(unit)]
			if !ok || !exists || !strings.HasPrefix(unit, "recon/risk/") || fieldText(risk.fields, "endpoint_key") != key {
				valid = false
				break
			}
			switch fieldText(risk.fields, "status") {
			case "not-applicable":
				// Valid N/A units remain in the ledger, but cannot on their own
				// turn an untested candidate into a resolved business unit.
			case "covered", "negated", "blocked":
				// An HTTP exchange establishes a baseline, not arbitrary SQLi,
				// authorization, or business-logic conclusions. Specialized risk
				// verifiers must be added explicitly rather than trusting labels.
				riskFields := make(map[string]any, len(risk.fields)+2)
				for name, value := range risk.fields {
					riskFields[name] = value
				}
				for _, name := range []string{"endpoint_url", "method"} {
					if value := fieldText(risk.fields, name); value != "" && value != fieldText(e.fields, name) {
						valid = false
					}
					riskFields[name] = e.fields[name]
				}
				family := fieldText(risk.fields, "risk_family")
				valid = valid && fieldText(risk.fields, "status") == "covered" && (family == "http-baseline" || family == "http-response") && sources.corroborates(riskFields)
				substantive = true
			default:
				valid = false
			}
		}
		if valid && substantive {
			out = append(out, e.fact)
		}
	}
	return out
}

func (d *Decision) setCoverageProgress(progress CoverageProgress) {
	d.CoverageProgressKnown = progress.Known
	d.CoverageInventoryGroups = progress.InventoryGroups
	d.CoverageUnresolvedGroups = progress.UnresolvedGroups
	d.CoverageMappedGroups = progress.MappedGroups
	d.CoverageEvidenceExecutions = progress.EvidenceExecutions
	d.CoverageRepairBlocked = progress.RepairBlocked
}
