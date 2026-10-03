package database

import (
	"strings"
	"testing"
)

func TestReconcileResultIngestionPostgresDoesNotSplitDiagnostic(t *testing.T) {
	parts := splitSQLStatements(reconcileResultIngestionSQL)
	if len(parts) != 1 {
		t.Fatalf("restart reconciliation was split into invalid SQL: %v", parts)
	}
	if strings.Contains(reconcileResultIngestionSQL, "ingestion interrupted") || strings.Count(reconcileResultIngestionSQL, "?") != 2 {
		t.Fatal("reason and timestamp must both be bound parameters")
	}
}
