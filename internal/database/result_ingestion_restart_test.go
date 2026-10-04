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
	if strings.Contains(reconcileResultIngestionSQL, "ingestion interrupted") || strings.Count(reconcileResultIngestionSQL, "?") != 3 {
		t.Fatal("diagnostic, update time and expiry cutoff must be bound parameters")
	}
}
