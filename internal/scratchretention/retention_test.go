package scratchretention

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeSession(t *testing.T, root, scope, id string, age time.Duration, now time.Time) string {
	t.Helper()
	path := filepath.Join(root, scope, id)
	if err := os.MkdirAll(filepath.Join(path, "trunc"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, "trunc", "output")
	if err := os.WriteFile(file, []byte("evidence payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	stamp := now.Add(-age)
	for _, target := range []string{file, filepath.Join(path, "trunc"), path} {
		if err := os.Chtimes(target, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestDefaultRootsFallsBackToRuntimePaths(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		reduction, workspace  string
		wantReduction, wantWS string
	}{
		{"both empty", "", "", filepath.Join("tmp", "reduction"), filepath.Join("tmp", "workspace")},
		{"explicit values", "/data/reduction", "/data/ws", "/data/reduction", "/data/ws"},
		{"blank strings count as empty", "  ", "\t", filepath.Join("tmp", "reduction"), filepath.Join("tmp", "workspace")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots := DefaultRoots(tc.reduction, tc.workspace)
			if len(roots) != 2 || roots[0] != tc.wantReduction || roots[1] != tc.wantWS {
				t.Fatalf("DefaultRoots(%q, %q) = %v", tc.reduction, tc.workspace, roots)
			}
			service := NewService(Config{Roots: roots, RetentionDays: 90})
			if len(service.cfg.RootsEffective()) != 2 {
				t.Fatalf("configured roots must survive filtering: %v", roots)
			}
		})
	}
}

func TestSweepRemovesOnlyExpiredSessions(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	old := makeSession(t, root, "conversations", "old-session", 120*24*time.Hour, now)
	recent := makeSession(t, root, "conversations", "recent-session", 5*24*time.Hour, now)
	oldProject := makeSession(t, root, "projects", "old-project", 200*24*time.Hour, now)

	service := NewService(Config{Roots: []string{root}, RetentionDays: 90})
	stats, err := service.Sweep(now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Deleted != 2 {
		t.Fatalf("expected the two expired sessions to be removed, got %d (%v)", stats.Deleted, stats.Paths)
	}
	for _, gone := range []string{old, oldProject} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("expired session still present: %s", gone)
		}
	}
	if _, err := os.Stat(recent); err != nil {
		t.Errorf("recent session must be kept: %v", err)
	}
	if stats.BytesFreed <= 0 {
		t.Errorf("byte accounting should be positive, got %d", stats.BytesFreed)
	}
}

// The newest activity anywhere in the tree decides, not the directory's own
// timestamp: a session whose subdirectory was written recently is still live.
func TestSweepKeepsSessionWithRecentNestedWrite(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	session := makeSession(t, root, "conversations", "resumed-session", 200*24*time.Hour, now)
	nested := filepath.Join(session, "trunc", "late-write")
	if err := os.WriteFile(nested, []byte("still writing"), 0o600); err != nil {
		t.Fatal(err)
	}

	service := NewService(Config{Roots: []string{root}, RetentionDays: 90})
	stats, err := service.Sweep(now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Deleted != 0 {
		t.Fatalf("a session with recent activity must be kept, deleted %v", stats.Paths)
	}
	if _, err := os.Stat(session); err != nil {
		t.Fatalf("session removed despite recent write: %v", err)
	}
}

func TestSweepRespectsProtectedSessions(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	protected := makeSession(t, root, "conversations", "live-session", 300*24*time.Hour, now)
	other := makeSession(t, root, "conversations", "stale-session", 300*24*time.Hour, now)

	service := NewService(Config{
		Roots:         []string{root},
		RetentionDays: 90,
		SkipSessions:  func() map[string]bool { return map[string]bool{"live-session": true} },
	})
	stats, err := service.Sweep(now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Deleted != 1 {
		t.Fatalf("only the unprotected session should go, got %v", stats.Paths)
	}
	if _, err := os.Stat(protected); err != nil {
		t.Fatalf("protected session removed: %v", err)
	}
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatal("stale session should be removed")
	}
}

// An unknown protection set must never be read as "nothing is protected".
func TestSweepSkipsEntirelyWhenProtectionUnknown(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	session := makeSession(t, root, "conversations", "any-session", 400*24*time.Hour, now)

	service := NewService(Config{
		Roots:         []string{root},
		RetentionDays: 90,
		SkipSessions:  func() map[string]bool { return nil },
	})
	stats, err := service.Sweep(now)
	if err != ErrProtectionUnknown {
		t.Fatalf("expected ErrProtectionUnknown, got %v", err)
	}
	if stats.Deleted != 0 {
		t.Fatalf("nothing may be deleted when protection is unknown: %v", stats.Paths)
	}
	if _, err := os.Stat(session); err != nil {
		t.Fatalf("session removed during an unknown-protection sweep: %v", err)
	}
}

func TestSweepDisabledByZeroOrNegativeRetention(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	session := makeSession(t, root, "conversations", "ancient", 999*24*time.Hour, now)
	for _, days := range []int{0, -1} {
		service := NewService(Config{Roots: []string{root}, RetentionDays: days})
		stats, err := service.Sweep(now)
		if err != nil || stats.Deleted != 0 {
			t.Fatalf("retention %d must disable cleanup: %v %v", days, stats, err)
		}
	}
	if _, err := os.Stat(session); err != nil {
		t.Fatal("disabled retention must keep directories")
	}
}

func TestSweepIgnoresMissingRootAndLooseFiles(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	// A loose file directly in the root must never be treated as a session.
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := NewService(Config{Roots: []string{root, filepath.Join(root, "does-not-exist")}, RetentionDays: 90})
	stats, err := service.Sweep(now)
	if err != nil {
		t.Fatalf("a missing root is normal and must not error: %v", err)
	}
	if stats.Deleted != 0 || len(stats.Errors) != 0 {
		t.Fatalf("unexpected activity: %+v", stats)
	}
	if _, err := os.Stat(filepath.Join(root, "README")); err != nil {
		t.Fatal("unrelated files must be left alone")
	}
}

func TestSweepIsSerialized(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	service := NewService(Config{
		Roots:         []string{root},
		RetentionDays: 90,
		SkipSessions:  func() map[string]bool { return map[string]bool{} },
	})
	// Hold the lock by running a sweep that blocks inside its protection callback.
	started := make(chan struct{})
	release := make(chan struct{})
	blocking := NewService(Config{
		Roots:         []string{root},
		RetentionDays: 90,
		SkipSessions: func() map[string]bool {
			close(started)
			<-release
			return map[string]bool{}
		},
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = blocking.Sweep(now)
	}()
	<-started
	if _, err := service.Sweep(now); err != ErrSweepInProgress {
		t.Fatalf("concurrent sweeps must be rejected, got %v", err)
	}
	close(release)
	<-done
}

// The exclusion belongs to the directory, not to a Service value. A second
// Service built for the same tree must contend with the first one; otherwise the
// startup sweep and the periodic loop (or two roots naming one directory) can
// walk and delete the same sessions at the same time.
func TestSweepSerializesAcrossServiceValues(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	// The same tree named two ways: once by its own path, once through a
	// traversal segment, so string equality alone would not match them.
	aliased := filepath.Join(root, "..", filepath.Base(root))
	first := NewService(Config{
		Roots:         []string{root},
		RetentionDays: 90,
		SkipSessions:  func() map[string]bool { return map[string]bool{} },
	})
	started := make(chan struct{})
	release := make(chan struct{})
	blocking := NewService(Config{
		Roots:         []string{aliased},
		RetentionDays: 90,
		SkipSessions: func() map[string]bool {
			close(started)
			<-release
			return map[string]bool{}
		},
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = blocking.Sweep(now)
	}()
	<-started
	_, err := first.Sweep(now)
	close(release)
	<-done
	if !errors.Is(err, ErrSweepInProgress) {
		t.Fatalf("a sweep of the same directory from another Service must be rejected, got %v", err)
	}
}

// A sweep that claims its roots must release them on every exit path, or the
// periodic loop would stop working after one pass.
func TestSweepReleasesRootsAfterCompletion(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	makeSession(t, root, "conversations", "one", 200*24*time.Hour, now)
	makeSession(t, root, "conversations", "two", 200*24*time.Hour, now)
	service := NewService(Config{
		Roots:         []string{root},
		RetentionDays: 90,
		SkipSessions:  func() map[string]bool { return map[string]bool{} },
	})
	if _, err := service.Sweep(now); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Sweep(now); err != nil {
		t.Fatalf("a completed sweep must release its roots: %v", err)
	}
}

// A day count is not a bound on disk use. A deployment that writes tens of
// gigabytes a day fills the volume long before anything reaches 90 days, so the
// capacity budget must be able to reclaim the least recently used cold trees.
func TestSweepEnforcesCapacityBudget(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	// Three sessions well inside the 90-day window, so only the byte budget can
	// explain a deletion. The youngest is still inside the grace period.
	fresh := makeSession(t, root, "conversations", "recently-active", 2*time.Hour, now)
	middle := makeSession(t, root, "conversations", "cold-middle", 20*24*time.Hour, now)
	oldest := makeSession(t, root, "conversations", "cold-oldest", 40*24*time.Hour, now)

	perSession := int64(len("evidence payload"))
	service := NewService(Config{
		Roots:         []string{root},
		RetentionDays: 90,
		// Room for one session only: two must go, oldest first.
		MaxTotalBytes: perSession + 1,
		SkipSessions:  func() map[string]bool { return map[string]bool{} },
	})
	stats, err := service.Sweep(now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Deleted != 2 {
		t.Fatalf("capacity budget should reclaim down to the limit, deleted %d (%v)", stats.Deleted, stats.Paths)
	}
	if stats.ReclaimedForCapacity != 2 {
		t.Fatalf("capacity-driven deletions must be reported, got %d", stats.ReclaimedForCapacity)
	}
	if _, err := os.Stat(middle); !os.IsNotExist(err) {
		t.Errorf("the older cold session should be reclaimed first: %s", middle)
	}
	if _, err := os.Stat(oldest); !os.IsNotExist(err) {
		t.Errorf("the oldest cold session should be reclaimed: %s", oldest)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("a session inside the grace period must be kept: %v", err)
	}
}

// The capacity rule must never compete with live work: a tree touched recently
// is skipped even when the budget would otherwise reach it.
func TestSweepCapacityRespectsGracePeriod(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	active := makeSession(t, root, "conversations", "still-writing", time.Minute, now)
	service := NewService(Config{
		Roots:         []string{root},
		RetentionDays: 90,
		MaxTotalBytes: 1,
		SkipSessions:  func() map[string]bool { return map[string]bool{} },
	})
	stats, err := service.Sweep(now)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Deleted != 0 {
		t.Fatalf("a session inside the grace period must not be reclaimed: %v", stats.Paths)
	}
	if _, err := os.Stat(active); err != nil {
		t.Fatalf("active session removed: %v", err)
	}
}

// Zero disables only the capacity rule; the day count keeps working.
func TestSweepCapacityDisabledByZero(t *testing.T) {
	now := time.Now()
	root := t.TempDir()
	makeSession(t, root, "conversations", "cold", 30*24*time.Hour, now)
	service := NewService(Config{
		Roots:         []string{root},
		RetentionDays: 90,
		MaxTotalBytes: 0,
		SkipSessions:  func() map[string]bool { return map[string]bool{} },
	})
	stats, err := service.Sweep(now)
	if err != nil || stats.Deleted != 0 {
		t.Fatalf("capacity 0 must not delete anything: %v %v", stats, err)
	}
}

func TestRetentionDaysEffectiveDefaults(t *testing.T) {
	if got := (Config{}).RetentionDaysEffective(); got != 0 {
		t.Fatalf("an unset Config value has no default at this layer, got %d", got)
	}
	if got := (Config{RetentionDays: 90}).RetentionDaysEffective(); got != 90 {
		t.Fatalf("configured retention lost: %d", got)
	}
	if got := (Config{RetentionDays: -1}).RetentionDaysEffective(); got != 0 {
		t.Fatalf("negative retention must disable cleanup: %d", got)
	}
	if roots := (Config{Roots: []string{" a ", "", "b"}}).RootsEffective(); len(roots) != 2 {
		t.Fatalf("blank roots must be dropped: %v", roots)
	}
	if DefaultRetentionDays != 90 {
		t.Fatalf("default retention must match monitor.retention_days: %d", DefaultRetentionDays)
	}
}
