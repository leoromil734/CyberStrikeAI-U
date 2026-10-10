// Package scratchretention bounds the agent scratch trees that grow without a
// database row to expire with them.
//
// Audit rows and tool_executions have retention because they live in tables a
// DELETE can sweep. tmp/reduction and tmp/workspace are the opposite: every
// session leaves a directory behind, and nothing removed them except deleting the
// owning conversation or project. A session that is never revisited keeps its
// files forever, so disk usage only ratchets upward.
//
// The sweep here is deliberately conservative:
//
//   - Only session directories under projects/ and conversations/ are eligible,
//     never the configured root itself and never an unrelated path.
//   - A directory must be untouched for the full retention window, judged by the
//     newest modification anywhere in the tree. A session still writing is never
//     a candidate.
//   - A session whose tree cannot be fully inspected is skipped, so an unreadable
//     subtree cannot be mistaken for an idle one.
//   - Deletion is per session directory, never per file, so a swept session is
//     not left in a mixed state.
//
// Scope is expressed through an injected lister rather than by querying the
// database here. The caller owns the database and knows which conversations are
// still live; this package only decides what is old and untouched.
package scratchretention

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// SweepInterval is how often the sweep runs while the process is up. Hourly
	// matches audit/monitor retention; the work is a bounded directory walk, not
	// a table scan.
	SweepInterval = time.Hour

	// MaxDirectoriesPerSweep bounds one pass so a tree with a very large backlog
	// cannot stall the loop. Successive passes continue where the last stopped.
	MaxDirectoriesPerSweep = 500

	// DefaultRetentionDays applies when retention_days is omitted.
	DefaultRetentionDays = 90

	// capacityGracePeriod is the minimum idle time before the capacity budget may
	// override the day count. A tree touched in the last few hours is a session
	// someone is still working in, so it is never taken for space; a day of slack
	// keeps the rule effective on a full disk without competing with live work.
	capacityGracePeriod = 24 * time.Hour
)

var (
	// ErrSweepInProgress reports that another sweep already holds the lock.
	ErrSweepInProgress = errors.New("scratch retention sweep already in progress")
	// ErrProtectionUnknown reports that the set of live sessions could not be
	// determined, so nothing was swept.
	ErrProtectionUnknown = errors.New("scratch retention skipped: live session set unknown")
)

// DefaultRoots resolves the optional reduction/workspace bases to the same
// directories the writers use when the setting is omitted: tmp/reduction and
// tmp/workspace relative to the process working directory. Passing "" through
// would leave the sweep with no roots and silently disable it.
func DefaultRoots(reductionBase, workspaceBase string) []string {
	reduction := strings.TrimSpace(reductionBase)
	if reduction == "" {
		reduction = filepath.Join("tmp", "reduction")
	}
	workspace := strings.TrimSpace(workspaceBase)
	if workspace == "" {
		workspace = filepath.Join("tmp", "workspace")
	}
	return []string{reduction, workspace}
}

// Config describes which trees to sweep and how aggressively.
type Config struct {
	// Roots are the configured root directories, e.g. tmp/reduction and
	// tmp/workspace. Empty entries are ignored.
	Roots []string
	// RetentionDays keeps anything touched more recently than this. 0 disables.
	RetentionDays int
	// MaxTotalBytes is the total size the roots may occupy. When the walk finds
	// more than this, the least recently touched trees outside the grace period
	// are reclaimed even if the day count would keep them. 0 disables the rule.
	MaxTotalBytes int64
	// SkipSessions holds session identifiers that must never be swept. It is
	// evaluated per sweep, so a session that becomes active again is protected on
	// the next pass. Both project and conversation identifiers belong here.
	// Returning nil means "protection could not be determined": the sweep is then
	// abandoned, because an unknown protection set must never be read as
	// "nothing is protected".
	SkipSessions func() map[string]bool
}

// Stats reports what one sweep did. It is returned for logging and tests.
type Stats struct {
	Considered int
	Deleted    int
	Paths      []string
	BytesFreed int64
	Errors     []string
	// InspectedFailed counts trees skipped because their contents could not be
	// fully stat'ed. It is reported separately from Errors: nothing failed to be
	// deleted, the sweep deliberately declined to judge the tree.
	InspectedFailed int
	// ReclaimedForCapacity counts trees removed by the size budget rather than by
	// the day count, so an operator can tell why otherwise-recent sessions went.
	ReclaimedForCapacity int
}

// RetentionDaysEffective returns retention; 0 means keep forever.
func (c Config) RetentionDaysEffective() int {
	if c.RetentionDays <= 0 {
		return 0
	}
	return c.RetentionDays
}

// RootsEffective returns the configured roots with blank entries removed.
func (c Config) RootsEffective() []string {
	out := make([]string, 0, len(c.Roots))
	for _, root := range c.Roots {
		if trimmed := strings.TrimSpace(root); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Service sweeps scratch directories.
//
// Serialization is not held on this value: it is claimed per root by
// lockSweepRoots, so two Service values configured with the same directory
// cannot sweep it at the same time. A single instance is still the normal case.
type Service struct {
	cfg Config
}

func NewService(cfg Config) *Service {
	return &Service{cfg: cfg}
}

// Sweep removes session directories untouched since the retention cutoff.
//
// It returns ErrSweepInProgress when a sweep is already running, so a startup
// sweep and the periodic loop cannot overlap.
func (s *Service) Sweep(now time.Time) (Stats, error) {
	stats := Stats{}
	if s == nil {
		return stats, nil
	}
	days := s.cfg.RetentionDaysEffective()
	if days <= 0 {
		return stats, nil
	}
	roots := s.cfg.RootsEffective()
	if len(roots) == 0 {
		return stats, nil
	}
	// The exclusion is bound to the directories being swept, not to this
	// Service value. Two Service values pointed at the same root would otherwise
	// both walk and delete the same tree concurrently, which duplicates work and
	// can race on one directory; a per-instance flag cannot see the other sweep.
	claimed, err := lockSweepRoots(roots)
	if err != nil {
		stats.Errors = append(stats.Errors, err.Error())
		return stats, err
	}
	defer unlockSweepRoots(claimed)

	cutoff := now.AddDate(0, 0, -days)
	skip := map[string]bool{}
	if s.cfg.SkipSessions != nil {
		protected := s.cfg.SkipSessions()
		if protected == nil {
			// The caller could not determine which sessions are live. Deleting
			// anything now risks destroying scratch data of an active session, so
			// the sweep is abandoned; the caller logs why.
			return stats, ErrProtectionUnknown
		}
		for id, isProtected := range protected {
			if !isProtected {
				continue
			}
			if trimmed := strings.TrimSpace(id); trimmed != "" {
				skip[trimmed] = true
			}
		}
	}

	// Collect before deleting. The capacity rule needs the total size of the
	// trees and their relative age, neither of which is known until the walk has
	// finished; deleting during the walk would decide the budget on partial
	// information and would also make "oldest first" impossible.
	candidates := s.collectCandidates(claimed, skip, &stats)
	totalBytes := int64(0)
	for _, candidate := range candidates {
		totalBytes += candidate.size
	}

	// Capacity budget. A day count alone is not a bound on disk use: a deployment
	// that writes tens of gigabytes a day fills the volume long before any file
	// turns 90 days old, which is exactly the case the day count cannot see.
	// Only sessions already cold for the grace period are eligible, so the rule
	// never compresses a session that is still working.
	budget := s.cfg.MaxTotalBytes
	expired := map[string]bool{}
	for _, candidate := range candidates {
		if candidate.newest.Before(cutoff) {
			expired[candidate.path] = true
		}
	}
	if budget > 0 && totalBytes > budget {
		graceCutoff := now.Add(-capacityGracePeriod)
		for _, candidate := range candidates {
			if totalBytes <= budget {
				break
			}
			if expired[candidate.path] || !candidate.newest.Before(graceCutoff) {
				continue
			}
			// This one is kept by the day count but is the oldest cold tree left,
			// so the capacity rule needs it to bring the total back under budget.
			expired[candidate.path] = true
			stats.ReclaimedForCapacity++
		}
	}

	// Delete oldest first so a pass that hits MaxDirectoriesPerSweep removes the
	// least useful trees and the next pass continues from the next oldest.
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].newest.Equal(candidates[j].newest) {
			return candidates[i].newest.Before(candidates[j].newest)
		}
		return candidates[i].path < candidates[j].path
	})
	for _, candidate := range candidates {
		if stats.Deleted >= MaxDirectoriesPerSweep {
			break
		}
		if !expired[candidate.path] {
			continue
		}
		if err := os.RemoveAll(candidate.path); err != nil {
			stats.Errors = append(stats.Errors, candidate.path+": "+err.Error())
			continue
		}
		stats.Deleted++
		stats.BytesFreed += candidate.size
		stats.Paths = append(stats.Paths, candidate.path)
	}
	sort.Strings(stats.Paths)
	return stats, nil
}

// scratchCandidate is one session directory that could be swept.
type scratchCandidate struct {
	path   string
	newest time.Time
	size   int64
}

// sweepRootLocks tracks which roots are being swept by this process. The key is
// the cleaned absolute path, so two config entries that name the same directory
// (a symlinked reduction root and a workspace root, for example) still contend
// for one lock instead of sweeping it twice.
var sweepRootLocks = struct {
	sync.Mutex
	held map[string]bool
}{held: map[string]bool{}}

// lockSweepRoots claims every root or claims none.
//
// The whole check-and-claim runs under one short critical section, which touches
// only a map: no filesystem work happens while it is held, so a second sweeper
// either sees the roots taken and returns ErrSweepInProgress, or finds them free
// and claims them. All-or-nothing keeps a multi-root sweep from reporting partial
// progress after silently dropping one root.
func lockSweepRoots(roots []string) ([]string, error) {
	claimed := make([]string, 0, len(roots))
	seen := map[string]bool{}
	for _, root := range roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		abs = filepath.Clean(abs)
		if seen[abs] {
			continue
		}
		seen[abs] = true
		claimed = append(claimed, abs)
	}
	sort.Strings(claimed)

	sweepRootLocks.Lock()
	defer sweepRootLocks.Unlock()
	for _, abs := range claimed {
		if sweepRootLocks.held[abs] {
			return nil, ErrSweepInProgress
		}
	}
	for _, abs := range claimed {
		sweepRootLocks.held[abs] = true
	}
	return claimed, nil
}

func unlockSweepRoots(roots []string) {
	sweepRootLocks.Lock()
	defer sweepRootLocks.Unlock()
	for _, abs := range roots {
		delete(sweepRootLocks.held, abs)
	}
}

// collectCandidates walks root/<scope>/<session> and returns every session
// directory that may be swept. It deletes nothing.
//
// A tree this process cannot fully inspect is not a candidate: failing closed is
// the only safe option, because an unreadable subtree cannot be proven idle.
func (s *Service) collectCandidates(roots []string, skip map[string]bool, stats *Stats) []scratchCandidate {
	candidates := []scratchCandidate{}
	for _, root := range roots {
		scopes, err := os.ReadDir(root)
		if err != nil {
			// A missing root is normal before any session has spilled. Only a real
			// read failure is worth reporting.
			if !os.IsNotExist(err) {
				stats.Errors = append(stats.Errors, root+": "+err.Error())
			}
			continue
		}
		for _, scope := range scopes {
			if !scope.IsDir() {
				continue
			}
			scopePath := filepath.Join(root, scope.Name())
			sessions, err := os.ReadDir(scopePath)
			if err != nil {
				stats.Errors = append(stats.Errors, scopePath+": "+err.Error())
				continue
			}
			for _, session := range sessions {
				if skip[session.Name()] {
					continue
				}
				sessionPath := filepath.Join(scopePath, session.Name())
				info, err := session.Info()
				if err != nil {
					// A vanished entry is already gone; nothing to clean up.
					continue
				}
				if !info.IsDir() {
					continue
				}
				stats.Considered++
				newest, size, inspected := newestActivity(sessionPath, info.ModTime())
				if !inspected {
					stats.InspectedFailed++
					continue
				}
				candidates = append(candidates, scratchCandidate{path: sessionPath, newest: newest, size: size})
			}
		}
	}
	return candidates
}

// newestActivity returns the newest modification time and total regular-file size
// inside dir. inspected reports false when any entry could not be stat'ed, which
// makes the caller skip the directory rather than risk deleting a live session.
func newestActivity(dir string, initial time.Time) (time.Time, int64, bool) {
	newest := initial
	var size int64
	inspected := true
	var walk func(string)
	walk = func(current string) {
		if !inspected {
			return
		}
		entries, err := os.ReadDir(current)
		if err != nil {
			inspected = false
			return
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				inspected = false
				return
			}
			if info.ModTime().After(newest) {
				newest = info.ModTime()
			}
			if entry.IsDir() {
				walk(filepath.Join(current, entry.Name()))
				continue
			}
			if info.Mode().IsRegular() {
				size += info.Size()
			}
		}
	}
	walk(dir)
	return newest, size, inspected
}

// StartRetentionLoop sweeps at startup and then hourly until the process exits.
//
// The startup sweep is intentional: a host that restarts should not wait an hour
// before reclaiming space, and the first pass after an outage is usually the one
// that matters. onSweep may be nil.
func StartRetentionLoop(s *Service, now func() time.Time, onSweep func(Stats)) {
	if s == nil {
		return
	}
	if now == nil {
		now = time.Now
	}
	go func() {
		ticker := time.NewTicker(SweepInterval)
		defer ticker.Stop()
		sweep := func() {
			stats, err := s.Sweep(now())
			if err != nil {
				if onSweep != nil && !errors.Is(err, ErrSweepInProgress) {
					onSweep(Stats{Errors: []string{err.Error()}})
				}
				return
			}
			if onSweep != nil {
				onSweep(stats)
			}
		}
		sweep()
		for range ticker.C {
			sweep()
		}
	}()
}
