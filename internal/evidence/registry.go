package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cyberstrike-ai/internal/tooloutput"
	"github.com/google/uuid"
)

// ManagedRoot is trusted configuration, NOT a value extracted from tool output.
// Each root belongs to one execution. For shared roots such as JSAPIscan runs,
// configure the execution's allocated job directory rather than the common parent.
// Files, when nonempty, is an exact relative-file allowlist (e.g. a spill file).
type ManagedRoot struct {
	Path string
	Access
	ExecutionID string
	Files       []string
}

type managedRoot struct {
	ManagedRoot
	directory *os.Root
}

type Registry struct {
	store    Store
	roots    []managedRoot
	maxBytes int64
}

const DefaultMaxArtifactBytes int64 = 1 << 30

func NewRegistry(store Store, roots []ManagedRoot, maxBytes int64) (*Registry, error) {
	if store == nil {
		return nil, errors.New("artifact store required")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxArtifactBytes
	}
	r := &Registry{store: store, maxBytes: maxBytes}
	ok := false
	defer func() {
		if !ok {
			_ = r.Close()
		}
	}()
	for _, root := range roots {
		if root.ExecutionID == "" || root.Owner == "" || root.ConversationID == "" || unsafeLexical(root.Path) {
			return nil, ErrUnsafePath
		}
		root.Path = filepath.Clean(root.Path)
		if err := noLinks(root.Path); err != nil {
			return nil, err
		}
		info, err := os.Lstat(root.Path)
		if err != nil || !info.IsDir() {
			return nil, ErrUnsafePath
		}
		root.Files = append([]string(nil), root.Files...)
		for _, file := range root.Files {
			if filepath.IsAbs(file) || file == "" || hasTraversal(file) || filepath.Clean(file) != file {
				return nil, ErrUnsafePath
			}
		}
		directory, err := os.OpenRoot(root.Path)
		if err != nil {
			return nil, ErrUnsafePath
		}
		pinned, err := directory.Stat(".")
		if err != nil || !os.SameFile(info, pinned) || noLinks(root.Path) != nil {
			directory.Close()
			return nil, ErrUnsafePath
		}
		r.roots = append(r.roots, managedRoot{ManagedRoot: root, directory: directory})
	}
	ok = true
	return r, nil
}

func (r *Registry) Close() error {
	var result error
	for _, root := range r.roots {
		result = errors.Join(result, root.directory.Close())
	}
	return result
}

// ReductionRoot reuses tooloutput's layout but restricts registration to the
// exact execution spill. Identifiers with path separators or traversal are refused.
func ReductionRoot(base string, e Execution) (ManagedRoot, error) {
	for _, id := range []string{e.ProjectID, e.ConversationID, e.ID} {
		if strings.ContainsAny(id, "/\\:") || id == "." || strings.Contains(id, "..") || len(id) > 180 {
			return ManagedRoot{}, ErrUnsafePath
		}
	}
	root, err := filepath.Abs(filepath.Join(tooloutput.SessionRoot(base, e.ProjectID, e.ConversationID), "trunc"))
	if err != nil {
		return ManagedRoot{}, ErrUnsafePath
	}
	return ManagedRoot{Path: root, Access: e.Access, ExecutionID: e.ID, Files: []string{e.ID}}, nil
}

func hasTraversal(path string) bool {
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return true
		}
	}
	return false
}

func unsafeLexical(path string) bool {
	if !filepath.IsAbs(path) || hasTraversal(path) || strings.ContainsRune(path, 0) {
		return true
	}
	// Reject UNC/device paths and alternate data streams as well as remote mounts
	// addressed via UNC. Root configuration is intended for local managed files.
	if strings.HasPrefix(path, "\\\\") || strings.HasPrefix(path, "//") {
		return true
	}
	rest := strings.TrimPrefix(path, filepath.VolumeName(path))
	return strings.Contains(rest, ":")
}

func noLinks(path string) error {
	path = filepath.Clean(path)
	for {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafePath
		}
		// Windows junctions/reparse aliases may not advertise ModeSymlink; compare
		// the resolved path as an additional check, never use it to grant access.
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || !samePath(filepath.Clean(resolved), path) {
			return ErrUnsafePath
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func samePath(a, b string) bool {
	if filepath.Separator == '\\' {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func (r *Registry) rootFor(e Execution, path string) (managedRoot, string, error) {
	if unsafeLexical(path) {
		return managedRoot{}, "", ErrUnsafePath
	}
	path = filepath.Clean(path)
	for _, root := range r.roots {
		if root.Access != e.Access || root.ExecutionID != e.ID {
			continue
		}
		rel, err := filepath.Rel(root.Path, path)
		if err != nil || rel == "." || filepath.IsAbs(rel) || hasTraversal(rel) {
			continue
		}
		allowed := len(root.Files) == 0
		for _, file := range root.Files {
			if samePath(rel, file) {
				allowed = true
				break
			}
		}
		if allowed {
			return root, rel, nil
		}
	}
	return managedRoot{}, "", ErrUnsafePath
}

// open confines resolution using os.Root (Go 1.25); component checks alone are
// insufficient because a tool can race a path substitution. A same-file check
// before/after open and a full hash on reuse provide additional fail-closed checks.
func (r *Registry) open(e Execution, path string) (*os.File, error) {
	root, rel, err := r.rootFor(e, path)
	if err != nil {
		return nil, err
	}
	if err = noLinks(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrUnsafePath
	}
	f, err := root.directory.Open(rel)
	if err != nil {
		return nil, ErrUnsafePath
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || !singleLink(f) || after.Size() > r.maxBytes {
		f.Close()
		if after != nil && after.Size() > r.maxBytes {
			return nil, ErrLimit
		}
		return nil, ErrUnsafePath
	}
	if err = noLinks(path); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

type contextReader struct {
	ctx context.Context
	io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func (r *Registry) digest(ctx context.Context, f *os.File) (int64, string, error) {
	before, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	if !singleLink(f) {
		return 0, "", ErrUnsafePath
	}
	h := sha256.New()
	n, err := io.CopyBuffer(h, contextReader{ctx, io.LimitReader(f, r.maxBytes+1)}, make([]byte, 64*1024))
	if err != nil {
		return 0, "", err
	}
	if n > r.maxBytes {
		return 0, "", ErrLimit
	}
	after, err := f.Stat()
	if err != nil || !singleLink(f) || n != before.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return 0, "", ErrChanged
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// Verify only reads paths permitted by a trusted execution-bound root. It does
// not accept preview hints as proof of a complete original.
func (r *Registry) Verify(ctx context.Context, e Execution, c Candidate) (VerifiedArtifact, error) {
	if err := e.Validate(ctx); err != nil {
		return VerifiedArtifact{}, err
	}
	stored, err := r.store.ResultExecution(ctx, e.ID)
	if err != nil || stored.Access != e.Access || stored.ScopeID != e.ScopeID || stored.AssessmentID != e.AssessmentID {
		return VerifiedArtifact{}, ErrDenied
	}
	if c.Kind == "" || len(c.Kind) > 32 || len(c.Format) > 32 || !ValidCompletion(c.Completion) {
		return VerifiedArtifact{}, errors.New("invalid artifact metadata")
	}
	f, err := r.open(e, c.Path)
	if err != nil {
		return VerifiedArtifact{}, err
	}
	defer f.Close()
	size, digest, err := r.digest(ctx, f)
	if err != nil {
		return VerifiedArtifact{}, err
	}
	if c.ExpectedSHA256 != "" && !strings.EqualFold(c.ExpectedSHA256, digest) {
		return VerifiedArtifact{}, ErrChanged
	}
	completion := c.Completion
	if stored.TimedOut || stored.Completion == Partial {
		completion = Partial
	} else if stored.Completion == Error {
		completion = Error
	}
	a := Artifact{ID: uuid.NewString(), ExecutionID: e.ID, Access: e.Access, Kind: c.Kind, Path: filepath.Clean(c.Path), Size: size, SHA256: digest, Format: strings.ToLower(c.Format), Completion: completion, ParseState: InitialParseState(c.Kind), CreatedAt: time.Now().UTC()}
	return VerifiedArtifact{artifact: a, verified: true}, nil
}

// ParseableArtifactKind reports whether the offline parser will ever attempt this
// artifact kind.
//
// The distinction matters because ParseState is read as a queue position. An
// input, log, manifest or source file is registered for provenance and is never
// handed to Parse, so recording it as Pending leaves a permanent "not parsed
// yet" that no worker will ever clear. Those rows accumulate without bound and
// cannot be told apart from a genuine parsing backlog, which is exactly the signal
// an operator needs. Recording them as Unsupported states the truth once: nothing
// is going to parse this, and the original is still retained.
func ParseableArtifactKind(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "output", "machine":
		return true
	}
	return false
}

// InitialParseState is the parse state an artifact has at registration, before
// any parser has run.
func InitialParseState(kind string) string {
	if ParseableArtifactKind(kind) {
		return Pending
	}
	return Unsupported
}

func (r *Registry) Register(ctx context.Context, e Execution, c Candidate) (Artifact, error) {
	v, err := r.Verify(ctx, e, c)
	if err != nil {
		return Artifact{}, err
	}
	return r.store.RegisterArtifact(ctx, v)
}

// OpenVerified accepts a registry ID, never a path. Hashes are streamed and
// checked every time; the returned descriptor refers to the checked original.
func (r *Registry) OpenVerified(ctx context.Context, id string) (*os.File, Artifact, error) {
	a, err := r.store.ResultArtifact(ctx, id)
	if err != nil {
		return nil, Artifact{}, err
	}
	if err = a.Access.Authorize(ctx); err != nil {
		return nil, Artifact{}, err
	}
	e, err := r.store.ResultExecution(ctx, a.ExecutionID)
	if err != nil || e.Access != a.Access {
		return nil, Artifact{}, ErrDenied
	}
	f, err := r.open(e, a.Path)
	if err != nil {
		return nil, Artifact{}, err
	}
	size, hash, err := r.digest(ctx, f)
	if err != nil || size != a.Size || hash != a.SHA256 {
		f.Close()
		return nil, Artifact{}, ErrChanged
	}
	return f, a, nil
}

// CheckUnchanged is also used after parsing or reading a range, to detect a
// writer changing the contents of an already-open descriptor during consumption.
func (r *Registry) CheckUnchanged(ctx context.Context, f *os.File, a Artifact) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	size, hash, err := r.digest(ctx, f)
	if err != nil || size != a.Size || hash != a.SHA256 {
		return ErrChanged
	}
	return nil
}

func (r *Registry) Metadata(ctx context.Context, id string) (Artifact, error) {
	return r.store.ResultArtifact(ctx, id)
}
func (r *Registry) Execution(ctx context.Context, id string) (Execution, error) {
	return r.store.ResultExecution(ctx, id)
}

func safeError(err error) string {
	switch {
	case errors.Is(err, ErrDenied):
		return "access_denied"
	case errors.Is(err, ErrLimit):
		return "limit_exceeded"
	case errors.Is(err, ErrChanged):
		return "original_changed"
	default:
		return "original_unavailable"
	}
}

// ErrorCode is safe for metadata/reporting. It never includes file contents,
// request parameters or an underlying OS error containing a sensitive path.
func ErrorCode(err error) string { return safeError(err) }
