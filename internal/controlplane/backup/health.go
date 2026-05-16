package backup

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"time"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// ErrNoBackupRecorded is the sentinel a Reporter returns when the operator
// has wired a status path but no successful backup has yet landed at it.
// The HTTP probe matches on this sentinel to render a 200 "no backup yet"
// envelope instead of a 5xx — a freshly provisioned environment is healthy,
// it has just not run its first backup.
var ErrNoBackupRecorded = errors.New("backup: no successful backup recorded yet")

// Status is the snapshot a Reporter exposes. Configured names whether a
// status source is wired at all; the remaining fields are zero on an
// unconfigured Status.
//
// LastSuccessAt is the parsed RFC3339 timestamp the operator's backup
// pipeline wrote to the status file on its last successful run. Age is
// time.Now (or the injected clock) minus LastSuccessAt — useful for
// rendering and for the freshness predicate. MaxAge is the operator-chosen
// staleness threshold; a zero MaxAge disables the freshness check entirely
// so a probe shipped before the operator picks a threshold does not flap.
type Status struct {
	Configured    bool
	LastSuccessAt time.Time
	Age           time.Duration
	MaxAge        time.Duration
}

// Fresh reports whether the most recent backup landed within MaxAge. A zero
// MaxAge disables the predicate and returns true so operators can wire the
// probe before deciding their threshold. An unconfigured Status also
// returns true: the probe makes no claim about freshness when no source is
// wired.
func (s Status) Fresh() bool {
	if !s.Configured || s.MaxAge <= 0 {
		return true
	}
	return s.Age <= s.MaxAge
}

// Reporter exposes the backup status to HTTP handlers and operator tooling.
// Implementations must be safe for concurrent use: the HTTP probe handler
// reads them while the operator's backup pipeline races to update the
// underlying source.
type Reporter interface {
	// Status returns the most recent backup status. Unconfigured reporters
	// return a Status with Configured=false and no error. Configured
	// reporters return ErrNoBackupRecorded when the status source exists in
	// principle but has not seen a successful backup yet, and a wrapped
	// yerr.CodeServer error when the source itself is unreadable or
	// corrupt.
	Status(ctx context.Context) (Status, error)
}

// Unconfigured returns a Reporter that always reports
// Status{Configured: false}, never an error. It is the right default for
// the local and test profiles, and for any process that has not opted in to
// the backup-health surface.
func Unconfigured() Reporter { return unconfiguredReporter{} }

type unconfiguredReporter struct{}

func (unconfiguredReporter) Status(context.Context) (Status, error) {
	return Status{Configured: false}, nil
}

// FileReporter reads the operator's backup-status file and reports the
// timestamp it carries. The file format is a single RFC3339 timestamp on
// the first line, optionally surrounded by whitespace and with an optional
// trailing newline. Any other shape is a parse error.
//
// FileReporter is safe for concurrent use: each call to Status opens the
// file fresh and never caches state, so an updated status file is observed
// on the next probe with no restart required.
type FileReporter struct {
	// path is the absolute filesystem path the operator's backup pipeline
	// writes its last-success timestamp to.
	path string
	// maxAge is the freshness threshold reported through Status.MaxAge.
	// A zero MaxAge disables Status.Fresh.
	maxAge time.Duration
	// now is the clock used to compute Status.Age. It defaults to
	// time.Now in NewFileReporter and is overridden by tests for
	// determinism.
	now func() time.Time
}

// NewFileReporter constructs a FileReporter that reads path on every call
// to Status. maxAge is the freshness threshold; pass zero to opt out of
// Status.Fresh. now is the clock used for Age computation; nil means
// time.Now.
//
// path must be non-empty. An empty path is a configuration bug — callers
// should pass Unconfigured() rather than a FileReporter at "" — so
// NewFileReporter returns yerr.CodeConfig rather than silently accepting
// it.
func NewFileReporter(path string, maxAge time.Duration, now func() time.Time) (*FileReporter, error) {
	if strings.TrimSpace(path) == "" {
		return nil, yerr.New(yerr.CodeConfig,
			"backup file reporter requires a non-empty path; pass backup.Unconfigured() when no backup source is wired")
	}
	if now == nil {
		now = time.Now
	}
	return &FileReporter{path: path, maxAge: maxAge, now: now}, nil
}

// Status reads the configured status file and returns the parsed timestamp.
//
// Error semantics:
//   - A missing status file returns ErrNoBackupRecorded, which the HTTP
//     probe renders as a 200 "no backup yet" response. The file may legally
//     not exist before the first backup lands.
//   - Any other read error is wrapped as yerr.CodeServer; the wrapped
//     message names the configured path but never echoes the file's
//     content, so a status file accidentally seeded with a secret cannot
//     leak through an error string.
//   - A file whose content does not parse as RFC3339 is reported as
//     yerr.CodeServer with the same redaction guarantee.
//
// The returned Status is always populated with Configured=true so callers
// can distinguish a configured-but-failing reporter from an unconfigured
// one even on the error path.
func (r *FileReporter) Status(ctx context.Context) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{Configured: true, MaxAge: r.maxAge}, err
	}

	raw, err := os.ReadFile(r.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Status{Configured: true, MaxAge: r.maxAge}, ErrNoBackupRecorded
		}
		return Status{Configured: true, MaxAge: r.maxAge},
			yerr.Newf(yerr.CodeServer,
				"backup: status file %q is unreadable", r.path)
	}

	// Treat the file as untrusted input: strip whitespace from the first
	// non-empty line and parse only that. Never echo the file's content in
	// an error message — a misconfigured pipeline that writes a secret to
	// the status file must not leak it through the probe.
	first := firstNonEmptyLine(raw)
	if first == "" {
		return Status{Configured: true, MaxAge: r.maxAge},
			yerr.Newf(yerr.CodeServer,
				"backup: status file %q is empty", r.path)
	}

	stamp, parseErr := time.Parse(time.RFC3339, first)
	if parseErr != nil {
		return Status{Configured: true, MaxAge: r.maxAge},
			yerr.Newf(yerr.CodeServer,
				"backup: status file %q does not contain an RFC3339 timestamp on its first non-empty line", r.path)
	}

	stamp = stamp.UTC()
	now := r.now().UTC()
	age := now.Sub(stamp)
	if age < 0 {
		// A backup timestamp from the future indicates clock skew on the
		// pipeline host. Report Age=0 rather than a negative duration so
		// downstream consumers (Fresh, JSON rendering) get a well-defined
		// value; the timestamp itself is preserved untouched.
		age = 0
	}

	return Status{
		Configured:    true,
		LastSuccessAt: stamp,
		Age:           age,
		MaxAge:        r.maxAge,
	}, nil
}

// firstNonEmptyLine returns the first line of raw with surrounding
// whitespace trimmed, or "" if every line is empty. It is the canonical
// parser for the status file format.
func firstNonEmptyLine(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}
