// Package audit writes the local yalla mutation audit log.
package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Record is one JSONL audit event for a mutating operation.
type Record struct {
	Timestamp   time.Time `json:"timestamp"`
	OperationID string    `json:"op"`
	Target      string    `json:"target,omitempty"`
	Status      int       `json:"status,omitempty"`
	ErrorCode   string    `json:"error_code,omitempty"`
	DurationMs  int64     `json:"duration_ms,omitempty"`
	RequestID   string    `json:"request_id,omitempty"`
	TraceID     string    `json:"trace_id,omitempty"`
}

// Logger appends and reads audit records from a single JSONL file.
type Logger struct {
	path string
}

// DefaultLogger returns the XDG/local-share audit logger.
func DefaultLogger() *Logger {
	base := strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "share")
	}
	return &Logger{path: filepath.Join(base, "yalla", "audit.log")}
}

// NewLogger returns a logger pinned to path.
func NewLogger(path string) *Logger { return &Logger{path: path} }

// Path returns the JSONL file path.
func (l *Logger) Path() string { return l.path }

// Append writes one redacted audit record.
func (l *Logger) Append(ctx context.Context, rec Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}
	rec.Target = redact(rec.Target)
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return enc.Encode(rec)
}

// Tail returns the last lines records from the audit log.
func (l *Logger) Tail(lines int) ([]string, error) {
	if lines <= 0 {
		lines = 50
	}
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var all []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		all = append(all, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return all, nil
}

var secretRE = regexp.MustCompile(`(?i)(token|api[_-]?key|authorization)=([^,\s]+)`)

func redact(s string) string {
	return secretRE.ReplaceAllString(s, `$1=[REDACTED]`)
}
