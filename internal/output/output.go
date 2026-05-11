// Package output renders user-facing data and diagnostics for the yalla CLI.
//
// The package owns the stdout/stderr contract:
//
//   - Data goes to Out (stdout) and only ever in JSON envelope form when
//     --json is set, or as plain text when it is not.
//   - Diagnostics, progress, prompts, and errors go to ErrOut (stderr).
//   - Every success response carries the "yalla.output.v1" schema_version.
//   - Every error response carries the "yalla.error.v1" schema_version,
//     a stable Code, a Message, and an optional Hint.
//
// All visible strings are scrubbed by the Redactor before they reach a
// writer, so secrets supplied via --token (or matched by the well-known
// transport patterns) never leak into logs, errors, or JSON output.
package output

import (
	"encoding/json"
	"fmt"
	"io"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Renderer drives every command's output. Construct one per invocation from
// the resolved IOStreams and global flags so the JSON contract and secret
// redaction are honoured uniformly across the command tree.
type Renderer struct {
	out      io.Writer
	err      io.Writer
	json     bool
	redactor *Redactor
}

// New constructs a Renderer. JSON mode and redaction are configured by the
// CLI layer based on the parsed --json flag and --token value.
func New(out, errOut io.Writer, jsonMode bool, redactor *Redactor) *Renderer {
	if redactor == nil {
		redactor = NewRedactor()
	}
	return &Renderer{out: out, err: errOut, json: jsonMode, redactor: redactor}
}

// JSON reports whether the renderer is in machine-readable mode. Subcommands
// can branch on this when they need to emit different shapes for human and
// agent consumption.
func (r *Renderer) JSON() bool { return r.json }

// Out returns the data writer (stdout). Prefer Data for structured payloads;
// this accessor is for raw passthrough only.
func (r *Renderer) Out() io.Writer { return r.out }

// ErrOut returns the diagnostics writer (stderr).
func (r *Renderer) ErrOut() io.Writer { return r.err }

// Redactor exposes the underlying redactor so callers can scrub strings they
// build outside the renderer (e.g. log payloads composed before formatting).
func (r *Renderer) Redactor() *Redactor { return r.redactor }

// Data marshals v as the canonical success envelope and writes it to stdout.
// In non-JSON mode the call is a no-op so callers can route plain text
// through Human without branching on r.JSON().
func (r *Renderer) Data(v any) error {
	if !r.json {
		return nil
	}
	env := successEnvelope{SchemaVersion: SuccessSchema, Data: v}
	enc := json.NewEncoder(r.out)
	enc.SetEscapeHTML(false)
	return enc.Encode(env)
}

// Raw writes raw bytes to stdout unchanged. Use only when the payload is
// already in its final shape (binary downloads, pre-rendered JSON streamed
// from the API). Redaction is *not* applied because callers passing raw
// bytes are responsible for their own contents.
func (r *Renderer) Raw(p []byte) (int, error) {
	return r.out.Write(p)
}

// Human writes a plain text line to stdout when not in JSON mode. In JSON
// mode the call is suppressed so stdout stays single-document JSON only.
// The text is run through the redactor first.
func (r *Renderer) Human(s string) {
	if r.json {
		return
	}
	fmt.Fprintln(r.out, r.redactor.Redact(s))
}

// Logf writes a diagnostic line to stderr after running the formatted result
// through the redactor. Use for progress, warnings, and verbose logs. Logf
// is safe to call regardless of --json: stderr is reserved for diagnostics
// in both modes.
func (r *Renderer) Logf(format string, args ...any) {
	fmt.Fprintln(r.err, r.redactor.Redact(fmt.Sprintf(format, args...)))
}

// Error renders a typed error to stderr. In JSON mode the error envelope is
// emitted with schema_version "yalla.error.v1"; in human mode a stable
// two-line shape ("Error [CODE]: msg" plus optional "  hint: ...") is used.
// Either way, secret redaction is applied to every visible field.
//
// Error returns the JSON encoder's error (if any). The caller usually
// ignores it because there is no recovery path once stderr cannot be
// written.
func (r *Renderer) Error(e *yerr.Error) error {
	if e == nil {
		return nil
	}
	code := string(e.Code)
	if code == "" {
		code = string(yerr.CodeInternal)
	}
	msg := r.redactor.Redact(e.Message)
	hint := r.redactor.Redact(e.Hint)
	if r.json {
		env := errorEnvelope{
			SchemaVersion: yerr.SchemaVersion,
			Error: errorPayload{
				Code:    code,
				Message: msg,
				Hint:    hint,
			},
		}
		enc := json.NewEncoder(r.err)
		enc.SetEscapeHTML(false)
		return enc.Encode(env)
	}
	fmt.Fprintf(r.err, "Error [%s]: %s\n", code, msg)
	if hint != "" {
		fmt.Fprintf(r.err, "  hint: %s\n", hint)
	}
	return nil
}
