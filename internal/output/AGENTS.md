# internal/output

Single source of truth for stdout/stderr formatting.

- `Renderer` is constructed once per command invocation by the CLI layer from
  the resolved `IOStreams`, the parsed `--json` flag, and a `Redactor` seeded
  with the user's `--token`. Subcommands must emit through it; do not write
  directly to stdout/stderr from a Cobra `RunE`.
- `--json` data must always go through `Renderer.Data` so the
  `yalla.output.v1` envelope is honoured. Hand-rolled JSON in commands is a
  contract violation.
- `--json` errors must go through `Renderer.Error` so the `yalla.error.v1`
  envelope, code, and exit-code mapping stay consistent. The CLI's terminal
  renderer (`internal/cli/error_render.go`) is the only call site that
  matters for top-level cobra failures.
- `Renderer.Human` is suppressed in JSON mode so plain text never sneaks onto
  stdout when an agent expects a single JSON document.
- `Renderer.Logf` always goes to stderr — diagnostics never live on stdout.
- `Redactor` is **defence-in-depth**. Classify errors cleanly first; do not
  rely on the redactor to hide unclassified fields. Add new transport-layer
  patterns (cookies, refresh tokens) here together with a regression test.
- The end-to-end secret-leak regression net lives at
  `internal/cli/redaction_security_test.go` (US-0011). Every new visible
  writer in the command tree must be exercised there with a sentinel token
  across `--json`, human, and `--verbose` modes, otherwise the redactor
  contract documented in `SECURITY.md` is not actually enforced.
- Schema constants (`SuccessSchema`, `yalla.error.v1`) are public API; bump
  the version only as part of a deliberate breaking change.
