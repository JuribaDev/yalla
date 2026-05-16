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

## Log redaction fuzzing (BE-0359)

`internal/output/redact_fuzz_test.go` is the runtime evidence for the
log-redaction control documented in the top-level `SECURITY.md` section
"Log Redaction Fuzzing". The file pins five invariants on `*Redactor.Redact`:

1. **No panic** for any combination of `(secret, haystack)` — the
   request-logging middleware in `internal/controlplane/telemetry/logging.go`
   leans on this; a panic inside `Redact` would tear down the per-request log
   record and surface the unredacted URL in the runtime panic dump.
2. **Explicit-secret never leaks**: a secret registered with `NewRedactor`
   does not survive a `Redact` pass for any haystack in the contract scope.
3. **Authorization / X-API-Key / X-Auth-Token header values never leak**:
   the structural bearer-header regex scrubs the value half for every
   header-line shape, regardless of the value's content.
4. **Query token values never leak**: the `?token=`, `?api_key=`,
   `?access_token=`, `?x-auth-token=` variants are all scrubbed for any
   value content.
5. **Idempotence**: `Redact(Redact(s)) == Redact(s)` for every input in the
   contract scope.

CI runs the seed corpus only (`go test ./...`). `-fuzz` exercises the random
generation stage and is operator-opt-in; the seed corpus is what guards
every commit. When adding a new redaction rule (cookies, refresh tokens,
new transport patterns), append a seed input to `redactFuzzSeeds` AND add
a fuzz target — the seed-only run alone is not sufficient to prove the new
rule survives mutated inputs.

The fuzz scope deliberately excludes three input classes; see the file-level
package doc in `redact_fuzz_test.go` for the rationale. The exclusions are
pinned by `TestRedactor_FuzzScopeExclusionsAreReal`, so a future redactor
change that closes a gap (for example, swapping `strings.ReplaceAll` for a
single-pass regex substitution that does not re-scan substituted text) will
deliberately break that test — the fix MUST update the fuzz scope comments,
the exclusion test, AND the `SECURITY.md` section at the same time so the
threat-model documentation stays accurate.
