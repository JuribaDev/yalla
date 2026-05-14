# internal/controlplane/config

Resolved, typed configuration for the backend API (`cmd/yalla-api`) and
worker (`cmd/yalla-worker`).

- `Load(LookupFunc) (*Config, error)` / `LoadFromEnv()` are the **only** entry
  points. Backend binaries call `LoadFromEnv()` once at startup and
  `os.Exit(1)` on error — fail fast, never half-start.
- Backend config is **environment-variable only**. There are no CLI flags or
  config files here; flags/files belong to the customer-facing CLI under
  `internal/config`.
- Env var names (the `Env*` constants) and profile names
  (`local`/`test`/`staging`/`production`) are **public, versioned contracts**.
  Adding one is a minor change; renaming or removing one is a major change.
- Profiles supply defaults and decide which fields are mandatory. `IsStrict()`
  (staging + production) requires every operational field; `local`/`test` are
  permissive so the backend runs easily on a dev machine and in unit tests.
- Every validation failure is a typed `yerr.CodeConfig` error and **must never
  echo a secret value**. `DatabaseURL` errors describe the fault without
  printing the DSN; signing-key errors reference an index, not the key.
- Secrets are `DatabaseURL`, `SigningKeys`, and `DokployToken`. Never log or
  format them directly — use `Redacted()`, `LogValue()` (slog.LogValuer), or
  `String()` (fmt.Stringer), all of which scrub credentials. There are tests
  asserting no secret leaks through any of these paths; keep them green when
  adding fields.
- When you add a config field: add its `Env*` constant, wire it in `Load`,
  add format/required validation in `Validate`, extend `RedactedConfig` +
  `LogValue` + `String` if it is a secret, and add success + failure tests.
- Tests inject `config.MapLookup(map[string]string{...})` instead of touching
  `os.Environ`; use `t.Parallel()`.
