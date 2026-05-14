# validate — request validation toolkit

`internal/controlplane/validate` is the single place handlers and services
validate untrusted request input. It is pure: no I/O, no Postgres, no knowledge
of feature flags or quota.

## Conventions

- **Collector pattern.** Build a `validate.New()` Collector, call validators
  against it (each takes `c *Collector, field string, ...`), then return
  `c.Err()` — nil or one `apierr.InvalidInput` carrying every violation. Never
  short-circuit on the first bad field.
- **Never echo the submitted value.** A `FieldViolation.Reason` carries only
  classification text (bounds, "must not be blank"). Reasons may interpolate
  bounds/counts via `Addf`, never input. This is what lets a secret env var be
  rejected without its value reaching a log/error. Add a "never echoes the
  value" test for any new validator.
- **Policy-dependent rules are options, not lookups.** `Domain` takes
  `DomainOptions{AllowWildcard}`; the caller resolves the feature flag + quota
  and passes the bool. Keep the package free of config/quota imports.
- **Field paths.** Dotted (`build.dockerfile_path`), indexed for slices
  (`env[0].name`), and a distinct segment for sensitive sub-lists
  (`env.secret[0]`).
- **Fuzz every string validator.** Seed `fuzzSeeds` covers long strings,
  invalid UTF-8, path traversal, control chars. A fuzz target asserts no panic
  and re-derives the accept invariants — mirror that for new validators.
- `DecodeJSON` is the strict JSON body decoder: size-capped, unknown-field- and
  trailing-data-rejecting, and every failure is a body-free `apierr.Invalid`.
