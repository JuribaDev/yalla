# internal/config

Resolved, typed configuration for every subcommand.

- `Load(FlagValues) (*Config, error)` is the **only** entry point. Subcommands
  receive the resolved `*Config` through the command context and never call
  the loader themselves.
- Precedence chain is **CLI flag > env var > config file > built-in default**.
  The flag layer respects the parse-time `Changed` bit (`*Set` booleans on
  `FlagValues`) so an unchanged flag does NOT silently overwrite a lower
  source.
- Env var names are part of the public agent contract: `YALLA_BASE_URL`,
  `YALLA_TOKEN`, `YALLA_CONFIG`, `YALLA_OUTPUT`, `YALLA_NO_INPUT`. Adding a
  new variable is a minor change; renaming or removing one is a major change.
- Config keys (`base_url`, `token`, `output`, `no_input`, `verbose`) are the
  `yalla config set <key>` surface and the on-disk YAML schema. They are
  normalised to snake_case and validated on read.
- A **missing config file is never an error**, regardless of whether the path
  came from `--config`, `YALLA_CONFIG`, or the default. Yalla must work out of
  the box. Other read errors (permission denied, parse error, invalid base
  URL) bubble up as typed `CodeConfig` errors.
- The on-disk file is YAML (`gopkg.in/yaml.v3`), written with `0600` perms
  inside a `0700` parent dir so credentials never land on a world-readable
  path.
- Validate `base_url` at load time (`http`/`https` scheme + non-empty host).
  Catching invalid URLs here keeps deep-stack dial errors out of the user's
  way.
- `Token` is a string. Never log, format, or print the literal value: rely on
  `internal/output.Redactor` for defence-in-depth, but classify cleanly first.
- `Loader.SnapshotForRenderer()` is the parse-time fallback used by
  `internal/cli/error_render.go` so JSON envelope mode and token redaction
  still work when cobra fails before `PersistentPreRunE`.
