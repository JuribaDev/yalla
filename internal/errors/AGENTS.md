# internal/errors

Stable failure contract for the CLI.

- `Code`, the exit-code map, and `SchemaVersion` are **public API**. Renaming a
  constant or remapping an exit code is a breaking change — bump SemVer and
  call it out in release notes.
- Always return `*Error` from internal packages. Use `New`/`Newf` to construct,
  `WithHint`/`WithHintf` to attach single-line remediation text, and `Wrap` to
  carry an underlying cause without losing the public Code/Message.
- The terminal renderer (in `internal/output`) is the only place errors are
  formatted for the user. Do not call `fmt.Errorf` for user-visible failures;
  the JSON envelope and exit code depend on the typed Code.
- Never embed raw secrets into `Message` or `Hint`. The output layer applies a
  redactor, but treat that as defence-in-depth: classify cleanly first.
- `From(err)` is the boundary shim that maps cobra parse errors and unknown
  third-party errors to a stable Code. If you discover another deterministic
  cobra phrase that should mean usage, add it to `usagePrefixes` together with
  a regression test.
