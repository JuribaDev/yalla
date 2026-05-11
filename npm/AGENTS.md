# npm wrapper

The npm package is a *trampoline* that executes the native Go binary. The
agent contract is what matters: `argv`, `stdin`, `stdout`, `stderr`, and the
exit code must round-trip without modification.

- `bin/yalla.js` is a `child_process.spawn(..., { stdio: 'inherit' })`. Do
  NOT pipe through, decorate, or rewrite output. Print only on hard wrapper
  failures (binary missing, download failed) and only to stderr.
- `lib/platform.js` is the source of truth for `<os>_<arch>` strings and
  archive extensions. Keep it in lockstep with `.goreleaser.yaml > builds`
  and the archive `name_template`. A drift here breaks every install.
- `lib/install.js` resolves the version from `YALLA_VERSION` first and then
  `package.json#version`. The release workflow stamps `package.json` from
  the git tag (`vX.Y.Z` -> `X.Y.Z`) before publishing.
- Postinstall errors must NOT abort `npm install`. The bin script retries
  the download lazily and surfaces a clear stderr message if it still fails.
- New runtime dependencies require a strong justification. The wrapper is
  intentionally zero-dep so installs stay reproducible and the supply chain
  surface stays minimal.
- Tests live under `test/` and run via `node --test`. Keep them
  dependency-free for the same reason.
