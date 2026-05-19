# deploy/config

Production configuration examples live here. Keep them safe to inspect in CI
and safe to copy into `/etc/yalla`.

- Never put rendered secrets, DSNs, API keys, cookies, or tokens in checked-in
  examples. Secret-shaped values must use `<redacted:...>` placeholders.
- Keep the canonical example coupled to both backend binaries:
  `/usr/local/bin/yalla-api` and `/usr/local/bin/yalla-worker`.
- Document API `/healthz` and `/readyz`, worker no-HTTP-listener health
  expectations, structured JSON logs, and stable `yalla.output.v1` /
  `yalla.error.v1` probe envelopes.
- Update `internal/release/config_examples_static_test.go`, `SECURITY.md`,
  `.github/workflows/ci.yml`, and `scripts/verify.sh` in the same edit when
  this artifact changes.
