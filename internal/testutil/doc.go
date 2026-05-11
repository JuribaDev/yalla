// Package testutil is the shared verification harness for the yalla CLI.
//
// It centralises the patterns every command and API story relies on:
//
//   - Running the Cobra root command with in-memory stdin/stdout/stderr so
//     tests can assert on the byte-for-byte stream contract (data on stdout,
//     diagnostics on stderr, exit codes through the typed-error pipeline).
//   - Decoding and validating the public JSON envelopes (yalla.output.v1 for
//     success, yalla.error.v1 for failure) including schema_version, error
//     codes, and exit-code parity.
//   - A golden-file workflow keyed off the -update-golden flag so deterministic
//     output (JSON envelopes, manifests, schemas, selected human banners) can
//     be pinned without hand-maintained string literals.
//   - HTTP test fixtures for Dokploy API contract tests: stub
//     http.RoundTripper, recorded httptest.Server, response builders, and the
//     YALLA_BASE_URL / YALLA_TOKEN wiring needed by the raw API executor.
//   - Environment isolation helpers so YALLA_* variables from the host shell
//     never leak into a test run.
//
// The package is intentionally CLI- and api-aware (it imports internal/cli to
// share the production exit-code path through cli.ExecuteForTest), so it must
// be consumed only from external _test packages or from sibling internal
// modules that do not create import cycles with internal/cli.
//
// See ralph/VERIFICATION.md for the focused vs full verification loops Ralph
// runs before every commit.
package testutil
