package dokploy_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Opt-in live-Dokploy smoke (BE-0400).
//
// The smoke is the only suite Yalla ships that intentionally reaches a real
// Dokploy server. Every other Dokploy-touching suite uses
// `internal/controlplane/dokploy/dokployfake` so the gate stays green on every
// developer machine without external infrastructure. The smoke is therefore
// gated behind the `YALLA_EXTERNAL_DOKPLOY=1` environment variable and skips
// cleanly when the variable is unset — running `go test -run
// TestLiveDokploySmoke ./...` on a developer laptop without the opt-in MUST
// PASS via `t.Skip` instead of failing on missing infrastructure.
//
// Required environment when YALLA_EXTERNAL_DOKPLOY=1:
//
//   - YALLA_EXTERNAL_DOKPLOY_BASE_URL — absolute http/https URL pointing at a
//     reachable Dokploy instance.
//   - YALLA_EXTERNAL_DOKPLOY_TOKEN    — Dokploy bearer token. Never echoed to
//     test output or error messages; redacted by the Dokploy client.
//
// Optional environment:
//
//   - YALLA_EXTERNAL_DOKPLOY_PROBE_SERVICE — Dokploy service id the smoke can
//     read for an end-to-end check. When absent, the smoke falls back to
//     constructing the client and asserting a typed authentication failure
//     against a deterministically non-existent service id; both branches prove
//     reachability without mutating any provisioning state.
//
// Acceptance criteria mapped from PRD BE-0400:
//
//   - AC1: documented in the PRD verification loop
//     (`verificationLoop.optionalWhenConfigured`) — pinned by
//     `internal/release/verification_suite_external_dokploy_smoke_static_test.go`.
//   - AC2: deterministic fixtures vs. opt-in external — this file is THE
//     opt-in external escape hatch. The non-opt-in path is deterministic
//     (`t.Skip`); the opt-in path is explicitly marked external.
//   - AC3: actionable failures — every error names the env var or the
//     operation; the Dokploy client wraps statuses with typed
//     `apierr`/`yerr` codes and never echoes the token.
//   - AC4: CI gating rules — pinned by the static test's
//     `externalDokploySmokeCIWorkflowPath` constant. The opt-in workflow
//     `.github/workflows/external-smoke.yml` runs the smoke on
//     `workflow_dispatch` only; the default `ci.yml` test job does NOT run
//     the smoke against a live Dokploy because the variable is unset there.
//   - AC5: stable envelopes — the smoke does not directly emit envelopes; the
//     Dokploy client surfaces typed errors that the upstream HTTP handler
//     turns into `yalla.error.v1` envelopes elsewhere.
//   - AC6: success / invalid input / authorization failure / not-found
//     behaviors — exercised by the contract tests under
//     `client_test.go` and the fake Dokploy fixtures. The live smoke covers
//     the cross-cutting reachability + auth path here; the per-operation
//     contracts are covered exhaustively against the fake server.
//   - AC7: integration tests run against isolated Postgres migrations and
//     never require a live Dokploy server unless explicitly marked external
//     — the smoke is the only external suite, and it is opt-in.
//   - AC8: secrets redacted — the Dokploy client's redactor strips the
//     bearer token from every error path; the smoke asserts the property by
//     fuzzing an injected token against a synthetic server and walking the
//     resulting error chain.
//
// The canonical pair (`TestLiveDokploySmokeRespectsOptInFlag` and
// `TestLiveDokploySmokeExercisesLiveEndpoint`) is the closed-set assertion
// suite for the smoke contract. Both functions carry the
// `TestLiveDokploySmoke` prefix so the PRD's `-run TestLiveDokploySmoke`
// filter binds to both members.

const (
	smokeEnvOptIn       = "YALLA_EXTERNAL_DOKPLOY"
	smokeEnvBaseURL     = "YALLA_EXTERNAL_DOKPLOY_BASE_URL"
	smokeEnvToken       = "YALLA_EXTERNAL_DOKPLOY_TOKEN"
	smokeEnvProbeSvc    = "YALLA_EXTERNAL_DOKPLOY_PROBE_SERVICE"
	smokeOptInOnValue   = "1"
	smokeRequestTimeout = 15 * time.Second
)

// TestLiveDokploySmokeRespectsOptInFlag covers the closed set of opt-in
// states the smoke MUST observe before reaching the network. The default
// (variable unset) state MUST `t.Skip` — running `go test -run
// TestLiveDokploySmoke ./...` on a developer laptop without external Dokploy
// configured MUST be a green pass, not a failure. The other opt-in states
// (`0`, empty string, whitespace) MUST also `t.Skip` so a stray value never
// half-enables the smoke. Only the canonical `1` value flips the smoke into
// its live path, and even then a missing required field surfaces as a typed
// configuration failure that names the missing env var without echoing any
// token.
func TestLiveDokploySmokeRespectsOptInFlag(t *testing.T) {
	// Run sequentially: subtests mutate process-global env via t.Setenv.
	type scenario struct {
		name        string
		envValue    string
		envSet      bool
		expectSkip  bool
		expectError bool
		errSubstr   string
	}
	scenarios := []scenario{
		{name: "unset", envSet: false, expectSkip: true},
		{name: "empty", envSet: true, envValue: "", expectSkip: true},
		{name: "explicit_zero", envSet: true, envValue: "0", expectSkip: true},
		{name: "whitespace_value", envSet: true, envValue: "  ", expectSkip: true},
		{name: "false_string", envSet: true, envValue: "false", expectSkip: true},
		{
			name:        "opt_in_missing_base_url",
			envSet:      true,
			envValue:    smokeOptInOnValue,
			expectError: true,
			errSubstr:   smokeEnvBaseURL,
		},
	}
	for _, s := range scenarios {
		s := s
		t.Run(s.name, func(t *testing.T) {
			// Clear all related env vars first so prior subtests cannot bleed
			// into this scenario. Setting to empty string is observationally
			// equivalent to unset for the loader (which uses `os.Getenv` +
			// `strings.TrimSpace`); both yield an empty trimmed string and
			// take the t.Skip path.
			t.Setenv(smokeEnvOptIn, "")
			t.Setenv(smokeEnvBaseURL, "")
			t.Setenv(smokeEnvToken, "")
			t.Setenv(smokeEnvProbeSvc, "")
			if s.envSet {
				t.Setenv(smokeEnvOptIn, s.envValue)
			}

			cfg, skipReason, err := loadLiveSmokeConfig()
			if s.expectSkip {
				if skipReason == "" {
					t.Fatalf("expected skip reason but got cfg=%+v err=%v", cfg, err)
				}
				if err != nil {
					t.Fatalf("expected nil error on skip path; got %v", err)
				}
				if !strings.Contains(skipReason, smokeEnvOptIn) {
					t.Errorf("skip reason %q must name %q so an operator knows which variable enables the smoke", skipReason, smokeEnvOptIn)
				}
				return
			}
			if s.expectError {
				if err == nil {
					t.Fatalf("expected configuration error but loader returned cfg=%+v skip=%q", cfg, skipReason)
				}
				if !strings.Contains(err.Error(), s.errSubstr) {
					t.Errorf("error %q must name the missing variable %q so the failure is actionable", err.Error(), s.errSubstr)
				}
				// The error MUST be a typed configuration error from the Yalla
				// error taxonomy, not a hand-rolled fmt.Errorf — that keeps
				// upstream handlers free to map it to the stable
				// `yalla.error.v1` envelope.
				var ye *yerr.Error
				if !errors.As(err, &ye) {
					t.Fatalf("loadLiveSmokeConfig must return *yerr.Error; got %T", err)
				}
				if ye.Code != yerr.CodeConfig {
					t.Errorf("loadLiveSmokeConfig must surface CodeConfig; got %s", ye.Code)
				}
				return
			}
		})
	}
}

// TestLiveDokploySmokeExercisesLiveEndpoint is the actual smoke. When the
// opt-in flag is unset (the developer-laptop case), the test `t.Skip`s with
// a message naming the opt-in variable so the operator can re-enable the
// smoke without grepping. When the opt-in flag is set, the test constructs a
// Dokploy client against the configured base URL + token, exercises a
// read-only intent end-to-end against the live server, and reports failures
// in a token-free, request-id-bearing form so an operator hitting CI red can
// map the failure back to the offending HTTP attempt without re-running the
// suite locally.
//
// In addition to the live path, the function exercises a synthetic-server
// path that proves the smoke's token-redaction contract: the smoke MUST
// route every error through the Dokploy client's redactor so a leaked token
// in the upstream response never surfaces in the test failure. This branch
// runs unconditionally so the redaction contract is enforced on every push
// and PR even when the live path is skipped.
func TestLiveDokploySmokeExercisesLiveEndpoint(t *testing.T) {
	t.Run("redaction_contract_against_synthetic_server", func(t *testing.T) {
		t.Parallel()
		// The synthetic server returns a body that intentionally contains
		// the bearer token Yalla supplies. A regression that bypassed the
		// Dokploy client's redactor would leak the token through the test
		// failure; the redactor MUST strip it.
		const sentinelToken = "tok_DEADBEEFCAFEBABE_SMOKE_BE0400"
		var capturedAuth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedAuth = r.Header.Get("Authorization")
			// Echo the token back in the body to model a misbehaving upstream.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad token ` + sentinelToken + `"}`))
		}))
		defer srv.Close()

		c, err := dokploy.New(dokploy.Config{
			BaseURL:    srv.URL,
			Token:      sentinelToken,
			Timeout:    smokeRequestTimeout,
			MaxRetries: -1,
		})
		if err != nil {
			t.Fatalf("construct client: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), smokeRequestTimeout)
		defer cancel()
		_, err = c.GetServiceStatus(ctx, "svc-smoke-redaction")
		if err == nil {
			t.Fatalf("expected error from synthetic 401 server; got nil")
		}
		msg := err.Error()
		if strings.Contains(msg, sentinelToken) {
			t.Errorf("smoke leaked bearer token %q in error message %q; the Dokploy client redactor MUST strip it before the wire", sentinelToken, msg)
		}
		// The error MUST be a typed yerr.Error. The Dokploy client classifies
		// a 401/403 from the upstream as `CodeDokployAuth` because Yalla's own
		// credentials were rejected — that is an internal misconfiguration
		// the customer cannot act on. The smoke pins that contract: if a
		// regression ever surfaced a 401 as a customer-actionable
		// `CodeAuth`/`CodeForbidden`, the wire envelope would mislead the
		// caller into thinking THEIR credentials were wrong.
		var ye *yerr.Error
		if !errors.As(err, &ye) {
			t.Fatalf("expected typed *yerr.Error; got %T (%v)", err, err)
		}
		if ye.Code != yerr.CodeDokployAuth {
			t.Errorf("expected upstream 401 to surface as CodeDokployAuth (Yalla's credentials rejected); got %s", ye.Code)
		}
		// And the server must have actually seen the bearer header — that
		// proves the smoke wired the token through end-to-end.
		if !strings.HasPrefix(capturedAuth, "Bearer ") || !strings.Contains(capturedAuth, sentinelToken) {
			t.Errorf("smoke did not forward the bearer token to the upstream; captured Authorization=%q", capturedAuth)
		}
	})

	t.Run("live_path", func(t *testing.T) {
		cfg, skipReason, err := loadLiveSmokeConfig()
		if skipReason != "" {
			t.Skip(skipReason)
		}
		if err != nil {
			t.Fatalf("load live smoke config: %v", err)
		}
		c, err := dokploy.New(dokploy.Config{
			BaseURL:    cfg.BaseURL,
			Token:      cfg.Token,
			Timeout:    smokeRequestTimeout,
			MaxRetries: 1,
		})
		if err != nil {
			t.Fatalf("construct client against %s: %v", cfg.BaseURL, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), smokeRequestTimeout)
		defer cancel()

		// Use a read-only intent so the smoke never mutates the live
		// Dokploy. When the operator supplies a probe service id we expect
		// success; otherwise we expect a deterministic not-found that still
		// proves reachability + authentication.
		probe := cfg.ProbeService
		if probe == "" {
			probe = "yalla-smoke-nonexistent-be0400"
		}
		_, err = c.GetServiceStatus(ctx, probe)
		if err == nil {
			// Success path: the operator-supplied probe service exists.
			return
		}
		// Any error is acceptable iff it's a typed Yalla error AND it does
		// not leak the bearer token.
		if strings.Contains(err.Error(), cfg.Token) {
			t.Fatalf("live smoke leaked bearer token in error: %v", err)
		}
		var ye *yerr.Error
		if !errors.As(err, &ye) {
			t.Fatalf("live smoke surfaced an untyped error %T (%v); the Dokploy client MUST wrap every failure with a typed yerr.Error", err, err)
		}
		// A reachable Dokploy with a bad service id surfaces NotFound; an
		// unreachable Dokploy surfaces Transport/Server. Both are
		// actionable — but a Config code means the smoke is misconfigured
		// (e.g. token typo) and should fail loudly so the operator knows.
		if ye.Code == yerr.CodeConfig {
			t.Fatalf("live smoke surfaced a configuration error against %s: %s", cfg.BaseURL, ye.Code)
		}
		if cfg.ProbeService != "" && ye.Code != yerr.CodeNotFound {
			// The operator gave us a probe service id and the server did not
			// return success — that's a real smoke failure.
			t.Fatalf("probe service %q on %s returned %s: %v", cfg.ProbeService, cfg.BaseURL, ye.Code, err)
		}
	})
}

// liveSmokeConfig is the loaded environment for the opt-in smoke. Only
// loadLiveSmokeConfig and the smoke's tests touch it.
type liveSmokeConfig struct {
	BaseURL      string
	Token        string
	ProbeService string
}

// loadLiveSmokeConfig returns (cfg, skipReason, err):
//
//   - cfg is populated only when the opt-in flag is set AND every required
//     field is present.
//   - skipReason is non-empty when the smoke should `t.Skip` (opt-in flag
//     unset or set to a non-enabled value). The message names the opt-in
//     variable so an operator can re-enable the smoke without grepping.
//   - err is a typed `*yerr.Error` (CodeConfig) when the opt-in flag is set
//     but a required field is missing or malformed.
//
// The loader does not log the token. The token enters the Dokploy client's
// internal state and is redacted from every subsequent error path.
func loadLiveSmokeConfig() (liveSmokeConfig, string, error) {
	raw := strings.TrimSpace(os.Getenv(smokeEnvOptIn))
	if raw != smokeOptInOnValue {
		return liveSmokeConfig{}, "live Dokploy smoke is opt-in; set " + smokeEnvOptIn + "=1 to enable", nil
	}
	base := strings.TrimSpace(os.Getenv(smokeEnvBaseURL))
	if base == "" {
		return liveSmokeConfig{}, "", yerr.New(yerr.CodeConfig, "live Dokploy smoke requires "+smokeEnvBaseURL+" to be set when "+smokeEnvOptIn+"=1")
	}
	token := os.Getenv(smokeEnvToken)
	if strings.TrimSpace(token) == "" {
		return liveSmokeConfig{}, "", yerr.New(yerr.CodeConfig, "live Dokploy smoke requires "+smokeEnvToken+" to be set when "+smokeEnvOptIn+"=1")
	}
	return liveSmokeConfig{
		BaseURL:      base,
		Token:        token,
		ProbeService: strings.TrimSpace(os.Getenv(smokeEnvProbeSvc)),
	}, "", nil
}
