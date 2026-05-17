package config

import (
	stderrors "errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Canonical pair for the BE-0402 config-validation verification suite.
//
// The PRD's `verificationLoop.requiredBackendCommands` declares
// `go test -run TestConfigValidation ./...` as the load-bearing config-
// validation gate. That filter binds to every test whose name starts
// with the `TestConfigValidation` prefix. The two functions in this
// file are the closed-set members the PRD-level static defence
// (`internal/release/verification_suite_config_validation_static_test.go`)
// pins:
//
//   - TestConfigValidationCoversCallSites exercises the closed-set
//     validation rules `config.Load` is the single chokepoint for.
//     The API binary (`cmd/yalla-api`) and the worker binary
//     (`cmd/yalla-worker`) both call `config.LoadFromEnv` once at
//     startup; a regression that silently accepted a malformed
//     YALLA_DATABASE_URL, a non-hex YALLA_SECRET_KEYS entry, an
//     out-of-range YALLA_SHUTDOWN_TIMEOUT, or a strict profile with
//     a missing operational field would let a misconfigured process
//     enter the request path. The coverage member walks a scenario
//     table built from every documented rule and asserts each
//     produces a typed `*yerr.Error` with `Code == CodeConfig`, an
//     error message that names the offending field, and an error
//     chain that NEVER echoes the seeded secret markers carried in
//     the baseline strict env. The set itself is part of the closed
//     coverage: a future relaxation of one rule must be a deliberate
//     edit to both the validator and this table.
//
//   - TestConfigValidationPreservesContractUnderContention fires
//     `configValidationWorkers * configValidationIterationsPerWorker`
//     goroutines that each build their own env map from the
//     scenario table and run `config.Load(MapLookup(env))`. Every
//     goroutine asserts the rule its OWN scenario predicts: the same
//     typed code, the same field-naming substring, and the same
//     secret-redaction guarantee. A cross-write under the race that
//     swapped two goroutines' scenarios — or a future regression that
//     introduced shared mutable state in the validator (a cached
//     profile-defaults table, a global rate-limit builder, a sync.Once
//     mutating a shared map) — would fail the per-iteration assertion
//     even when the aggregate pass count matched.
//
// Both members are deterministic by design: every scenario builds a
// fresh map from `strictEnv()` (see config_test.go) and the validator
// is a pure function from the env map to a `*Config` or a typed
// error. No test reaches the process environment, the network, a
// live Postgres, or a live Dokploy.

const (
	// configValidationSecretMarker is the literal substring seeded
	// into every secret-bearing field of the baseline strict env. The
	// coverage and contention members both assert no error string ever
	// echoes this marker so a future regression that started embedding
	// the offending value in the error message would fail the
	// redaction predicate before it could ship.
	configValidationSecretMarker = "SUPERSECRETMARKER"

	// configValidationWorkers + configValidationIterationsPerWorker
	// drive the contention burst. The product is the total per-
	// iteration assertions the burst exercises; the values are small
	// enough that the burst fits inside a few seconds on developer
	// laptops while still exercising every scenario across many
	// goroutines.
	configValidationWorkers              = 32
	configValidationIterationsPerWorker  = 64
	configValidationBurstTotalIterations = configValidationWorkers * configValidationIterationsPerWorker
)

// configValidationScenario captures one validation rule and the
// predicted error projection. The coverage member walks the closed
// scenario table built by buildConfigValidationScenarios; the
// contention burst reuses the same table so every parallel run
// exercises the identical decision set.
type configValidationScenario struct {
	name    string
	mutate  func(map[string]string)
	wantSub string
}

// buildConfigValidationScenarios is the closed-set scenario table.
// Each entry mutates the baseline strict env to trip a single
// validator branch and predicts the substring the error message MUST
// carry. The scenarios cover every documented validation rule in
// `Validate` and every documented presence check in
// `requireStrictFields`:
//
//   - profile, log level, listen addr, public URL, dokploy URL,
//     database scheme (Validate)
//   - signing-key minimum length, secret-key hex length, secret-key
//     non-hex characters (Validate)
//   - shutdown timeout malformed / too small / too large (Validate)
//   - backup status file must be absolute, backup max age must be
//     non-negative (Validate)
//   - rate-limit RPS negative, burst out-of-range, idle TTL out-of-
//     range, malformed disable flag, malformed integer (Validate)
//   - feature flag value malformed and feature flag name empty
//     (Validate)
//   - strict-profile presence checks for PublicURL, DatabaseURL,
//     SigningKeys, SecretKeys, DokployBaseURL, DokployToken
//     (requireStrictFields)
//
// The scenarios are deliberately distinct so a future regression
// that silently widened one branch (e.g. accepting `mysql://` URLs)
// fires on its OWN named scenario, not buried inside a generic
// "validation failed" assertion.
func buildConfigValidationScenarios() []configValidationScenario {
	return []configValidationScenario{
		{
			name:    "invalid_profile",
			mutate:  func(e map[string]string) { e[EnvProfile] = "prod" },
			wantSub: "invalid " + EnvProfile,
		},
		{
			name:    "invalid_log_level",
			mutate:  func(e map[string]string) { e[EnvLogLevel] = "trace" },
			wantSub: "invalid " + EnvLogLevel,
		},
		{
			name:    "invalid_listen_addr",
			mutate:  func(e map[string]string) { e[EnvAPIAddr] = "not-an-addr:::" },
			wantSub: EnvAPIAddr,
		},
		{
			name:    "invalid_public_url_scheme",
			mutate:  func(e map[string]string) { e[EnvPublicURL] = "ftp://api.example" },
			wantSub: EnvPublicURL,
		},
		{
			name:    "invalid_dokploy_url",
			mutate:  func(e map[string]string) { e[EnvDokployBaseURL] = "://broken" },
			wantSub: EnvDokployBaseURL,
		},
		{
			name:    "invalid_database_scheme",
			mutate:  func(e map[string]string) { e[EnvDatabaseURL] = "mysql://db:3306/yalla" },
			wantSub: "scheme must be postgres",
		},
		{
			name:    "short_signing_key",
			mutate:  func(e map[string]string) { e[EnvSigningKeys] = "tooshort" },
			wantSub: "too short",
		},
		{
			name: "wrong_length_secret_key",
			mutate: func(e map[string]string) {
				e[EnvSecretKeys] = "00112233"
			},
			wantSub: "wrong length",
		},
		{
			name: "non_hex_secret_key",
			mutate: func(e map[string]string) {
				e[EnvSecretKeys] = "ZZ11223344556677889900112233445566778899001122334455667788990011"
			},
			wantSub: "not valid hex",
		},
		{
			name:    "malformed_shutdown_timeout",
			mutate:  func(e map[string]string) { e[EnvShutdownTimeout] = "soon" },
			wantSub: EnvShutdownTimeout,
		},
		{
			name:    "shutdown_timeout_too_small",
			mutate:  func(e map[string]string) { e[EnvShutdownTimeout] = "0s" },
			wantSub: "out of range",
		},
		{
			name:    "shutdown_timeout_too_large",
			mutate:  func(e map[string]string) { e[EnvShutdownTimeout] = "10m" },
			wantSub: "out of range",
		},
		{
			name:    "backup_status_file_not_absolute",
			mutate:  func(e map[string]string) { e[EnvBackupStatusFile] = "relative/path.txt" },
			wantSub: EnvBackupStatusFile,
		},
		{
			name:    "backup_max_age_malformed",
			mutate:  func(e map[string]string) { e[EnvBackupMaxAge] = "not-a-duration" },
			wantSub: EnvBackupMaxAge,
		},
		{
			name:    "backup_max_age_negative",
			mutate:  func(e map[string]string) { e[EnvBackupMaxAge] = "-1h" },
			wantSub: EnvBackupMaxAge,
		},
		{
			name:    "feature_flag_bad_value",
			mutate:  func(e map[string]string) { e[EnvFeatureFlags] = "billing=maybe" },
			wantSub: EnvFeatureFlags,
		},
		{
			name:    "feature_flag_empty_name",
			mutate:  func(e map[string]string) { e[EnvFeatureFlags] = "=true" },
			wantSub: EnvFeatureFlags,
		},
		{
			name:    "rate_limit_negative_rps",
			mutate:  func(e map[string]string) { e[EnvRateLimitOrgReadRPS] = "-1" },
			wantSub: EnvRateLimitOrgReadRPS,
		},
		{
			name:    "rate_limit_burst_too_large",
			mutate:  func(e map[string]string) { e[EnvRateLimitKeyReadBurst] = "5000000" },
			wantSub: EnvRateLimitKeyReadBurst,
		},
		{
			name:    "rate_limit_idle_ttl_malformed",
			mutate:  func(e map[string]string) { e[EnvRateLimitIdleTTL] = "not-a-duration" },
			wantSub: EnvRateLimitIdleTTL,
		},
		{
			name:    "rate_limit_idle_ttl_too_short",
			mutate:  func(e map[string]string) { e[EnvRateLimitIdleTTL] = "1ms" },
			wantSub: EnvRateLimitIdleTTL,
		},
		{
			name:    "rate_limit_disabled_malformed",
			mutate:  func(e map[string]string) { e[EnvRateLimitDisabled] = "maybe" },
			wantSub: EnvRateLimitDisabled,
		},
		{
			name:    "rate_limit_int_malformed",
			mutate:  func(e map[string]string) { e[EnvRateLimitIPReadBurst] = "ten" },
			wantSub: EnvRateLimitIPReadBurst,
		},
		{
			name:    "strict_missing_public_url",
			mutate:  func(e map[string]string) { delete(e, EnvPublicURL) },
			wantSub: "requires",
		},
		{
			name:    "strict_missing_database_url",
			mutate:  func(e map[string]string) { delete(e, EnvDatabaseURL) },
			wantSub: "requires",
		},
		{
			name:    "strict_missing_signing_keys",
			mutate:  func(e map[string]string) { delete(e, EnvSigningKeys) },
			wantSub: "requires",
		},
		{
			name:    "strict_missing_secret_keys",
			mutate:  func(e map[string]string) { delete(e, EnvSecretKeys) },
			wantSub: "requires",
		},
		{
			name:    "strict_missing_dokploy_base_url",
			mutate:  func(e map[string]string) { delete(e, EnvDokployBaseURL) },
			wantSub: "requires",
		},
		{
			name:    "strict_missing_dokploy_token",
			mutate:  func(e map[string]string) { delete(e, EnvDokployToken) },
			wantSub: "requires",
		},
	}
}

// configValidationMarkedEnv returns a clone of the baseline strict
// env with every secret-bearing field rewritten to embed the
// `configValidationSecretMarker` literal. The marker is the redaction
// canary every error string MUST avoid; a regression that started
// formatting the offending DSN, signing key, secret key, or Dokploy
// token into the validation error would echo the marker and fail the
// redaction predicate before reaching production.
func configValidationMarkedEnv() map[string]string {
	env := strictEnv()
	env[EnvDatabaseURL] = "postgres://yalla:" + configValidationSecretMarker + "@db.internal:5432/yalla"
	env[EnvSigningKeys] = configValidationSecretMarker + "-signing-key-aaaa," + configValidationSecretMarker + "-rotated-bbbb"
	// SecretKeys must remain hex; embed an alternative redaction-evidence
	// strategy (a sentinel hex literal) so the wrong-length / non-hex
	// scenarios that swap the value with non-hex content carry no real
	// AES key material into the assertion. The marker stays in the
	// signing key + DSN + Dokploy token positions which are the most
	// common leak sites.
	env[EnvDokployToken] = configValidationSecretMarker + "-dokploy-token-zzzz"
	return env
}

// assessConfigValidationScenario runs one scenario against a fresh
// marked env and returns the (possibly empty) slice of failure
// reasons describing every way the validator's behaviour diverged
// from the predicted projection. Returning a slice (rather than
// failing inline) lets the contention member aggregate failures
// across many goroutines without t.Fatal'ing the entire burst on
// the first miss.
//
// The four invariants asserted are:
//
//  1. `Load` MUST return a non-nil error for the mutated env.
//  2. The error MUST wrap a `*yerr.Error` whose `Code` field equals
//     `yerr.CodeConfig`. The typed code is what the API and worker
//     binaries pivot their fail-fast exit on; an `error` returned as
//     a plain `errors.New` value would silently downgrade the exit
//     path to a generic "unknown error".
//  3. The error message MUST contain the scenario's predicted
//     substring (typically the offending env var name). This is the
//     AC3 actionable-failure surface — an operator reading the
//     error MUST be able to map the failure to a specific env var
//     without re-running the loader.
//  4. The error message MUST NOT contain the
//     `configValidationSecretMarker` literal seeded into the
//     baseline strict env. This is the AC8 redaction predicate —
//     validation errors describe which field failed without echoing
//     its value, even when the offending value is itself a secret.
func assessConfigValidationScenario(s configValidationScenario) []string {
	env := configValidationMarkedEnv()
	s.mutate(env)

	cfg, err := Load(MapLookup(env))
	var reasons []string
	if err == nil {
		reasons = append(reasons, fmt.Sprintf("Load succeeded (cfg=%v), want error containing %q", cfg, s.wantSub))
		return reasons
	}
	var typed *yerr.Error
	if !stderrors.As(err, &typed) {
		reasons = append(reasons, fmt.Sprintf("error %T is not *yerr.Error", err))
	} else if typed.Code != yerr.CodeConfig {
		reasons = append(reasons, fmt.Sprintf("error code = %q, want %q", typed.Code, yerr.CodeConfig))
	}
	msg := err.Error()
	if !strings.Contains(msg, s.wantSub) {
		reasons = append(reasons, fmt.Sprintf("error message %q does not contain %q", msg, s.wantSub))
	}
	if strings.Contains(msg, configValidationSecretMarker) {
		reasons = append(reasons, fmt.Sprintf("error message leaked secret marker %q (full message redacted from log to avoid amplifying the leak)", configValidationSecretMarker))
	}
	return reasons
}

// TestConfigValidationCoversCallSites is the closed-set coverage
// member of the canonical pair. It walks the scenario table built by
// buildConfigValidationScenarios and asserts each documented rule
// produces the predicted typed error code, the predicted field-
// naming substring, and the load-bearing redaction guarantee. A
// regression in any branch fires on the offending scenario name.
//
// The coverage invariant also asserts the table is non-empty so a
// future refactor that silently emptied the scenario set would fail
// here instead of vacuously passing.
func TestConfigValidationCoversCallSites(t *testing.T) {
	t.Parallel()

	scenarios := buildConfigValidationScenarios()
	if len(scenarios) == 0 {
		t.Fatal("buildConfigValidationScenarios returned no scenarios; the coverage member would vacuously pass")
	}

	for _, scen := range scenarios {
		scen := scen
		t.Run(scen.name, func(t *testing.T) {
			t.Parallel()
			for _, reason := range assessConfigValidationScenario(scen) {
				t.Errorf("scenario %s: %s", scen.name, reason)
			}
		})
	}

	// Sanity-check the baseline strict env itself loads cleanly. A
	// regression that silently broke `strictEnv()` would make every
	// scenario above tautologically pass (the unmodified env would
	// already fail Load) and the gate would silently de-grade.
	cfg, err := Load(MapLookup(configValidationMarkedEnv()))
	if err != nil {
		t.Fatalf("baseline marked env failed to load: %v", err)
	}
	if cfg == nil {
		t.Fatal("baseline marked env returned nil cfg")
	}
}

// TestConfigValidationPreservesContractUnderContention is the per-
// decision stability member of the canonical pair. It fires
// `configValidationWorkers * configValidationIterationsPerWorker`
// goroutines that each build their own env map from the scenario
// table and run `config.Load(MapLookup(env))` and asserts every
// goroutine sees the rule its OWN scenario predicts. A cross-write
// under the race that swapped two goroutines' scenarios — or a
// future regression that introduced shared mutable state in the
// validator — would fail the per-iteration assertion even when the
// aggregate pass count matched.
//
// The contention burst is the load-bearing stability check the
// gate's wire contract requires: the validator is pure today, but a
// future regression that introduced shared mutable state (a cached
// profile-defaults table, a global rate-limit builder, a sync.Once
// mutating a shared map) would surface here before reaching the API
// or worker binaries.
func TestConfigValidationPreservesContractUnderContention(t *testing.T) {
	t.Parallel()

	scenarios := buildConfigValidationScenarios()
	if len(scenarios) == 0 {
		t.Fatal("buildConfigValidationScenarios returned no scenarios; the contention burst would vacuously pass")
	}

	type failure struct {
		worker    int
		iteration int
		scenario  string
		reasons   []string
	}

	var (
		mu       sync.Mutex
		failures []failure
		total    int
	)

	var wg sync.WaitGroup
	wg.Add(configValidationWorkers)
	for w := 0; w < configValidationWorkers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < configValidationIterationsPerWorker; i++ {
				// Deterministic per-worker + per-iteration index so
				// every parallel run paginates the identical decision
				// set. A cross-write that swapped two goroutines'
				// scenarios would map this iteration to a different
				// rule than the one its predicate predicted.
				idx := (w*configValidationIterationsPerWorker + i) % len(scenarios)
				scen := scenarios[idx]
				reasons := assessConfigValidationScenario(scen)

				mu.Lock()
				total++
				if len(reasons) > 0 {
					failures = append(failures, failure{
						worker:    w,
						iteration: i,
						scenario:  scen.name,
						reasons:   reasons,
					})
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if total != configValidationBurstTotalIterations {
		t.Fatalf("observed %d validations, want %d (workers=%d iters=%d)",
			total, configValidationBurstTotalIterations, configValidationWorkers, configValidationIterationsPerWorker)
	}

	for _, f := range failures {
		t.Errorf("worker %d iteration %d scenario %s: %v", f.worker, f.iteration, f.scenario, f.reasons)
	}
}
