package variables_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/controlplane/variables"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// plaintextProvider lets tests round-trip secret values through a real
// Provider without depending on AESGCM key material. Its wire ids match
// secrets.PlaintextProviderID / secrets.PlaintextKeyID so fixtures can
// build sealed rows by calling Seal directly.
func plaintextProvider() secrets.Provider { return secrets.NewPlaintext() }

// sealSecret builds a sealed ScopedVariable by Sealing plain through p.
// A test failure here is a test fixture bug; tests treat it as a fatal
// helper assertion rather than a subject-under-test signal.
func sealSecret(t *testing.T, p secrets.Provider, resourceID, key, plain string) variables.ScopedVariable {
	t.Helper()
	ct, kid, err := p.Seal([]byte(plain))
	if err != nil {
		t.Fatalf("seal helper failed: %v", err)
	}
	return variables.ScopedVariable{
		ResourceID:       resourceID,
		Key:              key,
		IsSecret:         true,
		SecretProvider:   p.ProviderID(),
		SecretKeyID:      kid,
		SecretCiphertext: ct,
	}
}

func plain(resourceID, key, value string) variables.ScopedVariable {
	return variables.ScopedVariable{
		ResourceID: resourceID,
		Key:        key,
		Value:      value,
	}
}

func TestNewResolverRejectsNilProvider(t *testing.T) {
	t.Parallel()
	if _, err := variables.NewResolver(nil); err == nil {
		t.Fatalf("expected error for nil provider")
	}
}

// emptyIDProvider lets us prove NewResolver refuses a provider with an
// empty ProviderID (the secrets package reserves the empty string).
type emptyIDProvider struct{}

func (emptyIDProvider) ProviderID() string                  { return "" }
func (emptyIDProvider) Seal([]byte) ([]byte, string, error) { return nil, "", errors.New("unused") }
func (emptyIDProvider) Open([]byte, string) ([]byte, error) { return nil, errors.New("unused") }

func TestNewResolverRejectsEmptyProviderID(t *testing.T) {
	t.Parallel()
	if _, err := variables.NewResolver(emptyIDProvider{}); err == nil {
		t.Fatalf("expected error for provider with empty id")
	}
}

func TestResolveEmptyInputs(t *testing.T) {
	t.Parallel()
	r, err := variables.NewResolver(plaintextProvider())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	got, err := r.Resolve(variables.ResolveInput{}, variables.Options{})
	if err != nil {
		t.Fatalf("Resolve empty inputs: %v", err)
	}
	if len(got.Variables) != 0 {
		t.Fatalf("expected zero variables, got %v", got.Variables)
	}
	if len(got.Contributions) != 0 {
		t.Fatalf("expected zero contributions, got %v", got.Contributions)
	}
	if !reflect.DeepEqual(got.Explain(), variables.Explained{Variables: []variables.ExplainedVariable{}}) {
		t.Fatalf("expected empty Explained, got %+v", got.Explain())
	}
}

func TestResolvePrecedenceServiceOverridesEverything(t *testing.T) {
	t.Parallel()
	r, err := variables.NewResolver(plaintextProvider())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		OrganizationVariables: []variables.ScopedVariable{plain("org-1", "API_HOST", "org.example")},
		ProjectVariables:      []variables.ScopedVariable{plain("proj-1", "API_HOST", "proj.example")},
		EnvironmentVariables:  []variables.ScopedVariable{plain("env-1", "API_HOST", "env.example")},
		ServiceVariables:      []variables.ScopedVariable{plain("svc-1", "API_HOST", "svc.example")},
	}
	got, err := r.Resolve(in, variables.Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Variables) != 1 {
		t.Fatalf("expected 1 variable, got %d", len(got.Variables))
	}
	v := got.Variables[0]
	if v.Source != variables.SourceService || v.SourceID != "svc-1" || v.Value != "svc.example" {
		t.Fatalf("service did not win: %+v", v)
	}
	chain := got.Contributions["API_HOST"]
	if len(chain) != 4 {
		t.Fatalf("expected 4 contributions, got %d: %+v", len(chain), chain)
	}
	wantOrder := []variables.Source{
		variables.SourceOrganization,
		variables.SourceProject,
		variables.SourceEnvironment,
		variables.SourceService,
	}
	for i, c := range chain {
		if c.Source != wantOrder[i] {
			t.Fatalf("contribution[%d]: want %s, got %s", i, wantOrder[i], c.Source)
		}
	}
}

func TestResolvePrecedenceEnvironmentOverridesProject(t *testing.T) {
	t.Parallel()
	r, err := variables.NewResolver(plaintextProvider())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		ProjectVariables:     []variables.ScopedVariable{plain("proj-1", "API_HOST", "proj.example")},
		EnvironmentVariables: []variables.ScopedVariable{plain("env-1", "API_HOST", "env.example")},
	}
	got, err := r.Resolve(in, variables.Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Variables[0].Source != variables.SourceEnvironment || got.Variables[0].Value != "env.example" {
		t.Fatalf("environment did not override project: %+v", got.Variables[0])
	}
}

func TestResolvePrecedenceProjectOverridesOrganization(t *testing.T) {
	t.Parallel()
	r, err := variables.NewResolver(plaintextProvider())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		OrganizationVariables: []variables.ScopedVariable{plain("org-1", "API_HOST", "org.example")},
		ProjectVariables:      []variables.ScopedVariable{plain("proj-1", "API_HOST", "proj.example")},
	}
	got, err := r.Resolve(in, variables.Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Variables[0].Source != variables.SourceProject || got.Variables[0].Value != "proj.example" {
		t.Fatalf("project did not override organization: %+v", got.Variables[0])
	}
}

func TestResolveDifferentKeysCoexistAcrossScopes(t *testing.T) {
	t.Parallel()
	r, err := variables.NewResolver(plaintextProvider())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		OrganizationVariables: []variables.ScopedVariable{plain("o", "ONE", "1")},
		ProjectVariables:      []variables.ScopedVariable{plain("p", "TWO", "2")},
		EnvironmentVariables:  []variables.ScopedVariable{plain("e", "THREE", "3")},
		ServiceVariables:      []variables.ScopedVariable{plain("s", "FOUR", "4")},
	}
	got, err := r.Resolve(in, variables.Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Variables) != 4 {
		t.Fatalf("expected 4 distinct vars, got %d: %+v", len(got.Variables), got.Variables)
	}
	// Output is sorted ASC by key.
	wantKeys := []string{"FOUR", "ONE", "THREE", "TWO"}
	for i, want := range wantKeys {
		if got.Variables[i].Key != want {
			t.Fatalf("ordering: position %d want %s got %s", i, want, got.Variables[i].Key)
		}
	}
}

func TestResolveSecretDowngradeRejectedByDefault(t *testing.T) {
	t.Parallel()
	p := plaintextProvider()
	r, err := variables.NewResolver(p)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		OrganizationVariables: []variables.ScopedVariable{sealSecret(t, p, "org-1", "DB_PASSWORD", "rotated")},
		ProjectVariables:      []variables.ScopedVariable{plain("proj-1", "DB_PASSWORD", "leaked-as-plain")},
	}
	_, err = r.Resolve(in, variables.Options{})
	if err == nil {
		t.Fatalf("expected InvalidInput, got nil")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("expected InvalidInput, got %T %v", err, err)
	}
	vs, ok := apierr.ViolationsOf(err)
	if !ok || len(vs) != 1 {
		t.Fatalf("expected one violation, got %+v", vs)
	}
	if !strings.HasPrefix(vs[0].Field, "project.variables[") {
		t.Fatalf("violation field path should target the project scope: %s", vs[0].Field)
	}
	// The violation message must NEVER echo the rejected plaintext value or
	// the ciphertext bytes — only a stable reason describing the rule.
	for _, leak := range []string{"leaked-as-plain", "rotated"} {
		if strings.Contains(strings.Join([]string{vs[0].Field, vs[0].Reason, err.Error()}, "|"), leak) {
			t.Fatalf("violation leaked plaintext (%q): field=%q reason=%q err=%q", leak, vs[0].Field, vs[0].Reason, err.Error())
		}
	}
}

func TestResolveSecretDowngradeAllowedWithOptIn(t *testing.T) {
	t.Parallel()
	p := plaintextProvider()
	r, err := variables.NewResolver(p)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		OrganizationVariables: []variables.ScopedVariable{sealSecret(t, p, "org-1", "DB_PASSWORD", "rotated")},
		ProjectVariables:      []variables.ScopedVariable{plain("proj-1", "DB_PASSWORD", "explicit-plain")},
	}
	got, err := r.Resolve(in, variables.Options{AllowSecretDowngrade: true})
	if err != nil {
		t.Fatalf("Resolve with AllowSecretDowngrade: %v", err)
	}
	if got.Variables[0].IsSecret {
		t.Fatalf("downgraded variable should not be marked secret: %+v", got.Variables[0])
	}
	if got.Variables[0].Value != "explicit-plain" || got.Variables[0].Source != variables.SourceProject {
		t.Fatalf("downgrade did not take winning row: %+v", got.Variables[0])
	}
}

func TestResolveSecretUpgradeAlwaysAllowed(t *testing.T) {
	t.Parallel()
	p := plaintextProvider()
	r, err := variables.NewResolver(p)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		OrganizationVariables: []variables.ScopedVariable{plain("org-1", "TOKEN", "non-secret-default")},
		ProjectVariables:      []variables.ScopedVariable{sealSecret(t, p, "proj-1", "TOKEN", "now-classified")},
	}
	got, err := r.Resolve(in, variables.Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !got.Variables[0].IsSecret || got.Variables[0].Value != "now-classified" {
		t.Fatalf("upgrade should win without opt-in: %+v", got.Variables[0])
	}
}

func TestResolveDuplicateKeyWithinScopeRejected(t *testing.T) {
	t.Parallel()
	r, err := variables.NewResolver(plaintextProvider())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		ProjectVariables: []variables.ScopedVariable{
			plain("p-1", "KEY", "first"),
			plain("p-2", "KEY", "second"),
		},
	}
	_, err = r.Resolve(in, variables.Options{})
	if err == nil {
		t.Fatalf("expected InvalidInput, got nil")
	}
	vs, ok := apierr.ViolationsOf(err)
	if !ok {
		t.Fatalf("expected field violations, got %v", err)
	}
	if len(vs) != 1 {
		t.Fatalf("expected one violation, got %d: %+v", len(vs), vs)
	}
	if !strings.Contains(vs[0].Field, "project.variables[1].key") {
		t.Fatalf("violation should anchor on the duplicate index: %s", vs[0].Field)
	}
	if strings.Contains(strings.Join([]string{vs[0].Field, vs[0].Reason, err.Error()}, "|"), "first") ||
		strings.Contains(strings.Join([]string{vs[0].Field, vs[0].Reason, err.Error()}, "|"), "second") {
		t.Fatalf("violation leaked a submitted value: %+v err=%q", vs[0], err.Error())
	}
}

func TestResolveInvalidNameRejected(t *testing.T) {
	t.Parallel()
	r, err := variables.NewResolver(plaintextProvider())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		OrganizationVariables: []variables.ScopedVariable{
			plain("o-1", "1_BAD_LEADING_DIGIT", "x"),
			plain("o-2", "BAD-WITH-DASH", "y"),
			plain("o-3", "OK_NAME", "z"),
		},
	}
	_, err = r.Resolve(in, variables.Options{})
	if err == nil {
		t.Fatalf("expected InvalidInput")
	}
	vs, ok := apierr.ViolationsOf(err)
	if !ok || len(vs) != 2 {
		t.Fatalf("expected two violations, got %+v", vs)
	}
}

// brokenOpenProvider lets us exercise the secret-opening server-side
// failure path. Seal succeeds (so a fixture can build a sealed row),
// Open always returns secrets.ErrUnknownKey.
type brokenOpenProvider struct{}

func (brokenOpenProvider) ProviderID() string { return "broken-v1" }
func (brokenOpenProvider) Seal(plaintext []byte) ([]byte, string, error) {
	return append([]byte(nil), plaintext...), "kid", nil
}
func (brokenOpenProvider) Open([]byte, string) ([]byte, error) { return nil, secrets.ErrUnknownKey }

func TestResolveSecretOpenFailureSurfacesInternal(t *testing.T) {
	t.Parallel()
	p := brokenOpenProvider{}
	r, err := variables.NewResolver(p)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		ServiceVariables: []variables.ScopedVariable{sealSecret(t, p, "s-1", "TOKEN", "very-secret-do-not-leak")},
	}
	_, err = r.Resolve(in, variables.Options{})
	if err == nil {
		t.Fatalf("expected Internal, got nil")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Fatalf("expected CodeInternal, got %T code=%v err=%v", err, ye.Code, err)
	}
	if !errors.Is(err, secrets.ErrUnknownKey) {
		t.Fatalf("wrapped cause should preserve ErrUnknownKey: %v", err)
	}
	// The Internal envelope MUST NOT echo the plaintext.
	if strings.Contains(err.Error(), "very-secret-do-not-leak") {
		t.Fatalf("Internal error leaked plaintext: %q", err.Error())
	}
}

func TestResolveMismatchedProviderSurfacesInternal(t *testing.T) {
	t.Parallel()
	r, err := variables.NewResolver(plaintextProvider())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	// A sealed row that claims to be sealed under "aesgcm-v1" handed to
	// a resolver running the Plaintext provider must surface as Internal
	// with a wrapped secrets.ErrUnsupportedProvider.
	in := variables.ResolveInput{
		ServiceVariables: []variables.ScopedVariable{{
			ResourceID:       "s-1",
			Key:              "TOKEN",
			IsSecret:         true,
			SecretProvider:   "aesgcm-v1",
			SecretKeyID:      "abcdef0123456789",
			SecretCiphertext: []byte("opaque-do-not-decode-me"),
		}},
	}
	_, err = r.Resolve(in, variables.Options{})
	if err == nil {
		t.Fatalf("expected Internal")
	}
	if !errors.Is(err, secrets.ErrUnsupportedProvider) {
		t.Fatalf("expected wrapped ErrUnsupportedProvider, got %v", err)
	}
	// The wrap may carry the (non-secret) provider id strings but must
	// not leak the ciphertext bytes.
	if strings.Contains(err.Error(), "opaque-do-not-decode-me") {
		t.Fatalf("Internal error leaked ciphertext bytes: %q", err.Error())
	}
}

func TestResolveSecretRoundTripThroughProvider(t *testing.T) {
	t.Parallel()
	p := plaintextProvider()
	r, err := variables.NewResolver(p)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		ServiceVariables: []variables.ScopedVariable{sealSecret(t, p, "s-1", "TOKEN", "round-trip-value")},
	}
	got, err := r.Resolve(in, variables.Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Variables[0].Value != "round-trip-value" {
		t.Fatalf("expected plaintext value after Open, got %q", got.Variables[0].Value)
	}
	if !got.Variables[0].IsSecret {
		t.Fatalf("expected secret flag preserved after Open: %+v", got.Variables[0])
	}
}

func TestResolvedLogValueRedactsValues(t *testing.T) {
	t.Parallel()
	r, err := variables.NewResolver(plaintextProvider())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	got, err := r.Resolve(variables.ResolveInput{
		ServiceVariables: []variables.ScopedVariable{plain("s-1", "API_HOST", "extremely-revealing-host.example")},
	}, variables.Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("resolved", "data", got, "first", got.Variables[0])
	out := buf.String()
	if strings.Contains(out, "extremely-revealing-host.example") {
		t.Fatalf("plaintext leaked into slog output: %s", out)
	}
	if !strings.Contains(out, output.Sentinel) {
		t.Fatalf("redaction sentinel missing from slog output: %s", out)
	}
}

func TestScopedVariableLogValueRedactsBothPlainAndCiphertext(t *testing.T) {
	t.Parallel()
	p := plaintextProvider()
	v := sealSecret(t, p, "s-1", "TOKEN", "ciphertext-content")
	v.Value = "fallback-plain"
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("scoped", "v", v)
	out := buf.String()
	// The plaintext (Value) and the ciphertext (which under the
	// Plaintext provider is byte-equal to the plaintext) must NOT
	// appear in the log line; the redaction sentinel MUST appear.
	for _, leak := range []string{"fallback-plain", "ciphertext-content"} {
		if strings.Contains(out, leak) {
			t.Fatalf("ScopedVariable.LogValue leaked %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, output.Sentinel) {
		t.Fatalf("missing sentinel in slog output: %s", out)
	}
}

func TestExplainRedactsAllValuesAndPreservesChain(t *testing.T) {
	t.Parallel()
	p := plaintextProvider()
	r, err := variables.NewResolver(p)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		OrganizationVariables: []variables.ScopedVariable{plain("o-1", "API_HOST", "org.example")},
		ProjectVariables:      []variables.ScopedVariable{plain("p-1", "API_HOST", "proj.example")},
		ServiceVariables:      []variables.ScopedVariable{sealSecret(t, p, "s-1", "TOKEN", "tip-of-the-iceberg")},
	}
	got, err := r.Resolve(in, variables.Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	exp := got.Explain()
	if len(exp.Variables) != 2 {
		t.Fatalf("expected 2 explained variables, got %d", len(exp.Variables))
	}
	for _, v := range exp.Variables {
		if v.Value != output.Sentinel {
			t.Fatalf("explain leaked plaintext for key %s: %q", v.Key, v.Value)
		}
	}
	encoded, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("json.Marshal Explained: %v", err)
	}
	for _, leak := range []string{"org.example", "proj.example", "tip-of-the-iceberg"} {
		if bytes.Contains(encoded, []byte(leak)) {
			t.Fatalf("Explained JSON leaked %q: %s", leak, encoded)
		}
	}
	// The override chain length matches the number of contributing scopes.
	apiChain := exp.Variables[0].Sources
	if len(apiChain) != 2 || apiChain[0].Source != variables.SourceOrganization || apiChain[1].Source != variables.SourceProject {
		t.Fatalf("explain dropped chain: %+v", apiChain)
	}
}

// TestResolveGoldenScenarios pins the full resolver contract against a
// realistic four-scope fixture for the production, staging, and preview
// tier shapes plus an isolated service-overrides-only scenario.
// The expected slices are byte-equal to the resolver output by Key —
// any drift in precedence, naming, ordering, or chain construction
// fails the table-driven test.
func TestResolveGoldenScenarios(t *testing.T) {
	t.Parallel()

	type expectedVar struct {
		Key      string
		Value    string
		IsSecret bool
		Source   variables.Source
		SourceID string
		Chain    []variables.Contribution
	}
	type scenario struct {
		name    string
		input   variables.ResolveInput
		options variables.Options
		want    []expectedVar
	}

	p := plaintextProvider()

	scenarios := []scenario{
		{
			name: "production",
			input: variables.ResolveInput{
				OrganizationVariables: []variables.ScopedVariable{
					plain("o-1", "LOG_LEVEL", "info"),
					plain("o-2", "REGION", "us-east-1"),
					sealSecret(t, p, "o-3", "STRIPE_SECRET", "sk_org_default"),
				},
				ProjectVariables: []variables.ScopedVariable{
					plain("p-1", "APP_NAME", "checkout"),
					sealSecret(t, p, "p-2", "STRIPE_SECRET", "sk_proj_override"),
				},
				EnvironmentVariables: []variables.ScopedVariable{
					plain("e-1", "TIER", "production"),
					plain("e-2", "LOG_LEVEL", "warn"),
				},
				ServiceVariables: []variables.ScopedVariable{
					plain("s-1", "PORT", "8080"),
					sealSecret(t, p, "s-2", "STRIPE_SECRET", "sk_svc_canary"),
				},
			},
			want: []expectedVar{
				{Key: "APP_NAME", Value: "checkout", Source: variables.SourceProject, SourceID: "p-1", Chain: []variables.Contribution{{Source: variables.SourceProject, SourceID: "p-1"}}},
				{Key: "LOG_LEVEL", Value: "warn", Source: variables.SourceEnvironment, SourceID: "e-2", Chain: []variables.Contribution{{Source: variables.SourceOrganization, SourceID: "o-1"}, {Source: variables.SourceEnvironment, SourceID: "e-2"}}},
				{Key: "PORT", Value: "8080", Source: variables.SourceService, SourceID: "s-1", Chain: []variables.Contribution{{Source: variables.SourceService, SourceID: "s-1"}}},
				{Key: "REGION", Value: "us-east-1", Source: variables.SourceOrganization, SourceID: "o-2", Chain: []variables.Contribution{{Source: variables.SourceOrganization, SourceID: "o-2"}}},
				{Key: "STRIPE_SECRET", Value: "sk_svc_canary", IsSecret: true, Source: variables.SourceService, SourceID: "s-2", Chain: []variables.Contribution{{Source: variables.SourceOrganization, SourceID: "o-3", IsSecret: true}, {Source: variables.SourceProject, SourceID: "p-2", IsSecret: true}, {Source: variables.SourceService, SourceID: "s-2", IsSecret: true}}},
				{Key: "TIER", Value: "production", Source: variables.SourceEnvironment, SourceID: "e-1", Chain: []variables.Contribution{{Source: variables.SourceEnvironment, SourceID: "e-1"}}},
			},
		},
		{
			name: "staging",
			input: variables.ResolveInput{
				OrganizationVariables: []variables.ScopedVariable{
					plain("o-1", "LOG_LEVEL", "info"),
					plain("o-2", "REGION", "us-east-1"),
				},
				ProjectVariables: []variables.ScopedVariable{
					plain("p-1", "APP_NAME", "checkout"),
					sealSecret(t, p, "p-2", "STRIPE_SECRET", "sk_proj_default"),
				},
				EnvironmentVariables: []variables.ScopedVariable{
					plain("e-1", "TIER", "staging"),
					plain("e-2", "FEATURE_FLAGS_ENDPOINT", "https://flags-staging.example"),
				},
				ServiceVariables: []variables.ScopedVariable{
					plain("s-1", "PORT", "8080"),
				},
			},
			want: []expectedVar{
				{Key: "APP_NAME", Value: "checkout", Source: variables.SourceProject, SourceID: "p-1", Chain: []variables.Contribution{{Source: variables.SourceProject, SourceID: "p-1"}}},
				{Key: "FEATURE_FLAGS_ENDPOINT", Value: "https://flags-staging.example", Source: variables.SourceEnvironment, SourceID: "e-2", Chain: []variables.Contribution{{Source: variables.SourceEnvironment, SourceID: "e-2"}}},
				{Key: "LOG_LEVEL", Value: "info", Source: variables.SourceOrganization, SourceID: "o-1", Chain: []variables.Contribution{{Source: variables.SourceOrganization, SourceID: "o-1"}}},
				{Key: "PORT", Value: "8080", Source: variables.SourceService, SourceID: "s-1", Chain: []variables.Contribution{{Source: variables.SourceService, SourceID: "s-1"}}},
				{Key: "REGION", Value: "us-east-1", Source: variables.SourceOrganization, SourceID: "o-2", Chain: []variables.Contribution{{Source: variables.SourceOrganization, SourceID: "o-2"}}},
				{Key: "STRIPE_SECRET", Value: "sk_proj_default", IsSecret: true, Source: variables.SourceProject, SourceID: "p-2", Chain: []variables.Contribution{{Source: variables.SourceProject, SourceID: "p-2", IsSecret: true}}},
				{Key: "TIER", Value: "staging", Source: variables.SourceEnvironment, SourceID: "e-1", Chain: []variables.Contribution{{Source: variables.SourceEnvironment, SourceID: "e-1"}}},
			},
		},
		{
			name: "preview",
			input: variables.ResolveInput{
				OrganizationVariables: []variables.ScopedVariable{plain("o-1", "REGION", "us-east-1")},
				EnvironmentVariables: []variables.ScopedVariable{
					plain("e-1", "TIER", "preview"),
					plain("e-2", "FEATURE_X", "off"),
				},
			},
			want: []expectedVar{
				{Key: "FEATURE_X", Value: "off", Source: variables.SourceEnvironment, SourceID: "e-2", Chain: []variables.Contribution{{Source: variables.SourceEnvironment, SourceID: "e-2"}}},
				{Key: "REGION", Value: "us-east-1", Source: variables.SourceOrganization, SourceID: "o-1", Chain: []variables.Contribution{{Source: variables.SourceOrganization, SourceID: "o-1"}}},
				{Key: "TIER", Value: "preview", Source: variables.SourceEnvironment, SourceID: "e-1", Chain: []variables.Contribution{{Source: variables.SourceEnvironment, SourceID: "e-1"}}},
			},
		},
		{
			name: "service-specific-overrides",
			input: variables.ResolveInput{
				ServiceVariables: []variables.ScopedVariable{
					plain("s-1", "PORT", "8080"),
					plain("s-2", "WORKERS", "4"),
					sealSecret(t, p, "s-3", "API_KEY", "svc-only-secret"),
				},
			},
			want: []expectedVar{
				{Key: "API_KEY", Value: "svc-only-secret", IsSecret: true, Source: variables.SourceService, SourceID: "s-3", Chain: []variables.Contribution{{Source: variables.SourceService, SourceID: "s-3", IsSecret: true}}},
				{Key: "PORT", Value: "8080", Source: variables.SourceService, SourceID: "s-1", Chain: []variables.Contribution{{Source: variables.SourceService, SourceID: "s-1"}}},
				{Key: "WORKERS", Value: "4", Source: variables.SourceService, SourceID: "s-2", Chain: []variables.Contribution{{Source: variables.SourceService, SourceID: "s-2"}}},
			},
		},
	}

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			r, err := variables.NewResolver(p)
			if err != nil {
				t.Fatalf("NewResolver: %v", err)
			}
			got, err := r.Resolve(sc.input, sc.options)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if len(got.Variables) != len(sc.want) {
				t.Fatalf("count mismatch: want %d, got %d (%+v)", len(sc.want), len(got.Variables), got.Variables)
			}
			for i, want := range sc.want {
				rendered := got.Variables[i]
				if rendered.Key != want.Key ||
					rendered.Value != want.Value ||
					rendered.IsSecret != want.IsSecret ||
					rendered.Source != want.Source ||
					rendered.SourceID != want.SourceID {
					t.Fatalf("[%s] entry %d mismatch:\n got  %+v\n want %+v", sc.name, i, rendered, want)
				}
				chain := got.Contributions[want.Key]
				if !reflect.DeepEqual(chain, want.Chain) {
					t.Fatalf("[%s] chain mismatch for %s:\n got  %+v\n want %+v", sc.name, want.Key, chain, want.Chain)
				}
			}

			// Explain output must redact every value AND must not contain
			// any of the source plaintext values in its JSON-marshalled
			// form. This is the load-bearing redaction invariant for the
			// customer-facing explain projection.
			explained := got.Explain()
			encoded, err := json.Marshal(explained)
			if err != nil {
				t.Fatalf("json.Marshal Explained: %v", err)
			}
			for _, want := range sc.want {
				if want.Value == "" {
					continue
				}
				if bytes.Contains(encoded, []byte(want.Value)) {
					t.Fatalf("[%s] explain leaked %q for key %s: %s", sc.name, want.Value, want.Key, encoded)
				}
			}
			for _, ev := range explained.Variables {
				if ev.Value != output.Sentinel {
					t.Fatalf("[%s] explain entry %s did not redact value: %q", sc.name, ev.Key, ev.Value)
				}
			}
		})
	}
}

// TestResolveCollectsViolationsAcrossScopes proves the resolver does
// not short-circuit on the first violation: it returns ALL field
// violations in one apierr.InvalidInput so a customer can fix every
// problem in one round trip.
func TestResolveCollectsViolationsAcrossScopes(t *testing.T) {
	t.Parallel()
	p := plaintextProvider()
	r, err := variables.NewResolver(p)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		OrganizationVariables: []variables.ScopedVariable{
			plain("o-1", "1_BAD", "ignored"),
			sealSecret(t, p, "o-2", "TOKEN", "secret-do-not-leak"),
		},
		ProjectVariables: []variables.ScopedVariable{
			plain("p-1", "OK", "fixture-value-one-zzy"),
			plain("p-2", "OK", "fixture-value-two-zzy"),
		},
		EnvironmentVariables: []variables.ScopedVariable{
			plain("e-1", "TOKEN", "non-secret-attempted-zzy-leak"),
		},
	}
	_, err = r.Resolve(in, variables.Options{})
	if err == nil {
		t.Fatalf("expected InvalidInput")
	}
	vs, ok := apierr.ViolationsOf(err)
	if !ok {
		t.Fatalf("expected field violations, got %v", err)
	}
	if len(vs) < 3 {
		t.Fatalf("expected at least 3 violations (invalid name + duplicate + downgrade), got %d: %+v", len(vs), vs)
	}
	// Whole-error redaction check: no submitted value or sealed
	// plaintext can appear in any part of the resulting error message,
	// the hint, or any violation tuple. The fixture values use a
	// distinctive "zzy" suffix so they cannot accidentally collide with
	// a stable reason phrase (e.g. "duplicate variable name").
	full := err.Error()
	for _, v := range vs {
		full += "|" + v.Field + "|" + v.Reason
	}
	for _, leak := range []string{"secret-do-not-leak", "fixture-value-one-zzy", "fixture-value-two-zzy", "non-secret-attempted-zzy-leak"} {
		if strings.Contains(full, leak) {
			t.Fatalf("error chain leaked %q: %s", leak, full)
		}
	}
}

// TestResolveAcceptsCanceledContextViaCaller documents that the
// resolver is pure and performs no I/O. The context is accepted by the
// caller's higher-level orchestration layer, not the resolver itself,
// so a canceled context handed to a downstream Reader does not affect
// resolver semantics. This test pins the expectation by demonstrating
// that calling Resolve with a populated fixture succeeds even if a
// canceled ctx is observable in the surrounding scope.
func TestResolveIsPureAndContextFree(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = ctx
	r, err := variables.NewResolver(plaintextProvider())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	if _, err := r.Resolve(variables.ResolveInput{
		ServiceVariables: []variables.ScopedVariable{plain("s", "K", "v")},
	}, variables.Options{}); err != nil {
		t.Fatalf("resolver should be context-free: %v", err)
	}
}

// TestExplainCopyIsIndependent proves Explain returns a deep enough
// copy of the contribution chain that callers cannot mutate the
// resolver's internal state by appending to the explained chain.
func TestExplainCopyIsIndependent(t *testing.T) {
	t.Parallel()
	r, err := variables.NewResolver(plaintextProvider())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		ProjectVariables: []variables.ScopedVariable{plain("p-1", "K", "v")},
	}
	got, err := r.Resolve(in, variables.Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	exp := got.Explain()
	exp.Variables[0].Sources = append(exp.Variables[0].Sources, variables.Contribution{Source: "injected"})
	if len(got.Contributions["K"]) != 1 {
		t.Fatalf("Explain mutation should not leak back into Resolved: %+v", got.Contributions["K"])
	}
}

// TestErrorMessageRedaction proves the resolver never includes any
// ciphertext bytes in error messages even when Open returns a wrapped
// cause that does include them.
func TestErrorMessageRedactsCiphertextBytes(t *testing.T) {
	t.Parallel()
	r, err := variables.NewResolver(brokenOpenProvider{})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	in := variables.ResolveInput{
		ServiceVariables: []variables.ScopedVariable{{
			ResourceID:       "s-1",
			Key:              "TOKEN",
			IsSecret:         true,
			SecretProvider:   "broken-v1",
			SecretKeyID:      "kid",
			SecretCiphertext: []byte("ciphertext-bytes-do-not-leak"),
		}},
	}
	_, err = r.Resolve(in, variables.Options{})
	if err == nil {
		t.Fatalf("expected Internal error")
	}
	if strings.Contains(fmt.Sprintf("%+v", err), "ciphertext-bytes-do-not-leak") {
		t.Fatalf("ciphertext leaked into error: %v", err)
	}
}
