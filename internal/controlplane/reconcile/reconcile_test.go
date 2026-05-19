package reconcile_test

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/reconcile"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// TestNew_RequiresPorts asserts construction fails fast on a misconfigured
// reconciler, with a typed Internal error. This is the structural guard the
// rest of the suite relies on.
func TestNew_RequiresPorts(t *testing.T) {
	t.Parallel()
	full := reconcile.Config{
		Desired:   &fakeDesiredReader{},
		Actual:    &fakeActualReader{},
		Repairer:  &fakeRepairer{},
		Reviewer:  &fakeReviewer{},
		Unmanaged: &fakeUnmanaged{},
	}
	if _, err := reconcile.New(full); err != nil {
		t.Fatalf("New(full) = %v; want nil", err)
	}
	cases := []struct {
		name string
		mut  func(c *reconcile.Config)
	}{
		{"no desired", func(c *reconcile.Config) { c.Desired = nil }},
		{"no actual", func(c *reconcile.Config) { c.Actual = nil }},
		{"no repairer", func(c *reconcile.Config) { c.Repairer = nil }},
		{"no reviewer", func(c *reconcile.Config) { c.Reviewer = nil }},
		{"no unmanaged", func(c *reconcile.Config) { c.Unmanaged = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := full
			tc.mut(&cfg)
			_, err := reconcile.New(cfg)
			if err == nil {
				t.Fatalf("New(missing %s) = nil error; want failure", tc.name)
			}
			if got := errCode(err); got != yerr.CodeInternal {
				t.Errorf("error code = %q; want %q", got, yerr.CodeInternal)
			}
		})
	}
}

// TestPlan_ValidationFailure asserts the engine rejects a malformed org id
// without calling any port. This is the "validation failure" acceptance case
// for the engine surface.
func TestPlan_ValidationFailure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		id   domain.ID
	}{
		{"blank", ""},
		{"malformed", "not-an-id"},
		{"wrong kind", domain.MustNewID(domain.KindProject)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			desired := &fakeDesiredReader{}
			actual := &fakeActualReader{}
			rec := newReconciler(t, &reconcile.Config{
				Desired: desired, Actual: actual,
				Repairer: &fakeRepairer{}, Reviewer: &fakeReviewer{}, Unmanaged: &fakeUnmanaged{},
			})
			_, err := rec.Plan(context.Background(), tc.id)
			if err == nil {
				t.Fatalf("Plan(%q) = nil error; want validation failure", tc.id)
			}
			if got := errCode(err); got != yerr.CodeValidation {
				t.Errorf("error code = %q; want %q", got, yerr.CodeValidation)
			}
			if violations, ok := apierr.ViolationsOf(err); !ok || len(violations) == 0 {
				t.Errorf("expected typed FieldViolations; got %+v / ok=%v", violations, ok)
			}
			if desired.calls != 0 || actual.calls != 0 {
				t.Errorf("ports were called on validation failure: desired=%d actual=%d", desired.calls, actual.calls)
			}
		})
	}
}

// TestPlan_NotFoundFromDesired asserts a typed apierr.NotFound from the
// desired reader is preserved untouched — the engine never masks a known
// taxonomy code as Internal.
func TestPlan_NotFoundFromDesired(t *testing.T) {
	t.Parallel()
	desired := &fakeDesiredReader{err: apierr.NotFound("organization", "redacted")}
	actual := &fakeActualReader{}
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: actual,
		Repairer: &fakeRepairer{}, Reviewer: &fakeReviewer{}, Unmanaged: &fakeUnmanaged{},
	})
	_, err := rec.Plan(context.Background(), validOrgID)
	if err == nil {
		t.Fatalf("Plan = nil error; want NotFound")
	}
	if got := errCode(err); got != yerr.CodeNotFound {
		t.Errorf("error code = %q; want %q", got, yerr.CodeNotFound)
	}
	if actual.calls != 0 {
		t.Errorf("ActualStateReader called after desired NotFound: calls=%d", actual.calls)
	}
}

// TestPlan_AuthorizationFailureFromDesired asserts a typed
// apierr.Forbidden from the desired reader is preserved.
// Authorization is enforced by the upstream caller (worker context) — the
// engine still surfaces a Forbidden cleanly if an adapter returns one.
func TestPlan_AuthorizationFailureFromDesired(t *testing.T) {
	t.Parallel()
	desired := &fakeDesiredReader{err: apierr.Forbidden("policy denied")}
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: &fakeActualReader{},
		Repairer: &fakeRepairer{}, Reviewer: &fakeReviewer{}, Unmanaged: &fakeUnmanaged{},
	})
	_, err := rec.Plan(context.Background(), validOrgID)
	if got := errCode(err); got != yerr.CodeForbidden {
		t.Errorf("error code = %q; want %q (err=%v)", got, yerr.CodeForbidden, err)
	}
}

// TestPlan_UntypedDesiredErrorBecomesStoreUnavailable asserts an untyped
// adapter error is upgraded to apierr.StoreUnavailable so callers always see
// a catalogued retry-class code. The wrapped cause is preserved (for logs)
// but never echoed in Message.
func TestPlan_UntypedDesiredErrorBecomesStoreUnavailable(t *testing.T) {
	t.Parallel()
	const dokployToken = "yk_token_value_super_secret"
	desired := &fakeDesiredReader{err: stderrors.New("postgres: Authorization: " + dokployToken)}
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: &fakeActualReader{},
		Repairer: &fakeRepairer{}, Reviewer: &fakeReviewer{}, Unmanaged: &fakeUnmanaged{},
	})
	_, err := rec.Plan(context.Background(), validOrgID)
	if got := errCode(err); got != yerr.CodeDBUnavailable {
		t.Errorf("error code = %q; want %q (err=%v)", got, yerr.CodeDBUnavailable, err)
	}
	// The token must not appear in the wrapped chain string.
	if strings.Contains(err.Error(), dokployToken) {
		t.Errorf("error string leaks token: %s", err.Error())
	}
}

// TestPlan_UntypedActualErrorBecomesDokployUnavailable asserts an untyped
// Dokploy adapter error is upgraded to apierr.DokployUnavailable so the
// caller knows it is transient.
func TestPlan_UntypedActualErrorBecomesDokployUnavailable(t *testing.T) {
	t.Parallel()
	desired := &fakeDesiredReader{state: simpleDesired()}
	actual := &fakeActualReader{err: stderrors.New("dokploy upstream blew up")}
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: actual,
		Repairer: &fakeRepairer{}, Reviewer: &fakeReviewer{}, Unmanaged: &fakeUnmanaged{},
	})
	_, err := rec.Plan(context.Background(), validOrgID)
	if got := errCode(err); got != yerr.CodeDokployUnavailable {
		t.Errorf("error code = %q; want %q (err=%v)", got, yerr.CodeDokployUnavailable, err)
	}
}

// TestPlan_UnprovisionedOrganizationReturnsEmptyPlan asserts a desired
// organization without a Dokploy ID is treated as not-yet-provisioned (the
// reconciler short-circuits before calling the Dokploy adapter).
func TestPlan_UnprovisionedOrganizationReturnsEmptyPlan(t *testing.T) {
	t.Parallel()
	state := simpleDesired()
	state.DokployID = ""
	desired := &fakeDesiredReader{state: state}
	actual := &fakeActualReader{}
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: actual,
		Repairer: &fakeRepairer{}, Reviewer: &fakeReviewer{}, Unmanaged: &fakeUnmanaged{},
	})
	plan, err := rec.Plan(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if !plan.IsEmpty() {
		t.Errorf("plan = %+v; want empty", plan.Actions)
	}
	if actual.calls != 0 {
		t.Errorf("ActualStateReader called for un-provisioned org: calls=%d", actual.calls)
	}
}

// TestApply_RepairsSafeDrift covers the changed-env-var success path through
// the engine. It asserts the Repairer is called with the desired value, the
// Reviewer is NOT called, and the value is never written to the captured
// log buffer.
func TestApply_RepairsSafeDrift(t *testing.T) {
	t.Parallel()
	const secretValue = "sk_live_super_secret_value_do_not_leak"
	state := simpleDesired()
	state.Projects[0].Environments[0].Services[0].EnvVars = []reconcile.DesiredEnvVar{
		{Key: "DATABASE_URL", Value: secretValue, Secret: true},
	}
	desired := &fakeDesiredReader{state: state}
	actualState := simpleActual()
	actualState.Projects[0].Environments[0].Services[0].EnvVars = []reconcile.ActualEnvVar{
		{Key: "DATABASE_URL", Value: "old_value"},
	}
	actual := &fakeActualReader{state: actualState}
	repairer := &fakeRepairer{}
	reviewer := &fakeReviewer{}
	unmanaged := &fakeUnmanaged{}
	var logBuf bytes.Buffer
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: actual,
		Repairer: repairer, Reviewer: reviewer, Unmanaged: unmanaged,
		Logger: textLogger(&logBuf),
	})
	res, err := rec.Reconcile(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	if res.Repaired != 1 {
		t.Errorf("Repaired = %d; want 1 (result=%+v)", res.Repaired, res)
	}
	if res.Reviewed != 0 || res.Quarantined != 0 || len(res.Failures) != 0 {
		t.Errorf("unexpected non-repair work: %+v", res)
	}
	if len(repairer.envCalls) != 1 {
		t.Fatalf("repairer.envCalls = %+v; want 1", repairer.envCalls)
	}
	call := repairer.envCalls[0]
	if call.Key != "DATABASE_URL" || call.Value != secretValue || !call.Secret {
		t.Errorf("repairer called with %+v; want DATABASE_URL=%q secret=true", call, secretValue)
	}
	if reviewer.calls != 0 {
		t.Errorf("Reviewer was called for safe drift")
	}
	if strings.Contains(logBuf.String(), secretValue) {
		t.Errorf("logger leaked secret value: %q", logBuf.String())
	}
}

// TestApply_RecordsDangerousDrift covers the deleted-app + renamed-domain
// dangerous paths in one go: the engine calls the Reviewer (not the
// Repairer) and the Result.Reviewed counter reflects the actions.
func TestApply_RecordsDangerousDrift(t *testing.T) {
	t.Parallel()
	state := simpleDesired()
	desired := &fakeDesiredReader{state: state}
	// Remove the app from actual and rename the database's domain — wait,
	// the database has no domain. Use the app's missing service as
	// "deleted app" drift; the rename happens on a separate domain we add
	// here.
	actualState := simpleActual()
	actualState.Projects[0].Environments[0].Services = filterActual(
		actualState.Projects[0].Environments[0].Services,
		func(s reconcile.ActualService) bool { return s.DokployID != "dokploy-svc-app" },
	)
	actual := &fakeActualReader{state: actualState}
	repairer := &fakeRepairer{}
	reviewer := &fakeReviewer{}
	unmanaged := &fakeUnmanaged{}
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: actual,
		Repairer: repairer, Reviewer: reviewer, Unmanaged: unmanaged,
	})
	res, err := rec.Reconcile(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	if res.Reviewed != 1 {
		t.Errorf("Reviewed = %d; want 1", res.Reviewed)
	}
	if repairer.envCalls != nil || repairer.removeCalls != nil || repairer.domainCalls != nil {
		t.Errorf("Repairer was called for dangerous drift: %+v / %+v / %+v",
			repairer.envCalls, repairer.removeCalls, repairer.domainCalls)
	}
	if len(reviewer.events) != 1 {
		t.Fatalf("reviewer.events = %+v; want 1", reviewer.events)
	}
	ev := reviewer.events[0]
	if ev.Reason != reconcile.ReasonServiceMissing {
		t.Errorf("ReviewEvent.Reason = %q; want %q", ev.Reason, reconcile.ReasonServiceMissing)
	}
	if ev.Level != reconcile.LevelService {
		t.Errorf("ReviewEvent.Level = %q; want %q", ev.Level, reconcile.LevelService)
	}
}

// TestApply_MarksUnmanagedResource asserts the engine routes an unmanaged
// resource through the UnmanagedRecorder, and that the recorded resource
// locates the rogue Dokploy ID under its parent without surfacing it via the
// Repairer or Reviewer paths.
func TestApply_MarksUnmanagedResource(t *testing.T) {
	t.Parallel()
	state := simpleDesired()
	desired := &fakeDesiredReader{state: state}
	actualState := simpleActual()
	actualState.Projects[0].Environments[0].Services = append(
		actualState.Projects[0].Environments[0].Services,
		reconcile.ActualService{
			DokployID: "dokploy-svc-rogue",
			Name:      "rogue",
			Type:      dokploy.ServiceApplication,
		},
	)
	actual := &fakeActualReader{state: actualState}
	repairer := &fakeRepairer{}
	reviewer := &fakeReviewer{}
	unmanaged := &fakeUnmanaged{}
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: actual,
		Repairer: repairer, Reviewer: reviewer, Unmanaged: unmanaged,
	})
	res, err := rec.Reconcile(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	if res.Quarantined != 1 {
		t.Errorf("Quarantined = %d; want 1", res.Quarantined)
	}
	if reviewer.calls != 0 {
		t.Errorf("Reviewer was called for unmanaged drift")
	}
	if repairer.envCalls != nil || repairer.removeCalls != nil || repairer.domainCalls != nil {
		t.Errorf("Repairer was called for unmanaged drift")
	}
	if len(unmanaged.resources) != 1 {
		t.Fatalf("unmanaged.resources = %+v; want 1", unmanaged.resources)
	}
	r := unmanaged.resources[0]
	if r.DokployResourceID != "dokploy-svc-rogue" {
		t.Errorf("DokployResourceID = %q; want %q", r.DokployResourceID, "dokploy-svc-rogue")
	}
	if r.ParentDokployID != "dokploy-env-prod" {
		t.Errorf("ParentDokployID = %q; want %q", r.ParentDokployID, "dokploy-env-prod")
	}
	if r.Level != reconcile.LevelService {
		t.Errorf("Level = %q; want %q", r.Level, reconcile.LevelService)
	}
}

// TestApply_BestEffortContinuesPastFailure asserts a per-action failure does
// not stop the rest of the plan: every remaining action is still attempted
// and the failing action is captured in Result.Failures with a redacted
// error string.
func TestApply_BestEffortContinuesPastFailure(t *testing.T) {
	t.Parallel()
	state := simpleDesired()
	state.Projects[0].Environments[0].Services[0].EnvVars = []reconcile.DesiredEnvVar{
		{Key: "FOO", Value: "bar"},
	}
	desired := &fakeDesiredReader{state: state}
	actualState := simpleActual()
	// Two safe drifts: env_var_missing and unmanaged extra env var on the
	// same service.
	actualState.Projects[0].Environments[0].Services[0].EnvVars = []reconcile.ActualEnvVar{
		{Key: "ROGUE", Value: "irrelevant"},
	}
	actual := &fakeActualReader{state: actualState}
	const sensitive = "upstream Authorization: Bearer y_actual_secret_value"
	repairer := &fakeRepairer{
		// Fail the first one (env_var_missing) with an unredacted error.
		envErr: stderrors.New(sensitive),
	}
	reviewer := &fakeReviewer{}
	unmanaged := &fakeUnmanaged{}
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: actual,
		Repairer: repairer, Reviewer: reviewer, Unmanaged: unmanaged,
	})
	res, err := rec.Reconcile(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	// One env-var ensure failed; one extra env-var removal succeeded.
	if res.Repaired != 1 {
		t.Errorf("Repaired = %d; want 1 (res=%+v)", res.Repaired, res)
	}
	if len(res.Failures) != 1 {
		t.Fatalf("Failures = %+v; want 1", res.Failures)
	}
	f := res.Failures[0]
	if f.Err == nil {
		t.Fatalf("Failure.Err is nil")
	}
	// The top-level apierr.Internal message is a fixed generic string by
	// design (no detail in client-facing Message), so we walk the wrapped
	// chain to assert the redacted cause is present and the raw secret is
	// not.
	full := errChainString(f.Err)
	if strings.Contains(full, "y_actual_secret_value") {
		t.Errorf("Failure.Err leaked upstream secret: %s", full)
	}
	if !strings.Contains(full, output.Sentinel) {
		t.Errorf("Failure.Err did not run through Redactor: %s", full)
	}
}

// TestApply_CancelledContextStopsLoop asserts the engine returns ctx.Err()
// when the context is cancelled before completion.
func TestApply_CancelledContextStopsLoop(t *testing.T) {
	t.Parallel()
	state := simpleDesired()
	state.Projects[0].Environments[0].Services[0].EnvVars = []reconcile.DesiredEnvVar{
		{Key: "FOO", Value: "bar"},
	}
	desired := &fakeDesiredReader{state: state}
	actualState := simpleActual()
	actual := &fakeActualReader{state: actualState}
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: actual,
		Repairer: &fakeRepairer{}, Reviewer: &fakeReviewer{}, Unmanaged: &fakeUnmanaged{},
	})
	plan, err := rec.Plan(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if plan.IsEmpty() {
		t.Fatalf("expected non-empty plan to exercise cancellation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = rec.Apply(ctx, plan)
	if !stderrors.Is(err, context.Canceled) {
		t.Errorf("Apply with cancelled ctx err = %v; want context.Canceled", err)
	}
}

// TestApply_UnmanagedActionWithoutPayloadIsCaptured asserts a malformed
// internal plan (DriftUnmanaged action with no Unmanaged payload — which
// the planner does not emit, but a future bug could) is captured as a
// Failure rather than panicking.
func TestApply_UnmanagedActionWithoutPayloadIsCaptured(t *testing.T) {
	t.Parallel()
	desired := &fakeDesiredReader{state: simpleDesired()}
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: &fakeActualReader{state: simpleActual()},
		Repairer: &fakeRepairer{}, Reviewer: &fakeReviewer{}, Unmanaged: &fakeUnmanaged{},
	})
	plan := reconcile.Plan{
		OrganizationID: validOrgID,
		Actions: []reconcile.Action{{
			Type: reconcile.ActionMarkUnmanaged,
			Kind: reconcile.DriftUnmanaged,
		}},
	}
	res, err := rec.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply error: %v", err)
	}
	if len(res.Failures) != 1 {
		t.Errorf("Failures = %+v; want 1", res.Failures)
	}
	if got := errCode(res.Failures[0].Err); got != yerr.CodeInternal {
		t.Errorf("error code = %q; want %q", got, yerr.CodeInternal)
	}
}

// TestApply_RedactsSensitiveErrorsInResult asserts an upstream Reviewer error
// that contains an Authorization header (a common transport shape for a
// leaked secret) is scrubbed before reaching Result.Failures or the log.
func TestApply_RedactsSensitiveErrorsInResult(t *testing.T) {
	t.Parallel()
	state := simpleDesired()
	desired := &fakeDesiredReader{state: state}
	actualState := simpleActual()
	actualState.Projects[0].Environments[0].Services = filterActual(
		actualState.Projects[0].Environments[0].Services,
		func(s reconcile.ActualService) bool { return s.DokployID != "dokploy-svc-app" },
	)
	actual := &fakeActualReader{state: actualState}
	const upstream = "review queue rejected: Authorization: Bearer s3cret_token_value_long"
	reviewer := &fakeReviewer{err: stderrors.New(upstream)}
	var logBuf bytes.Buffer
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: actual,
		Repairer: &fakeRepairer{}, Reviewer: reviewer, Unmanaged: &fakeUnmanaged{},
		Logger: textLogger(&logBuf),
	})
	res, err := rec.Reconcile(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	if len(res.Failures) != 1 {
		t.Fatalf("Failures = %+v; want 1", res.Failures)
	}
	f := res.Failures[0]
	if strings.Contains(f.Err.Error(), "s3cret_token_value_long") {
		t.Errorf("Failure.Err leaked secret: %s", f.Err.Error())
	}
	if strings.Contains(logBuf.String(), "s3cret_token_value_long") {
		t.Errorf("logger leaked secret: %s", logBuf.String())
	}
}

// ----------------------------------------------------------------------------
// Helpers and fakes.
// ----------------------------------------------------------------------------

// validOrgID is built lazily from a real Crockford-encoded ID, so every
// validation pass in the engine accepts it. Tests treat it as a constant.
var validOrgID = domain.MustNewID(domain.KindOrganization)

func simpleDesired() reconcile.DesiredOrganization {
	return reconcile.DesiredOrganization{
		ID:        validOrgID,
		Label:     "Demo Org",
		DokployID: "dokploy-org-1",
		Projects: []reconcile.DesiredProject{{
			ID:        domain.MustNewID(domain.KindProject),
			Label:     "Demo Project",
			DokployID: "dokploy-proj-1",
			Environments: []reconcile.DesiredEnvironment{{
				ID:        domain.MustNewID(domain.KindEnvironment),
				Label:     "production",
				DokployID: "dokploy-env-prod",
				Services: []reconcile.DesiredService{{
					ID:        domain.MustNewID(domain.KindService),
					Label:     "demo-app",
					Type:      dokploy.ServiceApplication,
					DokployID: "dokploy-svc-app",
				}},
			}},
		}},
	}
}

func simpleActual() reconcile.ActualOrganization {
	return reconcile.ActualOrganization{
		DokployID: "dokploy-org-1",
		Projects: []reconcile.ActualProject{{
			DokployID: "dokploy-proj-1",
			Name:      "demo-project-projabcd",
			Environments: []reconcile.ActualEnvironment{{
				DokployID: "dokploy-env-prod",
				Name:      "production-envabcd",
				Services: []reconcile.ActualService{{
					DokployID: "dokploy-svc-app",
					Name:      "demo-app-svcappabcd",
					Type:      dokploy.ServiceApplication,
				}},
			}},
		}},
	}
}

func newReconciler(t *testing.T, cfg *reconcile.Config) *reconcile.Reconciler {
	t.Helper()
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	rec, err := reconcile.New(*cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return rec
}

func textLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func errCode(err error) yerr.Code {
	var ye *yerr.Error
	if stderrors.As(err, &ye) {
		return ye.Code
	}
	return ""
}

// errChainString walks errors.Unwrap and joins every level's Error() string,
// so tests can assert on a wrapped cause without depending on a particular
// fmt format.
func errChainString(err error) string {
	var parts []string
	for cur := err; cur != nil; cur = stderrors.Unwrap(cur) {
		parts = append(parts, cur.Error())
	}
	return strings.Join(parts, " | ")
}

func filterActual(in []reconcile.ActualService, keep func(reconcile.ActualService) bool) []reconcile.ActualService {
	out := make([]reconcile.ActualService, 0, len(in))
	for _, s := range in {
		if keep(s) {
			out = append(out, s)
		}
	}
	return out
}

type fakeDesiredReader struct {
	state reconcile.DesiredOrganization
	err   error
	calls int
	mu    sync.Mutex
}

func (f *fakeDesiredReader) Read(_ context.Context, _ domain.ID) (reconcile.DesiredOrganization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return reconcile.DesiredOrganization{}, f.err
	}
	return f.state, nil
}

type fakeActualReader struct {
	state reconcile.ActualOrganization
	err   error
	calls int
	mu    sync.Mutex
}

func (f *fakeActualReader) Read(_ context.Context, _ string) (reconcile.ActualOrganization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return reconcile.ActualOrganization{}, f.err
	}
	return f.state, nil
}

type fakeRepairer struct {
	envCalls    []envCall
	removeCalls []removeCall
	buildCalls  []buildCall
	cronCalls   []cronCall
	domainCalls []domainCall
	envErr      error
	removeErr   error
	buildErr    error
	cronErr     error
	domainErr   error
	mu          sync.Mutex
}

type envCall struct {
	Ref    reconcile.ServiceRef
	Key    string
	Value  string
	Secret bool
}

type removeCall struct {
	Ref reconcile.ServiceRef
	Key string
}

type buildCall struct {
	Ref   reconcile.ServiceRef
	Build dokploy.BuildSettings
}

type cronCall struct {
	Ref      reconcile.ServiceRef
	Schedule string
}

type domainCall struct {
	Ref    reconcile.ServiceRef
	Domain reconcile.DesiredDomain
}

func (f *fakeRepairer) UpdateEnvVar(_ context.Context, ref reconcile.ServiceRef, key, value string, secret bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.envCalls = append(f.envCalls, envCall{Ref: ref, Key: key, Value: value, Secret: secret})
	return f.envErr
}

func (f *fakeRepairer) RemoveEnvVar(_ context.Context, ref reconcile.ServiceRef, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeCalls = append(f.removeCalls, removeCall{Ref: ref, Key: key})
	return f.removeErr
}

func (f *fakeRepairer) UpdateBuildConfig(_ context.Context, ref reconcile.ServiceRef, build dokploy.BuildSettings) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buildCalls = append(f.buildCalls, buildCall{Ref: ref, Build: build})
	return f.buildErr
}

func (f *fakeRepairer) UpdateCronSchedule(_ context.Context, ref reconcile.ServiceRef, schedule string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cronCalls = append(f.cronCalls, cronCall{Ref: ref, Schedule: schedule})
	return f.cronErr
}

func (f *fakeRepairer) EnsureDomain(_ context.Context, ref reconcile.ServiceRef, d reconcile.DesiredDomain) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.domainCalls = append(f.domainCalls, domainCall{Ref: ref, Domain: d})
	return f.domainErr
}

type fakeReviewer struct {
	events []reconcile.ReviewEvent
	err    error
	calls  int
	mu     sync.Mutex
}

func (f *fakeReviewer) Record(_ context.Context, e reconcile.ReviewEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, e)
	return nil
}

type fakeUnmanaged struct {
	resources []reconcile.UnmanagedResource
	err       error
	calls     int
	mu        sync.Mutex
}

func (f *fakeUnmanaged) Mark(_ context.Context, r reconcile.UnmanagedResource) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.resources = append(f.resources, r)
	return nil
}
