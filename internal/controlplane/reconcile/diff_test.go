package reconcile_test

import (
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/reconcile"
)

// TestDiff_NoDrift asserts the planner returns an empty plan when desired and
// actual fully agree. It also asserts the empty plan reports IsEmpty() and
// that every partition view returns nil/empty.
func TestDiff_NoDrift(t *testing.T) {
	t.Parallel()
	desired, actual := matchedStateBuilder(t).build()
	plan := reconcile.Diff(desired, actual)
	if !plan.IsEmpty() {
		t.Fatalf("expected empty plan; got %+v", plan.Actions)
	}
	if got := plan.SafeActions(); len(got) != 0 {
		t.Errorf("SafeActions = %+v; want []", got)
	}
	if got := plan.DangerousActions(); len(got) != 0 {
		t.Errorf("DangerousActions = %+v; want []", got)
	}
	if got := plan.UnmanagedActions(); len(got) != 0 {
		t.Errorf("UnmanagedActions = %+v; want []", got)
	}
}

// TestDiff_DeletedApp covers the "deleted app" acceptance case: a managed
// application service exists in desired with a Dokploy ID, but Dokploy has
// removed it. Classification must be DriftDangerous with reason
// service_missing, not a safe ensure.
func TestDiff_DeletedApp(t *testing.T) {
	t.Parallel()
	b := matchedStateBuilder(t)
	// Remove the application from the actual state.
	b.actual.Projects[0].Environments[0].Services = filterServices(
		b.actual.Projects[0].Environments[0].Services, func(s reconcile.ActualService) bool {
			return s.DokployID != "dokploy-svc-app"
		},
	)
	desired, actual := b.build()
	plan := reconcile.Diff(desired, actual)
	if len(plan.Actions) != 1 {
		t.Fatalf("expected exactly one action, got %d: %+v", len(plan.Actions), plan.Actions)
	}
	got := plan.Actions[0]
	if got.Kind != reconcile.DriftDangerous {
		t.Errorf("Kind = %q; want %q", got.Kind, reconcile.DriftDangerous)
	}
	if got.Reason != reconcile.ReasonServiceMissing {
		t.Errorf("Reason = %q; want %q", got.Reason, reconcile.ReasonServiceMissing)
	}
	if got.Type != reconcile.ActionReviewMissingService {
		t.Errorf("Type = %q; want %q", got.Type, reconcile.ActionReviewMissingService)
	}
	if got.Service.DokployServiceID != "dokploy-svc-app" {
		t.Errorf("Service.DokployServiceID = %q; want %q", got.Service.DokployServiceID, "dokploy-svc-app")
	}
	if got.DesiredService == nil || got.DesiredService.Type != dokploy.ServiceApplication {
		t.Errorf("DesiredService not preserved: %+v", got.DesiredService)
	}
}

// TestDiff_MissingDatabase covers the "missing database" acceptance case: a
// managed database service exists in desired but is missing from Dokploy.
// Classification must be DriftDangerous with reason database_missing — a
// distinct reason from a missing application so review queues can route by
// blast radius.
func TestDiff_MissingDatabase(t *testing.T) {
	t.Parallel()
	b := matchedStateBuilder(t)
	b.actual.Projects[0].Environments[0].Services = filterServices(
		b.actual.Projects[0].Environments[0].Services, func(s reconcile.ActualService) bool {
			return s.DokployID != "dokploy-svc-db"
		},
	)
	desired, actual := b.build()
	plan := reconcile.Diff(desired, actual)
	if len(plan.Actions) != 1 {
		t.Fatalf("expected exactly one action, got %d: %+v", len(plan.Actions), plan.Actions)
	}
	got := plan.Actions[0]
	if got.Kind != reconcile.DriftDangerous {
		t.Errorf("Kind = %q; want %q", got.Kind, reconcile.DriftDangerous)
	}
	if got.Reason != reconcile.ReasonDatabaseMissing {
		t.Errorf("Reason = %q; want %q", got.Reason, reconcile.ReasonDatabaseMissing)
	}
	if got.Type != reconcile.ActionReviewMissingDatabase {
		t.Errorf("Type = %q; want %q", got.Type, reconcile.ActionReviewMissingDatabase)
	}
}

// TestDiff_RenamedDomain covers the "renamed domain" acceptance case: a
// desired domain whose Dokploy ID matches an actual domain, but the hosts no
// longer agree. Classification must be DriftDangerous with reason
// domain_renamed and a populated DomainRef.
func TestDiff_RenamedDomain(t *testing.T) {
	t.Parallel()
	b := matchedStateBuilder(t)
	// Rename the actual domain attached to dokploy-svc-app.
	svc := &b.actual.Projects[0].Environments[0].Services[0]
	svc.Domains[0].Host = "evil.example.com"
	desired, actual := b.build()
	plan := reconcile.Diff(desired, actual)
	if len(plan.Actions) != 1 {
		t.Fatalf("expected exactly one action, got %d: %+v", len(plan.Actions), plan.Actions)
	}
	got := plan.Actions[0]
	if got.Kind != reconcile.DriftDangerous {
		t.Errorf("Kind = %q; want %q", got.Kind, reconcile.DriftDangerous)
	}
	if got.Reason != reconcile.ReasonDomainRenamed {
		t.Errorf("Reason = %q; want %q", got.Reason, reconcile.ReasonDomainRenamed)
	}
	if got.Type != reconcile.ActionReviewRenamedDomain {
		t.Errorf("Type = %q; want %q", got.Type, reconcile.ActionReviewRenamedDomain)
	}
	if got.Domain.DokployDomainID != "dokploy-dom-1" {
		t.Errorf("Domain.DokployDomainID = %q; want %q", got.Domain.DokployDomainID, "dokploy-dom-1")
	}
	// The planner must not surface the rogue host in the action — host names
	// can be sensitive (preview-app subdomains carrying tenant labels), and
	// they reach the audit/review record through DomainRef.DomainID only.
	if got.DesiredDomain != nil && strings.Contains(got.DesiredDomain.Host, "evil") {
		t.Errorf("DesiredDomain leaked actual host: %+v", got.DesiredDomain)
	}
}

// TestDiff_ChangedEnvVar covers the "changed env var" acceptance case: a
// desired env var whose value differs from the actual value on Dokploy.
// Classification must be DriftSafe with reason env_var_changed; the Reason
// must never contain the value itself.
func TestDiff_ChangedEnvVar(t *testing.T) {
	t.Parallel()
	b := matchedStateBuilder(t)
	const secretValue = "sk_live_super_secret_value_do_not_leak"
	const otherSecretValue = "old_super_secret_value_also_sensitive"
	// Make desired carry the new value (secret); actual carries the old one.
	b.desired.Projects[0].Environments[0].Services[0].EnvVars = []reconcile.DesiredEnvVar{
		{Key: "DATABASE_URL", Value: secretValue, Secret: true},
	}
	b.actual.Projects[0].Environments[0].Services[0].EnvVars = []reconcile.ActualEnvVar{
		{Key: "DATABASE_URL", Value: otherSecretValue},
	}
	desired, actual := b.build()
	plan := reconcile.Diff(desired, actual)
	if len(plan.Actions) != 1 {
		t.Fatalf("expected exactly one action, got %d: %+v", len(plan.Actions), plan.Actions)
	}
	got := plan.Actions[0]
	if got.Kind != reconcile.DriftSafe {
		t.Errorf("Kind = %q; want %q", got.Kind, reconcile.DriftSafe)
	}
	if got.Reason != reconcile.ReasonEnvVarChanged {
		t.Errorf("Reason = %q; want %q", got.Reason, reconcile.ReasonEnvVarChanged)
	}
	if got.Type != reconcile.ActionUpdateEnvVar {
		t.Errorf("Type = %q; want %q", got.Type, reconcile.ActionUpdateEnvVar)
	}
	if got.EnvVarKey != "DATABASE_URL" {
		t.Errorf("EnvVarKey = %q; want %q", got.EnvVarKey, "DATABASE_URL")
	}
	if !got.DesiredSecret {
		t.Error("DesiredSecret must be true for a secret env var")
	}
	// The Reason and value-free fields must never carry the value.
	if strings.Contains(string(got.Reason), secretValue) ||
		strings.Contains(string(got.Reason), otherSecretValue) ||
		strings.Contains(got.EnvVarKey, secretValue) {
		t.Errorf("planner leaked an env-var value into a classification field: %+v", got)
	}
}

// TestDiff_UnmanagedResource covers the "unmanaged resource" acceptance case:
// a Dokploy service with no Yalla counterpart. Classification must be
// DriftUnmanaged with reason resource_unmanaged. The Unmanaged payload must
// locate it inside the hierarchy without exposing it on a customer-facing
// endpoint.
func TestDiff_UnmanagedResource(t *testing.T) {
	t.Parallel()
	b := matchedStateBuilder(t)
	b.actual.Projects[0].Environments[0].Services = append(
		b.actual.Projects[0].Environments[0].Services,
		reconcile.ActualService{
			DokployID: "dokploy-svc-rogue",
			Name:      "rogue",
			Type:      dokploy.ServiceApplication,
		},
	)
	desired, actual := b.build()
	plan := reconcile.Diff(desired, actual)
	if len(plan.Actions) != 1 {
		t.Fatalf("expected exactly one action, got %d: %+v", len(plan.Actions), plan.Actions)
	}
	got := plan.Actions[0]
	if got.Kind != reconcile.DriftUnmanaged {
		t.Errorf("Kind = %q; want %q", got.Kind, reconcile.DriftUnmanaged)
	}
	if got.Type != reconcile.ActionMarkUnmanaged {
		t.Errorf("Type = %q; want %q", got.Type, reconcile.ActionMarkUnmanaged)
	}
	if got.Reason != reconcile.ReasonResourceUnmanaged {
		t.Errorf("Reason = %q; want %q", got.Reason, reconcile.ReasonResourceUnmanaged)
	}
	if got.Unmanaged == nil {
		t.Fatalf("Unmanaged payload missing: %+v", got)
	}
	if got.Unmanaged.Level != reconcile.LevelService {
		t.Errorf("Unmanaged.Level = %q; want %q", got.Unmanaged.Level, reconcile.LevelService)
	}
	if got.Unmanaged.DokployResourceID != "dokploy-svc-rogue" {
		t.Errorf("Unmanaged.DokployResourceID = %q; want %q", got.Unmanaged.DokployResourceID, "dokploy-svc-rogue")
	}
	if got.Unmanaged.ParentDokployID != "dokploy-env-prod" {
		t.Errorf("Unmanaged.ParentDokployID = %q; want %q", got.Unmanaged.ParentDokployID, "dokploy-env-prod")
	}
}

// TestDiff_MissingEnvVarIsSafeEnsure asserts a desired env var with no actual
// counterpart is treated as safe drift (ensure), and the planner carries the
// desired value through DesiredValue only.
func TestDiff_MissingEnvVarIsSafeEnsure(t *testing.T) {
	t.Parallel()
	b := matchedStateBuilder(t)
	b.desired.Projects[0].Environments[0].Services[0].EnvVars = []reconcile.DesiredEnvVar{
		{Key: "FEATURE_FLAG", Value: "enabled", Secret: false},
	}
	b.actual.Projects[0].Environments[0].Services[0].EnvVars = nil
	desired, actual := b.build()
	plan := reconcile.Diff(desired, actual)
	if len(plan.Actions) != 1 {
		t.Fatalf("expected exactly one action: %+v", plan.Actions)
	}
	got := plan.Actions[0]
	if got.Kind != reconcile.DriftSafe || got.Reason != reconcile.ReasonEnvVarMissing {
		t.Errorf("classification = %q/%q; want safe/env_var_missing", got.Kind, got.Reason)
	}
	if got.DesiredValue != "enabled" {
		t.Errorf("DesiredValue = %q; want %q", got.DesiredValue, "enabled")
	}
}

// TestDiff_ExtraEnvVarIsSafeRemoval asserts an env var on Dokploy with no
// desired counterpart yields a safe RemoveExtraEnvVar action (never logs the
// value; the planner never reads it).
func TestDiff_ExtraEnvVarIsSafeRemoval(t *testing.T) {
	t.Parallel()
	b := matchedStateBuilder(t)
	const leakedValue = "rogue_token_value_should_never_appear_in_classification"
	b.desired.Projects[0].Environments[0].Services[0].EnvVars = nil
	b.actual.Projects[0].Environments[0].Services[0].EnvVars = []reconcile.ActualEnvVar{
		{Key: "ROGUE_VAR", Value: leakedValue},
	}
	desired, actual := b.build()
	plan := reconcile.Diff(desired, actual)
	if len(plan.Actions) != 1 {
		t.Fatalf("expected exactly one action: %+v", plan.Actions)
	}
	got := plan.Actions[0]
	if got.Type != reconcile.ActionRemoveExtraEnvVar {
		t.Errorf("Type = %q; want %q", got.Type, reconcile.ActionRemoveExtraEnvVar)
	}
	if got.Reason != reconcile.ReasonEnvVarExtra {
		t.Errorf("Reason = %q; want %q", got.Reason, reconcile.ReasonEnvVarExtra)
	}
	// The planner must not have routed the actual value into the action.
	if got.DesiredValue != "" {
		t.Errorf("DesiredValue must be empty for a removal; got %q", got.DesiredValue)
	}
	if strings.Contains(got.EnvVarKey, leakedValue) {
		t.Errorf("planner leaked an actual value into EnvVarKey: %q", got.EnvVarKey)
	}
}

// TestDiff_ServiceTypeChange asserts a service whose type has changed on
// Dokploy is dangerous drift.
func TestDiff_ServiceTypeChange(t *testing.T) {
	t.Parallel()
	b := matchedStateBuilder(t)
	b.actual.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceCompose
	desired, actual := b.build()
	plan := reconcile.Diff(desired, actual)
	if len(plan.Actions) == 0 {
		t.Fatalf("expected at least one action")
	}
	var found bool
	for _, a := range plan.Actions {
		if a.Type == reconcile.ActionReviewServiceTypeChange {
			found = true
			if a.Kind != reconcile.DriftDangerous {
				t.Errorf("Kind = %q; want %q", a.Kind, reconcile.DriftDangerous)
			}
			if a.Reason != reconcile.ReasonServiceTypeChanged {
				t.Errorf("Reason = %q; want %q", a.Reason, reconcile.ReasonServiceTypeChanged)
			}
		}
	}
	if !found {
		t.Errorf("expected ActionReviewServiceTypeChange; got %+v", plan.Actions)
	}
}

// TestDiff_UnprovisionedDesiredIsIgnored asserts the planner does NOT emit
// drift for a desired service whose DokployID is empty: the service is
// pending provisioning, not drifted.
func TestDiff_UnprovisionedDesiredIsIgnored(t *testing.T) {
	t.Parallel()
	b := matchedStateBuilder(t)
	b.desired.Projects[0].Environments[0].Services = append(
		b.desired.Projects[0].Environments[0].Services,
		reconcile.DesiredService{
			ID:    domain.MustNewID(domain.KindService),
			Label: "pending-svc",
			Type:  dokploy.ServiceApplication,
			// No DokployID — never provisioned.
		},
	)
	desired, actual := b.build()
	plan := reconcile.Diff(desired, actual)
	if !plan.IsEmpty() {
		t.Errorf("expected empty plan for un-provisioned desired service; got %+v", plan.Actions)
	}
}

// TestDiff_UnprovisionedOrganizationIsIgnoredViaEngine is tested in
// reconcile_test.go via the engine path; the pure Diff function operates on
// whatever the readers return, so an empty actual is just an
// every-managed-resource-missing case (covered by missing-app/db tests).

// TestDiff_ActionOrderingIsDeterministic asserts the planner returns actions
// in a stable order so tests can compare slices directly.
func TestDiff_ActionOrderingIsDeterministic(t *testing.T) {
	t.Parallel()
	b := matchedStateBuilder(t)
	// Introduce two unmanaged services in reverse insertion order to prove
	// stable sort.
	b.actual.Projects[0].Environments[0].Services = append(
		b.actual.Projects[0].Environments[0].Services,
		reconcile.ActualService{DokployID: "dokploy-svc-zzz", Name: "z", Type: dokploy.ServiceApplication},
		reconcile.ActualService{DokployID: "dokploy-svc-aaa", Name: "a", Type: dokploy.ServiceApplication},
	)
	desired, actual := b.build()
	plan := reconcile.Diff(desired, actual)
	if len(plan.Actions) < 2 {
		t.Fatalf("expected at least 2 unmanaged actions; got %+v", plan.Actions)
	}
	if plan.Actions[0].Unmanaged.DokployResourceID >= plan.Actions[1].Unmanaged.DokployResourceID {
		t.Errorf("actions not in deterministic order: %+v then %+v",
			plan.Actions[0].Unmanaged, plan.Actions[1].Unmanaged)
	}
}

// TestDriftKind_Valid asserts the closed enum guards.
func TestDriftKind_Valid(t *testing.T) {
	t.Parallel()
	for _, k := range []reconcile.DriftKind{
		reconcile.DriftSafe, reconcile.DriftDangerous, reconcile.DriftUnmanaged,
	} {
		if !k.Valid() {
			t.Errorf("DriftKind(%q).Valid() = false; want true", k)
		}
	}
	if reconcile.DriftKind("bogus").Valid() {
		t.Errorf("DriftKind(%q).Valid() = true; want false", "bogus")
	}
}

// ----------------------------------------------------------------------------
// Helpers.
// ----------------------------------------------------------------------------

// stateBuilder is a fixture builder: a baseline that desired and actual fully
// agree on, modified by individual tests to introduce exactly one drift.
type stateBuilder struct {
	t       *testing.T
	desired reconcile.DesiredOrganization
	actual  reconcile.ActualOrganization
}

func matchedStateBuilder(t *testing.T) *stateBuilder {
	t.Helper()
	orgID := domain.MustNewID(domain.KindOrganization)
	projID := domain.MustNewID(domain.KindProject)
	envID := domain.MustNewID(domain.KindEnvironment)
	appID := domain.MustNewID(domain.KindService)
	dbID := domain.MustNewID(domain.KindService)
	// Yalla does not yet have a domain Kind; use a service ID for the
	// domain's source-of-truth ID slot. The engine only inspects this for
	// non-emptiness.
	domainYallaID := domain.MustNewID(domain.KindService)
	desired := reconcile.DesiredOrganization{
		ID:        orgID,
		Label:     "Demo Org",
		DokployID: "dokploy-org-1",
		Projects: []reconcile.DesiredProject{{
			ID:        projID,
			Label:     "Demo Project",
			DokployID: "dokploy-proj-1",
			Environments: []reconcile.DesiredEnvironment{{
				ID:        envID,
				Label:     "production",
				DokployID: "dokploy-env-prod",
				Services: []reconcile.DesiredService{
					{
						ID:        appID,
						Label:     "demo-app",
						Type:      dokploy.ServiceApplication,
						DokployID: "dokploy-svc-app",
						EnvVars:   nil,
						Domains: []reconcile.DesiredDomain{{
							ID:        domainYallaID,
							Host:      "demo.example.com",
							HTTPS:     true,
							DokployID: "dokploy-dom-1",
						}},
					},
					{
						ID:        dbID,
						Label:     "demo-db",
						Type:      dokploy.ServiceDatabase,
						Engine:    "postgres",
						DokployID: "dokploy-svc-db",
					},
				},
			}},
		}},
	}
	actual := reconcile.ActualOrganization{
		DokployID: "dokploy-org-1",
		Projects: []reconcile.ActualProject{{
			DokployID: "dokploy-proj-1",
			Name:      "demo-project-projabcd",
			Environments: []reconcile.ActualEnvironment{{
				DokployID: "dokploy-env-prod",
				Name:      "production-envabcd",
				Services: []reconcile.ActualService{
					{
						DokployID: "dokploy-svc-app",
						Name:      "demo-app-svcappabcd",
						Type:      dokploy.ServiceApplication,
						Domains: []reconcile.ActualDomain{{
							DokployID: "dokploy-dom-1",
							Host:      "demo.example.com",
							HTTPS:     true,
						}},
					},
					{
						DokployID: "dokploy-svc-db",
						Name:      "demo-db-svcdbabcd",
						Type:      dokploy.ServiceDatabase,
						Engine:    "postgres",
					},
				},
			}},
		}},
	}
	return &stateBuilder{t: t, desired: desired, actual: actual}
}

func (b *stateBuilder) build() (reconcile.DesiredOrganization, reconcile.ActualOrganization) {
	b.t.Helper()
	return b.desired, b.actual
}

func filterServices(in []reconcile.ActualService, keep func(reconcile.ActualService) bool) []reconcile.ActualService {
	out := make([]reconcile.ActualService, 0, len(in))
	for _, s := range in {
		if keep(s) {
			out = append(out, s)
		}
	}
	return out
}
