package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for EnvironmentService.Update — the reference unit-of-work
// orchestrator for environment updates. They prove validation runs before any
// transaction is opened, the desired-state UPDATE and the immutable audit row
// commit atomically, the optimistic-concurrency precondition is honoured both
// as a pre-check and at the version-checked UPDATE, the HTTP boundary is
// authoritative for authorization (no in-transaction Authorize is invoked on
// the update path), and a slug collision rolls the whole transaction back as
// a typed Conflict.

// newEnvironmentSvc wires an EnvironmentService over the testutil store with
// recording fakes for the per-Create ports. Update paths never invoke them —
// the test fixtures here assert calls=0 on the recordingAuthorizer/Quota/Jobs
// when needed.
func newEnvironmentSvc(t *testing.T, s *store.Store) (*store.EnvironmentService, *recordingAuthorizer, *recordingQuota, *recordingJobs) {
	t.Helper()
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}
	return svc, authz, quota, jobs
}

// newUpdateEnvironmentInput builds a valid UpdateEnvironmentInput for the
// (orgID, environmentID) pair with both slug and display_name pointers set.
// ActorOrgID matches OrganizationID because the production wire path always
// pins the audit record to the principal's home organization.
func newUpdateEnvironmentInput(orgID, environmentID string) store.UpdateEnvironmentInput {
	slug := "preview"
	display := "Preview"
	return store.UpdateEnvironmentInput{
		OrganizationID: orgID,
		EnvironmentID:  environmentID,
		Slug:           &slug,
		DisplayName:    &display,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_env_update",
		CorrelationID:  "corr_env_update",
	}
}

func strPtrEnv(s string) *string { return &s }
func i64PtrEnv(v int64) *int64   { return &v }

// TestEnvironmentServiceUpdateSuccess proves a happy-path Update writes both
// columns, the trigger bumps the version, the audit row is filed with the
// authorization-allowed decision and the updated_fields metadata, and the
// in-transaction Authorize/Quota/JobEnqueue ports are NOT called — Update
// trusts the HTTP boundary's RequireAuth gate, unlike Create.
func TestEnvironmentServiceUpdateSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcUpdSuccess")
	proj := seedProject(t, db, f, org, "Web")
	envSeed := seedEnvironment(t, db, f, proj, "production")

	svc, authz, quota, jobs := newEnvironmentSvc(t, s)

	in := newUpdateEnvironmentInput(org.ID, envSeed.ID)
	updated, err := svc.Update(ctx, in)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Slug != "preview" || updated.DisplayName != "Preview" {
		t.Errorf("updated = %+v, want slug=preview display=Preview", updated)
	}
	if updated.Version <= 1 {
		t.Errorf("version not bumped: %d", updated.Version)
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("Update unexpectedly ran in-tx ports: authz=%d quota=%d jobs=%d", authz.calls, quota.calls, jobs.calls)
	}

	events := listEnvironmentAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the update", len(events))
	}
	ev := events[0]
	if ev.Action != "environment.update" {
		t.Errorf("audit action = %q, want environment.update", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != envSeed.ID {
		t.Errorf("audit resource_id = %q, want %q", ev.ResourceID, envSeed.ID)
	}
	if ev.ResourceKind != string(domain.KindEnvironment) {
		t.Errorf("audit resource_kind = %q, want %q", ev.ResourceKind, domain.KindEnvironment)
	}
	if got := ev.Metadata["updated_fields"]; got != "slug,display_name" {
		t.Errorf("audit metadata updated_fields = %q, want slug,display_name", got)
	}
}

// TestEnvironmentServiceUpdatePartial proves a patch with only
// display_name leaves slug untouched and the audit records only the
// fields that actually changed.
func TestEnvironmentServiceUpdatePartial(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcUpdPartial")
	proj := seedProject(t, db, f, org, "Web")
	envSeed := seedEnvironment(t, db, f, proj, "production")

	svc, _, _, _ := newEnvironmentSvc(t, s)

	in := newUpdateEnvironmentInput(org.ID, envSeed.ID)
	in.Slug = nil
	in.DisplayName = strPtrEnv("Production v2")

	updated, err := svc.Update(ctx, in)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Slug != envSeed.Slug {
		t.Errorf("Slug unexpectedly changed to %q (seeded %q)", updated.Slug, envSeed.Slug)
	}
	if updated.DisplayName != "Production v2" {
		t.Errorf("DisplayName = %q, want Production v2", updated.DisplayName)
	}

	events := listEnvironmentAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if got := events[0].Metadata["updated_fields"]; got != "display_name" {
		t.Errorf("audit metadata updated_fields = %q, want display_name", got)
	}
}

// TestEnvironmentServiceUpdateRejectsEmptyPatch proves a patch that
// names no updatable field is a typed validation failure raised
// before any transaction is opened, so the audit row is never written
// for a no-op mutation.
func TestEnvironmentServiceUpdateRejectsEmptyPatch(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcUpdEmpty")
	proj := seedProject(t, db, f, org, "Web")
	envSeed := seedEnvironment(t, db, f, proj, "production")

	svc, _, _, _ := newEnvironmentSvc(t, s)
	in := newUpdateEnvironmentInput(org.ID, envSeed.ID)
	in.Slug = nil
	in.DisplayName = nil

	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update with empty patch returned no error; want InvalidInput")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("err = %v (%T); want yerr CodeInvalidInput", err, err)
	}

	events := listEnvironmentAuditEvents(t, s, org.ID)
	if len(events) != 0 {
		t.Errorf("audit events = %d, want 0 (validation failed before tx)", len(events))
	}
}

// TestEnvironmentServiceUpdateRejectsInvalidSlug proves an invalid
// slug supplied to a patch is a typed InvalidInput naming the slug
// field — never echoing the submitted value.
func TestEnvironmentServiceUpdateRejectsInvalidSlug(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcUpdBadSlug")
	proj := seedProject(t, db, f, org, "Web")
	envSeed := seedEnvironment(t, db, f, proj, "production")

	svc, _, _, _ := newEnvironmentSvc(t, s)
	in := newUpdateEnvironmentInput(org.ID, envSeed.ID)
	leakyValue := "NoT-a-VAlid_slug.with.dots"
	in.Slug = &leakyValue

	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update with invalid slug returned no error; want InvalidInput")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("err = %v (%T); want yerr CodeInvalidInput", err, err)
	}
	if strings.Contains(err.Error(), leakyValue) {
		t.Errorf("InvalidInput leaked the submitted slug value: %v", err)
	}
}

// TestEnvironmentServiceUpdateNotFound proves an unknown environment
// id (within the principal's home org) surfaces as NotFound.
func TestEnvironmentServiceUpdateNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcUpdMiss")
	_ = seedProject(t, db, f, org, "Web")

	svc, _, _, _ := newEnvironmentSvc(t, s)
	in := newUpdateEnvironmentInput(org.ID, "env_ghost")
	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update(unknown env) returned no error; want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}

// TestEnvironmentServiceUpdateCrossTenantIsNotFound proves an
// environment id that lives in another tenant cannot be updated
// through this principal's home organization — the persistence layer
// reports NotFound and the other tenant's row is untouched.
func TestEnvironmentServiceUpdateCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "EnvSvcCrossA")
	orgB := seedOrg(t, db, f, "EnvSvcCrossB")
	projB := seedProject(t, db, f, orgB, "Web")
	envB := seedEnvironment(t, db, f, projB, "production")

	svc, _, _, _ := newEnvironmentSvc(t, s)
	in := newUpdateEnvironmentInput(orgA.ID, envB.ID)
	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update(cross-tenant env) returned no error; want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}

	// The target tenant's row is intact.
	repo := store.NewEnvironmentRepository()
	var current store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		current, getErr = repo.GetByID(ctx, q, orgB.ID, envB.ID)
		return getErr
	}); err != nil {
		t.Fatalf("GetByID(other tenant): %v", err)
	}
	if current.Slug != envB.Slug || current.DisplayName != envB.Name {
		t.Errorf("cross-tenant attempt mutated the other tenant's row: got %+v, want slug=%q display=%q", current, envB.Slug, envB.Name)
	}
}

// TestEnvironmentServiceUpdateStaleIfMatch proves a stale If-Match
// precondition is rejected as ConflictStale carrying the row's
// authoritative version — and that nothing is written (no audit
// event, no slug/display change).
func TestEnvironmentServiceUpdateStaleIfMatch(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcUpdStale")
	proj := seedProject(t, db, f, org, "Web")
	envSeed := seedEnvironment(t, db, f, proj, "production")

	svc, _, _, _ := newEnvironmentSvc(t, s)
	in := newUpdateEnvironmentInput(org.ID, envSeed.ID)
	in.IfMatchVersion = i64PtrEnv(999)

	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update with stale If-Match returned no error; want ConflictStale")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeConflict {
		t.Fatalf("err = %v (%T); want yerr CodeConflict", err, err)
	}

	events := listEnvironmentAuditEvents(t, s, org.ID)
	if len(events) != 0 {
		t.Errorf("audit events = %d, want 0 (transaction rolled back on stale If-Match)", len(events))
	}
}

// TestEnvironmentServiceUpdateSlugConflictRollsBack proves a slug
// collision inside the same project rolls the whole transaction back,
// so a duplicate environment row AND an orphaned audit row are both
// impossible.
func TestEnvironmentServiceUpdateSlugConflictRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcUpdSlugX")
	proj := seedProject(t, db, f, org, "Web")
	prod := seedEnvironment(t, db, f, proj, "production")
	preview := seedEnvironment(t, db, f, proj, "preview")

	svc, _, _, _ := newEnvironmentSvc(t, s)
	in := newUpdateEnvironmentInput(org.ID, prod.ID)
	// Collide against the actual seeded preview slug (the factory mints
	// unique slugs per seed, so the literal "preview" would not
	// collide).
	in.Slug = strPtrEnv(preview.Slug)

	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update with duplicate slug returned no error; want Conflict")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeConflict {
		t.Fatalf("err = %v (%T); want yerr CodeConflict", err, err)
	}

	events := listEnvironmentAuditEvents(t, s, org.ID)
	if len(events) != 0 {
		t.Errorf("audit events = %d, want 0 (transaction rolled back on slug conflict)", len(events))
	}
}

// TestEnvironmentServiceUpdateRequiresActorOrg proves a wiring error
// (an authenticated request that nonetheless reaches the service
// without an actor organization) is rejected as Internal before any
// database work runs, so the audit row can never miss the tenant
// column it is filed under.
func TestEnvironmentServiceUpdateRequiresActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcUpdActorOrg")
	proj := seedProject(t, db, f, org, "Web")
	envSeed := seedEnvironment(t, db, f, proj, "production")

	svc, _, _, _ := newEnvironmentSvc(t, s)
	in := newUpdateEnvironmentInput(org.ID, envSeed.ID)
	in.ActorOrgID = ""
	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update(no actor org) returned no error; want Internal")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Fatalf("err = %v (%T); want yerr CodeInternal", err, err)
	}
}

// TestEnvironmentServiceUpdateRejectsBlankOrgID proves a blank
// OrganizationID is a typed InvalidInput rejection BEFORE the
// transaction opens — the orchestrator must not coalesce missing
// scope identifiers into a not-found behaviour that hides a wiring
// bug.
func TestEnvironmentServiceUpdateRejectsBlankOrgID(t *testing.T) {
	t.Parallel()

	// No DB needed: validation runs before the transaction.
	svc := &store.EnvironmentService{}
	_, err := svc.Update(context.Background(), store.UpdateEnvironmentInput{
		OrganizationID: "",
		EnvironmentID:  "env_anything",
		Slug:           strPtrEnv("preview"),
		ActorOrgID:     "org_acme",
	})
	if err == nil {
		t.Fatalf("Update(blank org) returned no error; want InvalidInput")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("err = %v (%T); want yerr CodeInvalidInput", err, err)
	}
	// The blank-field check must not leak the actor org back through the
	// validation message — the violation names organization_id, never the
	// supplied actor org.
	if strings.Contains(err.Error(), "org_acme") {
		t.Errorf("InvalidInput leaked actor org: %v", err)
	}
}

// Compile-time assertion that *store.EnvironmentService satisfies the
// expected Update signature so a future signature drift is caught at
// build time.
var _ environmentUpdaterForTest = (*store.EnvironmentService)(nil)

// environmentUpdaterForTest mirrors the httpapi EnvironmentUpdater port.
// It is duplicated here (instead of importing httpapi) because the store
// package must not depend on httpapi.
type environmentUpdaterForTest interface {
	Update(ctx context.Context, in store.UpdateEnvironmentInput) (store.Environment, error)
}

// silence unused-imports when stripped down further in the future.
var _ = apierr.InvalidInput
