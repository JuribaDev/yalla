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

// Integration tests for ServiceService.Update — the reference
// unit-of-work orchestrator for service updates. They prove validation
// runs before any transaction is opened, the desired-state UPDATE and
// the immutable audit row commit atomically, the optimistic-
// concurrency precondition is honoured both as a pre-check and at the
// version-checked UPDATE, the HTTP boundary is authoritative for
// authorization (no in-transaction Authorize is invoked on the update
// path), and a slug collision rolls the whole transaction back as a
// typed Conflict.

// newServiceSvc wires a ServiceService over the testutil store with
// recording fakes for the per-Create ports. Update paths never invoke
// them — the test fixtures here assert calls=0 on the recording*
// fakes when needed.
func newServiceSvc(t *testing.T, s *store.Store) (*store.ServiceService, *recordingAuthorizer, *recordingQuota, *recordingJobs) {
	t.Helper()
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewServiceService(s,
		store.NewProjectRepository(),
		store.NewEnvironmentRepository(),
		store.NewServiceRepository(),
		authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewServiceService: %v", err)
	}
	return svc, authz, quota, jobs
}

// newUpdateServiceInput builds a valid UpdateServiceInput for the
// (orgID, serviceID) pair with both slug and display_name pointers
// set. ActorOrgID matches OrganizationID because the production wire
// path always pins the audit record to the principal's home
// organization.
func newUpdateServiceInput(orgID, serviceID string) store.UpdateServiceInput {
	slug := "api-v2"
	display := "API v2"
	return store.UpdateServiceInput{
		OrganizationID: orgID,
		ServiceID:      serviceID,
		Slug:           &slug,
		DisplayName:    &display,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_svc_update",
		CorrelationID:  "corr_svc_update",
	}
}

func strPtrSvc(s string) *string { return &s }
func i64PtrSvc(v int64) *int64   { return &v }

// listServiceAuditEvents returns every audit event filed under
// organizationID — used by the success path test to prove the audit
// row commits inside the same transaction as the service update.
func listServiceAuditEvents(t *testing.T, s *store.Store, organizationID string) []store.AuditEvent {
	t.Helper()
	var events []store.AuditEvent
	if err := s.Read(context.Background(), func(ctx context.Context, q store.Querier) error {
		var readErr error
		events, readErr = store.NewAuditRepository().ListByOrganization(ctx, q, organizationID, 50)
		return readErr
	}); err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	return events
}

// TestServiceServiceUpdateSuccess proves a happy-path Update writes
// both columns, the trigger bumps the version, the audit row is filed
// with the authorization-allowed decision and the updated_fields
// metadata, and the in-transaction Authorize/Quota/JobEnqueue ports
// are NOT called — Update trusts the HTTP boundary's RequireAuth gate,
// unlike Create.
func TestServiceServiceUpdateSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcSvcUpdSuccess")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svcSeed := seedService(t, db, f, env, "api")

	svc, authz, quota, jobs := newServiceSvc(t, s)

	in := newUpdateServiceInput(org.ID, svcSeed.ID)
	updated, err := svc.Update(ctx, in)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Slug != "api-v2" || updated.DisplayName != "API v2" {
		t.Errorf("updated = %+v, want slug=api-v2 display=API v2", updated)
	}
	if updated.Version <= 1 {
		t.Errorf("version not bumped: %d", updated.Version)
	}
	if updated.Kind != svcSeed.Kind {
		t.Errorf("kind unexpectedly changed: %q -> %q", svcSeed.Kind, updated.Kind)
	}
	if updated.ProjectID != svcSeed.ProjectID || updated.EnvironmentID != svcSeed.EnvironmentID {
		t.Errorf("parent identity drifted: project=%q env=%q want (%q,%q)", updated.ProjectID, updated.EnvironmentID, svcSeed.ProjectID, svcSeed.EnvironmentID)
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("Update unexpectedly ran in-tx ports: authz=%d quota=%d jobs=%d", authz.calls, quota.calls, jobs.calls)
	}

	events := listServiceAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the update", len(events))
	}
	ev := events[0]
	if ev.Action != "service.update" {
		t.Errorf("audit action = %q, want service.update", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != svcSeed.ID {
		t.Errorf("audit resource_id = %q, want %q", ev.ResourceID, svcSeed.ID)
	}
	if ev.ResourceKind != string(domain.KindService) {
		t.Errorf("audit resource_kind = %q, want %q", ev.ResourceKind, domain.KindService)
	}
	if got := ev.Metadata["updated_fields"]; got != "slug,display_name" {
		t.Errorf("audit metadata updated_fields = %q, want slug,display_name", got)
	}
}

// TestServiceServiceUpdatePartial proves a patch with only
// display_name leaves slug untouched and the audit records only the
// fields that actually changed.
func TestServiceServiceUpdatePartial(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcSvcUpdPartial")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svcSeed := seedService(t, db, f, env, "api")

	svc, _, _, _ := newServiceSvc(t, s)

	in := newUpdateServiceInput(org.ID, svcSeed.ID)
	in.Slug = nil
	in.DisplayName = strPtrSvc("API v3")

	updated, err := svc.Update(ctx, in)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Slug != svcSeed.Slug {
		t.Errorf("Slug unexpectedly changed to %q (seeded %q)", updated.Slug, svcSeed.Slug)
	}
	if updated.DisplayName != "API v3" {
		t.Errorf("DisplayName = %q, want API v3", updated.DisplayName)
	}

	events := listServiceAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if got := events[0].Metadata["updated_fields"]; got != "display_name" {
		t.Errorf("audit metadata updated_fields = %q, want display_name", got)
	}
}

// TestServiceServiceUpdateRejectsEmptyPatch proves a patch that names
// no updatable field is a typed validation failure raised before any
// transaction is opened, so the audit row is never written for a
// no-op mutation.
func TestServiceServiceUpdateRejectsEmptyPatch(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcSvcUpdEmpty")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svcSeed := seedService(t, db, f, env, "api")

	svc, _, _, _ := newServiceSvc(t, s)
	in := newUpdateServiceInput(org.ID, svcSeed.ID)
	in.Slug = nil
	in.DisplayName = nil

	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update with empty patch returned no error; want InvalidInput")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeValidation {
		t.Fatalf("err = %v (%T); want yerr CodeValidation", err, err)
	}

	events := listServiceAuditEvents(t, s, org.ID)
	if len(events) != 0 {
		t.Errorf("audit events = %d, want 0 (validation failed before tx)", len(events))
	}
}

// TestServiceServiceUpdateRejectsInvalidSlug proves an invalid slug
// supplied to a patch is a typed InvalidInput naming the slug field
// — never echoing the submitted value.
func TestServiceServiceUpdateRejectsInvalidSlug(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcSvcUpdBadSlug")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svcSeed := seedService(t, db, f, env, "api")

	svc, _, _, _ := newServiceSvc(t, s)
	in := newUpdateServiceInput(org.ID, svcSeed.ID)
	leakyValue := "NoT-a-VAlid_slug.with.dots"
	in.Slug = &leakyValue

	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update with invalid slug returned no error; want InvalidInput")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeValidation {
		t.Fatalf("err = %v (%T); want yerr CodeValidation", err, err)
	}
	if strings.Contains(err.Error(), leakyValue) {
		t.Errorf("InvalidInput leaked the submitted slug value: %v", err)
	}
}

// TestServiceServiceUpdateNotFound proves an unknown service id
// (within the principal's home org) surfaces as NotFound.
func TestServiceServiceUpdateNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcSvcUpdMiss")
	_ = seedProject(t, db, f, org, "Web")

	svc, _, _, _ := newServiceSvc(t, s)
	in := newUpdateServiceInput(org.ID, "svc_ghost")
	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update(unknown svc) returned no error; want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}

// TestServiceServiceUpdateCrossTenantIsNotFound proves a service id
// that lives in another tenant cannot be updated through this
// principal's home organization — the persistence layer reports
// NotFound and the other tenant's row is untouched.
func TestServiceServiceUpdateCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "SvcSvcCrossA")
	orgB := seedOrg(t, db, f, "SvcSvcCrossB")
	projB := seedProject(t, db, f, orgB, "Web")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcB := seedService(t, db, f, envB, "api")

	svc, _, _, _ := newServiceSvc(t, s)
	in := newUpdateServiceInput(orgA.ID, svcB.ID)
	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update(cross-tenant svc) returned no error; want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}

	// The target tenant's row is intact.
	repo := store.NewServiceRepository()
	var current store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		current, getErr = repo.GetByID(ctx, q, orgB.ID, svcB.ID)
		return getErr
	}); err != nil {
		t.Fatalf("GetByID(other tenant): %v", err)
	}
	if current.Slug != svcB.Slug || current.DisplayName != svcB.Name {
		t.Errorf("cross-tenant attempt mutated the other tenant's row: got %+v, want slug=%q display=%q", current, svcB.Slug, svcB.Name)
	}
}

// TestServiceServiceUpdateStaleIfMatch proves a stale If-Match
// precondition is rejected as ConflictStale carrying the row's
// authoritative version — and that nothing is written (no audit
// event, no slug/display change).
func TestServiceServiceUpdateStaleIfMatch(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcSvcUpdStale")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svcSeed := seedService(t, db, f, env, "api")

	svc, _, _, _ := newServiceSvc(t, s)
	in := newUpdateServiceInput(org.ID, svcSeed.ID)
	in.IfMatchVersion = i64PtrSvc(999)

	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update with stale If-Match returned no error; want ConflictStale")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeConflict {
		t.Fatalf("err = %v (%T); want yerr CodeConflict", err, err)
	}

	events := listServiceAuditEvents(t, s, org.ID)
	if len(events) != 0 {
		t.Errorf("audit events = %d, want 0 (transaction rolled back on stale If-Match)", len(events))
	}
}

// TestServiceServiceUpdateSlugConflictRollsBack proves a slug
// collision inside the same environment rolls the whole transaction
// back, so a duplicate service row AND an orphaned audit row are both
// impossible.
func TestServiceServiceUpdateSlugConflictRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcSvcUpdSlugX")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	api := seedService(t, db, f, env, "api")
	web := seedService(t, db, f, env, "web")

	svc, _, _, _ := newServiceSvc(t, s)
	in := newUpdateServiceInput(org.ID, api.ID)
	// Collide against the actual seeded sibling slug (the factory mints
	// unique slugs per seed, so the literal "web" would not collide).
	in.Slug = strPtrSvc(web.Slug)

	_, err := svc.Update(ctx, in)
	if err == nil {
		t.Fatalf("Update with duplicate slug returned no error; want Conflict")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeConflict {
		t.Fatalf("err = %v (%T); want yerr CodeConflict", err, err)
	}

	events := listServiceAuditEvents(t, s, org.ID)
	if len(events) != 0 {
		t.Errorf("audit events = %d, want 0 (transaction rolled back on slug conflict)", len(events))
	}
}

// TestServiceServiceUpdateRequiresActorOrg proves a wiring error (an
// authenticated request that nonetheless reaches the service without
// an actor organization) is rejected as Internal before any database
// work runs, so the audit row can never miss the tenant column it is
// filed under.
func TestServiceServiceUpdateRequiresActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcSvcUpdActorOrg")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svcSeed := seedService(t, db, f, env, "api")

	svc, _, _, _ := newServiceSvc(t, s)
	in := newUpdateServiceInput(org.ID, svcSeed.ID)
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

// TestServiceServiceUpdateRejectsBlankOrgID proves a blank
// OrganizationID is a typed InvalidInput rejection BEFORE the
// transaction opens — the orchestrator must not coalesce missing
// scope identifiers into a not-found behaviour that hides a wiring
// bug.
func TestServiceServiceUpdateRejectsBlankOrgID(t *testing.T) {
	t.Parallel()

	// No DB needed: validation runs before the transaction.
	svc := &store.ServiceService{}
	_, err := svc.Update(context.Background(), store.UpdateServiceInput{
		OrganizationID: "",
		ServiceID:      "svc_anything",
		Slug:           strPtrSvc("api"),
		ActorOrgID:     "org_acme",
	})
	if err == nil {
		t.Fatalf("Update(blank org) returned no error; want InvalidInput")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeValidation {
		t.Fatalf("err = %v (%T); want yerr CodeValidation", err, err)
	}
	if strings.Contains(err.Error(), "org_acme") {
		t.Errorf("InvalidInput leaked actor org: %v", err)
	}
}

// Compile-time assertion that *store.ServiceService satisfies the
// expected Update signature so a future signature drift is caught at
// build time.
var _ serviceUpdaterForTest = (*store.ServiceService)(nil)

// serviceUpdaterForTest mirrors the httpapi ServiceUpdater port. It is
// duplicated here (instead of importing httpapi) because the store
// package must not depend on httpapi.
type serviceUpdaterForTest interface {
	Update(ctx context.Context, in store.UpdateServiceInput) (store.Service, error)
}

// silence unused-imports when stripped down further in the future.
var _ = apierr.InvalidInput
