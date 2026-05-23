package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for the service account model — ServiceAccountRepository,
// ServiceAccountService, and the api_keys ownership link. They prove a service
// account belongs to exactly one organization, that tenant-scoped reads and
// mutations cannot cross the tenant boundary, that a service account owns API
// keys with project/environment/action scopes, and that a service-account key
// can never be attached to a service account in another organization. They run
// against an isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset.

// seedServiceAccount inserts a service_accounts row owned by org and returns
// the fixture. It uses a direct INSERT (not the service) so repository-level
// tests can seed without exercising the unit-of-work orchestration.
func seedServiceAccount(t *testing.T, db *testutil.DB, f *testutil.Factory, org testutil.Organization, label string) testutil.ServiceAccount {
	t.Helper()
	sa := f.ServiceAccount(org, label)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO service_accounts (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		sa.ID, sa.OrganizationID, sa.Slug, sa.Name); err != nil {
		t.Fatalf("seed service account: %v", err)
	}
	return sa
}

// insertServiceAccount persists sa through Store.Write and returns the stored
// row.
func insertServiceAccount(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceAccountRepository, sa store.ServiceAccount) store.ServiceAccount {
	t.Helper()
	var stored store.ServiceAccount
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Insert(ctx, tx, sa)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("insert service account: %v", err)
	}
	return stored
}

// newServiceAccountAPIKey builds a persistence-shaped APIKey owned by the given
// service account, from a freshly generated credential.
func newServiceAccountAPIKey(t *testing.T, f *testutil.Factory, orgID, serviceAccountID string, scopes []string) store.APIKey {
	t.Helper()
	gen, err := auth.Generate()
	if err != nil {
		t.Fatalf("auth.Generate: %v", err)
	}
	keyID := f.APIKey(testutil.Organization{ID: orgID}, testutil.User{}, "ci").ID
	return store.APIKey{
		ID:               keyID,
		OrganizationID:   orgID,
		Prefix:           gen.Prefix,
		SecretHash:       gen.SecretHash,
		Name:             "CI deploy key",
		Scopes:           scopes,
		ServiceAccountID: serviceAccountID,
	}
}

func TestServiceAccountRepositoryInsertAndGet(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	want := f.ServiceAccount(org, "CI Deployer")
	stored := insertServiceAccount(ctx, t, s, repo, store.ServiceAccount{
		ID:             want.ID,
		OrganizationID: want.OrganizationID,
		Slug:           want.Slug,
		DisplayName:    want.Name,
	})
	if stored.ID != want.ID || stored.OrganizationID != org.ID {
		t.Fatalf("Insert returned %+v, want id %q in org %q", stored, want.ID, org.ID)
	}
	if stored.CreatedAt.IsZero() || stored.UpdatedAt.IsZero() {
		t.Error("Insert did not return the database-assigned timestamps")
	}
	if stored.IsDisabled() {
		t.Error("a freshly inserted service account reports IsDisabled = true")
	}

	var got store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, want.ID)
		return err
	}); err != nil {
		t.Fatalf("Get returned %v, want the service account", err)
	}
	if got.ID != want.ID || got.Slug != want.Slug || got.DisplayName != want.Name {
		t.Errorf("Get returned %+v, want id/slug/name %q/%q/%q", got, want.ID, want.Slug, want.Name)
	}
}

func TestServiceAccountBelongsToOneOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "acme")
	sa := seedServiceAccount(t, db, f, org, "CI")

	t.Run("a service account requires an existing organization", func(t *testing.T) {
		orphan := f.ServiceAccount(testutil.Organization{ID: "org_does_not_exist"}, "Orphan")
		_, err := db.Exec(ctx,
			`INSERT INTO service_accounts (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
			orphan.ID, orphan.OrganizationID, orphan.Slug, orphan.Name)
		if !isConstraintViolation(err) {
			t.Fatalf("insert service account with missing org: err = %v, want constraint violation", err)
		}
	})

	t.Run("deleting the organization cascades to its service accounts", func(t *testing.T) {
		if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org.ID); err != nil {
			t.Fatalf("delete organization: %v", err)
		}
		var count int
		if err := db.QueryRow(ctx,
			`SELECT count(*) FROM service_accounts WHERE id = $1`, sa.ID).Scan(&count); err != nil {
			t.Fatalf("count service accounts: %v", err)
		}
		if count != 0 {
			t.Errorf("service account rows after org delete = %d, want 0", count)
		}
	})
}

func TestServiceAccountRepositoryGetIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	saA := seedServiceAccount(t, db, f, orgA, "CI A")

	// orgB must not be able to read orgA's service account by id.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgB.ID, saA.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Get error code = %v, want %s", err, yerr.CodeNotFound)
	}

	// orgA still sees its own service account.
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgA.ID, saA.ID)
		return getErr
	}); err != nil {
		t.Errorf("owner Get returned %v, want the service account", err)
	}
}

func TestServiceAccountRepositoryListByOrganizationIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	for i := 0; i < 3; i++ {
		seedServiceAccount(t, db, f, orgA, "CI")
	}
	seedServiceAccount(t, db, f, orgB, "CI")

	var listA, listB []store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		if listA, err = repo.ListByOrganization(ctx, q, orgA.ID); err != nil {
			return err
		}
		listB, err = repo.ListByOrganization(ctx, q, orgB.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(listA) != 3 {
		t.Errorf("orgA list = %d service accounts, want 3", len(listA))
	}
	if len(listB) != 1 {
		t.Errorf("orgB list = %d service accounts, want 1 (tenant scoped)", len(listB))
	}
	for _, sa := range listA {
		if sa.OrganizationID != orgA.ID {
			t.Errorf("orgA list contains a service account owned by %q", sa.OrganizationID)
		}
	}
}

func TestServiceAccountRepositoryInsertDuplicateSlugConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "acme")
	orgB := seedOrg(t, db, f, "beta")

	first := f.ServiceAccount(orgA, "CI")
	insertServiceAccount(ctx, t, s, repo, store.ServiceAccount{
		ID: first.ID, OrganizationID: orgA.ID, Slug: first.Slug, DisplayName: first.Name,
	})

	// Same slug, new id, same organization — rejected as a Conflict.
	dup := f.ServiceAccount(orgA, "CI dup")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insErr := repo.Insert(ctx, tx, store.ServiceAccount{
			ID: dup.ID, OrganizationID: orgA.ID, Slug: first.Slug, DisplayName: dup.Name,
		})
		return insErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("duplicate-slug Insert error code = %v, want %s", err, yerr.CodeConflict)
	}

	// Same slug, different organization — allowed: slugs are scoped, not global.
	other := f.ServiceAccount(orgB, "CI")
	insertServiceAccount(ctx, t, s, repo, store.ServiceAccount{
		ID: other.ID, OrganizationID: orgB.ID, Slug: first.Slug, DisplayName: other.Name,
	})
}

func TestServiceAccountRepositoryDisableIsIdempotentAndTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	sa := seedServiceAccount(t, db, f, org, "CI")

	firstDisable := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Disable(ctx, tx, org.ID, sa.ID, firstDisable)
	}); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	// Disabling again is a no-op success and preserves the first timestamp.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Disable(ctx, tx, org.ID, sa.ID, firstDisable.Add(time.Hour))
	}); err != nil {
		t.Fatalf("second Disable: %v", err)
	}

	var got store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, sa.ID)
		return err
	}); err != nil {
		t.Fatalf("Get after Disable: %v", err)
	}
	if !got.IsDisabled() {
		t.Fatal("service account is not marked disabled after Disable")
	}
	if got.DisabledAt == nil || !got.DisabledAt.Equal(firstDisable) {
		t.Errorf("disabled_at = %v, want the first disable time %v", got.DisabledAt, firstDisable)
	}

	// A cross-tenant disable must not match the row.
	otherOrg := seedOrg(t, db, f, "intruder")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Disable(ctx, tx, otherOrg.ID, sa.ID, firstDisable)
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Disable error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

func TestServiceAccountCanOwnAPIKeys(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	keyRepo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	sa := seedServiceAccount(t, db, f, org, "CI")

	scopes := []string{"projects:read", "services:deploy"}
	key := newServiceAccountAPIKey(t, f, org.ID, sa.ID, scopes)
	stored := insertAPIKey(ctx, t, s, keyRepo, key)
	if stored.ServiceAccountID != sa.ID {
		t.Fatalf("stored.ServiceAccountID = %q, want %q", stored.ServiceAccountID, sa.ID)
	}

	var owned []store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		owned, err = keyRepo.ListByServiceAccount(ctx, q, org.ID, sa.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByServiceAccount: %v", err)
	}
	if len(owned) != 1 || owned[0].ID != key.ID {
		t.Fatalf("ListByServiceAccount = %+v, want the one key %q", owned, key.ID)
	}
	if len(owned[0].Scopes) != 2 {
		t.Errorf("owned key scopes = %v, want the two persisted scopes", owned[0].Scopes)
	}

	// A human-owned key (no service_account_id) is not returned for the
	// service account.
	humanKey := newServiceAccountAPIKey(t, f, org.ID, "", []string{"projects:read"})
	insertAPIKey(ctx, t, s, keyRepo, humanKey)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		owned, err = keyRepo.ListByServiceAccount(ctx, q, org.ID, sa.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByServiceAccount after human key: %v", err)
	}
	if len(owned) != 1 {
		t.Errorf("ListByServiceAccount = %d keys, want 1 (human-owned keys excluded)", len(owned))
	}

	// The unscoped account-wide listing still sees both keys.
	var all []store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		all, err = keyRepo.ListByOrganization(ctx, q, org.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("ListByOrganization = %d keys, want 2", len(all))
	}
}

func TestServiceAccountAPIKeyCannotCrossTenantBoundary(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	keyRepo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	saA := seedServiceAccount(t, db, f, orgA, "CI A")

	// A key in orgB that claims a service account owned by orgA. The composite
	// foreign key (organization_id, service_account_id) must reject it: a
	// service-account key can never cross the tenant boundary.
	crossTenant := newServiceAccountAPIKey(t, f, orgB.ID, saA.ID, []string{"services:deploy"})
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insErr := keyRepo.Insert(ctx, tx, crossTenant)
		return insErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("cross-tenant service-account key Insert error code = %v, want %s", err, yerr.CodeConflict)
	}
}

// TestServiceAccountKeyDeployOnlyAndDeniedCrossProjectReads proves the scope
// model carries project/environment/action grants: a CI service account's key
// can be deploy-only for one project and carry no read grant for another
// project. The policy engine (a later story) enforces these scopes at request
// time; this test proves the persistence layer round-trips them faithfully.
func TestServiceAccountKeyDeployOnlyAndDeniedCrossProjectReads(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	keyRepo := store.NewAPIKeyRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	sa := seedServiceAccount(t, db, f, org, "CI")
	projA := seedProject(t, db, f, org, "A")
	projB := seedProject(t, db, f, org, "B")

	deployA := "project:" + projA.ID + ":services:deploy"
	readA := "project:" + projA.ID + ":projects:read"
	readB := "project:" + projB.ID + ":projects:read"

	// A CI key scoped to deploy project A only — no read grant anywhere.
	key := newServiceAccountAPIKey(t, f, org.ID, sa.ID, []string{deployA})
	insertAPIKey(ctx, t, s, keyRepo, key)

	var got store.APIKey
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = keyRepo.Get(ctx, q, org.ID, key.ID)
		return err
	}); err != nil {
		t.Fatalf("Get: %v", err)
	}

	has := func(scope string) bool {
		for _, sc := range got.Scopes {
			if sc == scope {
				return true
			}
		}
		return false
	}
	if !has(deployA) {
		t.Errorf("CI key scopes = %v, want it to allow deploy on project A", got.Scopes)
	}
	if has(readA) {
		t.Errorf("a deploy-only CI key carries a read grant: %v", got.Scopes)
	}
	if has(readB) {
		t.Errorf("a project-A CI key carries a cross-project read grant for project B: %v", got.Scopes)
	}
}

// --- ServiceAccountService unit-of-work integration tests --------------------

// newServiceAccountCreateInput builds a valid CreateServiceAccountInput for org.
func newServiceAccountCreateInput(orgID string) store.CreateServiceAccountInput {
	return store.CreateServiceAccountInput{
		OrganizationID:   orgID,
		ServiceAccountID: domain.MustNewID(domain.KindServiceAccount).String(),
		Slug:             "ci-deployer",
		DisplayName:      "CI Deployer",
	}
}

// serviceAccountExists reports whether a service account row identified by
// (orgID, serviceAccountID) is visible.
func serviceAccountExists(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceAccountRepository, orgID, serviceAccountID string) bool {
	t.Helper()
	var found bool
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgID, serviceAccountID)
		if getErr == nil {
			found = true
			return nil
		}
		if yerr.From(getErr).Code == yerr.CodeNotFound {
			return nil
		}
		return getErr
	})
	if err != nil {
		t.Fatalf("serviceAccountExists check: %v", err)
	}
	return found
}

func TestServiceAccountServiceCreateSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	svc, err := store.NewServiceAccountService(s, repo, authz, quota)
	if err != nil {
		t.Fatalf("NewServiceAccountService: %v", err)
	}
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	in := newServiceAccountCreateInput(orgID)

	created, err := svc.Create(ctx, in)
	if err != nil {
		t.Fatalf("Create returned %v, want nil", err)
	}
	if created.ID != in.ServiceAccountID || created.OrganizationID != orgID {
		t.Errorf("Create returned %+v, want id %q in org %q", created, in.ServiceAccountID, orgID)
	}
	if authz.calls != 1 || quota.calls != 1 {
		t.Errorf("step calls = authz:%d quota:%d, want 1 each", authz.calls, quota.calls)
	}
	if !serviceAccountExists(ctx, t, s, repo, orgID, in.ServiceAccountID) {
		t.Error("Create succeeded but the service account row was not committed")
	}
}

func TestServiceAccountServiceCreateValidationFailure(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	svc, err := store.NewServiceAccountService(s, store.NewServiceAccountRepository(), authz, quota)
	if err != nil {
		t.Fatalf("NewServiceAccountService: %v", err)
	}

	in := newServiceAccountCreateInput(domain.MustNewID(domain.KindOrganization).String())
	in.Slug = "Not A Slug!"
	in.DisplayName = ""

	_, createErr := svc.Create(context.Background(), in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeValidation {
		t.Fatalf("Create(invalid) error code = %v, want %s", createErr, yerr.CodeValidation)
	}
	if violations, ok := apierr.ViolationsOf(createErr); !ok || len(violations) == 0 {
		t.Errorf("Create(invalid) carried no field violations: ok=%v", ok)
	}
	if authz.calls != 0 || quota.calls != 0 {
		t.Errorf("validation failure still opened the transaction: authz:%d quota:%d", authz.calls, quota.calls)
	}
}

func TestServiceAccountServiceCreateAuthorizationFailure(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	authz := &recordingAuthorizer{err: apierr.Forbidden("service_account.create denied")}
	quota := &recordingQuota{}
	svc, err := store.NewServiceAccountService(s, repo, authz, quota)
	if err != nil {
		t.Fatalf("NewServiceAccountService: %v", err)
	}
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	in := newServiceAccountCreateInput(orgID)

	_, createErr := svc.Create(ctx, in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeForbidden {
		t.Fatalf("Create error code = %v, want %s", createErr, yerr.CodeForbidden)
	}
	if quota.calls != 0 {
		t.Errorf("a denied authorization still ran the quota step: quota:%d", quota.calls)
	}
	if serviceAccountExists(ctx, t, s, repo, orgID, in.ServiceAccountID) {
		t.Error("a denied authorization still persisted the service account row")
	}
}

func TestServiceAccountServiceCreateQuotaFailureRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{err: apierr.QuotaExceeded("service_accounts", 5)}
	svc, err := store.NewServiceAccountService(s, repo, authz, quota)
	if err != nil {
		t.Fatalf("NewServiceAccountService: %v", err)
	}
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	in := newServiceAccountCreateInput(orgID)

	_, createErr := svc.Create(ctx, in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("Create error code = %v, want %s", createErr, yerr.CodeQuotaExceeded)
	}
	if serviceAccountExists(ctx, t, s, repo, orgID, in.ServiceAccountID) {
		t.Error("an exhausted quota still persisted the service account row")
	}
}

func TestServiceAccountServiceCreateConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	svc, err := store.NewServiceAccountService(s, repo, &recordingAuthorizer{}, &recordingQuota{})
	if err != nil {
		t.Fatalf("NewServiceAccountService: %v", err)
	}
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	first := newServiceAccountCreateInput(orgID)
	if _, err := svc.Create(ctx, first); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	// Same slug, new service account id, same organization.
	second := newServiceAccountCreateInput(orgID)
	second.Slug = first.Slug
	_, createErr := svc.Create(ctx, second)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeConflict {
		t.Fatalf("duplicate-slug Create error code = %v, want %s", createErr, yerr.CodeConflict)
	}
	if serviceAccountExists(ctx, t, s, repo, orgID, second.ServiceAccountID) {
		t.Error("a conflicting Create still persisted the second service account row")
	}
}
