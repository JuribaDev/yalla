package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for ServiceDomainRepository's CRUD invariants (BE-0475).
// Tenant-isolation gets its own PRD story; this file pins the single-row
// lifecycle guarantees every caller depends on:
//
//   - Insert returns the committed row with version=1 and database-owned
//     timestamps.
//   - GetByID and ListByService read through tenant-scoped predicates.
//   - Update rewrites only the mutable routing fields, bumps version, refreshes
//     updated_at, preserves created_at, and honors a matching If-Match version.
//   - stale If-Match on Update/Delete returns typed ConflictStale; missing rows
//     return typed NotFound.
//   - DeleteByID removes the row and returns its final committed shape.
//   - CHECK, UNIQUE, FK, transaction rollback, cascade, and nil-Tx guards
//     surface through typed errors rather than raw driver failures.

type serviceDomainTxRollbackSentinel struct{}

func (serviceDomainTxRollbackSentinel) Error() string {
	return "rollback service domain test transaction"
}

func serviceDomainFixture(orgID, serviceID, hostname, path string) store.ServiceDomain {
	return store.ServiceDomain{
		ID:              domain.MustNewID(domain.KindServiceDomain).String(),
		OrganizationID:  orgID,
		ServiceID:       serviceID,
		Hostname:        hostname,
		Path:            path,
		Port:            443,
		HTTPS:           true,
		CertificateType: store.ServiceDomainCertificateLetsEncrypt,
	}
}

func insertServiceDomain(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceDomainRepository, d store.ServiceDomain) store.ServiceDomain {
	t.Helper()
	var stored store.ServiceDomain
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Insert(ctx, tx, d)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("insert service domain: %v", err)
	}
	return stored
}

func getServiceDomain(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceDomainRepository, orgID, serviceID, domainID string) store.ServiceDomain {
	t.Helper()
	var got store.ServiceDomain
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		row, err := repo.GetByID(ctx, q, orgID, serviceID, domainID)
		if err != nil {
			return err
		}
		got = row
		return nil
	}); err != nil {
		t.Fatalf("GetByID(%q): %v", domainID, err)
	}
	return got
}

func listServiceDomains(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceDomainRepository, orgID, serviceID string) []store.ServiceDomain {
	t.Helper()
	var got []store.ServiceDomain
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, err := repo.ListByService(ctx, q, orgID, serviceID)
		if err != nil {
			return err
		}
		got = rows
		return nil
	}); err != nil {
		t.Fatalf("ListByService(%q, %q): %v", orgID, serviceID, err)
	}
	return got
}

func countServiceDomainsForService(ctx context.Context, t *testing.T, db *testutil.DB, orgID, serviceID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM service_domains WHERE organization_id = $1 AND service_id = $2`,
		orgID, serviceID).Scan(&count); err != nil {
		t.Fatalf("count service_domains: %v", err)
	}
	return count
}

func assertServiceDomainSameIdentity(t *testing.T, got, want store.ServiceDomain) {
	t.Helper()
	if got.ID != want.ID ||
		got.OrganizationID != want.OrganizationID ||
		got.ServiceID != want.ServiceID {
		t.Fatalf("identity = (id=%q org=%q svc=%q), want (id=%q org=%q svc=%q)",
			got.ID, got.OrganizationID, got.ServiceID, want.ID, want.OrganizationID, want.ServiceID)
	}
}

func TestServiceDomainRepositoryInsertReturnsRowWithVersionAndTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "domain-acme")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	want := serviceDomainFixture(org.ID, svc.ID, "api-insert.example.test", "/")

	got := insertServiceDomain(ctx, t, s, repo, want)

	assertServiceDomainSameIdentity(t, got, want)
	if got.Hostname != want.Hostname || got.Path != want.Path || got.Port != want.Port || got.HTTPS != want.HTTPS || got.CertificateType != want.CertificateType {
		t.Errorf("routing fields = %+v, want %+v", got, want)
	}
	if got.Version != 1 {
		t.Errorf("version = %d, want 1", got.Version)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("timestamps must be database-populated, got created_at=%v updated_at=%v", got.CreatedAt, got.UpdatedAt)
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Errorf("created_at=%v updated_at=%v, want equal on fresh INSERT", got.CreatedAt, got.UpdatedAt)
	}

	reloaded := getServiceDomain(ctx, t, s, repo, org.ID, svc.ID, got.ID)
	if reloaded != got {
		t.Errorf("GetByID returned %+v, want inserted row %+v", reloaded, got)
	}
}

func TestServiceDomainRepositoryListByServiceOrdersDeterministically(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "domain-list")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(org.ID, svc.ID, "z.example.test", "/b"))
	insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(org.ID, svc.ID, "a.example.test", "/z"))
	insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(org.ID, svc.ID, "a.example.test", "/a"))

	got := listServiceDomains(ctx, t, s, repo, org.ID, svc.ID)
	if len(got) != 3 {
		t.Fatalf("ListByService returned %d rows, want 3", len(got))
	}
	want := []string{"a.example.test/a", "a.example.test/z", "z.example.test/b"}
	for i, row := range got {
		key := row.Hostname + row.Path
		if key != want[i] {
			t.Errorf("row %d = %q, want %q", i, key, want[i])
		}
	}
}

func TestServiceDomainRepositoryUpdateBumpsVersionAndPreservesIdentity(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "domain-update")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	baseline := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(org.ID, svc.ID, "old.example.test", "/old"))

	time.Sleep(time.Millisecond)
	desired := baseline
	desired.Hostname = "new.example.test"
	desired.Path = "/new"
	desired.Port = 8080
	desired.HTTPS = false
	desired.CertificateType = store.ServiceDomainCertificateNone
	version := baseline.Version

	var updated store.ServiceDomain
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Update(ctx, tx, desired, &version)
		if err != nil {
			return err
		}
		updated = row
		return nil
	}); err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}

	assertServiceDomainSameIdentity(t, updated, baseline)
	if updated.Hostname != desired.Hostname || updated.Path != desired.Path || updated.Port != desired.Port || updated.HTTPS != desired.HTTPS || updated.CertificateType != desired.CertificateType {
		t.Errorf("updated routing fields = %+v, want %+v", updated, desired)
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("updated version = %d, want %d", updated.Version, baseline.Version+1)
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("created_at changed from %v to %v", baseline.CreatedAt, updated.CreatedAt)
	}
	if !updated.UpdatedAt.After(baseline.UpdatedAt) {
		t.Errorf("updated_at = %v, want after baseline %v", updated.UpdatedAt, baseline.UpdatedAt)
	}
}

func TestServiceDomainRepositoryUpdateStaleVersionIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "domain-stale")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	baseline := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(org.ID, svc.ID, "stale.example.test", "/"))

	desired := baseline
	desired.Path = "/next"
	stale := baseline.Version + 99
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updateErr := repo.Update(ctx, tx, desired, &stale)
		return updateErr
	})
	wantErrCode(t, err, yerr.CodeConflict)

	got := getServiceDomain(ctx, t, s, repo, org.ID, svc.ID, baseline.ID)
	if got != baseline {
		t.Errorf("stale Update mutated row: got %+v, want %+v", got, baseline)
	}
}

func TestServiceDomainRepositoryDeleteRemovesAndReturnsRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "domain-delete")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	baseline := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(org.ID, svc.ID, "delete.example.test", "/"))

	var deleted store.ServiceDomain
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.DeleteByID(ctx, tx, org.ID, svc.ID, baseline.ID, nil)
		if err != nil {
			return err
		}
		deleted = row
		return nil
	}); err != nil {
		t.Fatalf("DeleteByID returned %v, want nil", err)
	}
	if deleted != baseline {
		t.Errorf("deleted row = %+v, want baseline %+v", deleted, baseline)
	}
	if count := countServiceDomainsForService(ctx, t, db, org.ID, svc.ID); count != 0 {
		t.Errorf("service_domains count after delete = %d, want 0", count)
	}
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.GetByID(ctx, q, org.ID, svc.ID, baseline.ID)
		return getErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)
}

func TestServiceDomainRepositoryDeleteStaleVersionIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "domain-delete-stale")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	baseline := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(org.ID, svc.ID, "delete-stale.example.test", "/"))

	stale := baseline.Version + 10
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, deleteErr := repo.DeleteByID(ctx, tx, org.ID, svc.ID, baseline.ID, &stale)
		return deleteErr
	})
	wantErrCode(t, err, yerr.CodeConflict)

	got := getServiceDomain(ctx, t, s, repo, org.ID, svc.ID, baseline.ID)
	if got != baseline {
		t.Errorf("stale DeleteByID mutated row: got %+v, want %+v", got, baseline)
	}
}

func TestServiceDomainRepositoryInsertConstraintViolationsAreConflicts(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "domain-constraints")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")

	cases := []struct {
		name   string
		mutate func(store.ServiceDomain) store.ServiceDomain
	}{
		{"blank hostname", func(d store.ServiceDomain) store.ServiceDomain { d.Hostname = ""; return d }},
		{"blank path", func(d store.ServiceDomain) store.ServiceDomain { d.Path = ""; return d }},
		{"zero port", func(d store.ServiceDomain) store.ServiceDomain { d.Port = 0; return d }},
		{"too large port", func(d store.ServiceDomain) store.ServiceDomain { d.Port = 65536; return d }},
		{"unknown certificate type", func(d store.ServiceDomain) store.ServiceDomain { d.CertificateType = "wildcard"; return d }},
		{"unknown service", func(d store.ServiceDomain) store.ServiceDomain { d.ServiceID = "svc_missing"; return d }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := serviceDomainFixture(org.ID, svc.ID, "constraint-"+tc.name+".example.test", "/")
			err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, insertErr := repo.Insert(ctx, tx, tc.mutate(base))
				return insertErr
			})
			wantErrCode(t, err, yerr.CodeConflict)
		})
	}
}

func TestServiceDomainRepositoryDuplicateHostnamePathIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "domain-dupe")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(org.ID, svc.ID, "dupe.example.test", "/"))

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		dupe := serviceDomainFixture(org.ID, svc.ID, "dupe.example.test", "/")
		_, insertErr := repo.Insert(ctx, tx, dupe)
		return insertErr
	})
	wantErrCode(t, err, yerr.CodeConflict)
}

func TestServiceDomainRepositoryInsertRollbackLeavesNoRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "domain-rollback")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	d := serviceDomainFixture(org.ID, svc.ID, "rollback.example.test", "/")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, insertErr := repo.Insert(ctx, tx, d); insertErr != nil {
			return insertErr
		}
		return serviceDomainTxRollbackSentinel{}
	})
	var sentinel serviceDomainTxRollbackSentinel
	if !errors.As(err, &sentinel) {
		t.Fatalf("Write returned %v, want rollback sentinel", err)
	}
	if count := countServiceDomainsForService(ctx, t, db, org.ID, svc.ID); count != 0 {
		t.Errorf("service_domains count after rollback = %d, want 0", count)
	}
}

func TestServiceDomainRepositoryCascadeFromServiceDelete(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "domain-cascade")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(org.ID, svc.ID, "cascade.example.test", "/"))

	if _, err := db.Exec(ctx, `DELETE FROM services WHERE organization_id = $1 AND id = $2`, org.ID, svc.ID); err != nil {
		t.Fatalf("delete parent service: %v", err)
	}
	if count := countServiceDomainsForService(ctx, t, db, org.ID, svc.ID); count != 0 {
		t.Errorf("service_domains count after service cascade = %d, want 0", count)
	}
}

func TestServiceDomainRepositoryNilTxGuards(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceDomainRepository()
	ctx := context.Background()
	d := serviceDomainFixture("org_nil", "svc_nil", "nil.example.test", "/")

	_, err := repo.Insert(ctx, nil, d)
	wantErrCode(t, err, yerr.CodeInternal)
	_, err = repo.Update(ctx, nil, d, nil)
	wantErrCode(t, err, yerr.CodeInternal)
	_, err = repo.DeleteByID(ctx, nil, d.OrganizationID, d.ServiceID, d.ID, nil)
	wantErrCode(t, err, yerr.CodeInternal)
}
