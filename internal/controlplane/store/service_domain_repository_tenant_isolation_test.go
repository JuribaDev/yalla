package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for service_domains (BE-0476).
// service_domains is a service-scoped leaf table. Each row carries the
// tenant boundary directly (organization_id) plus a composite FK to its
// parent service, and every repository method predicates on the full
// (organization_id, service_id, id) tuple where an id is present.
//
// What is intentionally not exercised here, and where the proof lives
// instead:
//   - CRUD row shape, constraints, optimistic versioning, transaction
//     rollback, and parent cascade are proved by
//     service_domain_repository_invariants_test.go (BE-0475).
//   - service_domains has no soft-delete column; DeleteByID is a hard
//     delete that returns the removed row snapshot.
//   - HTTP envelopes and policy decisions are pinned by the endpoint
//     contract and policy-matrix suites.

type serviceDomainTenantFixture struct {
	orgA testutil.Organization
	orgB testutil.Organization
	svcA testutil.Service
	svcB testutil.Service
}

func seedServiceDomainTenantFixture(t *testing.T, db *testutil.DB, f *testutil.Factory) serviceDomainTenantFixture {
	t.Helper()
	orgA := seedOrg(t, db, f, "domain-tenant-a")
	orgB := seedOrg(t, db, f, "domain-tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")
	return serviceDomainTenantFixture{
		orgA: orgA,
		orgB: orgB,
		svcA: svcA,
		svcB: svcB,
	}
}

func countServiceDomainsForOrg(ctx context.Context, t *testing.T, db *testutil.DB, orgID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM service_domains WHERE organization_id = $1`,
		orgID).Scan(&count); err != nil {
		t.Fatalf("count service_domains for org %q: %v", orgID, err)
	}
	return count
}

func assertServiceDomainByteIdentical(t *testing.T, label string, baseline, after store.ServiceDomain) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID || after.ServiceID != baseline.ServiceID {
		t.Errorf("%s: identity drifted: got id=%q org=%q service=%q, want id=%q org=%q service=%q",
			label, after.ID, after.OrganizationID, after.ServiceID, baseline.ID, baseline.OrganizationID, baseline.ServiceID)
	}
	if after.Hostname != baseline.Hostname {
		t.Errorf("%s: hostname = %q, want %q", label, after.Hostname, baseline.Hostname)
	}
	if after.Path != baseline.Path {
		t.Errorf("%s: path = %q, want %q", label, after.Path, baseline.Path)
	}
	if after.Port != baseline.Port {
		t.Errorf("%s: port = %d, want %d", label, after.Port, baseline.Port)
	}
	if after.HTTPS != baseline.HTTPS {
		t.Errorf("%s: https = %v, want %v", label, after.HTTPS, baseline.HTTPS)
	}
	if after.CertificateType != baseline.CertificateType {
		t.Errorf("%s: certificate_type = %q, want %q", label, after.CertificateType, baseline.CertificateType)
	}
	if after.Version != baseline.Version {
		t.Errorf("%s: version = %d, want %d - a peer-tenant UPDATE matched the bystander row",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: updated_at = %v, want %v - a peer-tenant UPDATE matched the bystander row",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}

func TestServiceDomainRepositoryListByServiceIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedServiceDomainTenantFixture(t, db, f)

	rowA := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(fixture.orgA.ID, fixture.svcA.ID, "shared-looking-a.example.test", "/same"))
	rowB1 := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(fixture.orgB.ID, fixture.svcB.ID, "shared-looking-b.example.test", "/same"))
	rowB2 := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(fixture.orgB.ID, fixture.svcB.ID, "shared-looking-a.example.test", "/tenant-b"))

	listA := listServiceDomains(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByService(orgA, svcA) returned %d rows, want exactly 1 - orgB domains leaked or changed orgA's apparent page size", len(listA))
	}
	if listA[0].ID != rowA.ID || listA[0].OrganizationID != fixture.orgA.ID || listA[0].ServiceID != fixture.svcA.ID {
		t.Errorf("ListByService(orgA, svcA)[0] = %+v, want orgA row %+v", listA[0], rowA)
	}

	listB := listServiceDomains(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID)
	if len(listB) != 2 {
		t.Fatalf("ListByService(orgB, svcB) returned %d rows, want exactly 2", len(listB))
	}
	for _, row := range listB {
		if row.ID == rowA.ID || row.OrganizationID != fixture.orgB.ID || row.ServiceID != fixture.svcB.ID {
			t.Errorf("ListByService(orgB, svcB) row = %+v, want only orgB/svcB rows", row)
		}
	}
	if listB[0].ID != rowB2.ID || listB[1].ID != rowB1.ID {
		t.Errorf("ListByService(orgB, svcB) order = [%q, %q], want hostname/path/id deterministic order [%q, %q]",
			listB[0].ID, listB[1].ID, rowB2.ID, rowB1.ID)
	}

	crossTenant := listServiceDomains(ctx, t, s, repo, fixture.orgA.ID, fixture.svcB.ID)
	if len(crossTenant) != 0 {
		t.Errorf("ListByService(orgA, svcB) returned %d rows, want 0 - orgB service domains leaked through a cross-tenant service_id", len(crossTenant))
	}
	if crossTenant == nil {
		t.Error("ListByService(orgA, svcB) returned nil; the repository contract is a non-nil empty slice")
	}
}

func TestServiceDomainRepositoryGetByIDCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedServiceDomainTenantFixture(t, db, f)

	rowB := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(fixture.orgB.ID, fixture.svcB.ID, "get-cross.example.test", "/"))
	baselineB := getServiceDomain(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.GetByID(ctx, q, fixture.orgA.ID, fixture.svcB.ID, rowB.ID)
		return getErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterB := getServiceDomain(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)
	assertServiceDomainByteIdentical(t, "GetByID(orgA, svcB, domainB) bystander orgB", baselineB, afterB)
}

func TestServiceDomainRepositoryUpdateCrossTenantIsNotFoundAndDoesNotTouchBystanders(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedServiceDomainTenantFixture(t, db, f)

	rowA := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(fixture.orgA.ID, fixture.svcA.ID, "update-a.example.test", "/"))
	rowB := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(fixture.orgB.ID, fixture.svcB.ID, "update-b.example.test", "/"))
	baselineA := getServiceDomain(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID, rowA.ID)
	baselineB := getServiceDomain(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)

	desired := baselineB
	desired.OrganizationID = fixture.orgA.ID
	desired.Hostname = "update-cross-tenant-attempt.example.test"
	desired.Path = "/attempt"
	desired.Port = 8081
	desired.HTTPS = false
	desired.CertificateType = store.ServiceDomainCertificateNone
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updateErr := repo.Update(ctx, tx, desired, nil)
		return updateErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterA := getServiceDomain(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID, rowA.ID)
	afterB := getServiceDomain(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)
	assertServiceDomainByteIdentical(t, "Update(orgA, svcB, domainB) orgA peer", baselineA, afterA)
	assertServiceDomainByteIdentical(t, "Update(orgA, svcB, domainB) orgB bystander", baselineB, afterB)
}

func TestServiceDomainRepositoryDeleteCrossTenantIsNotFoundAndDoesNotTouchBystanders(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedServiceDomainTenantFixture(t, db, f)

	rowA := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(fixture.orgA.ID, fixture.svcA.ID, "delete-a.example.test", "/"))
	rowB := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(fixture.orgB.ID, fixture.svcB.ID, "delete-b.example.test", "/"))
	baselineA := getServiceDomain(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID, rowA.ID)
	baselineB := getServiceDomain(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, deleteErr := repo.DeleteByID(ctx, tx, fixture.orgA.ID, fixture.svcB.ID, rowB.ID, nil)
		return deleteErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterA := getServiceDomain(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID, rowA.ID)
	afterB := getServiceDomain(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)
	assertServiceDomainByteIdentical(t, "DeleteByID(orgA, svcB, domainB) orgA peer", baselineA, afterA)
	assertServiceDomainByteIdentical(t, "DeleteByID(orgA, svcB, domainB) orgB bystander", baselineB, afterB)
	if count := countServiceDomainsForOrg(ctx, t, db, fixture.orgB.ID); count != 1 {
		t.Errorf("orgB service_domains count after cross-tenant delete = %d, want 1", count)
	}
	if count := countServiceDomainsForOrg(ctx, t, db, fixture.orgA.ID); count != 1 {
		t.Errorf("orgA service_domains count after cross-tenant delete = %d, want 1", count)
	}
}

func TestServiceDomainReaderListDomainsCrossTenantServiceIDIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceDomainRepository()
	reader, err := store.NewServiceDomainReader(s)
	if err != nil {
		t.Fatalf("NewServiceDomainReader: %v", err)
	}
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedServiceDomainTenantFixture(t, db, f)

	rowB := insertServiceDomain(ctx, t, s, repo, serviceDomainFixture(fixture.orgB.ID, fixture.svcB.ID, "reader-b.example.test", "/"))
	baselineB := getServiceDomain(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)

	_, err = reader.ListDomains(ctx, store.ListServiceDomainsInput{
		OrganizationID: fixture.orgA.ID,
		ServiceID:      fixture.svcB.ID,
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterB := getServiceDomain(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)
	assertServiceDomainByteIdentical(t, "ServiceDomainReader.ListDomains(orgA, svcB) bystander orgB", baselineB, afterB)
}
