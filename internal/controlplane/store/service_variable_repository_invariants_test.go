package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration and unit tests for ServiceVariableRepository (BE-0449).
// service_variable_test.go covers ListByService ordering, reader
// contracts, and sibling-service isolation — the Upsert and
// DeleteByServiceExceptKeys mutation surface is untested at the
// repository level. This file pins the row-shape, timestamp,
// optimistic-versioning, CHECK, FK, CASCADE, and transaction-rollback
// invariants the bulk-replace surface needs.
//
// What this file proves:
//
//   - Upsert INSERT row shape: version=1, created_at == updated_at
//     byte-equal on a fresh row, identifiers echoed verbatim.
//   - Upsert ON CONFLICT UPDATE branch: id and created_at byte-equal
//     to baseline (caller-supplied id is ignored on conflict),
//     bump_version increments version, set_updated_at refreshes
//     updated_at strictly after baseline.
//   - Upsert with cross-tenant or unknown (organization_id,
//     service_id) surfaces typed apierr.Conflict — the composite FK
//     to services refuses the row.
//   - Upsert duplicate PRIMARY KEY (id reused under a different
//     (organization_id, service_id, key) tuple) surfaces as a typed
//     apierr.Conflict via the PK uniqueness violation.
//   - Upsert with IsSecret=true + non-empty Value violates the
//     service_variables_secret_columns_consistent CHECK and surfaces
//     as apierr.Conflict.
//   - DeleteByServiceExceptKeys with nil/empty keepKeys clears every
//     variable of the service; with a non-empty list retains exactly
//     the listed keys; cross-tenant (organization_id, service_id)
//     deletes nothing.
//   - ON DELETE CASCADE from services removes a tenant's variables
//     when the parent services row is deleted.
//   - Upsert rolls back when the surrounding Write closure returns a
//     non-nil error.
//   - Upsert / DeleteByServiceExceptKeys nil-Tx guards render typed
//     apierr.Internal.

func newServiceVariableID(f *testutil.Factory, label string) string {
	parent := testutil.Environment{
		ID:             "env_irrelevant",
		ProjectID:      "prj_irrelevant",
		OrganizationID: "org_irrelevant",
	}
	return "svar_" + f.Service(parent, label).ID[len("svc_"):]
}

func upsertServiceVariable(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.ServiceVariableRepository,
	id, organizationID, serviceID, key string,
	in store.ServiceVariableUpsert,
) store.ServiceVariable {
	t.Helper()
	var stored store.ServiceVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Upsert(ctx, tx, id, organizationID, serviceID, key, in)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("upsert service variable: %v", err)
	}
	return stored
}

func listServiceVariablesOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.ServiceVariableRepository,
	organizationID, serviceID string,
) []store.ServiceVariable {
	t.Helper()
	var out []store.ServiceVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, lerr := repo.ListByService(ctx, q, organizationID, serviceID)
		if lerr != nil {
			return lerr
		}
		out = rows
		return nil
	}); err != nil {
		t.Fatalf("ListByService(%q, %q): %v", organizationID, serviceID, err)
	}
	return out
}

func TestServiceVariableRepositoryUpsertInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	id := newServiceVariableID(f, "insert")

	got := upsertServiceVariable(ctx, t, s, repo, id, org.ID, svc.ID, "REGION",
		store.ServiceVariableUpsert{Value: "us-east-1", IsSecret: false})

	if got.ID != id {
		t.Errorf("Upsert returned id %q, want %q", got.ID, id)
	}
	if got.OrganizationID != org.ID || got.ServiceID != svc.ID {
		t.Errorf("Upsert returned (org=%q svc=%q), want (org=%q svc=%q)",
			got.OrganizationID, got.ServiceID, org.ID, svc.ID)
	}
	if got.Key != "REGION" || got.Value != "us-east-1" {
		t.Errorf("Upsert returned key=%q value=%q", got.Key, got.Value)
	}
	if got.Version != 1 {
		t.Errorf("Upsert version = %d, want 1 (schema default)", got.Version)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("Upsert returned zero timestamp")
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Errorf("Upsert created_at = %v, updated_at = %v; BEFORE UPDATE must not fire on a fresh row",
			got.CreatedAt, got.UpdatedAt)
	}
}

func TestServiceVariableRepositoryUpsertUpdateBranchPreservesIdentity(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	baselineID := newServiceVariableID(f, "baseline")
	baseline := upsertServiceVariable(ctx, t, s, repo, baselineID, org.ID, svc.ID, "DB_URL",
		store.ServiceVariableUpsert{Value: "postgres://old", IsSecret: false})

	time.Sleep(time.Millisecond)

	overrideID := newServiceVariableID(f, "override")
	updated := upsertServiceVariable(ctx, t, s, repo, overrideID, org.ID, svc.ID, "DB_URL",
		store.ServiceVariableUpsert{Value: "postgres://new", IsSecret: false})

	if updated.ID != baseline.ID {
		t.Errorf("Upsert(conflict) mutated id: was %q, now %q (caller-supplied id must be ignored on the conflict branch)",
			baseline.ID, updated.ID)
	}
	if updated.Value != "postgres://new" {
		t.Errorf("Upsert(conflict) value = %q, want postgres://new", updated.Value)
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("Upsert(conflict) version = %d, want %d", updated.Version, baseline.Version+1)
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("Upsert(conflict) mutated created_at")
	}
	if !updated.UpdatedAt.After(baseline.UpdatedAt) {
		t.Errorf("Upsert(conflict) updated_at = %v, want > baseline %v",
			updated.UpdatedAt, baseline.UpdatedAt)
	}
}

func TestServiceVariableRepositoryUpsertCrossTenantServiceReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "b-only")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcB := seedService(t, db, f, envB, "api")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx,
			newServiceVariableID(f, "cross"),
			orgA.ID, svcB.ID, "REGION",
			store.ServiceVariableUpsert{Value: "leak", IsSecret: false})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(cross-tenant svc) error = %v, want code %s", err, yerr.CodeConflict)
	}

	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx,
			newServiceVariableID(f, "ghost"),
			orgA.ID, "svc_does_not_exist", "REGION",
			store.ServiceVariableUpsert{Value: "leak", IsSecret: false})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(unknown svc) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestServiceVariableRepositoryUpsertDuplicatePrimaryKeyReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	id := newServiceVariableID(f, "dupe")
	upsertServiceVariable(ctx, t, s, repo, id, org.ID, svc.ID, "KEY_A",
		store.ServiceVariableUpsert{Value: "v1", IsSecret: false})

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, id, org.ID, svc.ID, "KEY_B",
			store.ServiceVariableUpsert{Value: "v2", IsSecret: false})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(duplicate id) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestServiceVariableRepositoryUpsertSecretConsistencyCheckReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx,
			newServiceVariableID(f, "drift"),
			org.ID, svc.ID, "API_TOKEN",
			store.ServiceVariableUpsert{
				Value:            "leaked-plaintext",
				IsSecret:         true,
				SecretProvider:   "plaintext-v1",
				SecretKeyID:      "plaintext",
				SecretCiphertext: []byte("ct"),
			})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(secret + plain value) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestServiceVariableRepositoryDeleteByServiceExceptKeysEmptyClearsAll(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	upsertServiceVariable(ctx, t, s, repo, newServiceVariableID(f, "a"), org.ID, svc.ID, "KEY_A",
		store.ServiceVariableUpsert{Value: "1", IsSecret: false})
	upsertServiceVariable(ctx, t, s, repo, newServiceVariableID(f, "b"), org.ID, svc.ID, "KEY_B",
		store.ServiceVariableUpsert{Value: "2", IsSecret: false})

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptKeys(ctx, tx, org.ID, svc.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptKeys(nil): %v", err)
	}
	if remaining := listServiceVariablesOrFail(ctx, t, s, repo, org.ID, svc.ID); len(remaining) != 0 {
		t.Errorf("after nil-keep clear %d rows remain, want 0", len(remaining))
	}

	upsertServiceVariable(ctx, t, s, repo, newServiceVariableID(f, "c"), org.ID, svc.ID, "KEY_C",
		store.ServiceVariableUpsert{Value: "3", IsSecret: false})
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptKeys(ctx, tx, org.ID, svc.ID, []string{})
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptKeys([]): %v", err)
	}
	if remaining := listServiceVariablesOrFail(ctx, t, s, repo, org.ID, svc.ID); len(remaining) != 0 {
		t.Errorf("after empty-keep clear %d rows remain, want 0", len(remaining))
	}
}

func TestServiceVariableRepositoryDeleteByServiceExceptKeysRetainsListed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	keeper := upsertServiceVariable(ctx, t, s, repo, newServiceVariableID(f, "keeper"), org.ID, svc.ID, "KEEP_ME",
		store.ServiceVariableUpsert{Value: "stay", IsSecret: false})
	dropped := upsertServiceVariable(ctx, t, s, repo, newServiceVariableID(f, "drop"), org.ID, svc.ID, "DROP_ME",
		store.ServiceVariableUpsert{Value: "gone", IsSecret: false})

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptKeys(ctx, tx, org.ID, svc.ID, []string{"KEEP_ME"})
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptKeys([KEEP_ME]): %v", err)
	}

	remaining := listServiceVariablesOrFail(ctx, t, s, repo, org.ID, svc.ID)
	if len(remaining) != 1 {
		t.Fatalf("after subset-keep %d rows remain, want 1", len(remaining))
	}
	if remaining[0].ID != keeper.ID {
		t.Errorf("survivor id = %q, want keeper %q", remaining[0].ID, keeper.ID)
	}
	if remaining[0].ID == dropped.ID {
		t.Errorf("dropped row %q survived", dropped.ID)
	}
}

func TestServiceVariableRepositoryDeleteByServiceExceptKeysIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "ledger")
	projB := seedProject(t, db, f, orgB, "ledger")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcA := seedService(t, db, f, envA, "api")
	svcB := seedService(t, db, f, envB, "api")
	bystander := upsertServiceVariable(ctx, t, s, repo, newServiceVariableID(f, "bystander"), orgB.ID, svcB.ID, "K",
		store.ServiceVariableUpsert{Value: "b", IsSecret: false})
	upsertServiceVariable(ctx, t, s, repo, newServiceVariableID(f, "victim"), orgA.ID, svcA.ID, "K",
		store.ServiceVariableUpsert{Value: "a", IsSecret: false})

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptKeys(ctx, tx, orgA.ID, svcB.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptKeys(cross-tenant): %v", err)
	}

	remainingB := listServiceVariablesOrFail(ctx, t, s, repo, orgB.ID, svcB.ID)
	if len(remainingB) != 1 || remainingB[0].ID != bystander.ID {
		t.Errorf("orgB rows after cross-tenant clear = %+v, want exactly bystander %q",
			remainingB, bystander.ID)
	}

	remainingA := listServiceVariablesOrFail(ctx, t, s, repo, orgA.ID, svcA.ID)
	if len(remainingA) != 1 {
		t.Errorf("orgA rows after cross-tenant clear = %+v, want exactly 1 (own variable)", remainingA)
	}
}

func TestServiceVariableRepositoryServiceDeleteCascades(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	upsertServiceVariable(ctx, t, s, repo, newServiceVariableID(f, "casc-a"), org.ID, svc.ID, "K1",
		store.ServiceVariableUpsert{Value: "1", IsSecret: false})
	upsertServiceVariable(ctx, t, s, repo, newServiceVariableID(f, "casc-b"), org.ID, svc.ID, "K2",
		store.ServiceVariableUpsert{Value: "2", IsSecret: false})

	// ServiceRepository.ScheduleDeletion is a soft delete; remove the
	// parent via raw SQL to fire ON DELETE CASCADE.
	if _, err := db.Exec(ctx, `DELETE FROM services WHERE id = $1`, svc.ID); err != nil {
		t.Fatalf("DELETE services: %v", err)
	}

	if remaining := listServiceVariablesOrFail(ctx, t, s, repo, org.ID, svc.ID); len(remaining) != 0 {
		t.Errorf("ListByService after parent delete returned %d rows, want 0", len(remaining))
	}
}

func TestServiceVariableRepositoryUpsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	id := newServiceVariableID(f, "rollback")

	bailout := serviceVariableTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, upErr := repo.Upsert(ctx, tx, id, org.ID, svc.ID, "ROLLBACK",
			store.ServiceVariableUpsert{Value: "should-not-stick", IsSecret: false}); upErr != nil {
			return upErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	listed := listServiceVariablesOrFail(ctx, t, s, repo, org.ID, svc.ID)
	for _, v := range listed {
		if v.ID == id {
			t.Errorf("rolled-back variable id %q is visible at ListByService; the transaction did NOT roll back", id)
		}
	}
}

type serviceVariableTxRollbackSentinel struct{}

func (serviceVariableTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this service variable transaction"
}

func TestServiceVariableRepositoryUpsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceVariableRepository()

	_, err := repo.Upsert(context.Background(), nil,
		"svar_irrelevant", "org_irrelevant", "svc_irrelevant", "KEY",
		store.ServiceVariableUpsert{Value: "v", IsSecret: false})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Upsert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

func TestServiceVariableRepositoryDeleteByServiceExceptKeysWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceVariableRepository()

	err := repo.DeleteByServiceExceptKeys(context.Background(), nil,
		"org_irrelevant", "svc_irrelevant", nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("DeleteByServiceExceptKeys(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
