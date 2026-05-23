package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration and unit tests for EnvironmentVariableRepository (BE-0449).
// environment_variable_test.go covers ListByEnvironment ordering and
// reader contracts only — the Upsert and DeleteByEnvironmentExceptKeys
// mutation surface is untested at the repository level. This file pins
// the row-shape, timestamp, optimistic-versioning, CHECK, FK, CASCADE,
// and transaction-rollback invariants the bulk-replace surface needs.
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
//     environment_id) surfaces typed apierr.Conflict — the composite
//     FK to environments refuses the row.
//   - Upsert duplicate PRIMARY KEY (id reused under a different
//     (organization_id, environment_id, key) tuple) surfaces as a
//     typed apierr.Conflict via the PK uniqueness violation.
//   - Upsert with IsSecret=true + non-empty Value violates the
//     environment_variables_secret_columns_consistent CHECK and
//     surfaces as apierr.Conflict.
//   - DeleteByEnvironmentExceptKeys with nil/empty keepKeys clears
//     every variable of the environment; with a non-empty list
//     retains exactly the listed keys; cross-tenant (organization_id,
//     environment_id) deletes nothing.
//   - ON DELETE CASCADE from environments removes a tenant's
//     variables when the parent environments row is deleted.
//   - Upsert rolls back when the surrounding Write closure returns a
//     non-nil error.
//   - Upsert / DeleteByEnvironmentExceptKeys nil-Tx guards render
//     typed apierr.Internal.

func newEnvironmentVariableID(f *testutil.Factory, label string) string {
	parent := testutil.Project{ID: "prj_irrelevant", OrganizationID: "org_irrelevant"}
	return "evar_" + f.Environment(parent, label).ID[len("env_"):]
}

func upsertEnvironmentVariable(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.EnvironmentVariableRepository,
	id, organizationID, environmentID, key string,
	in store.EnvironmentVariableUpsert,
) store.EnvironmentVariable {
	t.Helper()
	var stored store.EnvironmentVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Upsert(ctx, tx, id, organizationID, environmentID, key, in)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("upsert environment variable: %v", err)
	}
	return stored
}

func listEnvironmentVariablesOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.EnvironmentVariableRepository,
	organizationID, environmentID string,
) []store.EnvironmentVariable {
	t.Helper()
	var out []store.EnvironmentVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, lerr := repo.ListByEnvironment(ctx, q, organizationID, environmentID)
		if lerr != nil {
			return lerr
		}
		out = rows
		return nil
	}); err != nil {
		t.Fatalf("ListByEnvironment(%q, %q): %v", organizationID, environmentID, err)
	}
	return out
}

func TestEnvironmentVariableRepositoryUpsertInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	id := newEnvironmentVariableID(f, "insert")

	got := upsertEnvironmentVariable(ctx, t, s, repo, id, org.ID, env.ID, "REGION",
		store.EnvironmentVariableUpsert{Value: "us-east-1", IsSecret: false})

	if got.ID != id {
		t.Errorf("Upsert returned id %q, want %q", got.ID, id)
	}
	if got.OrganizationID != org.ID || got.EnvironmentID != env.ID {
		t.Errorf("Upsert returned (org=%q env=%q), want (org=%q env=%q)",
			got.OrganizationID, got.EnvironmentID, org.ID, env.ID)
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

func TestEnvironmentVariableRepositoryUpsertUpdateBranchPreservesIdentity(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	baselineID := newEnvironmentVariableID(f, "baseline")
	baseline := upsertEnvironmentVariable(ctx, t, s, repo, baselineID, org.ID, env.ID, "DB_URL",
		store.EnvironmentVariableUpsert{Value: "postgres://old", IsSecret: false})

	time.Sleep(time.Millisecond)

	overrideID := newEnvironmentVariableID(f, "override")
	updated := upsertEnvironmentVariable(ctx, t, s, repo, overrideID, org.ID, env.ID, "DB_URL",
		store.EnvironmentVariableUpsert{Value: "postgres://new", IsSecret: false})

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

func TestEnvironmentVariableRepositoryUpsertCrossTenantEnvironmentReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "b-only")
	envB := seedEnvironment(t, db, f, projB, "production")

	// orgA tries to attach a variable to orgB's environment via composite
	// FK (organization_id, environment_id). The FK refuses the insert
	// structurally.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx,
			newEnvironmentVariableID(f, "cross"),
			orgA.ID, envB.ID, "REGION",
			store.EnvironmentVariableUpsert{Value: "leak", IsSecret: false})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(cross-tenant env) error = %v, want code %s", err, yerr.CodeConflict)
	}

	// Unknown environment under orgA — same FK chokepoint, same typed
	// code.
	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx,
			newEnvironmentVariableID(f, "ghost"),
			orgA.ID, "env_does_not_exist", "REGION",
			store.EnvironmentVariableUpsert{Value: "leak", IsSecret: false})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(unknown env) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestEnvironmentVariableRepositoryUpsertDuplicatePrimaryKeyReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	id := newEnvironmentVariableID(f, "dupe")
	upsertEnvironmentVariable(ctx, t, s, repo, id, org.ID, env.ID, "KEY_A",
		store.EnvironmentVariableUpsert{Value: "v1", IsSecret: false})

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, id, org.ID, env.ID, "KEY_B",
			store.EnvironmentVariableUpsert{Value: "v2", IsSecret: false})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(duplicate id) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestEnvironmentVariableRepositoryUpsertSecretConsistencyCheckReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx,
			newEnvironmentVariableID(f, "drift"),
			org.ID, env.ID, "API_TOKEN",
			store.EnvironmentVariableUpsert{
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

func TestEnvironmentVariableRepositoryDeleteByEnvironmentExceptKeysEmptyClearsAll(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	upsertEnvironmentVariable(ctx, t, s, repo, newEnvironmentVariableID(f, "a"), org.ID, env.ID, "KEY_A",
		store.EnvironmentVariableUpsert{Value: "1", IsSecret: false})
	upsertEnvironmentVariable(ctx, t, s, repo, newEnvironmentVariableID(f, "b"), org.ID, env.ID, "KEY_B",
		store.EnvironmentVariableUpsert{Value: "2", IsSecret: false})

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptKeys(ctx, tx, org.ID, env.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptKeys(nil): %v", err)
	}
	if remaining := listEnvironmentVariablesOrFail(ctx, t, s, repo, org.ID, env.ID); len(remaining) != 0 {
		t.Errorf("after nil-keep clear %d rows remain, want 0", len(remaining))
	}

	upsertEnvironmentVariable(ctx, t, s, repo, newEnvironmentVariableID(f, "c"), org.ID, env.ID, "KEY_C",
		store.EnvironmentVariableUpsert{Value: "3", IsSecret: false})
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptKeys(ctx, tx, org.ID, env.ID, []string{})
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptKeys([]): %v", err)
	}
	if remaining := listEnvironmentVariablesOrFail(ctx, t, s, repo, org.ID, env.ID); len(remaining) != 0 {
		t.Errorf("after empty-keep clear %d rows remain, want 0", len(remaining))
	}
}

func TestEnvironmentVariableRepositoryDeleteByEnvironmentExceptKeysRetainsListed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	keeper := upsertEnvironmentVariable(ctx, t, s, repo, newEnvironmentVariableID(f, "keeper"), org.ID, env.ID, "KEEP_ME",
		store.EnvironmentVariableUpsert{Value: "stay", IsSecret: false})
	dropped := upsertEnvironmentVariable(ctx, t, s, repo, newEnvironmentVariableID(f, "drop"), org.ID, env.ID, "DROP_ME",
		store.EnvironmentVariableUpsert{Value: "gone", IsSecret: false})

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptKeys(ctx, tx, org.ID, env.ID, []string{"KEEP_ME"})
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptKeys([KEEP_ME]): %v", err)
	}

	remaining := listEnvironmentVariablesOrFail(ctx, t, s, repo, org.ID, env.ID)
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

func TestEnvironmentVariableRepositoryDeleteByEnvironmentExceptKeysIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "ledger")
	projB := seedProject(t, db, f, orgB, "ledger")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	bystander := upsertEnvironmentVariable(ctx, t, s, repo, newEnvironmentVariableID(f, "bystander"), orgB.ID, envB.ID, "K",
		store.EnvironmentVariableUpsert{Value: "b", IsSecret: false})
	upsertEnvironmentVariable(ctx, t, s, repo, newEnvironmentVariableID(f, "victim"), orgA.ID, envA.ID, "K",
		store.EnvironmentVariableUpsert{Value: "a", IsSecret: false})

	// orgA targets orgB's envID. Composite WHERE matches zero rows.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptKeys(ctx, tx, orgA.ID, envB.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptKeys(cross-tenant): %v", err)
	}

	remainingB := listEnvironmentVariablesOrFail(ctx, t, s, repo, orgB.ID, envB.ID)
	if len(remainingB) != 1 || remainingB[0].ID != bystander.ID {
		t.Errorf("orgB rows after cross-tenant clear = %+v, want exactly bystander %q",
			remainingB, bystander.ID)
	}

	remainingA := listEnvironmentVariablesOrFail(ctx, t, s, repo, orgA.ID, envA.ID)
	if len(remainingA) != 1 {
		t.Errorf("orgA rows after cross-tenant clear = %+v, want exactly 1 (own variable)", remainingA)
	}
}

func TestEnvironmentVariableRepositoryEnvironmentDeleteCascades(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	upsertEnvironmentVariable(ctx, t, s, repo, newEnvironmentVariableID(f, "casc-a"), org.ID, env.ID, "K1",
		store.EnvironmentVariableUpsert{Value: "1", IsSecret: false})
	upsertEnvironmentVariable(ctx, t, s, repo, newEnvironmentVariableID(f, "casc-b"), org.ID, env.ID, "K2",
		store.EnvironmentVariableUpsert{Value: "2", IsSecret: false})

	// EnvironmentRepository.ScheduleDeletion is a soft delete; remove
	// the parent via raw SQL to fire ON DELETE CASCADE.
	if _, err := db.Exec(ctx, `DELETE FROM environments WHERE id = $1`, env.ID); err != nil {
		t.Fatalf("DELETE environments: %v", err)
	}

	if remaining := listEnvironmentVariablesOrFail(ctx, t, s, repo, org.ID, env.ID); len(remaining) != 0 {
		t.Errorf("ListByEnvironment after parent delete returned %d rows, want 0", len(remaining))
	}
}

func TestEnvironmentVariableRepositoryUpsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	id := newEnvironmentVariableID(f, "rollback")

	bailout := environmentVariableTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, upErr := repo.Upsert(ctx, tx, id, org.ID, env.ID, "ROLLBACK",
			store.EnvironmentVariableUpsert{Value: "should-not-stick", IsSecret: false}); upErr != nil {
			return upErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	listed := listEnvironmentVariablesOrFail(ctx, t, s, repo, org.ID, env.ID)
	for _, v := range listed {
		if v.ID == id {
			t.Errorf("rolled-back variable id %q is visible at ListByEnvironment; the transaction did NOT roll back", id)
		}
	}
}

type environmentVariableTxRollbackSentinel struct{}

func (environmentVariableTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this environment variable transaction"
}

func TestEnvironmentVariableRepositoryUpsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewEnvironmentVariableRepository()

	_, err := repo.Upsert(context.Background(), nil,
		"evar_irrelevant", "org_irrelevant", "env_irrelevant", "KEY",
		store.EnvironmentVariableUpsert{Value: "v", IsSecret: false})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Upsert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

func TestEnvironmentVariableRepositoryDeleteByEnvironmentExceptKeysWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewEnvironmentVariableRepository()

	err := repo.DeleteByEnvironmentExceptKeys(context.Background(), nil,
		"org_irrelevant", "env_irrelevant", nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("DeleteByEnvironmentExceptKeys(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
