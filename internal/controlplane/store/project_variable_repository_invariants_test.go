package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration and unit tests for ProjectVariableRepository (BE-0449).
// project_variable_test.go already covers ListByProject ordering,
// reader contracts, Upsert INSERT/UPDATE happy paths, cross-tenant
// upsert rejection, the bulk DeleteByProjectExceptKeys surface, and
// the nil-Tx guards. This file pins the row-shape, timestamp,
// optimistic-versioning, CHECK, CASCADE, and transaction-rollback
// invariants those tests do not anchor — the bookkeeping a regression
// in a trigger, an ON DELETE clause, or the secret-columns CHECK would
// silently break.
//
// What this file proves on top of project_variable_test.go:
//
//   - Upsert INSERT row shape: version=1 (the schema default),
//     created_at == updated_at byte-equal on a fresh row, non-zero
//     timestamps.
//   - Upsert ON CONFLICT UPDATE branch: id and created_at byte-equal
//     to the baseline (the caller-supplied id is ignored on the
//     conflict branch), bump_version increments version by exactly 1,
//     set_updated_at refreshes updated_at strictly after the baseline.
//   - Upsert duplicate PRIMARY KEY (id reused under a different
//     (organization_id, project_id, key) tuple) surfaces as a typed
//     apierr.Conflict via the PK uniqueness violation, not the
//     ON CONFLICT branch.
//   - Upsert with IsSecret=true + non-empty Value violates
//     project_variables_secret_columns_consistent and surfaces as
//     apierr.Conflict — secret bytes and plaintext can never share a
//     row.
//   - ON DELETE CASCADE from projects removes a project's variables
//     when the parent projects row is deleted.
//   - Upsert rolls back when the surrounding Write closure returns a
//     non-nil error — no half-written variable can survive an aborted
//     audit / policy step.

func TestProjectVariableRepositoryUpsertInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	id := "pvar_" + f.Project(org, "iv_insert").ID[len("prj_"):]

	var got store.ProjectVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Upsert(ctx, tx, id, org.ID, proj.ID, "REGION",
			store.ProjectVariableUpsert{Value: "us-east-1", IsSecret: false})
		if err != nil {
			return err
		}
		got = row
		return nil
	}); err != nil {
		t.Fatalf("Upsert(INSERT): %v", err)
	}

	if got.ID != id {
		t.Errorf("Upsert returned id %q, want %q", got.ID, id)
	}
	if got.Version != 1 {
		t.Errorf("Upsert version = %d, want 1 (schema default)", got.Version)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("Upsert returned zero timestamp: created_at=%v updated_at=%v", got.CreatedAt, got.UpdatedAt)
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Errorf("Upsert created_at = %v, updated_at = %v; the BEFORE UPDATE trigger must NOT have fired on a fresh row",
			got.CreatedAt, got.UpdatedAt)
	}
}

func TestProjectVariableRepositoryUpsertUpdateBranchPreservesIdentity(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	baselineID := "pvar_" + f.Project(org, "iv_baseline").ID[len("prj_"):]

	var baseline store.ProjectVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Upsert(ctx, tx, baselineID, org.ID, proj.ID, "DB_URL",
			store.ProjectVariableUpsert{Value: "postgres://old", IsSecret: false})
		if err != nil {
			return err
		}
		baseline = row
		return nil
	}); err != nil {
		t.Fatalf("Upsert(baseline): %v", err)
	}

	time.Sleep(time.Millisecond)

	overrideID := "pvar_" + f.Project(org, "iv_override").ID[len("prj_"):]
	var updated store.ProjectVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Upsert(ctx, tx, overrideID, org.ID, proj.ID, "DB_URL",
			store.ProjectVariableUpsert{Value: "postgres://new", IsSecret: false})
		if err != nil {
			return err
		}
		updated = row
		return nil
	}); err != nil {
		t.Fatalf("Upsert(conflict): %v", err)
	}

	if updated.ID != baseline.ID {
		t.Errorf("Upsert(conflict) mutated id: was %q, now %q (caller-supplied id must be ignored on the conflict branch)",
			baseline.ID, updated.ID)
	}
	if updated.Value != "postgres://new" {
		t.Errorf("Upsert(conflict) value = %q, want postgres://new", updated.Value)
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("Upsert(conflict) version = %d, want %d (bump_version must fire)",
			updated.Version, baseline.Version+1)
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("Upsert(conflict) mutated created_at")
	}
	if !updated.UpdatedAt.After(baseline.UpdatedAt) {
		t.Errorf("Upsert(conflict) updated_at = %v, want > baseline %v (set_updated_at must refresh)",
			updated.UpdatedAt, baseline.UpdatedAt)
	}
}

func TestProjectVariableRepositoryUpsertDuplicatePrimaryKeyReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	id := "pvar_" + f.Project(org, "iv_dupe").ID[len("prj_"):]

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Upsert(ctx, tx, id, org.ID, proj.ID, "KEY_A",
			store.ProjectVariableUpsert{Value: "v1", IsSecret: false})
		return err
	}); err != nil {
		t.Fatalf("Upsert(first): %v", err)
	}

	// Second Upsert reuses the id at a DIFFERENT key. The ON CONFLICT
	// branch keys on (organization_id, project_id, key) — different
	// key — so the failure path is the PRIMARY KEY (id) violation.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, id, org.ID, proj.ID, "KEY_B",
			store.ProjectVariableUpsert{Value: "v2", IsSecret: false})
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(duplicate id) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

func TestProjectVariableRepositoryUpsertSecretConsistencyCheckReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")

	// IsSecret=true with a non-empty Value violates the CHECK.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx,
			"pvar_"+f.Project(org, "iv_drift").ID[len("prj_"):],
			org.ID, proj.ID, "API_TOKEN",
			store.ProjectVariableUpsert{
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

func TestProjectVariableRepositoryProjectDeleteCascades(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Upsert(ctx, tx,
			"pvar_"+f.Project(org, "iv_cascade").ID[len("prj_"):],
			org.ID, proj.ID, "K1",
			store.ProjectVariableUpsert{Value: "v1", IsSecret: false})
		return err
	}); err != nil {
		t.Fatalf("Upsert(cascade fixture): %v", err)
	}

	// ProjectRepository.ScheduleDeletion is a soft delete; remove the
	// parent via raw SQL to trigger ON DELETE CASCADE.
	if _, err := db.Exec(ctx, `DELETE FROM projects WHERE id = $1`, proj.ID); err != nil {
		t.Fatalf("DELETE projects: %v", err)
	}

	var rows []store.ProjectVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, lerr := repo.ListByProject(ctx, q, org.ID, proj.ID)
		if lerr != nil {
			return lerr
		}
		rows = got
		return nil
	}); err != nil {
		t.Fatalf("ListByProject after CASCADE: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("ListByProject after parent delete returned %d rows, want 0 (ON DELETE CASCADE must remove children)",
			len(rows))
	}
}

func TestProjectVariableRepositoryUpsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	id := "pvar_" + f.Project(org, "iv_rollback").ID[len("prj_"):]

	bailout := projectVariableTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, upErr := repo.Upsert(ctx, tx, id, org.ID, proj.ID, "ROLLBACK_KEY",
			store.ProjectVariableUpsert{Value: "should-not-stick", IsSecret: false}); upErr != nil {
			return upErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	var rows []store.ProjectVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		got, lerr := repo.ListByProject(ctx, q, org.ID, proj.ID)
		if lerr != nil {
			return lerr
		}
		rows = got
		return nil
	}); err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	for _, v := range rows {
		if v.ID == id {
			t.Errorf("rolled-back variable id %q is visible at ListByProject; the transaction did NOT roll back", id)
		}
	}
}

// projectVariableTxRollbackSentinel is a typed error a transaction
// closure can return to force a rollback. Name is intentionally distinct
// from every other rollback sentinel in store_test to avoid a same-
// package collision.
type projectVariableTxRollbackSentinel struct{}

func (projectVariableTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this project variable transaction"
}
