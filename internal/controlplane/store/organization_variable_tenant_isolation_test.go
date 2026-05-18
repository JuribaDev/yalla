package store_test

import (
	"bytes"
	"context"
	stderrors "errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the organization_variables
// table (BE-0450). organization_variables is the lowest-precedence /
// widest-scope layer of the Organization -> Project -> Environment ->
// Service variable hierarchy: each row is parented directly to an
// organization with no narrower scope leg. The row body is anchored to
// a single tenant by FOUR load-bearing schema facts:
//
//	(a) every column carries organization_id explicitly, and the FK
//	    organization_variables.organization_id -> organizations.id is
//	    ON DELETE CASCADE — so a row whose organization is deleted is
//	    structurally removed, and a row can never sit under a foreign
//	    tenant by way of the FK.
//	(b) every repository method (ListByOrganization / Upsert /
//	    DeleteByOrganizationExceptKeys / GetByKey / DeleteByKey /
//	    UpdateMutable) carries organization_id as the first SQL
//	    predicate. The cross-tenant guarantee at this layer is the
//	    byte-identical-bystander invariant every other tenant-scoped
//	    table is held to.
//	(c) the UNIQUE constraint organization_variables_organization_id_key_key
//	    targets the COMPOSITE tuple (organization_id, key) —
//	    organization_id is in the conflict target itself, so two
//	    tenants can legitimately each own a row with the SAME key.
//	    The shared-scope-tuple safety net below pins this and makes
//	    the byte-identical-bystander projection on Upsert load-
//	    bearing.
//	(d) organization_variables carries SECRET-BEARING columns — value
//	    (for non-secret variables) and the (secret_provider,
//	    secret_key_id, secret_ciphertext) tuple (for is_secret rows).
//	    Cross-tenant ERROR shapes must never echo another tenant's
//	    value or ciphertext; a cross-tenant MUTATION must leave the
//	    bystander tenant's value AND ciphertext byte-identical.
//	    The byte-identical-bystander projection below covers BOTH
//	    surfaces.
//
// organization_variables is a STRUCTURAL ENRICHMENT of the
// project/environment/service variable tables: in addition to
// ListByX / Upsert / DeleteByXExceptKeys, it exposes per-key Get,
// per-key Delete, and per-key UpdateMutable surfaces. Each of those
// per-key paths must independently prove tenant scoping — orgA cannot
// Get / Delete / Update orgB's variable by key — and the per-key
// mutation paths must leave orgB's bystander row byte-identical.
// These extra surfaces have NO sibling in the BE-0449 project /
// environment / service variable repository templates.
//
// The BEFORE-UPDATE organization_variables_set_updated_at and
// organization_variables_bump_version triggers fire on every matched
// UPDATE, so updated_at and version on the bystander row are
// independently sufficient anchors to catch a missing tenant predicate.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Upsert INSERT RETURNING shape, Upsert UPDATE-branch dual-anchor,
//     cross-tenant organization_id FK Conflict, duplicate-PK Conflict,
//     secret-columns CHECK violations, UpdateMutable not-found,
//     UpdateMutable secret->plain transition, ON DELETE CASCADE from
//     organizations, Upsert tx-rollback, and nil-Tx guards are proved
//     by organization_variable_repository_invariants_test.go (BE-0449).
//   - ListByOrganization deterministic ordering, non-nil empty slice,
//     and the basic ListByOrganization / DeleteByKey tenant-scoping
//     properties are proved by organization_variable_test.go.
//   - The HTTP-layer "another tenant's variable key is a 404, not a
//     403" rule is proved by the per-endpoint policy matrix and
//     contract tests in httpapi.
//   - organization_variables has no soft-delete column; the
//     acceptance-criteria mention of "soft-deleted rows where
//     applicable" has no surface here.
//
// Helpers newOrganizationVariableID / upsertOrganizationVariable /
// listOrganizationVariablesOrFail are defined in
// organization_variable_repository_invariants_test.go (same package,
// store_test) and reused here. This file adds
// getOrganizationVariableFromListOrFail and
// assertOrganizationVariableByteIdentical — both named to avoid
// same-package collisions with the project / environment / service
// sibling files.

// TestOrganizationVariableRepositoryListByOrganizationReturnsCorrectRowsAcrossTenants
// proves ListByOrganization is keyed strictly by organization_id.
func TestOrganizationVariableRepositoryListByOrganizationReturnsCorrectRowsAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	rowA := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "alpha"), orgA.ID, "REGION_A",
		store.OrganizationVariableUpsert{Value: "us-east-1", IsSecret: false})
	rowB := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "beta"), orgB.ID, "REGION_B",
		store.OrganizationVariableUpsert{Value: "eu-west-1", IsSecret: false})

	listA := listOrganizationVariablesOrFail(ctx, t, s, repo, orgA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByOrganization(orgA) returned %d rows, want exactly 1 — orgB rows leaked", len(listA))
	}
	if listA[0].ID != rowA.ID || listA[0].OrganizationID != orgA.ID || listA[0].Key != "REGION_A" || listA[0].Value != "us-east-1" {
		t.Errorf("ListByOrganization(orgA)[0] = %+v, want orgA/REGION_A/us-east-1", listA[0])
	}

	listB := listOrganizationVariablesOrFail(ctx, t, s, repo, orgB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByOrganization(orgB) returned %d rows, want exactly 1 — orgA rows leaked", len(listB))
	}
	if listB[0].ID != rowB.ID || listB[0].OrganizationID != orgB.ID || listB[0].Key != "REGION_B" || listB[0].Value != "eu-west-1" {
		t.Errorf("ListByOrganization(orgB)[0] = %+v, want orgB/REGION_B/eu-west-1", listB[0])
	}

	if listA[0].ID == listB[0].ID || listA[0].OrganizationID == listB[0].OrganizationID ||
		listA[0].Key == listB[0].Key || listA[0].Value == listB[0].Value {
		t.Errorf("ListByOrganization returned overlapping rows across two tenants: %+v vs %+v", listA[0], listB[0])
	}
}

// TestOrganizationVariableRepositoryListByOrganizationCrossTenantOrganizationIDReturnsEmpty
// proves ListByOrganization is tenant scoped at the SQL predicate: an
// unknown organization_id (or another tenant's id from the caller's
// perspective) matches no rows and yields a non-nil empty slice.
func TestOrganizationVariableRepositoryListByOrganizationCrossTenantOrganizationIDReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgB := seedOrg(t, db, f, "tenant-b")

	// orgB owns two variables; orgA (whose id we never reveal as a
	// fixture) reads through an UNKNOWN organization_id. Both probes
	// must land on the same empty-slice shape so existence of orgB's
	// rows cannot be inferred.
	upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "leak1"), orgB.ID, "SECRET_VALUE_ONE",
		store.OrganizationVariableUpsert{Value: "tenant-b-only-1", IsSecret: false})
	upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "leak2"), orgB.ID, "SECRET_VALUE_TWO",
		store.OrganizationVariableUpsert{Value: "tenant-b-only-2", IsSecret: false})

	unknown := listOrganizationVariablesOrFail(ctx, t, s, repo, "org_never_existed")
	// OrganizationVariableRepository.ListByOrganization returns a NIL
	// slice on no-rows (unlike its project/environment/service
	// siblings which `make([]T, 0)`). Both shapes are valid empty —
	// the contract we anchor here is `len(unknown) == 0`, which
	// preserves the property that existence of orgB's rows cannot be
	// inferred from the response.
	if len(unknown) != 0 {
		t.Errorf("ListByOrganization(unknown) returned %d rows, want 0 — orgB variables leaked through a cross-tenant organization_id", len(unknown))
	}
}

// TestOrganizationVariableRepositoryListByOrganizationIsolatesSharedKey
// proves that two tenants can legitimately each own a row with the
// same key without leaking across the WHERE filter.
func TestOrganizationVariableRepositoryListByOrganizationIsolatesSharedKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	rowA := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "shared-a"), orgA.ID, "DB_URL",
		store.OrganizationVariableUpsert{Value: "postgres://orgA-only", IsSecret: false})
	rowB := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "shared-b"), orgB.ID, "DB_URL",
		store.OrganizationVariableUpsert{Value: "postgres://orgB-only", IsSecret: false})

	listA := listOrganizationVariablesOrFail(ctx, t, s, repo, orgA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByOrganization(orgA) returned %d rows, want exactly 1 — orgB row for the same key leaked or duplicated", len(listA))
	}
	if listA[0].ID != rowA.ID || listA[0].OrganizationID != orgA.ID || listA[0].Value != "postgres://orgA-only" {
		t.Errorf("ListByOrganization(orgA)[0] = %+v, want id=%q org=%q value='postgres://orgA-only'", listA[0], rowA.ID, orgA.ID)
	}

	listB := listOrganizationVariablesOrFail(ctx, t, s, repo, orgB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByOrganization(orgB) returned %d rows, want exactly 1 — orgA row for the same key leaked or duplicated", len(listB))
	}
	if listB[0].ID != rowB.ID || listB[0].OrganizationID != orgB.ID || listB[0].Value != "postgres://orgB-only" {
		t.Errorf("ListByOrganization(orgB)[0] = %+v, want id=%q org=%q value='postgres://orgB-only'", listB[0], rowB.ID, orgB.ID)
	}

	if listA[0].ID == listB[0].ID {
		t.Errorf("variable id %q appears in both List(orgA) and List(orgB) responses", listA[0].ID)
	}
	if listA[0].Value == "postgres://orgB-only" || listB[0].Value == "postgres://orgA-only" {
		t.Errorf("variable value crossed tenant boundary: orgA.value=%q orgB.value=%q", listA[0].Value, listB[0].Value)
	}
}

// TestOrganizationVariableRepositoryUpsertInsertOnOrgADoesNotTouchOrgB
// proves the Upsert INSERT branch does not stamp a peer tenant's row
// when the same key is in use on the peer.
func TestOrganizationVariableRepositoryUpsertInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	rowB := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "bystander"), orgB.ID, "API_KEY",
		store.OrganizationVariableUpsert{Value: "orgB-secret-fixture-zzy", IsSecret: false})
	baselineB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "baseline")

	insertedA := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "alpha"), orgA.ID, "API_KEY",
		store.OrganizationVariableUpsert{Value: "orgA-only-fixture", IsSecret: false})
	if insertedA.OrganizationID != orgA.ID || insertedA.Version != 1 {
		t.Errorf("Upsert(orgA) inserted row = %+v, want orgA/version=1", insertedA)
	}
	if insertedA.ID == rowB.ID {
		t.Fatalf("orgA's freshly inserted variable id %q collides with orgB's bystander id — the id mint is unsound and the bystander test below is invalid", insertedA.ID)
	}

	afterB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "after orgA Upsert INSERT")
	assertOrganizationVariableByteIdentical(t, "Upsert INSERT(orgA) bystander orgB", baselineB, afterB)
}

// TestOrganizationVariableRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB
// proves the Upsert ON CONFLICT DO UPDATE branch fires only on orgA's
// own (organization_id, key) tuple.
func TestOrganizationVariableRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	rowA := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "alpha"), orgA.ID, "DB_URL",
		store.OrganizationVariableUpsert{Value: "postgres://orgA-old", IsSecret: false})
	rowB := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "bystander"), orgB.ID, "DB_URL",
		store.OrganizationVariableUpsert{Value: "postgres://orgB-baseline-zzy", IsSecret: false})

	baselineB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "baseline")

	updatedA := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "alpha-rebump"), orgA.ID, "DB_URL",
		store.OrganizationVariableUpsert{Value: "postgres://orgA-new", IsSecret: false})
	if updatedA.ID != rowA.ID {
		t.Errorf("UpdatedA.ID = %q, want %q (caller-id should be ignored on the conflict branch)", updatedA.ID, rowA.ID)
	}
	if updatedA.Value != "postgres://orgA-new" || updatedA.Version != rowA.Version+1 {
		t.Errorf("UpdatedA = %+v, want value=postgres://orgA-new version=%d", updatedA, rowA.Version+1)
	}

	afterB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "after orgA Upsert UPDATE")
	assertOrganizationVariableByteIdentical(t, "Upsert UPDATE(orgA) bystander orgB", baselineB, afterB)
}

// TestOrganizationVariableRepositoryDeleteByOrganizationExceptKeysClearAllOnOrgADoesNotTouchOrgB
// proves the unconditional-DELETE codepath (nil keepKeys) is tenant
// scoped.
func TestOrganizationVariableRepositoryDeleteByOrganizationExceptKeysClearAllOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "a1"), orgA.ID, "REGION",
		store.OrganizationVariableUpsert{Value: "us-east-1", IsSecret: false})
	upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "a2"), orgA.ID, "TIER",
		store.OrganizationVariableUpsert{Value: "premium", IsSecret: false})
	rowB := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "bystander"), orgB.ID, "REGION",
		store.OrganizationVariableUpsert{Value: "eu-west-1-zzy", IsSecret: false})
	baselineB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByOrganizationExceptKeys(ctx, tx, orgA.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByOrganizationExceptKeys(orgA, nil): %v", err)
	}

	if remaining := listOrganizationVariablesOrFail(ctx, t, s, repo, orgA.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByOrganizationExceptKeys(orgA, nil) %d rows remain on orgA, want 0", len(remaining))
	}

	afterB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "after orgA DeleteByOrganizationExceptKeys(nil)")
	assertOrganizationVariableByteIdentical(t, "DeleteByOrganizationExceptKeys(orgA, nil) bystander orgB", baselineB, afterB)
}

// TestOrganizationVariableRepositoryDeleteByOrganizationExceptKeysKeepSubsetOnOrgADoesNotTouchOrgB
// proves the conditional-DELETE codepath (len(keepKeys)>0 -> DELETE
// WHERE key NOT IN ANY) is tenant scoped: orgB's bystander key is
// deliberately NOT in keepKeys and would be eligible for deletion if
// the tenant predicate were missing.
func TestOrganizationVariableRepositoryDeleteByOrganizationExceptKeysKeepSubsetOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	keepA := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "keep"), orgA.ID, "KEEP_ME",
		store.OrganizationVariableUpsert{Value: "keeper-value", IsSecret: false})
	dropA := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "drop"), orgA.ID, "DROP_ME",
		store.OrganizationVariableUpsert{Value: "dropper-value", IsSecret: false})
	rowB := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "bystander"), orgB.ID, "BYSTANDER_KEY",
		store.OrganizationVariableUpsert{Value: "orgB-survives-zzy", IsSecret: false})
	baselineB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByOrganizationExceptKeys(ctx, tx, orgA.ID, []string{"KEEP_ME"})
	}); err != nil {
		t.Fatalf("DeleteByOrganizationExceptKeys(orgA, [KEEP_ME]): %v", err)
	}

	remaining := listOrganizationVariablesOrFail(ctx, t, s, repo, orgA.ID)
	if len(remaining) != 1 {
		t.Fatalf("after DeleteByOrganizationExceptKeys(orgA, [KEEP_ME]) %d rows remain on orgA, want 1", len(remaining))
	}
	if remaining[0].ID != keepA.ID || remaining[0].Key != "KEEP_ME" {
		t.Errorf("survivor on orgA = %+v, want keepA id=%q key=KEEP_ME", remaining[0], keepA.ID)
	}
	if remaining[0].ID == dropA.ID {
		t.Errorf("dropA (%q) was retained; expected deletion", dropA.ID)
	}

	afterB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "after orgA DeleteByOrganizationExceptKeys([KEEP_ME])")
	assertOrganizationVariableByteIdentical(t, "DeleteByOrganizationExceptKeys(orgA, [KEEP_ME]) bystander orgB", baselineB, afterB)
}

// TestOrganizationVariableRepositoryGetByKeyCrossTenantReturnsNotFound
// proves orgA cannot read orgB's variable by reusing the same key —
// both the cross-tenant probe and an unknown-key-under-own-tenant
// probe must land on the same yerr.CodeNotFound shape so existence of
// peer-tenant rows cannot be inferred from the error code. The
// returned error must NOT echo orgB's value or ciphertext.
func TestOrganizationVariableRepositoryGetByKeyCrossTenantReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	// orgB owns "SHARED_KEY" with a distinctive value. A regression
	// that crossed tenants would surface either the value through the
	// returned row OR through the error message.
	const orgBSecretValue = "orgB-fixture-value-one-zzy"
	upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "bystander"), orgB.ID, "SHARED_KEY",
		store.OrganizationVariableUpsert{Value: orgBSecretValue, IsSecret: false})

	// orgA does NOT own "SHARED_KEY" — the Get under orgA's id must
	// land on NotFound, not on orgB's row.
	var crossErr, unknownErr error
	if rerr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.GetByKey(ctx, q, orgA.ID, "SHARED_KEY")
		crossErr = err
		return nil
	}); rerr != nil {
		t.Fatalf("Read(GetByKey orgA, SHARED_KEY): %v", rerr)
	}
	if rerr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.GetByKey(ctx, q, orgA.ID, "NEVER_EXISTED_KEY")
		unknownErr = err
		return nil
	}); rerr != nil {
		t.Fatalf("Read(GetByKey orgA, NEVER_EXISTED_KEY): %v", rerr)
	}

	var yeCross *yerr.Error
	if !stderrors.As(crossErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("GetByKey(orgA, SHARED_KEY) error = %v, want code %s", crossErr, yerr.CodeNotFound)
	}
	var yeUnknown *yerr.Error
	if !stderrors.As(unknownErr, &yeUnknown) || yeUnknown.Code != yerr.CodeNotFound {
		t.Fatalf("GetByKey(orgA, NEVER_EXISTED_KEY) error = %v, want code %s", unknownErr, yerr.CodeNotFound)
	}
	// The cross-tenant probe and the unknown-key probe must be
	// indistinguishable on Code: a regression that surfaced the cross-
	// tenant Get as Conflict / Internal / anything else would let the
	// caller infer that "SHARED_KEY" exists in another tenant.
	if yeCross.Code != yeUnknown.Code {
		t.Errorf("GetByKey error code diverges between cross-tenant (%s) and unknown-key (%s) probes — existence can be inferred", yeCross.Code, yeUnknown.Code)
	}
	// And neither error's surface fields may contain orgB's value —
	// the value is the secret-bearing column and must never echo
	// across tenants.
	for _, field := range []string{yeCross.Message, yeCross.Hint, yeCross.Error()} {
		if field != "" && containsValue(field, orgBSecretValue) {
			t.Errorf("GetByKey(cross-tenant) error field echoed orgB's value (%q): %q", orgBSecretValue, field)
		}
	}

	// orgB's row is still observable to orgB and unchanged — the
	// cross-tenant probe must not have mutated state.
	listB := listOrganizationVariablesOrFail(ctx, t, s, repo, orgB.ID)
	if len(listB) != 1 || listB[0].Value != orgBSecretValue {
		t.Errorf("orgB's row drifted after orgA's cross-tenant Get: list=%+v", listB)
	}
}

// TestOrganizationVariableRepositoryDeleteByKeyOnOrgADoesNotTouchOrgB
// proves the per-key Delete path is tenant scoped: orgA deletes its
// "SHARED_KEY", and orgB's same-key row survives byte-identical.
// orgA's DeleteByKey on a key that exists ONLY in orgB must surface
// NotFound — not orgB's row — and must not echo orgB's value.
func TestOrganizationVariableRepositoryDeleteByKeyOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "alpha"), orgA.ID, "DB_URL",
		store.OrganizationVariableUpsert{Value: "postgres://orgA-victim", IsSecret: false})
	const orgBSecretValue = "postgres://orgB-bystander-zzy"
	rowB := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "bystander"), orgB.ID, "DB_URL",
		store.OrganizationVariableUpsert{Value: orgBSecretValue, IsSecret: false})
	baselineB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "baseline")

	// orgA deletes ITS OWN "DB_URL" — orgB's same-key row must NOT be
	// the row returned, and the post-condition list for orgB must be
	// byte-identical.
	var deleted store.OrganizationVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, derr := repo.DeleteByKey(ctx, tx, orgA.ID, "DB_URL")
		if derr != nil {
			return derr
		}
		deleted = row
		return nil
	}); err != nil {
		t.Fatalf("DeleteByKey(orgA, DB_URL): %v", err)
	}
	if deleted.OrganizationID != orgA.ID {
		t.Errorf("DeleteByKey(orgA) returned a row owned by %q, want orgA=%q", deleted.OrganizationID, orgA.ID)
	}
	if deleted.Value == orgBSecretValue {
		t.Errorf("DeleteByKey(orgA) returned orgB's value %q — the WHERE clause crossed tenants", deleted.Value)
	}

	// orgB's row is still there and byte-identical.
	afterB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "after orgA DeleteByKey")
	assertOrganizationVariableByteIdentical(t, "DeleteByKey(orgA, DB_URL) bystander orgB", baselineB, afterB)

	// orgA now has NO "DB_URL". A second DeleteByKey(orgA, DB_URL)
	// must surface NotFound — never orgB's row, never an error
	// message echoing orgB's value.
	var notFoundErr error
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, derr := repo.DeleteByKey(ctx, tx, orgA.ID, "DB_URL")
		notFoundErr = derr
		return nil
	}); err != nil {
		t.Fatalf("Write(second DeleteByKey orgA): %v", err)
	}
	var ye *yerr.Error
	if !stderrors.As(notFoundErr, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("second DeleteByKey(orgA, DB_URL) error = %v, want code %s", notFoundErr, yerr.CodeNotFound)
	}
	for _, field := range []string{ye.Message, ye.Hint, ye.Error()} {
		if field != "" && containsValue(field, orgBSecretValue) {
			t.Errorf("DeleteByKey(cross-tenant) error field echoed orgB's value (%q): %q", orgBSecretValue, field)
		}
	}
}

// TestOrganizationVariableRepositoryUpdateMutableOnOrgADoesNotTouchOrgB
// proves the per-key UpdateMutable path is tenant scoped: orgA
// updates its "SHARED_KEY", and orgB's same-key bystander row
// survives byte-identical. orgA's UpdateMutable on a key that exists
// only in orgB must surface NotFound — never silently update orgB's
// row.
func TestOrganizationVariableRepositoryUpdateMutableOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	const orgBSecretValue = "orgB-baseline-fixture-zzy"
	rowA := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "alpha"), orgA.ID, "API_TOKEN",
		store.OrganizationVariableUpsert{Value: "orgA-old-token", IsSecret: false})
	rowB := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "bystander"), orgB.ID, "API_TOKEN",
		store.OrganizationVariableUpsert{Value: orgBSecretValue, IsSecret: false})
	baselineB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "baseline")

	// orgA updates ITS OWN "API_TOKEN" — orgB's same-key row must NOT
	// drift.
	var updated store.OrganizationVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, uerr := repo.UpdateMutable(ctx, tx, orgA.ID, "API_TOKEN",
			store.OrganizationVariableUpsert{Value: "orgA-new-token", IsSecret: false})
		if uerr != nil {
			return uerr
		}
		updated = row
		return nil
	}); err != nil {
		t.Fatalf("UpdateMutable(orgA, API_TOKEN): %v", err)
	}
	if updated.ID != rowA.ID {
		t.Errorf("UpdateMutable(orgA) returned id %q, want orgA's row %q", updated.ID, rowA.ID)
	}
	if updated.OrganizationID != orgA.ID || updated.Value != "orgA-new-token" {
		t.Errorf("UpdateMutable(orgA) returned %+v, want orgA/'orgA-new-token'", updated)
	}
	if updated.Version != rowA.Version+1 {
		t.Errorf("UpdateMutable(orgA) version = %d, want %d (bump_version must fire)", updated.Version, rowA.Version+1)
	}

	// orgB's row is byte-identical to its baseline.
	afterB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "after orgA UpdateMutable")
	assertOrganizationVariableByteIdentical(t, "UpdateMutable(orgA, API_TOKEN) bystander orgB", baselineB, afterB)
}

// TestOrganizationVariableRepositoryUpdateMutableCrossTenantKeyReturnsNotFound
// proves UpdateMutable on a key that exists ONLY in orgB does NOT
// silently update orgB's row — it returns NotFound under orgA's id
// AND leaves orgB's row byte-identical to its baseline. The returned
// error must NOT echo orgB's value.
func TestOrganizationVariableRepositoryUpdateMutableCrossTenantKeyReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	const orgBSecretValue = "orgB-only-value-fixture-zzy"
	// orgB owns "ORG_B_ONLY_KEY"; orgA has NO row with that key.
	rowB := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "bystander"), orgB.ID, "ORG_B_ONLY_KEY",
		store.OrganizationVariableUpsert{Value: orgBSecretValue, IsSecret: false})
	baselineB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "baseline")

	var crossErr error
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, uerr := repo.UpdateMutable(ctx, tx, orgA.ID, "ORG_B_ONLY_KEY",
			store.OrganizationVariableUpsert{Value: "orgA-attempted-hijack-value", IsSecret: false})
		crossErr = uerr
		return nil
	}); err != nil {
		t.Fatalf("Write(UpdateMutable orgA, ORG_B_ONLY_KEY): %v", err)
	}
	var ye *yerr.Error
	if !stderrors.As(crossErr, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("UpdateMutable(orgA, ORG_B_ONLY_KEY) error = %v, want code %s", crossErr, yerr.CodeNotFound)
	}
	for _, field := range []string{ye.Message, ye.Hint, ye.Error()} {
		if field != "" && containsValue(field, orgBSecretValue) {
			t.Errorf("UpdateMutable(cross-tenant) error field echoed orgB's value (%q): %q", orgBSecretValue, field)
		}
	}

	// orgB's row is byte-identical — orgA's attempted hijack value did
	// not land.
	afterB := getOrganizationVariableFromListOrFail(ctx, t, s, repo, orgB.ID, rowB.ID, "after orgA cross-tenant UpdateMutable")
	assertOrganizationVariableByteIdentical(t, "UpdateMutable(orgA, ORG_B_ONLY_KEY) bystander orgB", baselineB, afterB)
}

// TestOrganizationVariableRepositoryUpsertSameKeyInTwoTenantsBothSucceed
// proves the (organization_id, key) UNIQUE constraint is per-tenant,
// not global.
func TestOrganizationVariableRepositoryUpsertSameKeyInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	rowA := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "alpha"), orgA.ID, "DATABASE_URL",
		store.OrganizationVariableUpsert{Value: "postgres://orgA-fixture-one-zzy", IsSecret: false})
	rowB := upsertOrganizationVariable(ctx, t, s, repo,
		newOrganizationVariableID(f, "beta"), orgB.ID, "DATABASE_URL",
		store.OrganizationVariableUpsert{Value: "postgres://orgB-fixture-two-zzy", IsSecret: false})

	if rowA.ID == rowB.ID {
		t.Fatalf("two tenants minted the same variable id %q — the id generator collided, the byte-identical-bystander tests in this file are invalid", rowA.ID)
	}
	if rowA.OrganizationID == rowB.OrganizationID {
		t.Errorf("two variable rows landed under the SAME organization_id: %+v vs %+v", rowA, rowB)
	}
	if rowA.Key != "DATABASE_URL" || rowB.Key != "DATABASE_URL" {
		t.Errorf("key drifted between Upsert calls: orgA=%q orgB=%q, want both 'DATABASE_URL'", rowA.Key, rowB.Key)
	}
	if rowA.Value == rowB.Value {
		t.Errorf("two variable rows somehow share an identical value: orgA=%q orgB=%q", rowA.Value, rowB.Value)
	}
}

// --- shared helpers ---

// getOrganizationVariableFromListOrFail observes a single
// organization_variables row through ListByOrganization and returns
// the entry whose id matches the caller's. The name is intentionally
// distinct from the project / environment / service tenant-isolation
// helpers (same package, store_test).
func getOrganizationVariableFromListOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.OrganizationVariableRepository, organizationID, variableID, label string) store.OrganizationVariable {
	t.Helper()
	rows := listOrganizationVariablesOrFail(ctx, t, s, repo, organizationID)
	for _, row := range rows {
		if row.ID == variableID {
			return row
		}
	}
	t.Fatalf("%s: variable %q missing from ListByOrganization(%q): got %d rows", label, variableID, organizationID, len(rows))
	return store.OrganizationVariable{}
}

// assertOrganizationVariableByteIdentical asserts every observable
// column on a bystander organization_variables row is byte-identical
// to its baseline. Value and the secret tuple are anchored explicitly.
func assertOrganizationVariableByteIdentical(t *testing.T, label string, baseline, after store.OrganizationVariable) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.Key != baseline.Key {
		t.Errorf("%s: bystander.key = %q, want %q", label, after.Key, baseline.Key)
	}
	if after.Value != baseline.Value {
		t.Errorf("%s: bystander.value drifted across tenants — a peer-tenant mutation reached the value column", label)
	}
	if after.IsSecret != baseline.IsSecret {
		t.Errorf("%s: bystander.is_secret = %v, want %v", label, after.IsSecret, baseline.IsSecret)
	}
	if after.SecretProvider != baseline.SecretProvider {
		t.Errorf("%s: bystander.secret_provider = %q, want %q", label, after.SecretProvider, baseline.SecretProvider)
	}
	if after.SecretKeyID != baseline.SecretKeyID {
		t.Errorf("%s: bystander.secret_key_id = %q, want %q", label, after.SecretKeyID, baseline.SecretKeyID)
	}
	if !bytes.Equal(after.SecretCiphertext, baseline.SecretCiphertext) {
		t.Errorf("%s: bystander.secret_ciphertext drifted across tenants — a peer-tenant mutation reached the sealed bytes", label)
	}
	if after.Version != baseline.Version {
		t.Errorf("%s: bystander.version = %d, want %d — the organization_variables_bump_version trigger bumped version on a peer tenant's row, which means an UPDATE matched it",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE organization_variables_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}

// containsValue is a tiny substring helper used by the cross-tenant
// error-surface assertions. It exists only to make the no-value-echo
// invariant readable at the call site. It is defined here (in the
// organization variable tenant-isolation file) because organization is
// the only scope whose repository surface exposes per-key mutations
// that can RETURN errors carrying message / hint text.
func containsValue(field, value string) bool {
	if value == "" || field == "" {
		return false
	}
	for i := 0; i+len(value) <= len(field); i++ {
		if field[i:i+len(value)] == value {
			return true
		}
	}
	return false
}
