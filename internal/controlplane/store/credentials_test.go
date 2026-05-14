package store_test

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for CredentialReader — the store-backed adapter that
// satisfies auth.CredentialStore, the BE-0020 "store wiring" for the
// authentication middleware. They prove each port method against a real,
// freshly migrated Postgres database, prove cross-tenant isolation, and run
// the whole authentication chain end to end: a real API key and a real session
// token, resolved through the real Authenticator over the real store. They
// skip when YALLA_TEST_DATABASE_URL is unset.

// compile-time proof that the store adapter satisfies the auth port.
var _ auth.CredentialStore = (*store.CredentialReader)(nil)

func newCredentialReader(t *testing.T, s *store.Store) *store.CredentialReader {
	t.Helper()
	cr, err := store.NewCredentialReader(s)
	if err != nil {
		t.Fatalf("store.NewCredentialReader: %v", err)
	}
	return cr
}

func TestNewCredentialReaderNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewCredentialReader(nil); err == nil {
		t.Fatal("NewCredentialReader(nil): error = nil, want non-nil")
	}
}

func TestCredentialReaderFindAPIKeyByPrefix(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	reader := newCredentialReader(t, s)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, org, "ada")
	key, gen := newAPIKey(t, f, org.ID, createdBy)
	stored := insertAPIKey(ctx, t, s, repo, key)

	rec, err := reader.FindAPIKeyByPrefix(ctx, gen.Prefix)
	if err != nil {
		t.Fatalf("FindAPIKeyByPrefix returned %v, want nil", err)
	}
	if rec.KeyID != stored.ID || rec.OrganizationID != org.ID {
		t.Errorf("record id/org = %q/%q, want %q/%q", rec.KeyID, rec.OrganizationID, stored.ID, org.ID)
	}
	if rec.SecretHash != gen.SecretHash {
		t.Error("record SecretHash does not match the generated key")
	}
	if rec.CreatedBy != createdBy {
		t.Errorf("record CreatedBy = %q, want %q", rec.CreatedBy, createdBy)
	}
}

func TestCredentialReaderFindAPIKeyByPrefixNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	reader := newCredentialReader(t, newStore(t, db))
	ctx := context.Background()

	_, err := reader.FindAPIKeyByPrefix(ctx, "yk_nonexistentprefix")
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("FindAPIKeyByPrefix error = %v, want a typed E_NOT_FOUND", err)
	}
}

func TestCredentialReaderFindServiceAccount(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	reader := newCredentialReader(t, newStore(t, db))
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "alpha")
	orgB := seedOrg(t, db, f, "beta")
	saA := seedServiceAccount(t, db, f, orgA, "ci")

	rec, err := reader.FindServiceAccount(ctx, orgA.ID, saA.ID)
	if err != nil {
		t.Fatalf("FindServiceAccount returned %v, want nil", err)
	}
	if rec.ID != saA.ID || rec.Disabled {
		t.Errorf("record = %+v, want id %q, not disabled", rec, saA.ID)
	}

	// Cross-tenant: orgA's service account paired with orgB must not match.
	_, err = reader.FindServiceAccount(ctx, orgB.ID, saA.ID)
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant FindServiceAccount error = %v, want E_NOT_FOUND", err)
	}
}

func TestCredentialReaderOrganizationRoleVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	reader := newCredentialReader(t, newStore(t, db))
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	member := seedUser(t, db, f, org, "ada")
	nonMember := seedUser(t, db, f, org, "bob")
	seedMembership(t, db, org.ID, member, "admin", 9)

	version, ok, err := reader.OrganizationRoleVersion(ctx, org.ID, member)
	if err != nil {
		t.Fatalf("OrganizationRoleVersion returned %v, want nil", err)
	}
	if !ok || version != 9 {
		t.Errorf("version/ok = %d/%t, want 9/true", version, ok)
	}

	// A user with no membership is the not-found case: ok == false, no error.
	version, ok, err = reader.OrganizationRoleVersion(ctx, org.ID, nonMember)
	if err != nil {
		t.Fatalf("OrganizationRoleVersion for a non-member returned %v, want nil", err)
	}
	if ok || version != 0 {
		t.Errorf("version/ok = %d/%t, want 0/false for a user with no membership", version, ok)
	}
}

// TestAuthenticatorEndToEndAPIKey runs the whole API-key authentication chain
// against real Postgres: a real key minted by auth.Generate, persisted through
// the store, then resolved by the real Authenticator over the real
// CredentialReader.
func TestAuthenticatorEndToEndAPIKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyRepository()
	reader := newCredentialReader(t, s)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	createdBy := seedUser(t, db, f, org, "ada")
	key, gen := newAPIKey(t, f, org.ID, createdBy)
	insertAPIKey(ctx, t, s, repo, key)

	authenticator, err := auth.NewAuthenticator(auth.AuthenticatorConfig{Store: reader})
	if err != nil {
		t.Fatalf("auth.NewAuthenticator: %v", err)
	}

	id, err := authenticator.Authenticate(ctx, gen.Token.Reveal())
	if err != nil {
		t.Fatalf("Authenticate returned %v, want nil", err)
	}
	if id.Method != auth.MethodAPIKey {
		t.Errorf("Method = %q, want %q", id.Method, auth.MethodAPIKey)
	}
	if id.Principal.ID != createdBy || id.Principal.OrganizationID != org.ID {
		t.Errorf("Principal = %+v, want id %q in org %q", id.Principal, createdBy, org.ID)
	}

	// A revoked key no longer authenticates — and the failure is the uniform
	// invalid-credentials result, not a leak of why.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Revoke(ctx, tx, org.ID, key.ID, time.Now())
	}); err != nil {
		t.Fatalf("revoke key: %v", err)
	}
	if _, err := authenticator.Authenticate(ctx, gen.Token.Reveal()); !stderrors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("Authenticate of a revoked key error = %v, want ErrInvalidCredentials", err)
	}
}

// TestAuthenticatorEndToEndSession runs the whole session-token authentication
// chain against real Postgres: a real membership row supplies the current
// role/revocation version that the real Authenticator checks the minted
// token's embedded version against.
func TestAuthenticatorEndToEndSession(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	reader := newCredentialReader(t, newStore(t, db))
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, userID, "admin", 3)

	const signingKey = "end-to-end-session-signing-key"
	authenticator, err := auth.NewAuthenticator(auth.AuthenticatorConfig{
		Store:       reader,
		SigningKeys: []string{signingKey},
	})
	if err != nil {
		t.Fatalf("auth.NewAuthenticator: %v", err)
	}

	mint := func(roleVersion int64) string {
		t.Helper()
		tok, err := auth.MintSession(auth.MintSessionParams{
			SigningKey:     signingKey,
			Issuer:         auth.SessionIssuer,
			Audience:       auth.SessionAudience,
			UserID:         userID,
			OrganizationID: org.ID,
			Role:           "admin",
			RoleVersion:    roleVersion,
			TTL:            time.Hour,
		})
		if err != nil {
			t.Fatalf("MintSession: %v", err)
		}
		return tok.Reveal()
	}

	// A token whose embedded version matches the membership row authenticates.
	id, err := authenticator.Authenticate(ctx, mint(3))
	if err != nil {
		t.Fatalf("Authenticate returned %v, want nil", err)
	}
	if id.Method != auth.MethodSession {
		t.Errorf("Method = %q, want %q", id.Method, auth.MethodSession)
	}
	if id.Principal.ID != userID || id.Principal.OrganizationID != org.ID {
		t.Errorf("Principal = %+v, want id %q in org %q", id.Principal, userID, org.ID)
	}

	// A token minted with a stale version is revoked by the version check.
	if _, err := authenticator.Authenticate(ctx, mint(2)); !stderrors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("Authenticate of a stale-version token error = %v, want ErrInvalidCredentials", err)
	}
}
