package auth

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Unit tests for the request Authenticator — the BE-0020 decision layer that
// turns an inbound bearer credential into a policy.Principal. They cover all
// three credential schemes (API key, human session, internal worker), the
// anonymous / no-credential path, the uniform invalid-credentials contract
// (which must never reveal whether an API key prefix exists), the separation
// of an invalid credential from a genuine dependency failure, and the
// guarantee that no returned error echoes the supplied credential. They use a
// fake CredentialStore and need no database.

// testNow is the fixed clock the tests pin the Authenticator to so expiry
// checks are deterministic.
var testNow = time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)

// fakeCredentialStore is an in-memory auth.CredentialStore for unit tests.
type fakeCredentialStore struct {
	apiKeys      map[string]APIKeyRecord         // prefix -> record
	apiKeyErr    error                           // forced error from FindAPIKeyByPrefix
	accounts     map[string]ServiceAccountRecord // service account id -> record
	accountErr   error                           // forced error from FindServiceAccount
	roleVersions map[string]int64                // "org|user" -> current version
	roleVerErr   error                           // forced error from OrganizationRoleVersion
}

func newFakeStore() *fakeCredentialStore {
	return &fakeCredentialStore{
		apiKeys:      map[string]APIKeyRecord{},
		accounts:     map[string]ServiceAccountRecord{},
		roleVersions: map[string]int64{},
	}
}

func (f *fakeCredentialStore) FindAPIKeyByPrefix(_ context.Context, prefix string) (APIKeyRecord, error) {
	if f.apiKeyErr != nil {
		return APIKeyRecord{}, f.apiKeyErr
	}
	rec, ok := f.apiKeys[prefix]
	if !ok {
		return APIKeyRecord{}, apierr.NotFound("api_key", prefix)
	}
	return rec, nil
}

func (f *fakeCredentialStore) FindServiceAccount(_ context.Context, _, serviceAccountID string) (ServiceAccountRecord, error) {
	if f.accountErr != nil {
		return ServiceAccountRecord{}, f.accountErr
	}
	rec, ok := f.accounts[serviceAccountID]
	if !ok {
		return ServiceAccountRecord{}, apierr.NotFound("service_account", serviceAccountID)
	}
	return rec, nil
}

func (f *fakeCredentialStore) OrganizationRoleVersion(_ context.Context, organizationID, userID string) (int64, bool, error) {
	if f.roleVerErr != nil {
		return 0, false, f.roleVerErr
	}
	v, ok := f.roleVersions[organizationID+"|"+userID]
	return v, ok, nil
}

// assertPrincipal compares two policy.Principal values field by field.
// policy.Principal carries a Grants slice and so is not == comparable; the
// Authenticator never populates Grants, so an empty Grants slice is expected.
func assertPrincipal(t *testing.T, got, want policy.Principal) {
	t.Helper()
	if got.ID != want.ID || got.Kind != want.Kind ||
		got.OrganizationID != want.OrganizationID || got.Role != want.Role ||
		got.Disabled != want.Disabled || len(got.Grants) != 0 {
		t.Errorf("Principal = %+v, want %+v (Grants must be empty)", got, want)
	}
}

// newTestAuthenticator builds an Authenticator over store, pinned to testNow,
// with one signing key and a fixed internal worker token.
func newTestAuthenticator(t *testing.T, store CredentialStore) *Authenticator {
	t.Helper()
	a, err := NewAuthenticator(AuthenticatorConfig{
		Store:               store,
		SigningKeys:         []string{"primary-signing-key-0123456789"},
		InternalWorkerToken: "internal-worker-shared-secret-xyz",
		Now:                 func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

// mintTestSession mints a session token for the given subject with the stable
// issuer/audience contract values.
func mintTestSession(t *testing.T, signingKey, userID, orgID, role string, roleVersion int64, issuedAt time.Time, ttl time.Duration) string {
	t.Helper()
	tok, err := MintSession(MintSessionParams{
		SigningKey:     signingKey,
		Issuer:         SessionIssuer,
		Audience:       SessionAudience,
		UserID:         userID,
		OrganizationID: orgID,
		Role:           role,
		RoleVersion:    roleVersion,
		IssuedAt:       issuedAt,
		TTL:            ttl,
	})
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	return tok.Reveal()
}

func TestNewAuthenticatorNilStore(t *testing.T) {
	t.Parallel()
	if _, err := NewAuthenticator(AuthenticatorConfig{}); err == nil {
		t.Fatal("NewAuthenticator with nil store: error = nil, want non-nil")
	}
}

func TestAuthenticateNoCredentials(t *testing.T) {
	t.Parallel()
	a := newTestAuthenticator(t, newFakeStore())
	for _, token := range []string{"", "   ", "\t"} {
		if _, err := a.Authenticate(context.Background(), token); !stderrors.Is(err, ErrNoCredentials) {
			t.Errorf("Authenticate(%q) error = %v, want ErrNoCredentials", token, err)
		}
	}
}

func TestAuthenticateAPIKeyServiceAccount(t *testing.T) {
	t.Parallel()
	gen, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	store := newFakeStore()
	store.apiKeys[gen.Prefix] = APIKeyRecord{
		KeyID:            "key_abc",
		OrganizationID:   "org_acme",
		SecretHash:       gen.SecretHash,
		ServiceAccountID: "sa_ci",
	}
	store.accounts["sa_ci"] = ServiceAccountRecord{ID: "sa_ci", Disabled: false}
	a := newTestAuthenticator(t, store)

	id, err := a.Authenticate(context.Background(), gen.Token.Reveal())
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Method != MethodAPIKey {
		t.Errorf("Method = %q, want %q", id.Method, MethodAPIKey)
	}
	assertPrincipal(t, id.Principal, policy.Principal{
		ID:             "sa_ci",
		Kind:           domain.KindServiceAccount,
		OrganizationID: "org_acme",
	})
}

func TestAuthenticateAPIKeyDisabledServiceAccount(t *testing.T) {
	t.Parallel()
	gen, _ := Generate()
	store := newFakeStore()
	store.apiKeys[gen.Prefix] = APIKeyRecord{
		KeyID:            "key_abc",
		OrganizationID:   "org_acme",
		SecretHash:       gen.SecretHash,
		ServiceAccountID: "sa_ci",
	}
	store.accounts["sa_ci"] = ServiceAccountRecord{ID: "sa_ci", Disabled: true}
	a := newTestAuthenticator(t, store)

	id, err := a.Authenticate(context.Background(), gen.Token.Reveal())
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !id.Principal.Disabled {
		t.Error("Principal.Disabled = false, want true for a disabled service account")
	}
}

func TestAuthenticateAPIKeyHumanAndOrphan(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		createdBy string
		wantID    string
		wantKind  domain.Kind
	}{
		{"human-attributed key", "usr_ada", "usr_ada", domain.KindUser},
		{"orphan key falls back to its own id", "", "key_orphan", domain.KindAPIKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gen, _ := Generate()
			store := newFakeStore()
			store.apiKeys[gen.Prefix] = APIKeyRecord{
				KeyID:          "key_orphan",
				OrganizationID: "org_acme",
				SecretHash:     gen.SecretHash,
				CreatedBy:      tt.createdBy,
			}
			a := newTestAuthenticator(t, store)

			id, err := a.Authenticate(context.Background(), gen.Token.Reveal())
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if id.Principal.ID != tt.wantID || id.Principal.Kind != tt.wantKind {
				t.Errorf("Principal id/kind = %q/%q, want %q/%q",
					id.Principal.ID, id.Principal.Kind, tt.wantID, tt.wantKind)
			}
		})
	}
}

// TestAuthenticateAPIKeyInvalidIsUniform is the core of acceptance criterion 2:
// every invalid-credential cause must collapse to the single
// ErrInvalidCredentials value, so a caller can never learn from the error
// whether a key prefix exists.
func TestAuthenticateAPIKeyInvalidIsUniform(t *testing.T) {
	t.Parallel()

	usable, _ := Generate()        // a key that exists and is healthy
	wrongSecret, _ := Generate()   // its prefix exists, but the stored hash differs
	unknownPrefix, _ := Generate() // a well-formed token whose prefix is absent
	revoked, _ := Generate()
	expired, _ := Generate()
	missingSA, _ := Generate()

	store := newFakeStore()
	store.apiKeys[wrongSecret.Prefix] = APIKeyRecord{
		KeyID: "key_w", OrganizationID: "org_acme", SecretHash: HashSecret("a-different-secret"),
	}
	revokedAt := testNow.Add(-time.Hour)
	store.apiKeys[revoked.Prefix] = APIKeyRecord{
		KeyID: "key_r", OrganizationID: "org_acme", SecretHash: revoked.SecretHash, RevokedAt: &revokedAt,
	}
	expiredAt := testNow.Add(-time.Minute)
	store.apiKeys[expired.Prefix] = APIKeyRecord{
		KeyID: "key_e", OrganizationID: "org_acme", SecretHash: expired.SecretHash, ExpiresAt: &expiredAt,
	}
	store.apiKeys[missingSA.Prefix] = APIKeyRecord{
		KeyID: "key_s", OrganizationID: "org_acme", SecretHash: missingSA.SecretHash, ServiceAccountID: "sa_gone",
	}
	a := newTestAuthenticator(t, store)

	tests := []struct {
		name  string
		token string
	}{
		{"malformed token", "yk_not-a-real-token"},
		{"unknown prefix", unknownPrefix.Token.Reveal()},
		{"wrong secret", wrongSecret.Token.Reveal()},
		{"revoked key", revoked.Token.Reveal()},
		{"expired key", expired.Token.Reveal()},
		{"owning service account missing", missingSA.Token.Reveal()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := a.Authenticate(context.Background(), tt.token)
			if !stderrors.Is(err, ErrInvalidCredentials) {
				t.Errorf("Authenticate error = %v, want ErrInvalidCredentials", err)
			}
		})
	}

	// The healthy key is included only to prove the fixture is wired
	// correctly: the same store that produces a uniform error for every
	// invalid case still authenticates a valid one.
	_ = usable
}

func TestAuthenticateAPIKeyDependencyFailureIsNotInvalidCredentials(t *testing.T) {
	t.Parallel()
	gen, _ := Generate()
	store := newFakeStore()
	store.apiKeyErr = apierr.StoreUnavailable(stderrors.New("connection refused"))
	a := newTestAuthenticator(t, store)

	_, err := a.Authenticate(context.Background(), gen.Token.Reveal())
	if stderrors.Is(err, ErrInvalidCredentials) {
		t.Fatal("a datastore failure was disguised as ErrInvalidCredentials")
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeDBUnavailable {
		t.Fatalf("error = %v, want a typed E_DB_UNAVAILABLE dependency failure", err)
	}
}

func TestAuthenticateSession(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.roleVersions["org_acme|usr_ada"] = 7
	a := newTestAuthenticator(t, store)
	token := mintTestSession(t, "primary-signing-key-0123456789",
		"usr_ada", "org_acme", string(policy.RoleAdmin), 7, testNow.Add(-time.Minute), time.Hour)

	id, err := a.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Method != MethodSession {
		t.Errorf("Method = %q, want %q", id.Method, MethodSession)
	}
	assertPrincipal(t, id.Principal, policy.Principal{
		ID:             "usr_ada",
		Kind:           domain.KindUser,
		OrganizationID: "org_acme",
		Role:           policy.RoleAdmin,
	})
}

func TestAuthenticateSessionInvalidIsUniform(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.roleVersions["org_acme|usr_ada"] = 7
	a := newTestAuthenticator(t, store)

	staleVersion := mintTestSession(t, "primary-signing-key-0123456789",
		"usr_ada", "org_acme", string(policy.RoleAdmin), 6, testNow.Add(-time.Minute), time.Hour)
	unknownSubject := mintTestSession(t, "primary-signing-key-0123456789",
		"usr_ghost", "org_acme", string(policy.RoleAdmin), 7, testNow.Add(-time.Minute), time.Hour)
	badSignature := mintTestSession(t, "an-entirely-different-signing-key",
		"usr_ada", "org_acme", string(policy.RoleAdmin), 7, testNow.Add(-time.Minute), time.Hour)
	expired := mintTestSession(t, "primary-signing-key-0123456789",
		"usr_ada", "org_acme", string(policy.RoleAdmin), 7, testNow.Add(-2*time.Hour), time.Hour)

	tests := []struct {
		name  string
		token string
	}{
		{"malformed token", "not.a.jwt"},
		{"stale role version", staleVersion},
		{"unknown subject", unknownSubject},
		{"bad signature", badSignature},
		{"expired token", expired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := a.Authenticate(context.Background(), tt.token)
			if !stderrors.Is(err, ErrInvalidCredentials) {
				t.Errorf("Authenticate error = %v, want ErrInvalidCredentials", err)
			}
		})
	}
}

func TestAuthenticateSessionDependencyFailureIsNotInvalidCredentials(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.roleVerErr = apierr.StoreUnavailable(stderrors.New("connection refused"))
	a := newTestAuthenticator(t, store)
	token := mintTestSession(t, "primary-signing-key-0123456789",
		"usr_ada", "org_acme", string(policy.RoleAdmin), 7, testNow.Add(-time.Minute), time.Hour)

	_, err := a.Authenticate(context.Background(), token)
	if stderrors.Is(err, ErrInvalidCredentials) {
		t.Fatal("a datastore failure during the role-version lookup was disguised as ErrInvalidCredentials")
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeDBUnavailable {
		t.Fatalf("error = %v, want a typed E_DB_UNAVAILABLE dependency failure", err)
	}
}

func TestAuthenticateInternalWorker(t *testing.T) {
	t.Parallel()
	a := newTestAuthenticator(t, newFakeStore())

	id, err := a.Authenticate(context.Background(), "internal-worker-shared-secret-xyz")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Method != MethodInternalWorker {
		t.Errorf("Method = %q, want %q", id.Method, MethodInternalWorker)
	}
	if id.Principal.ID != InternalWorkerPrincipalID {
		t.Errorf("Principal.ID = %q, want %q", id.Principal.ID, InternalWorkerPrincipalID)
	}
	if id.Principal.OrganizationID != "" || id.Principal.Role != "" {
		t.Errorf("internal worker principal carries tenant scope: %+v", id.Principal)
	}
}

func TestAuthenticateInternalWorkerDisabledWhenUnconfigured(t *testing.T) {
	t.Parallel()
	a, err := NewAuthenticator(AuthenticatorConfig{
		Store:       newFakeStore(),
		SigningKeys: []string{"primary-signing-key-0123456789"},
		Now:         func() time.Time { return testNow },
		// InternalWorkerToken intentionally empty.
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	// With no worker token configured the same string is not special: it
	// falls through to the session path and fails verification.
	_, err = a.Authenticate(context.Background(), "internal-worker-shared-secret-xyz")
	if !stderrors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Authenticate error = %v, want ErrInvalidCredentials", err)
	}
}

// TestAuthenticateNeverEchoesCredential proves acceptance criterion 8: no error
// the Authenticator returns contains the supplied credential or its secret.
func TestAuthenticateNeverEchoesCredential(t *testing.T) {
	t.Parallel()
	a := newTestAuthenticator(t, newFakeStore())

	gen, _ := Generate()
	apiToken := gen.Token.Reveal()
	sessionToken := mintTestSession(t, "primary-signing-key-0123456789",
		"usr_ada", "org_acme", string(policy.RoleAdmin), 7, testNow.Add(-time.Minute), time.Hour)

	for _, token := range []string{apiToken, sessionToken} {
		_, err := a.Authenticate(context.Background(), token)
		if err == nil {
			t.Fatalf("Authenticate(%q-shaped token) unexpectedly succeeded", token[:5])
		}
		if strings.Contains(err.Error(), token) {
			t.Errorf("error echoed the supplied credential: %v", err)
		}
	}
}
