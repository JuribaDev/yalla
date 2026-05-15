package store

import (
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// White-box validation coverage for APIKeyService.Create. buildAPIKeyToCreate
// is the rejection boundary: it is the first thing Create calls, runs before
// any transaction is opened, and is the only path that produces the typed
// 400 a malformed request becomes on the wire. The tests exercise every
// classifiable failure mode and prove the rejection never echoes the
// offending value back to the caller.

// validAPIKeyInput returns a CreateAPIKeyInput that buildAPIKeyToCreate accepts.
// Each test mutates one field and asserts the targeted failure, so a future
// refactor that subtly changes another field cannot make a focused test
// pass by accident.
func validAPIKeyInput() CreateAPIKeyInput {
	return CreateAPIKeyInput{
		OrganizationID: string(domain.MustNewID(domain.KindOrganization)),
		Name:           "CI deploy key",
		Scopes:         []string{"projects:read", "services:deploy"},
		Prefix:         "yk_aaabbbcccdddeeefff",
		SecretHash:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ActorID:        string(domain.MustNewID(domain.KindUser)),
		ActorKind:      string(domain.KindUser),
		ActorOrgID:     string(domain.MustNewID(domain.KindOrganization)),
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	}
}

func TestBuildAPIKeyToCreateAcceptsValidInput(t *testing.T) {
	t.Parallel()

	key, err := buildAPIKeyToCreate(validAPIKeyInput(), time.Now())
	if err != nil {
		t.Fatalf("buildAPIKeyToCreate(valid) error = %v, want nil", err)
	}
	if key.ID == "" || !strings.HasPrefix(key.ID, string(domain.KindAPIKey)+"_") {
		t.Errorf("buildAPIKeyToCreate returned id %q, want a freshly minted key_ id", key.ID)
	}
	if key.Name != "CI deploy key" {
		t.Errorf("buildAPIKeyToCreate name = %q, want trimmed %q", key.Name, "CI deploy key")
	}
	if len(key.Scopes) != 2 || key.Scopes[0] != "projects:read" || key.Scopes[1] != "services:deploy" {
		t.Errorf("buildAPIKeyToCreate scopes = %v, want the two normalised scopes", key.Scopes)
	}
	if key.ExpiresAt != nil {
		t.Errorf("buildAPIKeyToCreate expires_at = %v, want nil when not supplied", key.ExpiresAt)
	}
}

func TestBuildAPIKeyToCreateAcceptsEmptyScopes(t *testing.T) {
	t.Parallel()

	in := validAPIKeyInput()
	in.Scopes = nil
	key, err := buildAPIKeyToCreate(in, time.Now())
	if err != nil {
		t.Fatalf("buildAPIKeyToCreate(no scopes) error = %v, want nil", err)
	}
	if key.Scopes == nil {
		t.Error("buildAPIKeyToCreate normalised nil scopes to nil; the api_keys.scopes column would receive SQL NULL")
	}
	if len(key.Scopes) != 0 {
		t.Errorf("buildAPIKeyToCreate scopes = %v, want an empty slice", key.Scopes)
	}
}

func TestBuildAPIKeyToCreateAcceptsFutureExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	future := now.Add(24 * time.Hour)
	in := validAPIKeyInput()
	in.ExpiresAt = &future

	key, err := buildAPIKeyToCreate(in, now)
	if err != nil {
		t.Fatalf("buildAPIKeyToCreate(future expiry) error = %v, want nil", err)
	}
	if key.ExpiresAt == nil || !key.ExpiresAt.Equal(future) {
		t.Errorf("buildAPIKeyToCreate expires_at = %v, want %v", key.ExpiresAt, future)
	}
}

func TestBuildAPIKeyToCreateAcceptsServiceAccount(t *testing.T) {
	t.Parallel()

	saID := string(domain.MustNewID(domain.KindServiceAccount))
	in := validAPIKeyInput()
	in.ServiceAccountID = saID
	in.CreatedBy = ""

	key, err := buildAPIKeyToCreate(in, time.Now())
	if err != nil {
		t.Fatalf("buildAPIKeyToCreate(sa) error = %v, want nil", err)
	}
	if key.ServiceAccountID != saID {
		t.Errorf("buildAPIKeyToCreate service_account_id = %q, want %q", key.ServiceAccountID, saID)
	}
}

func TestBuildAPIKeyToCreateRejectsBadInput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		mutate    func(in *CreateAPIKeyInput)
		wantField string
	}{
		{
			name: "organization_id not an id",
			mutate: func(in *CreateAPIKeyInput) {
				in.OrganizationID = "not-an-id"
			},
			wantField: "organization_id",
		},
		{
			name: "organization_id wrong kind",
			mutate: func(in *CreateAPIKeyInput) {
				in.OrganizationID = string(domain.MustNewID(domain.KindUser))
			},
			wantField: "organization_id",
		},
		{
			name: "name blank",
			mutate: func(in *CreateAPIKeyInput) {
				in.Name = "   "
			},
			wantField: "name",
		},
		{
			name: "name too long",
			mutate: func(in *CreateAPIKeyInput) {
				in.Name = strings.Repeat("a", apiKeyNameMaxLen+1)
			},
			wantField: "name",
		},
		{
			name: "name with control character",
			mutate: func(in *CreateAPIKeyInput) {
				in.Name = "tab\there"
			},
			wantField: "name",
		},
		{
			name: "name with invalid utf-8",
			mutate: func(in *CreateAPIKeyInput) {
				in.Name = "bad\xff"
			},
			wantField: "name",
		},
		{
			name: "scope blank",
			mutate: func(in *CreateAPIKeyInput) {
				in.Scopes = []string{"projects:read", ""}
			},
			wantField: "scopes[1]",
		},
		{
			name: "scope too long",
			mutate: func(in *CreateAPIKeyInput) {
				in.Scopes = []string{strings.Repeat("a", apiKeyScopeMaxLen+1)}
			},
			wantField: "scopes[0]",
		},
		{
			name: "scope outside alphabet",
			mutate: func(in *CreateAPIKeyInput) {
				in.Scopes = []string{"Projects:Read"}
			},
			wantField: "scopes[0]",
		},
		{
			name: "scope duplicate",
			mutate: func(in *CreateAPIKeyInput) {
				in.Scopes = []string{"projects:read", "projects:read"}
			},
			wantField: "scopes[1]",
		},
		{
			name: "too many scopes",
			mutate: func(in *CreateAPIKeyInput) {
				scopes := make([]string, apiKeyMaxScopes+1)
				for i := range scopes {
					scopes[i] = "x" + uniqueScopeSuffix(i)
				}
				in.Scopes = scopes
			},
			wantField: "scopes",
		},
		{
			name: "expires_at in the past",
			mutate: func(in *CreateAPIKeyInput) {
				past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
				in.ExpiresAt = &past
			},
			wantField: "expires_at",
		},
		{
			name: "expires_at now",
			mutate: func(in *CreateAPIKeyInput) {
				now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
				in.ExpiresAt = &now
			},
			wantField: "expires_at",
		},
		{
			name: "service_account_id wrong kind",
			mutate: func(in *CreateAPIKeyInput) {
				in.ServiceAccountID = string(domain.MustNewID(domain.KindUser))
			},
			wantField: "service_account_id",
		},
		{
			name: "created_by wrong kind",
			mutate: func(in *CreateAPIKeyInput) {
				in.CreatedBy = string(domain.MustNewID(domain.KindOrganization))
			},
			wantField: "created_by",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := validAPIKeyInput()
			tc.mutate(&in)
			_, err := buildAPIKeyToCreate(in, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			if err == nil {
				t.Fatal("buildAPIKeyToCreate error = nil, want InvalidAPIKeyInput")
			}
			ye := yerr.From(err)
			if ye.Code != yerr.CodeInvalidInput {
				t.Fatalf("buildAPIKeyToCreate code = %s, want %s", ye.Code, yerr.CodeInvalidInput)
			}
			violations, ok := apierr.ViolationsOf(err)
			if !ok {
				t.Fatalf("apierr.ViolationsOf returned ok=false for %v", err)
			}
			if !hasField(violations, tc.wantField) {
				t.Errorf("violations = %+v, want a violation on field %q", violations, tc.wantField)
			}
			for _, v := range violations {
				if v.Reason == "" {
					t.Errorf("violation has empty reason: %+v", v)
				}
				// The rejection must never echo a long input value back.
				// Reasons are fixed phrases set by the validator itself.
				if strings.Contains(v.Reason, "Projects:Read") {
					t.Errorf("violation reason %q echoes the submitted value", v.Reason)
				}
			}
		})
	}
}

// TestBuildAPIKeyToCreateMissingCredentialsIsInternal proves a blank Prefix
// or SecretHash — which can only happen through a wiring bug in the handler —
// is reported as Internal, never as InvalidAPIKeyInput. A client cannot supply
// those fields, so a buggy server must not pretend the request was bad.
func TestBuildAPIKeyToCreateMissingCredentialsIsInternal(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(in *CreateAPIKeyInput)
	}{
		{"blank prefix", func(in *CreateAPIKeyInput) { in.Prefix = "" }},
		{"whitespace prefix", func(in *CreateAPIKeyInput) { in.Prefix = "   " }},
		{"blank secret hash", func(in *CreateAPIKeyInput) { in.SecretHash = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := validAPIKeyInput()
			tc.mutate(&in)
			_, err := buildAPIKeyToCreate(in, time.Now())
			if err == nil {
				t.Fatal("buildAPIKeyToCreate error = nil, want Internal")
			}
			ye := yerr.From(err)
			if ye.Code != yerr.CodeInternal {
				t.Fatalf("buildAPIKeyToCreate code = %s, want %s", ye.Code, yerr.CodeInternal)
			}
		})
	}
}

// TestNewAPIKeyServiceRejectsNilDependencies proves the constructor guard
// fails fast for every dependency. A nil port can never be served at
// runtime, so the misconfigured wiring is rejected at startup rather than
// on the first request.
func TestNewAPIKeyServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()

	s := &Store{}
	orgs := NewOrganizationRepository()
	sas := NewServiceAccountRepository()
	keys := NewAPIKeyRepository()
	audit := NewAuditRepository()

	cases := []struct {
		name string
		call func() error
	}{
		{"nil store", func() error { _, err := NewAPIKeyService(nil, orgs, sas, keys, audit); return err }},
		{"nil orgs", func() error { _, err := NewAPIKeyService(s, nil, sas, keys, audit); return err }},
		{"nil service accounts", func() error { _, err := NewAPIKeyService(s, orgs, nil, keys, audit); return err }},
		{"nil api keys", func() error { _, err := NewAPIKeyService(s, orgs, sas, nil, audit); return err }},
		{"nil audit", func() error { _, err := NewAPIKeyService(s, orgs, sas, keys, nil); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.call(); err == nil {
				t.Fatalf("NewAPIKeyService(%s) error = nil, want a constructor error", tc.name)
			}
		})
	}
	if _, err := NewAPIKeyService(s, orgs, sas, keys, audit); err != nil {
		t.Errorf("NewAPIKeyService(all set) error = %v, want nil", err)
	}
}

// hasField reports whether violations carries a FieldViolation whose Field
// equals want.
func hasField(violations []apierr.FieldViolation, want string) bool {
	for _, v := range violations {
		if v.Field == want {
			return true
		}
	}
	return false
}

// uniqueScopeSuffix yields a short, alphabet-safe suffix for the i-th
// generated scope in the too-many-scopes test, so every entry is unique and
// the only violation is the count cap.
func uniqueScopeSuffix(i int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz"
	var out strings.Builder
	if i == 0 {
		return "a"
	}
	for i > 0 {
		out.WriteByte(alpha[i%26])
		i /= 26
	}
	return out.String()
}
