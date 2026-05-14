package auth_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/JuribaDev/yalla/internal/output"
)

// Unit tests for the human session token primitives: minting, full
// verification, the revocation-version contract, and the redaction contract on
// the plaintext SessionToken type. None of these touch a database.

const (
	testIssuer   = "https://yalla.test"
	testAudience = "yalla-control-plane"
	testSignKey  = "session-signing-key-aaaaaaaaaaaaaaaaaaaaaaaa"
	testRotKey   = "session-signing-key-bbbbbbbbbbbbbbbbbbbbbbbb"
)

// validMintParams returns mint parameters that produce a token which verifies
// cleanly, so each test can mutate exactly the one field it exercises.
func validMintParams(t *testing.T) auth.MintSessionParams {
	t.Helper()
	return auth.MintSessionParams{
		SigningKey:     testSignKey,
		Issuer:         testIssuer,
		Audience:       testAudience,
		UserID:         string(domain.MustNewID(domain.KindUser)),
		OrganizationID: string(domain.MustNewID(domain.KindOrganization)),
		Role:           string(policy.RoleAdmin),
		RoleVersion:    7,
		IssuedAt:       time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC),
		TTL:            time.Hour,
	}
}

func validVerifyParams() auth.VerifySessionParams {
	return auth.VerifySessionParams{
		SigningKeys: []string{testSignKey, testRotKey},
		Issuer:      testIssuer,
		Audience:    testAudience,
		Now:         time.Date(2026, 5, 14, 12, 30, 0, 0, time.UTC),
	}
}

func TestMintSessionRoundTrips(t *testing.T) {
	t.Parallel()

	mp := validMintParams(t)
	token, err := auth.MintSession(mp)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	if token.Reveal() == "" {
		t.Fatal("MintSession returned an empty token")
	}

	claims, err := auth.VerifySession(token.Reveal(), validVerifyParams())
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if claims.UserID != mp.UserID {
		t.Errorf("UserID = %q, want %q", claims.UserID, mp.UserID)
	}
	if claims.OrganizationID != mp.OrganizationID {
		t.Errorf("OrganizationID = %q, want %q", claims.OrganizationID, mp.OrganizationID)
	}
	if claims.Role != mp.Role {
		t.Errorf("Role = %q, want %q", claims.Role, mp.Role)
	}
	if claims.RoleVersion != mp.RoleVersion {
		t.Errorf("RoleVersion = %d, want %d", claims.RoleVersion, mp.RoleVersion)
	}
	if claims.Issuer != testIssuer || claims.Audience != testAudience {
		t.Errorf("issuer/audience = %q/%q, want %q/%q", claims.Issuer, claims.Audience, testIssuer, testAudience)
	}
	if !claims.IssuedAt.Equal(mp.IssuedAt) {
		t.Errorf("IssuedAt = %s, want %s", claims.IssuedAt, mp.IssuedAt)
	}
	if !claims.ExpiresAt.Equal(mp.IssuedAt.Add(mp.TTL)) {
		t.Errorf("ExpiresAt = %s, want %s", claims.ExpiresAt, mp.IssuedAt.Add(mp.TTL))
	}
}

func TestSessionClaimsPrincipalMatchesInternalShape(t *testing.T) {
	t.Parallel()

	mp := validMintParams(t)
	token, err := auth.MintSession(mp)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	claims, err := auth.VerifySession(token.Reveal(), validVerifyParams())
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}

	p := claims.Principal()
	if p.ID != mp.UserID || p.Kind != domain.KindUser ||
		p.OrganizationID != mp.OrganizationID || p.Role != policy.RoleAdmin {
		t.Errorf("Principal() = %+v, want id=%s kind=%s org=%s role=%s",
			p, mp.UserID, domain.KindUser, mp.OrganizationID, policy.RoleAdmin)
	}
	if len(p.Grants) != 0 || p.Disabled {
		t.Errorf("Principal() = %+v, want no grants and not disabled", p)
	}
	// The policy engine must accept the session-derived principal exactly as
	// it accepts an API-key-derived one: there is a single Principal shape.
	if err := policy.NewEngine().Authorize(p, "project.create", policy.Resource{
		Kind:  domain.KindOrganization,
		Scope: policy.Scope{OrganizationID: mp.OrganizationID},
	}); err != nil {
		t.Errorf("policy rejected a session principal: %v", err)
	}
}

func TestVerifySessionRejectsExpiredToken(t *testing.T) {
	t.Parallel()

	token, err := auth.MintSession(validMintParams(t))
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	vp := validVerifyParams()
	vp.Now = time.Date(2026, 5, 14, 13, 0, 1, 0, time.UTC) // 1s past the 1h TTL
	if _, err := auth.VerifySession(token.Reveal(), vp); !errors.Is(err, auth.ErrTokenExpired) {
		t.Fatalf("VerifySession(expired) = %v, want ErrTokenExpired", err)
	}
}

func TestVerifySessionRejectsWrongAudience(t *testing.T) {
	t.Parallel()

	token, err := auth.MintSession(validMintParams(t))
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	vp := validVerifyParams()
	vp.Audience = "some-other-service"
	if _, err := auth.VerifySession(token.Reveal(), vp); !errors.Is(err, auth.ErrTokenAudience) {
		t.Fatalf("VerifySession(wrong audience) = %v, want ErrTokenAudience", err)
	}
}

func TestVerifySessionRejectsWrongIssuer(t *testing.T) {
	t.Parallel()

	token, err := auth.MintSession(validMintParams(t))
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	vp := validVerifyParams()
	vp.Issuer = "https://attacker.example"
	if _, err := auth.VerifySession(token.Reveal(), vp); !errors.Is(err, auth.ErrTokenIssuer) {
		t.Fatalf("VerifySession(wrong issuer) = %v, want ErrTokenIssuer", err)
	}
}

func TestVerifySessionRejectsBadSignature(t *testing.T) {
	t.Parallel()

	token, err := auth.MintSession(validMintParams(t))
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}

	// A signing key that is not in the accepted set must be rejected.
	vp := validVerifyParams()
	vp.SigningKeys = []string{"a-completely-different-key-cccccccccccccc"}
	if _, err := auth.VerifySession(token.Reveal(), vp); !errors.Is(err, auth.ErrTokenSignature) {
		t.Fatalf("VerifySession(unknown key) = %v, want ErrTokenSignature", err)
	}

	// A tampered payload invalidates the signature even with the right key.
	parts := strings.Split(token.Reveal(), ".")
	if len(parts) != 3 {
		t.Fatalf("minted token has %d segments, want 3", len(parts))
	}
	forgedPayload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"` + testIssuer + `","aud":"` + testAudience +
			`","sub":"usr_forged","iat":1,"exp":9999999999,"org":"org_forged","role":"owner","rver":0}`))
	tampered := parts[0] + "." + forgedPayload + "." + parts[2]
	if _, err := auth.VerifySession(tampered, validVerifyParams()); !errors.Is(err, auth.ErrTokenSignature) {
		t.Fatalf("VerifySession(tampered payload) = %v, want ErrTokenSignature", err)
	}
}

func TestVerifySessionAcceptsRotatedKey(t *testing.T) {
	t.Parallel()

	// A token minted with the rotation key still verifies while that key
	// remains in the accepted set.
	mp := validMintParams(t)
	mp.SigningKey = testRotKey
	token, err := auth.MintSession(mp)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	if _, err := auth.VerifySession(token.Reveal(), validVerifyParams()); err != nil {
		t.Fatalf("VerifySession(rotated key) = %v, want nil", err)
	}
}

func TestVerifySessionRejectsMalformedTokens(t *testing.T) {
	t.Parallel()

	good, err := auth.MintSession(validMintParams(t))
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	parts := strings.Split(good.Reveal(), ".")

	cases := map[string]string{
		"empty":                 "",
		"one segment":           "notatoken",
		"two segments":          parts[0] + "." + parts[1],
		"four segments":         good.Reveal() + ".extra",
		"alg none header":       base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + parts[1] + ".",
		"wrong header":          base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS512","typ":"JWT"}`)) + "." + parts[1] + "." + parts[2],
		"non-base64 payload":    parts[0] + ".!!!notbase64!!!." + parts[2],
		"empty signature":       parts[0] + "." + parts[1] + ".",
		"payload not json":      parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + parts[2],
		"payload missing sub":   parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testIssuer+`","aud":"`+testAudience+`","iat":1,"exp":2,"org":"o","role":"admin","rver":0}`)) + "." + parts[2],
		"exp before iat":        parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testIssuer+`","aud":"`+testAudience+`","sub":"u","iat":100,"exp":50,"org":"o","role":"admin","rver":0}`)) + "." + parts[2],
		"unknown payload field": parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+testIssuer+`","aud":"`+testAudience+`","sub":"u","iat":1,"exp":2,"org":"o","role":"admin","rver":0,"evil":true}`)) + "." + parts[2],
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := auth.VerifySession(token, validVerifyParams())
			// A malformed token may fail the structural check (ErrMalformedToken)
			// or, when the structure is intact but the bytes were rewritten, the
			// signature check. Either way it must never verify, and the error
			// must never echo the supplied token.
			if err == nil {
				t.Fatalf("VerifySession(%q) accepted a malformed token", name)
			}
			if !errors.Is(err, auth.ErrMalformedToken) && !errors.Is(err, auth.ErrTokenSignature) {
				t.Fatalf("VerifySession(%q) = %v, want ErrMalformedToken or ErrTokenSignature", name, err)
			}
			if token != "" && strings.Contains(err.Error(), token) {
				t.Fatalf("VerifySession error echoed the malformed token")
			}
		})
	}
}

func TestVerifySessionRevocationVersion(t *testing.T) {
	t.Parallel()

	mp := validMintParams(t)
	mp.RoleVersion = 7
	token, err := auth.MintSession(mp)
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}

	// Current version matches the token: it verifies.
	vp := validVerifyParams()
	vp.CurrentRoleVersion = func(userID, orgID string) (int64, bool) {
		if userID != mp.UserID || orgID != mp.OrganizationID {
			t.Errorf("CurrentRoleVersion called with %q/%q, want %q/%q", userID, orgID, mp.UserID, mp.OrganizationID)
		}
		return 7, true
	}
	if _, err := auth.VerifySession(token.Reveal(), vp); err != nil {
		t.Fatalf("VerifySession(current version) = %v, want nil", err)
	}

	// The subject's version moved on: every outstanding token is revoked.
	vp.CurrentRoleVersion = func(string, string) (int64, bool) { return 8, true }
	if _, err := auth.VerifySession(token.Reveal(), vp); !errors.Is(err, auth.ErrTokenRevoked) {
		t.Fatalf("VerifySession(stale version) = %v, want ErrTokenRevoked", err)
	}

	// The subject no longer has an active membership: not-found.
	vp.CurrentRoleVersion = func(string, string) (int64, bool) { return 0, false }
	if _, err := auth.VerifySession(token.Reveal(), vp); !errors.Is(err, auth.ErrUnknownSubject) {
		t.Fatalf("VerifySession(unknown subject) = %v, want ErrUnknownSubject", err)
	}
}

func TestMintSessionRejectsIncompleteParams(t *testing.T) {
	t.Parallel()

	cases := map[string]func(*auth.MintSessionParams){
		"no signing key":  func(p *auth.MintSessionParams) { p.SigningKey = "" },
		"no issuer":       func(p *auth.MintSessionParams) { p.Issuer = "  " },
		"no audience":     func(p *auth.MintSessionParams) { p.Audience = "" },
		"no user id":      func(p *auth.MintSessionParams) { p.UserID = "" },
		"no organization": func(p *auth.MintSessionParams) { p.OrganizationID = "" },
		"no role":         func(p *auth.MintSessionParams) { p.Role = "" },
		"zero ttl":        func(p *auth.MintSessionParams) { p.TTL = 0 },
		"negative ttl":    func(p *auth.MintSessionParams) { p.TTL = -time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mp := validMintParams(t)
			mutate(&mp)
			tok, err := auth.MintSession(mp)
			if !errors.Is(err, auth.ErrInvalidMintParams) {
				t.Fatalf("MintSession(%q) err = %v, want ErrInvalidMintParams", name, err)
			}
			if tok != "" {
				t.Fatalf("MintSession(%q) returned a non-empty token on failure", name)
			}
			if strings.Contains(err.Error(), testSignKey) {
				t.Fatalf("MintSession error echoed the signing key")
			}
		})
	}
}

func TestSessionTokenRedactsItselfInEveryRendering(t *testing.T) {
	t.Parallel()

	token, err := auth.MintSession(validMintParams(t))
	if err != nil {
		t.Fatalf("MintSession: %v", err)
	}
	plaintext := token.Reveal()
	if plaintext == "" {
		t.Fatal("Reveal returned an empty token")
	}

	jsonBytes, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("json.Marshal(token): %v", err)
	}
	renderings := map[string]string{
		"%v":       fmt.Sprintf("%v", token),
		"%+v":      fmt.Sprintf("%+v", token),
		"%#v":      fmt.Sprintf("%#v", token),
		"String":   token.String(),
		"GoString": token.GoString(),
		"JSON":     string(jsonBytes),
		"slog":     slog.AnyValue(token).String(),
	}
	for verb, rendered := range renderings {
		if strings.Contains(rendered, plaintext) {
			t.Errorf("%s rendering leaked the plaintext session token", verb)
		}
		if !strings.Contains(rendered, output.Sentinel) {
			t.Errorf("%s rendering = %q, want the redaction sentinel", verb, rendered)
		}
	}

	// The struct as a whole, and a slog rendering of the token, never expose
	// the plaintext token body.
	testutil.AssertRedactedValue(t, struct{ Token auth.SessionToken }{token}, plaintext)
	testutil.AssertRedacted(t, slog.AnyValue(token).String(), plaintext)
}
