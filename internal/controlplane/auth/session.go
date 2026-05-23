package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/output"
)

// Session tokens authenticate human users between the (future) frontend and
// the backend. The token shape and verification rules are a public
// compatibility contract:
//
//   - A session token is a compact HS256 JWT: three base64url segments,
//     "<header>.<payload>.<signature>", with a fixed header
//     {"alg":"HS256","typ":"JWT"}. Any other algorithm or header shape is
//     rejected as malformed — the "alg":"none" downgrade is unrepresentable.
//   - The payload carries the registered claims iss/aud/sub/iat/exp plus the
//     Yalla claims org (organization id), role, and rver (the role/revocation
//     version). user_id, org_id, role version, and expiration are therefore
//     all in the claims.
//   - Verification checks, in order: structural shape, the HMAC signature
//     against every accepted signing key, the issuer, the audience, the
//     expiry, and finally the revocation version. A token minted before the
//     subject's role/membership changed — or before a forced sign-out — has a
//     stale rver and is rejected, so a single counter bump revokes every token
//     already in the wild without a denylist.
//   - Both API-key authentication and human session authentication resolve to
//     one internal identity shape: SessionClaims.Principal returns the same
//     policy.Principal type the API-key path produces.
//
// Signing keys are HMAC secrets, so verification is a constant-time
// comparison. The first configured key mints new tokens; the rest stay
// accepted so a key can be rotated without invalidating live sessions.
//
// The minted SessionToken is a credential: like the API-key Token, every
// standard rendering yields output.Sentinel and the plaintext is reachable
// only through an explicit Reveal call.

// sessionTokenHeader is the fixed, base64url-encoded JWT header. It is a
// constant so an incoming token must match it byte-for-byte: a token carrying
// any other "alg" (notably "none") or "typ" never reaches signature
// verification.
const sessionTokenHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg":"HS256","typ":"JWT"}

// Session token verification errors. They are sentinel values so the auth
// middleware can branch on the failure mode; none of them ever echoes the
// supplied token or any signing key. ErrMalformedToken (shared with the
// API-key parser) covers every structural failure: wrong segment count, a
// non-matching header, undecodable base64, or unparseable claim JSON.
var (
	// ErrTokenSignature means no accepted signing key produced the token's
	// signature — the token was forged, tampered with, or signed with a key
	// that is no longer accepted.
	ErrTokenSignature = errors.New("auth: session token signature is invalid")
	// ErrTokenExpired means the token's exp claim is at or before the
	// verification clock.
	ErrTokenExpired = errors.New("auth: session token is expired")
	// ErrTokenIssuer means the token's iss claim does not match the expected
	// issuer.
	ErrTokenIssuer = errors.New("auth: session token issuer is not accepted")
	// ErrTokenAudience means the token's aud claim does not match the expected
	// audience — e.g. a token minted for another service was replayed here.
	ErrTokenAudience = errors.New("auth: session token audience is not accepted")
	// ErrTokenRevoked means the token's revocation version is stale: the
	// subject's role/membership changed, or every session was forcibly
	// invalidated, after the token was minted.
	ErrTokenRevoked = errors.New("auth: session token is revoked")
	// ErrUnknownSubject means the token is structurally valid and correctly
	// signed, but the (user, organization) it names has no active membership —
	// the not-found case for session authentication.
	ErrUnknownSubject = errors.New("auth: session token subject is unknown")
)

// SessionToken is a minted, signed session token in compact JWT form. It is a
// credential: String, GoString, LogValue, and MarshalJSON all yield
// output.Sentinel, so it cannot leak through fmt, slog, or JSON. The plaintext
// is reachable only through the explicit Reveal method.
type SessionToken string

// String returns the redaction sentinel, never the plaintext token.
func (t SessionToken) String() string { return output.Sentinel }

// GoString returns the redaction sentinel so %#v cannot leak the plaintext.
func (t SessionToken) GoString() string { return output.Sentinel }

// LogValue implements slog.LogValuer so a SessionToken logged with slog is
// scrubbed automatically.
func (t SessionToken) LogValue() slog.Value { return slog.StringValue(output.Sentinel) }

// MarshalJSON encodes the redaction sentinel so a SessionToken can never be
// serialised into a response or audit record as plaintext.
func (t SessionToken) MarshalJSON() ([]byte, error) { return json.Marshal(output.Sentinel) }

// Reveal returns the plaintext token. It is the only way to read the token
// body, and exists so that exposing a credential is always an explicit,
// greppable act — call it once, when handing the token to its owner.
func (t SessionToken) Reveal() string { return string(t) }

// SessionClaims is the verified payload of a session token. Times are always
// in UTC.
type SessionClaims struct {
	// UserID is the domain ID of the human the token authenticates.
	UserID string
	// OrganizationID is the organization the session is scoped to.
	OrganizationID string
	// Role is the user's organization-wide role at mint time. It maps to a
	// policy.Role; an unknown role string contributes no capabilities.
	Role string
	// RoleVersion is the role/revocation version the token was minted with.
	// Verification rejects a token whose RoleVersion differs from the current
	// version, so bumping the counter revokes every outstanding token.
	RoleVersion int64
	// Issuer is the token's iss claim.
	Issuer string
	// Audience is the token's aud claim.
	Audience string
	// IssuedAt is the token's iat claim.
	IssuedAt time.Time
	// ExpiresAt is the token's exp claim.
	ExpiresAt time.Time
}

// Principal maps the verified claims onto the single internal identity shape
// the policy engine consumes. Both API-key authentication and human session
// authentication resolve to this same policy.Principal type, so the policy
// engine has exactly one input shape regardless of how the request
// authenticated. Grants are intentionally left empty here: scoped grants are
// resolved from the store by the auth middleware, not carried in the token.
func (c SessionClaims) Principal() policy.Principal {
	return policy.Principal{
		ID:             c.UserID,
		Kind:           domain.KindUser,
		OrganizationID: c.OrganizationID,
		Role:           policy.Role(c.Role),
	}
}

// sessionPayload is the on-the-wire JSON claim set. Field names are a public
// compatibility contract: iss/aud/sub/iat/exp are the standard registered
// claims, org/role/rver are the Yalla-specific claims.
type sessionPayload struct {
	Issuer      string `json:"iss"`
	Audience    string `json:"aud"`
	Subject     string `json:"sub"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	Org         string `json:"org"`
	Role        string `json:"role"`
	RoleVersion int64  `json:"rver"`
}

// MintSessionParams is the input to MintSession.
type MintSessionParams struct {
	// SigningKey is the HMAC secret used to sign the token — the active
	// signing key. Required.
	SigningKey string
	// Issuer is the iss claim written into the token. Required.
	Issuer string
	// Audience is the aud claim written into the token. Required.
	Audience string
	// UserID is the domain ID of the human the token authenticates. Required.
	UserID string
	// OrganizationID is the organization the session is scoped to. Required.
	OrganizationID string
	// Role is the user's organization-wide role. Required.
	Role string
	// RoleVersion is the current role/revocation version for the subject. A
	// token is rejected once the subject's version moves past this value.
	RoleVersion int64
	// IssuedAt is the iat claim. The zero value defaults to time.Now().
	IssuedAt time.Time
	// TTL is how long the token stays valid after IssuedAt. Required (> 0).
	TTL time.Duration
}

// ErrInvalidMintParams is returned by MintSession when its parameters are
// incomplete. It never echoes a signing key or any other secret.
var ErrInvalidMintParams = errors.New("auth: invalid session mint parameters")

// MintSession signs a session token from params. The returned SessionToken is
// a credential — never log or persist its Reveal value; hand it to its owner
// once. MintSession performs no I/O and is safe to call concurrently.
func MintSession(params MintSessionParams) (SessionToken, error) {
	switch {
	case params.SigningKey == "":
		return "", ErrInvalidMintParams
	case strings.TrimSpace(params.Issuer) == "":
		return "", ErrInvalidMintParams
	case strings.TrimSpace(params.Audience) == "":
		return "", ErrInvalidMintParams
	case strings.TrimSpace(params.UserID) == "":
		return "", ErrInvalidMintParams
	case strings.TrimSpace(params.OrganizationID) == "":
		return "", ErrInvalidMintParams
	case strings.TrimSpace(params.Role) == "":
		return "", ErrInvalidMintParams
	case params.TTL <= 0:
		return "", ErrInvalidMintParams
	}

	issuedAt := params.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	issuedAt = issuedAt.UTC()
	expiresAt := issuedAt.Add(params.TTL)

	payload := sessionPayload{
		Issuer:      params.Issuer,
		Audience:    params.Audience,
		Subject:     params.UserID,
		IssuedAt:    issuedAt.Unix(),
		ExpiresAt:   expiresAt.Unix(),
		Org:         params.OrganizationID,
		Role:        params.Role,
		RoleVersion: params.RoleVersion,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	signingInput := sessionTokenHeader + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	signature := signSession(params.SigningKey, signingInput)
	return SessionToken(signingInput + "." + signature), nil
}

// VerifySessionParams is the input to VerifySession.
type VerifySessionParams struct {
	// SigningKeys are the accepted HMAC secrets. Index 0 is the active key;
	// the remainder stay accepted during rotation. A token verifies if any of
	// them produced its signature.
	SigningKeys []string
	// Issuer is the only accepted iss claim. Required.
	Issuer string
	// Audience is the only accepted aud claim. Required.
	Audience string
	// Now is the verification clock. The zero value defaults to time.Now().
	Now time.Time
	// CurrentRoleVersion reports the current role/revocation version for the
	// (userID, organizationID) the token names. ok must be false when no such
	// active membership exists; VerifySession then returns ErrUnknownSubject.
	// When CurrentRoleVersion is nil the revocation check is skipped — callers
	// that authenticate without a store (pure unit tests) may leave it unset.
	CurrentRoleVersion func(userID, organizationID string) (version int64, ok bool)
}

// VerifySession parses and fully validates a session token, returning its
// claims. The checks run in a fixed order — structural shape, signature,
// issuer, audience, expiry, revocation — and every failure is one of the
// sentinel errors (ErrMalformedToken, ErrTokenSignature, ErrTokenIssuer,
// ErrTokenAudience, ErrTokenExpired, ErrTokenRevoked, ErrUnknownSubject). No
// error ever echoes the supplied token or a signing key. VerifySession
// performs no I/O itself; the only lookup is the injected CurrentRoleVersion.
func VerifySession(token string, params VerifySessionParams) (SessionClaims, error) {
	headerB64, rest, ok := strings.Cut(token, ".")
	if !ok || headerB64 != sessionTokenHeader {
		return SessionClaims{}, ErrMalformedToken
	}
	payloadB64, signatureB64, ok := strings.Cut(rest, ".")
	if !ok || payloadB64 == "" || signatureB64 == "" {
		return SessionClaims{}, ErrMalformedToken
	}
	if strings.Contains(signatureB64, ".") {
		return SessionClaims{}, ErrMalformedToken
	}

	signingInput := headerB64 + "." + payloadB64
	if !verifySessionSignature(params.SigningKeys, signingInput, signatureB64) {
		return SessionClaims{}, ErrTokenSignature
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return SessionClaims{}, ErrMalformedToken
	}
	decoder := json.NewDecoder(strings.NewReader(string(payloadJSON)))
	decoder.DisallowUnknownFields()
	var payload sessionPayload
	if err := decoder.Decode(&payload); err != nil {
		return SessionClaims{}, ErrMalformedToken
	}
	if payload.Subject == "" || payload.Org == "" || payload.Role == "" ||
		payload.Issuer == "" || payload.Audience == "" ||
		payload.IssuedAt == 0 || payload.ExpiresAt == 0 {
		return SessionClaims{}, ErrMalformedToken
	}
	if payload.ExpiresAt <= payload.IssuedAt {
		return SessionClaims{}, ErrMalformedToken
	}

	if payload.Issuer != params.Issuer {
		return SessionClaims{}, ErrTokenIssuer
	}
	if payload.Audience != params.Audience {
		return SessionClaims{}, ErrTokenAudience
	}

	now := params.Now
	if now.IsZero() {
		now = time.Now()
	}
	expiresAt := time.Unix(payload.ExpiresAt, 0).UTC()
	if !now.UTC().Before(expiresAt) {
		return SessionClaims{}, ErrTokenExpired
	}

	if params.CurrentRoleVersion != nil {
		current, ok := params.CurrentRoleVersion(payload.Subject, payload.Org)
		if !ok {
			return SessionClaims{}, ErrUnknownSubject
		}
		if current != payload.RoleVersion {
			return SessionClaims{}, ErrTokenRevoked
		}
	}

	return SessionClaims{
		UserID:         payload.Subject,
		OrganizationID: payload.Org,
		Role:           payload.Role,
		RoleVersion:    payload.RoleVersion,
		Issuer:         payload.Issuer,
		Audience:       payload.Audience,
		IssuedAt:       time.Unix(payload.IssuedAt, 0).UTC(),
		ExpiresAt:      expiresAt,
	}, nil
}

// signSession returns the base64url-encoded HMAC-SHA256 signature of
// signingInput under key.
func signSession(key, signingInput string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(signingInput))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifySessionSignature reports whether any of keys produced signatureB64
// over signingInput. Every candidate key is checked with a constant-time
// comparison, so a caller cannot learn which key matched — or whether any
// did — from timing.
func verifySessionSignature(keys []string, signingInput, signatureB64 string) bool {
	want, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}
	matched := false
	for _, key := range keys {
		if key == "" {
			continue
		}
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), want) {
			matched = true
		}
	}
	return matched
}
