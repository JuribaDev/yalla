package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	stderrors "errors"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// The Authenticator turns an inbound bearer credential into the single
// internal identity shape — policy.Principal — that the policy engine
// consumes, regardless of how the request authenticated. It is the decision
// layer behind the BE-0020 authorization middleware; the thin HTTP wrapper
// lives in internal/controlplane/httpapi.
//
// Three credential schemes are recognised, and the wire contract is stable:
//
//   - API key: a token with the public "yk_<prefix>_<secret>" shape. The
//     prefix is looked up, the secret is verified with a constant-time hash
//     comparison, and the key's revoke/expiry lifecycle is checked. Every
//     failure mode — a malformed token, an unknown prefix, a wrong secret, a
//     revoked or expired key — collapses to the single ErrInvalidCredentials
//     value, so a caller can never learn from the error whether a given prefix
//     exists.
//   - Human session: a compact HS256 JWT verified by VerifySession against the
//     configured signing keys, issuer, audience, and the member's current
//     role/revocation version. Every verification failure likewise collapses
//     to ErrInvalidCredentials.
//   - Internal worker: a single configured shared secret, compared in constant
//     time. It authenticates the worker process itself for private callbacks;
//     it is not a tenant credential and resolves to a role-less principal.
//
// A genuine datastore failure encountered while resolving a credential is
// never disguised as ErrInvalidCredentials: it is propagated unchanged so the
// middleware can surface it as a dependency failure (a 5xx) rather than a
// silent authentication denial (a 401).
//
// The Authenticator performs no I/O of its own beyond the injected
// CredentialStore port, holds no mutable state after construction, and is safe
// for concurrent use.

// Stable session-token contract values. MintSession callers must mint tokens
// with exactly this issuer and audience, and VerifySession (through the
// Authenticator) accepts only these — a token minted for any other issuer or
// audience is rejected. Changing either is a public-API change.
const (
	// SessionIssuer is the only accepted iss claim for a Yalla session token.
	SessionIssuer = "yalla-control-plane"
	// SessionAudience is the only accepted aud claim for a Yalla session token.
	SessionAudience = "yalla-control-plane-api"
)

// InternalWorkerPrincipalID is the stable principal ID assigned to a request
// authenticated with the internal worker token. It is deliberately not a
// domain ID: the worker is the control plane's own process, not a tenant
// resource, and it carries no organization or role — so the policy engine
// denies it every tenant action by construction. Internal worker endpoints
// gate on the authentication method, not on a policy capability.
const InternalWorkerPrincipalID = "internal-worker"

// Authenticator errors. ErrNoCredentials and ErrInvalidCredentials are
// sentinel values so the HTTP middleware can branch on the failure mode; both
// are static strings and neither ever echoes the supplied credential. Every
// other error returned by Authenticate is a genuine dependency failure
// surfaced unchanged from the CredentialStore.
var (
	// ErrNoCredentials means the request supplied no credential at all.
	ErrNoCredentials = stderrors.New("auth: no credentials supplied")
	// ErrInvalidCredentials means a credential was supplied but did not
	// authenticate. It is deliberately uniform across every invalid-credential
	// cause — malformed token, unknown API key prefix, wrong secret, revoked
	// or expired key, bad signature, expired or revoked session — so the error
	// never reveals which check failed or whether a given key prefix exists.
	ErrInvalidCredentials = stderrors.New("auth: credentials are invalid")
)

// Method names the credential scheme a request authenticated with. It travels
// on the resolved Identity so middleware can gate an endpoint on the scheme
// itself — for example, restricting an internal callback endpoint to
// MethodInternalWorker.
type Method string

const (
	// MethodAPIKey is a Yalla API key ("yk_..." bearer token).
	MethodAPIKey Method = "api_key"
	// MethodSession is a human session token (HS256 JWT bearer token).
	MethodSession Method = "session"
	// MethodInternalWorker is the internal worker shared secret.
	MethodInternalWorker Method = "internal_worker"
)

// Identity is the result of a successful authentication: the resolved
// policy.Principal plus the credential scheme that produced it.
type Identity struct {
	// Principal is the internal identity the policy engine authorizes. Both
	// the API-key and session schemes resolve to a tenant principal; the
	// internal worker scheme resolves to a role-less, org-less principal.
	Principal policy.Principal
	// Method is the credential scheme the request authenticated with.
	Method Method
}

// APIKeyRecord is the auth-layer view of a stored API key. It is intentionally
// free of any persistence type so this package never imports store: the store
// package (or any other adapter) maps its own row type onto this DTO when it
// satisfies CredentialStore.
type APIKeyRecord struct {
	// KeyID is the API key's own domain ID. It is the principal ID of last
	// resort for an orphan key — one owned by no service account and
	// attributed to no surviving user.
	KeyID string
	// OrganizationID is the tenant the key belongs to.
	OrganizationID string
	// SecretHash is the one-way hash of the key's secret body, the only
	// representation of the secret that is ever persisted.
	SecretHash string
	// ServiceAccountID is the service account that owns the key, or "" when
	// the key is not owned by a service account.
	ServiceAccountID string
	// CreatedBy is the user who minted the key, or "" when the key has lost
	// attribution (its creator's user row was deleted).
	CreatedBy string
	// RevokedAt is set when the key has been explicitly revoked.
	RevokedAt *time.Time
	// ExpiresAt is set when the key has a time bound.
	ExpiresAt *time.Time
}

// ServiceAccountRecord is the auth-layer view of a service account that owns
// an API key. Like APIKeyRecord it is free of any persistence type.
type ServiceAccountRecord struct {
	// ID is the service account's domain ID.
	ID string
	// Disabled reports whether the service account has been parked. A request
	// that authenticates as a disabled service account resolves to a disabled
	// principal, which the policy engine denies every action.
	Disabled bool
}

// CredentialStore is the read-only persistence surface the Authenticator
// needs. It is a narrow port: an adapter (the store package's CredentialReader
// in production, a fake in unit tests) satisfies it, so this package never
// imports store and the Authenticator stays unit-testable without a database.
type CredentialStore interface {
	// FindAPIKeyByPrefix returns the API key with the given globally-unique
	// public prefix. The lookup is intentionally not tenant scoped:
	// authentication runs before the caller's tenant is known. A missing
	// prefix must be reported as a not-found *yerr.Error so the Authenticator
	// can collapse it into ErrInvalidCredentials without revealing whether the
	// prefix exists; any other error is treated as a dependency failure and
	// propagated unchanged.
	FindAPIKeyByPrefix(ctx context.Context, prefix string) (APIKeyRecord, error)
	// FindServiceAccount returns the service account that owns an API key,
	// scoped to its organization. A missing service account must be reported
	// as a not-found *yerr.Error.
	FindServiceAccount(ctx context.Context, organizationID, serviceAccountID string) (ServiceAccountRecord, error)
	// OrganizationRoleVersion returns the current role/revocation version for
	// (organizationID, userID). ok must be false when the user has no
	// membership in the organization — the not-found case the session
	// verifier maps to an unknown subject. A datastore failure must be
	// returned as a non-nil error, never disguised as ok == false, so a
	// transient outage surfaces as a dependency failure rather than a silent
	// authentication denial.
	OrganizationRoleVersion(ctx context.Context, organizationID, userID string) (version int64, ok bool, err error)
}

// AuthenticatorConfig carries the dependencies and contract values an
// Authenticator is built from.
type AuthenticatorConfig struct {
	// Store is the credential persistence port. Required.
	Store CredentialStore
	// SigningKeys are the accepted HMAC session-token signing keys; index 0 is
	// the active key and the rest stay accepted during rotation. It may be
	// empty (no session keys configured), in which case every session token
	// fails signature verification and resolves to ErrInvalidCredentials.
	SigningKeys []string
	// InternalWorkerToken is the shared secret that authenticates the internal
	// worker process. An empty value disables internal worker authentication
	// entirely — no token can then resolve to MethodInternalWorker.
	InternalWorkerToken string
	// Now is the clock used for API-key expiry and session-token expiry
	// checks. A nil Now defaults to time.Now.
	Now func() time.Time
}

// Authenticator resolves inbound bearer credentials into an Identity. Build
// one with NewAuthenticator at process startup and share it across requests.
type Authenticator struct {
	store       CredentialStore
	signingKeys []string
	workerToken string
	now         func() time.Time
}

// NewAuthenticator builds an Authenticator from cfg. It returns an error for a
// nil credential store so a misconfigured authenticator fails at construction
// rather than on its first request. The signing keys are copied so a later
// mutation of the caller's slice cannot change verification behaviour.
func NewAuthenticator(cfg AuthenticatorConfig) (*Authenticator, error) {
	if cfg.Store == nil {
		return nil, stderrors.New("auth: nil credential store")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	keys := make([]string, len(cfg.SigningKeys))
	copy(keys, cfg.SigningKeys)
	return &Authenticator{
		store:       cfg.Store,
		signingKeys: keys,
		workerToken: cfg.InternalWorkerToken,
		now:         now,
	}, nil
}

// Authenticate resolves bearerToken into an Identity. An empty token yields
// ErrNoCredentials; an unrecognised or unverifiable credential yields
// ErrInvalidCredentials; a genuine datastore failure is propagated unchanged.
// The token is never echoed in any returned error.
//
// The scheme is selected by shape: a "yk_"-prefixed token is an API key, a
// token that matches the configured internal worker secret is the internal
// worker, and anything else is verified as a session token.
func (a *Authenticator) Authenticate(ctx context.Context, bearerToken string) (Identity, error) {
	token := strings.TrimSpace(bearerToken)
	if token == "" {
		return Identity{}, ErrNoCredentials
	}
	switch {
	case strings.HasPrefix(token, tokenNamespace):
		return a.authenticateAPIKey(ctx, token)
	case a.workerToken != "" && constantTimeEqual(token, a.workerToken):
		return Identity{Principal: internalWorkerPrincipal(), Method: MethodInternalWorker}, nil
	default:
		return a.authenticateSession(ctx, token)
	}
}

// authenticateAPIKey verifies an API key token end to end: parse its shape,
// look the prefix up, verify the secret in constant time, check the
// revoke/expiry lifecycle, and resolve the owning principal. Every
// invalid-credential path returns the uniform ErrInvalidCredentials; only a
// genuine datastore failure is propagated.
func (a *Authenticator) authenticateAPIKey(ctx context.Context, token string) (Identity, error) {
	prefix, secret, err := ParseToken(token)
	if err != nil {
		return Identity{}, ErrInvalidCredentials
	}
	rec, err := a.store.FindAPIKeyByPrefix(ctx, prefix)
	if err != nil {
		if isNotFound(err) {
			return Identity{}, ErrInvalidCredentials
		}
		return Identity{}, err
	}
	if !VerifySecret(secret, rec.SecretHash) {
		return Identity{}, ErrInvalidCredentials
	}
	now := a.now()
	revoked := rec.RevokedAt != nil
	expired := rec.ExpiresAt != nil && !now.Before(*rec.ExpiresAt)
	if revoked || expired {
		return Identity{}, ErrInvalidCredentials
	}
	principal, err := a.apiKeyPrincipal(ctx, rec)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Principal: principal, Method: MethodAPIKey}, nil
}

// apiKeyPrincipal resolves the policy.Principal an API key authenticates as.
// A service-account-owned key resolves to the service account (and inherits
// its disabled state); a key attributed to a human resolves to that user; an
// orphan key — owned by no service account and attributed to no surviving user
// — authenticates as itself.
//
// API-key principals carry no organization Role and no scoped Grants here:
// resolving an API key's authority from its stored scopes is a later story, so
// for now an API-key principal can perform only self actions until a scoped
// grant is attached. This is deny-by-default and safe.
func (a *Authenticator) apiKeyPrincipal(ctx context.Context, rec APIKeyRecord) (policy.Principal, error) {
	if rec.ServiceAccountID != "" {
		sa, err := a.store.FindServiceAccount(ctx, rec.OrganizationID, rec.ServiceAccountID)
		if err != nil {
			if isNotFound(err) {
				// The key references a service account that no longer exists:
				// it cannot resolve to a principal, so it does not
				// authenticate.
				return policy.Principal{}, ErrInvalidCredentials
			}
			return policy.Principal{}, err
		}
		return policy.Principal{
			ID:             sa.ID,
			Kind:           domain.KindServiceAccount,
			OrganizationID: rec.OrganizationID,
			Disabled:       sa.Disabled,
		}, nil
	}
	if rec.CreatedBy != "" {
		return policy.Principal{
			ID:             rec.CreatedBy,
			Kind:           domain.KindUser,
			OrganizationID: rec.OrganizationID,
		}, nil
	}
	return policy.Principal{
		ID:             rec.KeyID,
		Kind:           domain.KindAPIKey,
		OrganizationID: rec.OrganizationID,
	}, nil
}

// authenticateSession verifies a human session token. The injected
// CurrentRoleVersion lookup is the only I/O; a datastore failure inside it is
// captured and propagated so a transient outage surfaces as a dependency
// failure rather than an authentication denial, while every genuine
// verification failure collapses to ErrInvalidCredentials.
func (a *Authenticator) authenticateSession(ctx context.Context, token string) (Identity, error) {
	var lookupErr error
	params := VerifySessionParams{
		SigningKeys: a.signingKeys,
		Issuer:      SessionIssuer,
		Audience:    SessionAudience,
		Now:         a.now(),
		CurrentRoleVersion: func(userID, organizationID string) (int64, bool) {
			version, ok, err := a.store.OrganizationRoleVersion(ctx, organizationID, userID)
			if err != nil {
				lookupErr = err
				return 0, false
			}
			return version, ok
		},
	}
	claims, err := VerifySession(token, params)
	if lookupErr != nil {
		return Identity{}, lookupErr
	}
	if err != nil {
		return Identity{}, ErrInvalidCredentials
	}
	return Identity{Principal: claims.Principal(), Method: MethodSession}, nil
}

// internalWorkerPrincipal returns the principal for a request authenticated
// with the internal worker token. It is intentionally role-less and
// org-less — the policy engine denies it every tenant action — so internal
// endpoints must gate on the authentication method, not on a capability.
func internalWorkerPrincipal() policy.Principal {
	return policy.Principal{ID: InternalWorkerPrincipalID}
}

// isNotFound reports whether err is a typed not-found error from the
// CredentialStore — the one error class the Authenticator collapses into
// ErrInvalidCredentials rather than treating as a dependency failure.
func isNotFound(err error) bool {
	var ye *yerr.Error
	return stderrors.As(err, &ye) && ye.Code == yerr.CodeNotFound
}

// constantTimeEqual reports whether a and b are equal, in time that does not
// depend on where they first differ. Both inputs are hashed first so the
// comparison is over fixed-length digests and does not leak the length of the
// configured worker token.
func constantTimeEqual(a, b string) bool {
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}
