package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// This file is the HTTP authorization middleware for the Yalla Control Plane
// API. It is the boundary every authenticated route is wrapped in: it
// extracts the bearer credential, resolves it to a policy.Principal through
// the auth.Authenticator, attaches the principal to the request context, names
// the principal and organization on the per-request log record, and authorizes
// the route's action against the target resource — all before the handler
// runs.
//
// The wire contract is deterministic:
//
//   - A request with no usable credential is 401 E_AUTHENTICATION_REQUIRED
//     ("authentication is required").
//   - A request with a credential that does not authenticate is 401 E_AUTH
//     ("the supplied credentials are invalid") — uniform across every cause, so
//     the response never reveals whether an API key prefix exists.
//   - An authenticated principal that is not authorized for the route's action
//     is 403 E_FORBIDDEN, and the message carries the stable policy reason
//     code.
//   - A dependency failure encountered while resolving the credential is
//     surfaced as its own typed status (a 5xx), never disguised as a 401.
//
// Every response is rendered through the apienvelope package, so the
// yalla.output.v1 / yalla.error.v1 contract holds on the middleware path too;
// the middleware never marshals JSON itself.

// Authenticator is the narrow authentication port the middleware depends on.
// *auth.Authenticator satisfies it in production; tests supply a fake. Keeping
// the dependency an interface keeps the middleware unit-testable without a
// real credential store.
type Authenticator interface {
	Authenticate(ctx context.Context, bearerToken string) (auth.Identity, error)
}

// authMethodCtxKey is an unexported key type so the auth.Method we attach
// to the request context after authentication cannot collide with values
// set by other packages. Downstream middleware (the rate-limit gate, in
// particular) reads the method back so it can exempt internal-worker
// callbacks without re-authenticating the request.
type authMethodCtxKey struct{}

// withAuthMethod returns a child context carrying the credential scheme
// the request authenticated with. RequireAuth and RequireInternalWorker
// both call it so every authenticated downstream handler can recover the
// method without re-running the credential store.
func withAuthMethod(ctx context.Context, method auth.Method) context.Context {
	if method == "" {
		return ctx
	}
	return context.WithValue(ctx, authMethodCtxKey{}, method)
}

// AuthMethodFromContext returns the credential scheme the request
// authenticated with, or ("", false) when no authenticator ran. It is the
// only way downstream middleware can tell an internal-worker request from
// a customer API-key or session request after auth has already resolved.
func AuthMethodFromContext(ctx context.Context) (auth.Method, bool) {
	if ctx == nil {
		return "", false
	}
	m, ok := ctx.Value(authMethodCtxKey{}).(auth.Method)
	if !ok || m == "" {
		return "", false
	}
	return m, true
}

// ResourceResolver derives the policy.Resource an authenticated request acts
// on from its path and query parameters. RequireAuth calls it after the
// principal is resolved, so the authorization decision is made against the
// real target resource — not merely the principal's home organization — which
// is what turns a cross-tenant path parameter into a 403 rather than a silent
// allow. A nil resolver defaults to the principal's own organization scope,
// which suits self and organization-root actions that have no deeper target.
type ResourceResolver func(r *http.Request) policy.Resource

// RequireAuth builds middleware that authenticates the request, attaches the
// resolved principal to the context, records the principal and organization on
// the per-request log record, and authorizes action against the resource the
// resolver returns. The wrapped handler runs only when authentication and
// authorization both pass; otherwise a stable yalla.error.v1 envelope is
// written and the handler is skipped.
//
// action must be a catalogued policy action; resource may be nil, in which
// case authorization is evaluated against the principal's own organization
// scope.
func RequireAuth(a Authenticator, engine *policy.Engine, action policy.Action, resource ResourceResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := bearerToken(r)
			if err != nil {
				writeAuthError(w, r, err)
				return
			}
			id, err := a.Authenticate(r.Context(), token)
			if err != nil {
				writeAuthError(w, r, err)
				return
			}

			// Attach the principal and enrich the request log record before
			// the authorization decision, so a denied request is still
			// attributable to its principal in the logs. The credential
			// scheme rides along too so downstream middleware (the
			// rate-limit gate in particular) can recognise an internal
			// worker without re-running the credential store.
			ctx := policy.WithPrincipal(r.Context(), id.Principal)
			ctx = withAuthMethod(ctx, id.Method)
			telemetry.SetOrgID(ctx, id.Principal.OrganizationID)
			telemetry.SetPrincipalID(ctx, id.Principal.ID)
			r = r.WithContext(ctx)

			res := policy.Resource{Scope: policy.Scope{OrganizationID: id.Principal.OrganizationID}}
			if resource != nil {
				res = resource(r)
			}
			if err := engine.Authorize(id.Principal, action, res); err != nil {
				apienvelope.WriteError(w, requestID(r), toAPIError(err))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireInternalWorker builds middleware that admits only requests
// authenticated with the internal worker credential. It is the gate for
// private callback endpoints: a missing or invalid credential is the usual 401,
// and a valid customer credential (an API key or a human session) is 403
// E_FORBIDDEN — the endpoint is not part of the customer-facing surface.
//
// The internal worker principal carries no organization or role, so internal
// endpoints authorize on the authentication method here rather than through a
// policy capability.
func RequireInternalWorker(a Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := bearerToken(r)
			if err != nil {
				writeAuthError(w, r, err)
				return
			}
			id, err := a.Authenticate(r.Context(), token)
			if err != nil {
				writeAuthError(w, r, err)
				return
			}
			if id.Method != auth.MethodInternalWorker {
				apienvelope.WriteError(w, requestID(r),
					apierr.Forbidden("this endpoint requires an internal worker credential"))
				return
			}
			ctx := policy.WithPrincipal(r.Context(), id.Principal)
			ctx = withAuthMethod(ctx, id.Method)
			telemetry.SetPrincipalID(ctx, id.Principal.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerToken extracts the credential from the request's Authorization header.
// It accepts only the "Bearer <token>" scheme (matched case-insensitively, as
// RFC 7235 specifies) with a non-empty token. A missing header, a non-Bearer
// scheme, or an empty token are all reported as auth.ErrNoCredentials — the
// request supplied nothing the middleware can authenticate — so they map to a
// uniform "authentication is required" response. The header value is never
// echoed in the returned error.
func bearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", auth.ErrNoCredentials
	}
	const scheme = "bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", auth.ErrNoCredentials
	}
	token := strings.TrimSpace(header[len(scheme):])
	if token == "" {
		return "", auth.ErrNoCredentials
	}
	return token, nil
}

// writeAuthError renders an authentication failure as a stable yalla.error.v1
// envelope. Missing credentials map to 401 E_AUTHENTICATION_REQUIRED; invalid
// credentials map to 401 E_AUTH with a fixed generic message, so the response
// never reveals which check failed or whether a key prefix exists. Anything
// else is a genuine dependency failure surfaced from the credential store and
// is rendered with its own typed status.
func writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrNoCredentials):
		apienvelope.WriteError(w, requestID(r), apierr.AuthenticationRequired())
	case errors.Is(err, auth.ErrInvalidCredentials):
		apienvelope.WriteError(w, requestID(r), apierr.Unauthenticated("the supplied credentials are invalid"))
	default:
		apienvelope.WriteError(w, requestID(r), toAPIError(err))
	}
}

// toAPIError normalises an arbitrary error onto the *yerr.Error the envelope
// renderer expects. A typed error (every apierr constructor, and the typed
// errors the policy engine returns) passes through unchanged so its stable
// code and HTTP status are preserved; anything else collapses to a generic
// internal error rather than leaking its raw text onto the wire.
func toAPIError(err error) *yerr.Error {
	var ye *yerr.Error
	if errors.As(err, &ye) {
		return ye
	}
	return apierr.Internal(err)
}
