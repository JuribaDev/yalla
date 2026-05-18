package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// errNoMembershipReader is returned when GET /v1/organizations/{org_id}/members
// is reached without a membership reader wired into NewHandler. Like
// errNoOrganizationReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it as a
// typed internal failure rather than serving an empty or misleading list.
var errNoMembershipReader = errors.New("httpapi: no membership reader configured")

// errNoMembershipCreator is returned when POST /v1/organizations/{org_id}/members
// is reached without a membership creator wired into NewHandler. Like
// errNoMembershipReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it as a
// typed internal failure rather than silently failing to persist the resource.
var errNoMembershipCreator = errors.New("httpapi: no membership creator configured")

// errNoMembershipUpdater is returned when PATCH
// /v1/organizations/{org_id}/members/{member_id} is reached without a
// membership updater wired into NewHandler. Like errNoMembershipCreator it
// can only happen through a wiring error — a programming mistake, not a
// client error — so the handler reports it as a typed internal failure
// rather than silently failing to persist the role change.
var errNoMembershipUpdater = errors.New("httpapi: no membership updater configured")

// errNoMembershipRemover is returned when DELETE
// /v1/organizations/{org_id}/members/{member_id} is reached without a
// membership remover wired into NewHandler. Like errNoMembershipUpdater it
// can only happen through a wiring error — a programming mistake, not a
// client error — so the handler reports it as a typed internal failure
// rather than silently failing to persist the removal.
var errNoMembershipRemover = errors.New("httpapi: no membership remover configured")

// MembershipReader is the narrow persistence port GET
// /v1/organizations/{org_id}/members and GET
// /v1/organizations/{org_id}/members/{member_id} depend on.
// *store.MembershipReader satisfies it in production; tests supply a fake.
// Keeping the dependency an interface keeps the handler unit-testable without
// a real database, the same way OrganizationReader keeps GET /v1/organizations
// testable.
//
// Both reads are tenant scoped at the persistence layer: the repository
// filters by organization_id, so a cross-tenant id simply matches no rows —
// ListMembers yields an empty list and GetMember surfaces a typed not-found,
// never another organization's members. The organizationIDResolver these
// routes use authorizes the calls against the {org_id} path parameter before
// the handler runs, so a cross-tenant id is rejected as a 403 long before
// this port is reached.
type MembershipReader interface {
	ListMembers(ctx context.Context, organizationID string) ([]store.OrganizationMember, error)
	GetMember(ctx context.Context, organizationID, userID string) (store.OrganizationMember, error)
}

// listMembersPayload is the data block of the GET
// /v1/organizations/{org_id}/members success envelope: every membership of the
// organization named by the {org_id} path parameter, joined with each member's
// global user identity. Every field is a non-secret identifier, role name,
// email, display name, or timestamp — the endpoint never returns credential
// material, so the payload is safe to log and audit verbatim. Members is
// always a non-nil slice so agents can iterate it without a nil check.
type listMembersPayload struct {
	Members []memberResource `json:"members"`
}

// memberResource is one entry in a listMembersPayload: the source-of-truth
// membership joined with the user identity it links to. It is the HTTP wire
// shape, deliberately distinct from store.OrganizationMember so the
// persistence layout can evolve without breaking the public contract.
//
// RoleVersion is the counter that backs version-based session revocation; it
// is exposed so admin tooling and agents can correlate a session token's
// embedded version against the current row, and it carries no credential
// material itself.
type memberResource struct {
	UserID          string `json:"user_id"`
	Email           string `json:"email"`
	UserDisplayName string `json:"user_display_name"`
	Role            string `json:"role"`
	RoleVersion     int64  `json:"role_version"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// memberResourceOf projects a store.OrganizationMember into the stable wire
// shape. Timestamps are rendered as UTC RFC 3339 strings so the contract is
// independent of the database driver's time representation and the response
// is deterministic for a given row.
func memberResourceOf(m store.OrganizationMember) memberResource {
	return memberResource{
		UserID:          m.UserID,
		Email:           m.Email,
		UserDisplayName: m.UserDisplayName,
		Role:            m.Role,
		RoleVersion:     m.RoleVersion,
		CreatedAt:       m.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:       m.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

// listMembersHandler builds the GET /v1/organizations/{org_id}/members handler.
// It lists the memberships of the organization named by the {org_id} path
// parameter, joined with each member's global user identity, by reading them
// from the source-of-truth database through the MembershipReader port.
//
// RequireAuth gates the route on action members.read before the handler runs
// — authorized through organizationIDResolver against the organization the
// path names — and attaches the resolved principal, so a request that reaches
// the handler has already cleared the tenant boundary: a cross-tenant {org_id}
// was rejected as a 403 by the policy engine, never reaching this code. A
// request that arrives here with no principal is therefore a wiring error and
// is reported as a typed internal error rather than reading for a zero
// principal. A reader-store outage surfaces as its own typed 5xx, and an
// {org_id} with no rows is a deterministic empty list — the membership read
// has no "not found" path of its own, mirroring every list endpoint.
func listMembersHandler(reader MembershipReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoMembershipReader))
			return
		}
		members, err := reader.ListMembers(r.Context(), r.PathValue("org_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]memberResource, 0, len(members))
		for _, m := range members {
			out = append(out, memberResourceOf(m))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listMembersPayload{Members: out})
	}
}

// getMemberPayload is the data block of the GET
// /v1/organizations/{org_id}/members/{member_id} success envelope: the
// single membership addressed by the {member_id} path parameter, in the same
// stable wire shape GET /v1/organizations/{org_id}/members returns for each
// list element. It carries no credential material.
type getMemberPayload struct {
	Member memberResource `json:"member"`
}

// getMemberHandler builds the GET /v1/organizations/{org_id}/members/{member_id}
// handler. It reads the single membership named by ({org_id}, {member_id}) —
// joined with the member's global user identity — from the source-of-truth
// database through the MembershipReader port, and renders it in a stable
// yalla.output.v1 envelope.
//
// RequireAuth gates the route on action members.read before the handler runs
// — authorized through organizationIDResolver against the organization the
// path names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the tenant boundary: a
// cross-tenant {org_id} was rejected as a 403 by the policy engine, never
// reaching this code. A request that arrives here with no principal is
// therefore a wiring error and is reported as a typed internal error rather
// than reading for a zero principal. A reader-store outage surfaces as its
// own typed 5xx, and a {member_id} with no row in the tenant is a
// deterministic 404 — a user id paired with the wrong organization is the
// same not-found, indistinguishable from a missing row, so the endpoint can
// never reveal whether another tenant has that member.
func getMemberHandler(reader MembershipReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoMembershipReader))
			return
		}
		member, err := reader.GetMember(r.Context(), r.PathValue("org_id"), r.PathValue("member_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), getMemberPayload{
			Member: memberResourceOf(member),
		})
	}
}

// MembershipCreator is the narrow persistence port POST
// /v1/organizations/{org_id}/members depends on. *store.MembershipService
// satisfies it in production; tests supply a fake. Like OrganizationCreator
// it is an interface declared here so the handler stays unit-testable without
// a real database — the concrete orchestrator (the existence checks, the
// memberships row, and the audit record committed in one transaction) lives
// in the store layer.
type MembershipCreator interface {
	Add(ctx context.Context, in store.AddMembershipInput) (store.OrganizationMember, error)
}

// addMemberRequest is the decoded POST /v1/organizations/{org_id}/members
// request body. UserID names the existing global user to add to the
// organization the {org_id} path parameter names, and Role is the
// organization-wide role to grant. The store layer validates both before any
// database work — an invalid request never opens a transaction — and neither
// field carries credential material; the user identifier is the opaque
// global id, never a password or token.
type addMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// addMemberPayload is the data block of the POST
// /v1/organizations/{org_id}/members success envelope: the membership that
// was created, in the same stable wire shape GET
// /v1/organizations/{org_id}/members returns for each list element. It
// carries no credential material.
type addMemberPayload struct {
	Member memberResource `json:"member"`
}

// addMemberHandler builds the POST /v1/organizations/{org_id}/members
// handler. It decodes and delegates: the request body is strictly decoded
// (oversized, malformed, or unknown-field bodies become a typed 400 that
// never echoes the input), then the add-member unit of work — confirm the
// organization exists, confirm the user exists, write the memberships row,
// append the audit record, all in one transaction — runs in the store layer
// through the MembershipCreator port.
//
// RequireAuth gates the route on action members.manage before the handler
// runs — authorized through organizationIDResolver against the organization
// the path names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the tenant boundary: a
// cross-tenant {org_id} was rejected as a 403 by the policy engine, never
// reaching this code. A request that arrives here with no principal is
// therefore a wiring error and is reported as a typed internal error. The
// principal and the request correlation identifiers are passed to the
// creator so the audit record names the actor; a validation failure, a
// not-found {org_id} or user_id, an already-a-member conflict, and a
// datastore outage each surface as their own typed status, never disguised
// as one another.
func addMemberHandler(creator MembershipCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if creator == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoMembershipCreator))
			return
		}

		var req addMemberRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		member, err := creator.Add(r.Context(), store.AddMembershipInput{
			OrganizationID: r.PathValue("org_id"),
			UserID:         req.UserID,
			Role:           req.Role,
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusCreated, requestID(r), addMemberPayload{
			Member: memberResourceOf(member),
		})
	}
}

// MembershipUpdater is the narrow persistence port PATCH
// /v1/organizations/{org_id}/members/{member_id} depends on.
// *store.MembershipService satisfies it in production; tests supply a fake.
// Like MembershipCreator it is an interface declared here so the handler
// stays unit-testable without a real database — the concrete orchestrator
// (the existence check, the role update with the role_version bump that
// sweeps every outstanding session, and the audit record committed in one
// transaction) lives in the store layer.
type MembershipUpdater interface {
	UpdateMember(ctx context.Context, in store.UpdateMembershipInput) (store.OrganizationMember, error)
}

// updateMemberRequest is the decoded PATCH
// /v1/organizations/{org_id}/members/{member_id} request body. Role is the
// only currently-mutable field on a membership; a future story may broaden
// the patch surface — when that lands, every new field becomes a separate
// optional pointer and a patch that names no field is rejected as 400. The
// store layer validates the value before any database work — an invalid
// request never opens a transaction — and the field carries no credential
// material.
//
// Role is a pointer so a missing field can be distinguished from an empty
// string: omitting it is a "patch with no field" client error, supplying ""
// is a validation failure on the field itself, and the policy that "every
// patch must change something" is enforced by the same code path that
// rejects an unknown role.
type updateMemberRequest struct {
	Role *string `json:"role"`
}

// updateMemberPayload is the data block of the PATCH
// /v1/organizations/{org_id}/members/{member_id} success envelope: the
// membership after the role change — including the freshly bumped
// role_version that backs session-token revocation — in the same stable wire
// shape the GET endpoint uses. It carries no credential material.
type updateMemberPayload struct {
	Member memberResource `json:"member"`
}

// memberIDResolver derives the policy.Resource a PATCH or DELETE
// /v1/organizations/{org_id}/members/{member_id} request acts on from its
// path parameters. The resource scope is the organization the path names —
// the same scope used by the rest of the membership endpoints — so action
// members.manage is authorized against the tenant boundary the path
// declares. A cross-tenant {org_id} is denied at the policy boundary before
// the handler runs, so a cross-tenant member_id can never mutate another
// tenant's membership graph.
func memberIDResolver(r *http.Request) policy.Resource {
	return policy.Resource{
		Kind:  domain.KindUser,
		Scope: policy.Scope{OrganizationID: r.PathValue("org_id")},
	}
}

// updateMemberHandler builds the PATCH
// /v1/organizations/{org_id}/members/{member_id} handler. It decodes and
// delegates: the request body is strictly decoded (oversized, malformed, or
// unknown-field bodies become a typed 400 that never echoes the input),
// then the update-member unit of work — confirm the membership exists,
// update the role (atomically bumping role_version so every outstanding
// session for the member is invalidated), append the audit record, all in
// one transaction — runs in the store layer through the MembershipUpdater
// port.
//
// RequireAuth gates the route on action members.manage before the handler
// runs — authorized through memberIDResolver against the organization the
// path names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the tenant boundary: a
// cross-tenant {org_id} was rejected as a 403 by the policy engine, never
// reaching this code. A request that arrives here with no principal is
// therefore a wiring error and is reported as a typed internal error. The
// principal and the request correlation identifiers are passed to the
// updater so the audit record names the actor; a validation failure (bad
// body, missing role, unknown role), a not-found membership (cross-tenant
// or missing user), and a datastore outage each surface as their own typed
// status, never disguised as one another.
func updateMemberHandler(updater MembershipUpdater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if updater == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoMembershipUpdater))
			return
		}

		var req updateMemberRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		// A PATCH with no role field is itself a client error: the only
		// mutable field on a membership today is role, so a patch that
		// names no field is a no-op. Surface it as 400 E_VALIDATION
		// naming the role field — the same shape the store layer would
		// reject a blank role with, kept consistent at the boundary so
		// agents see one stable contract for "patch with no field".
		if req.Role == nil {
			apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
				Field:  "role",
				Reason: "must be provided",
			}))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		member, err := updater.UpdateMember(r.Context(), store.UpdateMembershipInput{
			OrganizationID: r.PathValue("org_id"),
			UserID:         r.PathValue("member_id"),
			Role:           *req.Role,
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusOK, requestID(r), updateMemberPayload{
			Member: memberResourceOf(member),
		})
	}
}

// MembershipRemover is the narrow persistence port DELETE
// /v1/organizations/{org_id}/members/{member_id} depends on.
// *store.MembershipService satisfies it in production; tests supply a fake.
// Like MembershipUpdater it is an interface declared here so the handler
// stays unit-testable without a real database — the concrete orchestrator
// (the existence check, the memberships row DELETE, and the audit record
// committed in one transaction) lives in the store layer.
type MembershipRemover interface {
	Remove(ctx context.Context, in store.RemoveMembershipInput) (store.OrganizationMember, error)
}

// removeMemberPayload is the data block of the DELETE
// /v1/organizations/{org_id}/members/{member_id} success envelope: the
// membership exactly as it stood at the moment of removal, in the same
// stable wire shape the GET endpoint uses. Returning the terminal view
// (rather than 204 No Content) mirrors the organization scheduled-deletion
// contract and lets agents and CI see what was removed without a second
// request. The row no longer exists by the time the response is rendered;
// this payload is the audit-grade record of what was removed. It carries no
// credential material — a membership row stores a role, never a secret.
type removeMemberPayload struct {
	Member memberResource `json:"member"`
}

// removeMemberHandler builds the DELETE
// /v1/organizations/{org_id}/members/{member_id} handler. It delegates to
// the remove-member unit of work — confirm the membership exists, delete
// the memberships row, append the audit record, all in one transaction —
// which runs in the store layer through the MembershipRemover port.
//
// RequireAuth gates the route on action members.manage before the handler
// runs — authorized through memberIDResolver against the organization the
// path names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the tenant boundary: a
// cross-tenant {org_id} was rejected as a 403 by the policy engine, never
// reaching this code. A request that arrives here with no principal is
// therefore a wiring error and is reported as a typed internal error. The
// principal and the request correlation identifiers are passed to the
// remover so the audit record names the actor; a not-found membership
// (cross-tenant or missing user) and a datastore outage each surface as
// their own typed status, never disguised as one another.
//
// The response is 200 OK carrying the membership that was just removed —
// the same wire shape every other membership endpoint returns, projected
// from the row as it stood at the moment of removal. The row no longer
// exists when this returns; the body is the audit-grade record of what was
// removed.
func removeMemberHandler(remover MembershipRemover) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if remover == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoMembershipRemover))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		member, err := remover.Remove(r.Context(), store.RemoveMembershipInput{
			OrganizationID: r.PathValue("org_id"),
			UserID:         r.PathValue("member_id"),
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusOK, requestID(r), removeMemberPayload{
			Member: memberResourceOf(member),
		})
	}
}
