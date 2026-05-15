package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
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

// MembershipReader is the narrow persistence port GET
// /v1/organizations/{org_id}/members depends on. *store.MembershipReader
// satisfies it in production; tests supply a fake. Keeping the dependency an
// interface keeps the handler unit-testable without a real database, the same
// way OrganizationReader keeps GET /v1/organizations testable.
//
// ListMembers is tenant scoped at the persistence layer: the repository
// filters by organization_id, so a cross-tenant id simply matches no rows and
// yields an empty list, never another organization's members. The
// organizationIDResolver this route uses authorizes the call against the
// {org_id} path parameter before the handler runs, so a cross-tenant id is
// rejected as a 403 long before this port is reached.
type MembershipReader interface {
	ListMembers(ctx context.Context, organizationID string) ([]store.OrganizationMember, error)
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
