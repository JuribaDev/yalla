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

// errNoOrganizationReader is returned when GET /v1/organizations is reached
// without an organization reader wired into NewHandler. Like
// errNoPrincipalOnContext it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it as a
// typed internal failure rather than serving an empty or misleading list.
var errNoOrganizationReader = errors.New("httpapi: no organization reader configured")

// errNoOrganizationCreator is returned when POST /v1/organizations is reached
// without an organization creator wired into NewHandler. Like
// errNoOrganizationReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it as a
// typed internal failure rather than silently failing to persist the resource.
var errNoOrganizationCreator = errors.New("httpapi: no organization creator configured")

// OrganizationReader is the narrow persistence port GET /v1/organizations
// depends on. *store.OrganizationReader satisfies it in production; tests
// supply a fake. Keeping the dependency an interface keeps the handler
// unit-testable without a real database, the same way the auth middleware
// depends on the Authenticator interface rather than a concrete credential
// store.
type OrganizationReader interface {
	GetOrganization(ctx context.Context, organizationID string) (store.Organization, error)
}

// organizationsPayload is the data block of the GET /v1/organizations success
// envelope: every organization the authenticated principal can see through the
// control plane, as the source-of-truth database stores them. Every field is a
// non-secret identifier, slug, display name, or timestamp — the endpoint never
// returns credential material, so the payload is safe to log and audit
// verbatim. Organizations is always a non-nil slice so agents can iterate it
// without a nil check.
type organizationsPayload struct {
	Organizations []organizationResource `json:"organizations"`
}

// organizationResource is one organization in an organizationsPayload: the
// source-of-truth organization resource — its id, slug, display name, and
// lifecycle timestamps — as the control plane stores it. It is the HTTP wire
// shape, deliberately distinct from store.Organization so the persistence
// layout can evolve without breaking the public contract.
type organizationResource struct {
	OrganizationID string `json:"organization_id"`
	Slug           string `json:"slug"`
	DisplayName    string `json:"display_name"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

// organizationResourceOf projects a store.Organization into the stable wire
// shape. Timestamps are rendered as UTC RFC 3339 strings so the contract is
// independent of the database driver's time representation and the response is
// deterministic for a given row.
func organizationResourceOf(o store.Organization) organizationResource {
	return organizationResource{
		OrganizationID: o.ID,
		Slug:           o.Slug,
		DisplayName:    o.DisplayName,
		CreatedAt:      o.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:      o.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

// organizationsHandler builds the GET /v1/organizations handler. It lists the
// organizations visible to the authenticated principal — resolved by
// RequireAuth and carried on the request context — by reading them from the
// source-of-truth database.
//
// A principal is bound to exactly one home organization, and the route carries
// no path parameter, so the handler only ever reads the principal's own home
// organization: the tenant boundary is structural here — there is no caller
// input that could point the read at another tenant. The response is a
// single-element list; the array shape is forward-compatible with credentials
// that may span organizations later.
//
// RequireAuth gates the route on action organization.read before the handler
// runs, so a request that reaches the handler with no principal is a wiring
// error and is reported as a typed internal error rather than serving an empty
// list. A reader-store outage surfaces as its own typed 5xx, and a home
// organization that has no row is the typed NotFound the reader produces —
// never disguised as an empty success.
func organizationsHandler(reader OrganizationReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoOrganizationReader))
			return
		}
		org, err := reader.GetOrganization(r.Context(), p.OrganizationID)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), organizationsPayload{
			Organizations: []organizationResource{organizationResourceOf(org)},
		})
	}
}

// OrganizationCreator is the narrow persistence port POST /v1/organizations
// depends on. *store.OrganizationService satisfies it in production; tests
// supply a fake. Like OrganizationReader it is an interface declared here so
// the handler stays unit-testable without a real database — the concrete
// orchestrator (the desired-state write and the audit record committed in one
// transaction) lives in the store layer.
type OrganizationCreator interface {
	Create(ctx context.Context, in store.CreateOrganizationInput) (store.Organization, error)
}

// createOrganizationRequest is the decoded POST /v1/organizations request body.
// Slug is the canonical [a-z0-9-] identifier the organization is addressed by;
// DisplayName is its human-authored label. The store layer validates both
// before any database work — an invalid request never opens a transaction —
// and neither field carries credential material.
type createOrganizationRequest struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// createOrganizationPayload is the data block of the POST /v1/organizations
// success envelope: the organization that was created, in the same stable wire
// shape GET /v1/organizations returns. It carries no credential material.
type createOrganizationPayload struct {
	Organization organizationResource `json:"organization"`
}

// createOrganizationHandler builds the POST /v1/organizations handler. It
// decodes and delegates: the request body is strictly decoded (oversized,
// malformed, or unknown-field bodies become a typed 400 that never echoes the
// input), then the create-organization unit of work — validate, write the
// row, append the audit record, all in one transaction — runs in the store
// layer through the OrganizationCreator port.
//
// RequireAuth gates the route on action organization.create before the handler
// runs and attaches the resolved principal, so a request that reaches the
// handler with no principal is a wiring error reported as a typed internal
// error. The principal and the request correlation identifiers are passed to
// the creator so the audit record names the actor; a slug conflict, a
// validation failure, and a datastore outage each surface as their own typed
// status, never disguised as one another.
func createOrganizationHandler(creator OrganizationCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if creator == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoOrganizationCreator))
			return
		}

		var req createOrganizationRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		org, err := creator.Create(r.Context(), store.CreateOrganizationInput{
			Slug:          req.Slug,
			DisplayName:   req.DisplayName,
			ActorID:       p.ID,
			ActorKind:     string(p.Kind),
			ActorOrgID:    p.OrganizationID,
			RequestID:     correlation.RequestID,
			CorrelationID: correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusCreated, requestID(r), createOrganizationPayload{
			Organization: organizationResourceOf(org),
		})
	}
}
