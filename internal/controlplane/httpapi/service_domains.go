package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// errNoServiceDomainReader is returned when GET
// /v1/services/{service_id}/domains is reached without a
// ServiceDomainReader wired into NewHandler. Like
// errNoServiceMetricsReader it can only happen through a wiring error
// — a programming mistake, not a client error — so the handler reports
// it as a typed internal failure rather than serving a misleading
// empty list (which would invite an agent to believe the service
// exists with no domain rows when in fact no domain source is
// configured).
var errNoServiceDomainReader = errors.New("httpapi: no service domain reader configured")

// errNoServiceDomainCreator is returned when POST
// /v1/services/{service_id}/domains is reached without a
// ServiceDomainCreator wired into NewHandler. Like
// errNoServiceDomainReader it can only happen through a wiring error —
// a programming mistake, not a client error — so the handler reports
// it as a typed internal failure rather than serving a misleading 2xx
// with no side effect.
var errNoServiceDomainCreator = errors.New("httpapi: no service domain creator configured")

// errNoServiceDomainUpdater is returned when PATCH
// /v1/services/{service_id}/domains/{domain_id} is reached without a
// ServiceDomainUpdater wired into NewHandler. Like
// errNoServiceDomainCreator it can only happen through a wiring error
// — a programming mistake, not a client error — so the handler reports
// it as a typed internal failure rather than serving a misleading 2xx
// with no side effect.
var errNoServiceDomainUpdater = errors.New("httpapi: no service domain updater configured")

// errNoServiceDomainDeleter is returned when DELETE
// /v1/services/{service_id}/domains/{domain_id} is reached without a
// ServiceDomainDeleter wired into NewHandler. Like
// errNoServiceDomainUpdater it can only happen through a wiring error
// — a programming mistake, not a client error — so the handler reports
// it as a typed internal failure rather than serving a misleading 2xx
// (a 200 OK echoing the deleted snapshot when no row was actually
// removed would be the worst possible signal for an agent).
var errNoServiceDomainDeleter = errors.New("httpapi: no service domain deleter configured")

// ServiceDomainReader is the narrow persistence port GET
// /v1/services/{service_id}/domains depends on.
// *store.ServiceDomainReader satisfies it in production; tests supply
// a fake. Keeping the dependency an interface keeps the handler
// unit-testable without a real database — the concrete adapter
// performs the tenant-scoped service existence check inside a short-
// lived read-only transaction (so a cross-tenant or unknown
// service_id surfaces as a typed apierr.NotFound before any domain
// fetch runs) and projects the resulting domain set onto the stable
// wire shape this handler returns.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action domain.read against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the reader has already
// cleared the policy boundary. The store layer still re-validates the
// tenant scope at the SQL leg — defense-in-depth against a grant
// change that landed between the HTTP authorize and the read.
type ServiceDomainReader interface {
	ListDomains(ctx context.Context, in store.ListServiceDomainsInput) (store.ServiceDomains, error)
}

// serviceDomain is the wire-shape of one entry in the domain list. It
// is the projection of store.ServiceDomain onto stable JSON tag names;
// an agent reading the payload can branch on hostname, path, port,
// https, and certificate_type without escape-decoding them. The
// payload carries no secret material: the certificate_type column
// names the issuance behavior (lets-encrypt, custom, none) but the
// actual certificate material is held by the worker / Dokploy layer
// and never round-tripped through this endpoint.
type serviceDomain struct {
	ID              string `json:"id"`
	ServiceID       string `json:"service_id"`
	Hostname        string `json:"hostname"`
	Path            string `json:"path"`
	Port            int    `json:"port"`
	HTTPS           bool   `json:"https"`
	CertificateType string `json:"certificate_type"`
	Version         int64  `json:"version"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// listServiceDomainsPayload is the data block of the GET
// /v1/services/{service_id}/domains success envelope: the service id
// the domains belong to (echoed back so an agent can distinguish a
// multi-resource batch in a future domains-stream endpoint even
// though today's GET addresses exactly one service) and the domains
// themselves in deterministic (hostname, path, id) order. An empty
// domains slice marshals as "domains": [] rather than "domains":
// null, which is what every list payload in the API surface returns
// to keep agents from special-casing the absent-vs-empty distinction.
type listServiceDomainsPayload struct {
	ServiceID string          `json:"service_id"`
	Domains   []serviceDomain `json:"domains"`
}

// listServiceDomainsHandler builds the GET /v1/services/{service_id}/domains
// handler. It reads the domain rows for the service named by the
// {service_id} path parameter through the ServiceDomainReader port
// and renders them in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action domain.read before the
// handler runs — authorized through serviceIDResolver against the
// (principal home organization, {service_id}) resource the path
// names — and attaches the resolved principal to the context.
// domain.read is a CapRead action, so the gate admits the
// principal's organization-wide read roles (owner, admin, developer,
// viewer, ci). The support principal's cross-tenant read exception
// does NOT apply through this endpoint because the resolver pins the
// resource scope to the principal's home organization, not the path
// service's tenant — support cross-tenant domain reads remain
// available through endpoints whose path carries an explicit
// {org_id}. The path carries no parent project_id or environment_id,
// so the policy engine cannot pin those legs of the resource scope at
// authorization time — project-, environment-, and service-scoped
// grants are denied at the boundary by the engine's covers() rule (a
// grant with a pinned ProjectID cannot cover a resource with no
// ProjectID); principals whose only access is a scoped grant must use
// a parent-scoped route to address a service by its (project,
// environment, service) tuple.
//
// The handler reads from the principal's home organization id only —
// it never trusts a caller-supplied organization id — so the tenant
// boundary is structural at the persistence layer too: a cross-tenant
// service_id reaches the store with the principal's home organization
// id and is rejected as a typed NotFound by the tenant-scoped
// existence check. A request that arrives with no principal is a
// wiring error reported as a typed internal error; a reader-store
// outage surfaces as its own typed 5xx; an unknown or cross-tenant
// service_id is a typed 404, never disguised as an empty success.
//
// The response carries no credential material: the certificate_type
// column names the issuance behavior (lets-encrypt, custom, none)
// only, and the actual certificate material is held by the worker /
// Dokploy layer and never round-tripped through this endpoint. The
// empty Domains slice marshals as "domains": [], never "domains":
// null, so an agent does not need to special-case the absent-vs-empty
// distinction.
func listServiceDomainsHandler(reader ServiceDomainReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceDomainReader))
			return
		}

		result, err := reader.ListDomains(r.Context(), store.ListServiceDomainsInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		payload := listServiceDomainsPayload{
			ServiceID: result.ServiceID,
			Domains:   make([]serviceDomain, 0, len(result.Domains)),
		}
		for _, d := range result.Domains {
			payload.Domains = append(payload.Domains, serviceDomain{
				ID:              d.ID,
				ServiceID:       d.ServiceID,
				Hostname:        d.Hostname,
				Path:            d.Path,
				Port:            d.Port,
				HTTPS:           d.HTTPS,
				CertificateType: d.CertificateType,
				Version:         d.Version,
				CreatedAt:       d.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
				UpdatedAt:       d.UpdatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
			})
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}

// serviceDomainOf projects a store.ServiceDomain onto the stable wire
// shape. It is the single chokepoint between the persistence layer and
// the response: a future column added to store.ServiceDomain is
// reviewed for its wire exposure here rather than leaking by default.
// Both timestamps are rendered as RFC 3339 strings with nanosecond
// precision and a "Z" zone — the same format every other dated
// resource the service-domains surface returns.
func serviceDomainOf(d store.ServiceDomain) serviceDomain {
	return serviceDomain{
		ID:              d.ID,
		ServiceID:       d.ServiceID,
		Hostname:        d.Hostname,
		Path:            d.Path,
		Port:            d.Port,
		HTTPS:           d.HTTPS,
		CertificateType: d.CertificateType,
		Version:         d.Version,
		CreatedAt:       d.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		UpdatedAt:       d.UpdatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
	}
}

// ServiceDomainCreator is the narrow persistence port POST
// /v1/services/{service_id}/domains depends on.
// *store.ServiceDomainService satisfies it in production; tests supply
// a fake. Keeping the dependency an interface keeps the handler unit-
// testable without a real database — the concrete orchestrator (the
// parent-service existence check / in-transaction authorize /
// desired-state write / audit append composition committed in one
// transaction) lives in the store layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action domain.create against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the creator has already
// cleared the policy boundary. The store layer still re-authorizes
// inside the same *Tx as the desired-state write — defense-in-depth
// against a grant change that landed between the HTTP authorize and
// the domain row write.
type ServiceDomainCreator interface {
	Create(ctx context.Context, in store.CreateServiceDomainInput) (store.ServiceDomain, error)
}

// createServiceDomainRequest is the decoded POST
// /v1/services/{service_id}/domains request body. ID is the caller-
// supplied canonical domain id — the agent contract mints ids client-
// side so a retried POST is structurally idempotent under the (hostname,
// path) uniqueness constraint rather than depending on a header. The
// (hostname, path) tuple names the public routable address; port and
// https describe how Yalla's worker should terminate inbound traffic;
// certificate_type ("lets-encrypt", "custom", or "none") drives TLS
// issuance behavior in the worker — the actual certificate material is
// held by the worker / Dokploy layer and never round-tripped through
// this endpoint.
//
// The request body intentionally exposes no organization_id,
// project_id, environment_id, or service_id field: the organization is
// derived from the authenticated principal's home organization, the
// service comes from the {service_id} path parameter, and the new
// domain inherits its parent service's transitive parents from the
// persisted services row — there is no caller-supplied parameter that
// could redirect the create at another tenant, another project, or
// another environment.
//
// Path defaults to "/" when omitted. HTTPS defaults to true (the
// schema-side default — most customer hostnames terminate TLS).
// CertificateType defaults to "lets-encrypt" (the schema-side default).
// The store layer validates every field before any database work, so
// an invalid request never opens a transaction — and the request body
// never carries credential material.
type createServiceDomainRequest struct {
	ID              string `json:"id"`
	Hostname        string `json:"hostname"`
	Path            string `json:"path"`
	Port            int    `json:"port"`
	HTTPS           *bool  `json:"https"`
	CertificateType string `json:"certificate_type"`
}

// createServiceDomainPayload is the data block of the POST
// /v1/services/{service_id}/domains success envelope: the domain that
// was created, in the same stable wire shape GET
// /v1/services/{service_id}/domains returns. It carries no credential
// material — a service_domains row stores none.
type createServiceDomainPayload struct {
	Domain serviceDomain `json:"domain"`
}

// createServiceDomainHandler builds the POST
// /v1/services/{service_id}/domains handler. It decodes and delegates:
// the request body is strictly decoded (oversized, malformed, or
// unknown-field bodies become a typed 400 that never echoes the input),
// then the create-domain unit of work — re-authorize, write the domain
// row, append the audit record, all in one transaction — runs in the
// store layer through the ServiceDomainCreator port.
//
// RequireAuth gates the route on action domain.create through
// serviceIDResolver before the handler runs and attaches the resolved
// principal, so a request that reaches the handler with no principal
// is a wiring error reported as a typed internal error.
// domain.create is a CapWrite action evaluated against the (principal
// home organization, {service_id}) resource, so the gate admits the
// principal's organization-wide write roles (owner, admin, developer,
// ci) and denies viewer (CapRead only), denies support (CapRead-only
// — support is a deliberate cross-tenant READ exception, never a
// write one). The path carries no parent project_id, so the policy
// engine cannot pin the ProjectID leg of the resource scope at
// authorization time — project-, environment-, and service-scoped
// grants are denied at the boundary by the engine's covers() rule (a
// grant scope that pins ProjectID cannot cover a resource scope that
// does not); principals whose only access is a scoped grant must use
// a parent-scoped route to address a service by its (project,
// environment, service) tuple.
//
// The handler resolves the organization id from the authenticated
// principal's home organization and the service id from the
// {service_id} PATH parameter — never from the request body — so the
// tenant boundary is structural here: there is no caller input that
// could point the write at another tenant. A cross-tenant service_id
// reaches the persistence layer with the principal's home organization
// id and is rejected as a deterministic 404 by the store-layer's
// tenant-scoped service existence check (the same property GET
// /v1/services/{service_id}/domains inherits), never disguised as a
// 200 or a 403 that would confirm the foreign service's existence.
// The principal and the request correlation identifiers are passed to
// the creator so the audit record names the actor; a validation
// failure, a (hostname, path) conflict, a denied in-tx authorize, and
// a datastore outage each surface as their own typed status, never
// disguised as one another.
func createServiceDomainHandler(creator ServiceDomainCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if creator == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceDomainCreator))
			return
		}

		var req createServiceDomainRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		// HTTPS is a pointer so the absent-vs-explicit-false distinction
		// is visible at this seam: an omitted field defaults to the
		// schema default (true), an explicit `false` rides through to
		// the store layer unchanged.
		https := true
		if req.HTTPS != nil {
			https = *req.HTTPS
		}

		correlation := telemetry.FromContext(r.Context())
		created, err := creator.Create(r.Context(), store.CreateServiceDomainInput{
			OrganizationID:  p.OrganizationID,
			ServiceID:       r.PathValue("service_id"),
			DomainID:        req.ID,
			Hostname:        req.Hostname,
			Path:            req.Path,
			Port:            req.Port,
			HTTPS:           https,
			CertificateType: req.CertificateType,
			ActorID:         p.ID,
			ActorKind:       string(p.Kind),
			ActorOrgID:      p.OrganizationID,
			RequestID:       correlation.RequestID,
			CorrelationID:   correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusCreated, requestID(r), createServiceDomainPayload{
			Domain: serviceDomainOf(created),
		})
	}
}

// ServiceDomainUpdater is the narrow persistence port PATCH
// /v1/services/{service_id}/domains/{domain_id} depends on.
// *store.ServiceDomainService satisfies it in production; tests supply
// a fake. Keeping the dependency an interface keeps the handler unit-
// testable without a real database — the concrete orchestrator (the
// row read / If-Match precondition / desired-state write / audit
// append composition committed in one transaction) lives in the store
// layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action domain.update against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the updater has already
// cleared the policy boundary. The store layer does not re-authorize
// inside the same *Tx for the update path: domain.update is enforced
// only at the HTTP boundary, matching service.update, project.update,
// and the other CapWrite partial-update endpoints — the in-transaction
// Authorizer is reserved for Create (the create-time race against
// grant changes during a quota reservation).
type ServiceDomainUpdater interface {
	Update(ctx context.Context, in store.UpdateServiceDomainInput) (store.ServiceDomain, error)
}

// updateServiceDomainRequest is the decoded PATCH
// /v1/services/{service_id}/domains/{domain_id} request body. Every
// field is an optional pointer so the absent-vs-zero distinction is
// preserved at the seam — an omitted hostname means "leave the
// hostname alone", and an empty path means "fall back to the
// schema-side default '/'". A patch that names no updatable field is
// itself a 400 — a mutation that changes nothing is a client error,
// not a silent success.
//
// The request body intentionally exposes no organization_id,
// service_id, or id field: the organization is derived from the
// authenticated principal's home organization, the service comes from
// the {service_id} path parameter, and the domain id from the
// {domain_id} path parameter — there is no caller-supplied parameter
// in the body that could redirect the write at another tenant.
type updateServiceDomainRequest struct {
	Hostname        *string `json:"hostname"`
	Path            *string `json:"path"`
	Port            *int    `json:"port"`
	HTTPS           *bool   `json:"https"`
	CertificateType *string `json:"certificate_type"`
}

// updateServiceDomainPayload is the data block of the PATCH
// /v1/services/{service_id}/domains/{domain_id} success envelope: the
// domain after the update, in the same stable wire shape the other
// service-domain endpoints return. It carries no credential material —
// the service_domains table itself stores none; the certificate_type
// column names the issuance behavior only.
type updateServiceDomainPayload struct {
	Domain serviceDomain `json:"domain"`
}

// updateServiceDomainHandler builds the PATCH
// /v1/services/{service_id}/domains/{domain_id} handler. It decodes and
// delegates: the request body is strictly decoded (oversized,
// malformed, or unknown-field bodies become a typed 400 that never
// echoes the input), the If-Match header is parsed as an optional
// optimistic-concurrency precondition, and then the update-domain unit
// of work — read the current row, apply the patch, write the row
// back, append the audit record, all in one transaction — runs in the
// store layer through the ServiceDomainUpdater port.
//
// RequireAuth gates the route on action domain.update before the
// handler runs — authorized through serviceIDResolver against the
// (principal home organization, {service_id}) resource the path
// names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the policy boundary.
// domain.update is a CapWrite action, so the gate admits the
// principal's organization-wide write roles (owner, admin, developer,
// ci) and denies viewer (CapRead only), denies support (CapRead +
// CapSupport — support is a deliberate cross-tenant READ exception,
// never a write one). The path carries no parent project_id, so the
// policy engine cannot pin the ProjectID leg of the resource scope at
// authorization time — project-, environment-, and service-scoped
// grants are denied at the boundary by the engine's covers() rule (a
// grant scope that pins ProjectID cannot cover a resource scope that
// does not); principals whose only access is a scoped grant must use
// a parent-scoped route to address a service by its (project,
// environment, service) tuple.
//
// The handler resolves the organization id from the authenticated
// principal's home organization, the service id from the {service_id}
// PATH parameter, and the domain id from the {domain_id} PATH
// parameter — never from the request body — so the tenant boundary is
// structural here: there is no caller input that could point the
// write at another tenant. A cross-tenant service_id or domain_id
// reaches the persistence layer with the principal's home
// organization id and is rejected as a deterministic 404 by the
// store-layer's tenant-scoped GetByID query, never disguised as a 200
// or a 403 that would confirm the foreign row's existence. On
// success, the handler mirrors the row's authoritative version into
// the ETag response header so the caller can echo it back as the next
// If-Match precondition without re-reading the row.
func updateServiceDomainHandler(updater ServiceDomainUpdater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if updater == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceDomainUpdater))
			return
		}

		ifMatchVersion, ifMatchErr := parseIfMatchVersion(r)
		if ifMatchErr != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(ifMatchErr))
			return
		}

		var req updateServiceDomainRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		updated, err := updater.Update(r.Context(), store.UpdateServiceDomainInput{
			OrganizationID:  p.OrganizationID,
			ServiceID:       r.PathValue("service_id"),
			DomainID:        r.PathValue("domain_id"),
			Hostname:        req.Hostname,
			Path:            req.Path,
			Port:            req.Port,
			HTTPS:           req.HTTPS,
			CertificateType: req.CertificateType,
			IfMatchVersion:  ifMatchVersion,
			ActorID:         p.ID,
			ActorKind:       string(p.Kind),
			ActorOrgID:      p.OrganizationID,
			RequestID:       correlation.RequestID,
			CorrelationID:   correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		writeOrganizationETag(w, updated.Version)
		apienvelope.WriteData(w, http.StatusOK, requestID(r), updateServiceDomainPayload{
			Domain: serviceDomainOf(updated),
		})
	}
}

// ServiceDomainDeleter is the narrow persistence port DELETE
// /v1/services/{service_id}/domains/{domain_id} depends on.
// *store.ServiceDomainService satisfies it in production; tests supply
// a fake. Keeping the dependency an interface keeps the handler unit-
// testable without a real database — the concrete orchestrator (the
// tenant-scoped DELETE / optional If-Match precondition / audit append
// composition committed in one transaction) lives in the store layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action domain.delete against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the deleter has already
// cleared the policy boundary. The store layer does not re-authorize
// inside the same *Tx for the delete path: domain.delete is enforced
// only at the HTTP boundary, matching service.delete, project.delete,
// and the other CapWrite endpoints — the in-transaction Authorizer is
// reserved for Create (the create-time race against grant changes
// during a quota reservation).
type ServiceDomainDeleter interface {
	Delete(ctx context.Context, in store.DeleteServiceDomainInput) (store.ServiceDomain, error)
}

// deleteServiceDomainPayload is the data block of the DELETE
// /v1/services/{service_id}/domains/{domain_id} success envelope: the
// domain row as it stood at the moment of removal, in the same stable
// wire shape every other service-domain endpoint returns. It carries
// no credential material — the service_domains table itself stores
// none; the certificate_type column names the issuance behavior only.
// The row is gone from the database by the time this body reaches the
// wire; an audit trail of the deletion lives independently of the row.
type deleteServiceDomainPayload struct {
	Domain serviceDomain `json:"domain"`
}

// deleteServiceDomainHandler builds the DELETE
// /v1/services/{service_id}/domains/{domain_id} handler. It delegates
// to the ServiceDomainDeleter port the tenant-scoped delete + audit
// unit of work, then projects the deleted snapshot onto the wire. The
// optional If-Match header is parsed as an optimistic-concurrency
// precondition before the deleter runs.
//
// RequireAuth gates the route on action domain.delete before the
// handler runs — authorized through serviceIDResolver against the
// (principal home organization, {service_id}) resource the path
// names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the policy boundary.
// domain.delete is a CapWrite action, so the gate admits the
// principal's organization-wide write roles (owner, admin, developer,
// ci) and denies viewer (CapRead only), denies support (CapRead +
// CapSupport — support is a deliberate cross-tenant READ exception,
// never a write one). The path carries no parent project_id, so the
// policy engine cannot pin the ProjectID leg of the resource scope at
// authorization time — project-, environment-, and service-scoped
// grants are denied at the boundary by the engine's covers() rule (a
// grant scope that pins ProjectID cannot cover a resource scope that
// does not); principals whose only access is a scoped grant must use
// a parent-scoped route to address a service by its (project,
// environment, service) tuple.
//
// The handler resolves the organization id from the authenticated
// principal's home organization, the service id from the {service_id}
// PATH parameter, and the domain id from the {domain_id} PATH
// parameter — never from the request body (a DELETE has none) — so
// the tenant boundary is structural here: there is no caller input
// that could point the delete at another tenant. A cross-tenant
// service_id or domain_id reaches the persistence layer with the
// principal's home organization id and is rejected as a deterministic
// 404 by the store-layer's tenant-scoped DELETE predicate, never
// disguised as a 200 or a 403 that would confirm the foreign row's
// existence.
//
// The response is 200 OK carrying the deleted domain as a snapshot —
// agents can confirm what was destroyed without re-reading. The row
// is gone from the database by the time this body reaches the wire;
// an audit trail of the deletion lives independently of the row. A
// 204 No Content was deliberately not chosen: a body-bearing success
// keeps the wire contract uniform with every other service-domain
// endpoint and prevents agents from special-casing the no-body code
// path.
func deleteServiceDomainHandler(deleter ServiceDomainDeleter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if deleter == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceDomainDeleter))
			return
		}

		ifMatchVersion, ifMatchErr := parseIfMatchVersion(r)
		if ifMatchErr != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(ifMatchErr))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		deleted, err := deleter.Delete(r.Context(), store.DeleteServiceDomainInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
			DomainID:       r.PathValue("domain_id"),
			IfMatchVersion: ifMatchVersion,
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

		apienvelope.WriteData(w, http.StatusOK, requestID(r), deleteServiceDomainPayload{
			Domain: serviceDomainOf(deleted),
		})
	}
}
