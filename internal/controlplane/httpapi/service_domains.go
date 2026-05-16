package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
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
