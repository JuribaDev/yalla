package store

import (
	"context"
	"errors"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// ServiceDomain is a single service-scoped public-facing hostname route —
// a (hostname, path) tuple bound to a single service that maps an
// inbound HTTP request to the running Dokploy resource. A service may
// hold many domains; a (hostname, path) tuple may appear on at most
// one service across the entire cluster (the table's UNIQUE
// (hostname, path) constraint, enforced at the database).
//
// The struct shape is the stable structural row the httpapi service-
// domains payload projects onto the wire as-is (modulo JSON tag
// naming) — no pointer-typed fields, no embedded interfaces, no
// Dokploy- or worker-specific identifiers. Adding a new field is a
// strictly forward-compatible operation; renaming or removing one is
// a wire break.
type ServiceDomain struct {
	ID              string
	OrganizationID  string
	ServiceID       string
	Hostname        string
	Path            string
	Port            int
	HTTPS           bool
	CertificateType string
	Version         int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// serviceDomainColumns is the SELECT projection used by every read in
// this repository. Keeping it as a single string keeps the column list
// in lockstep with scanServiceDomain.
const serviceDomainColumns = `id, organization_id, service_id, hostname, path, port, https, certificate_type, version, created_at, updated_at`

// serviceDomainListMaxRows caps how many rows a single ListByService
// call returns. An unbounded query can never be issued by accident; an
// HTTP layer that wants pagination later will add an explicit offset
// or cursor parameter rather than relax this ceiling.
const serviceDomainListMaxRows = 500

// ServiceDomainRepository is the persistence half of the service-
// domains surface. Every read is tenant-scoped: the organization_id
// and service_id legs of the predicate are non-optional, so a missing
// or cross-tenant id simply matches no rows and yields an empty list —
// never another tenant's domains. The repository is stateless; the
// constructor exists so call sites depend on a value rather than a
// bare struct literal.
type ServiceDomainRepository struct{}

// NewServiceDomainRepository builds a stateless ServiceDomainRepository.
func NewServiceDomainRepository() *ServiceDomainRepository {
	return &ServiceDomainRepository{}
}

// ListByService returns every service-scoped domain owned by
// (organizationID, serviceID), in deterministic (hostname ASC, path
// ASC, id ASC) order so an agent observing the response sees a stable
// ordering across calls. The read is tenant-scoped at the SQL
// predicate, so a cross-tenant (organization, service) tuple matches
// no rows. A raw driver error surfaces as the typed
// apierr.StoreUnavailable — the cause is wrapped for logging only,
// never leaked into the customer-facing message.
//
// This method does NOT verify the service exists; callers that need
// to distinguish "service missing" from "service has no domains" must
// Get the service first (the ServiceDomainReader adapter does so in
// the same short-lived transaction).
func (r *ServiceDomainRepository) ListByService(ctx context.Context, q Querier, organizationID, serviceID string) ([]ServiceDomain, error) {
	rows, err := q.Query(ctx,
		`SELECT `+serviceDomainColumns+`
		   FROM service_domains
		  WHERE organization_id = $1 AND service_id = $2
		  ORDER BY hostname ASC, path ASC, id ASC
		  LIMIT $3`,
		organizationID, serviceID, serviceDomainListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]ServiceDomain, 0)
	for rows.Next() {
		d, scanErr := scanServiceDomain(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// scanServiceDomain scans one service_domains row in
// serviceDomainColumns order.
func scanServiceDomain(row scanRow) (ServiceDomain, error) {
	var d ServiceDomain
	if err := row.Scan(
		&d.ID,
		&d.OrganizationID,
		&d.ServiceID,
		&d.Hostname,
		&d.Path,
		&d.Port,
		&d.HTTPS,
		&d.CertificateType,
		&d.Version,
		&d.CreatedAt,
		&d.UpdatedAt,
	); err != nil {
		return ServiceDomain{}, err
	}
	return d, nil
}

// ServiceDomainReader is the store-backed read adapter for the
// service-domains surface: the persistence surface the httpapi layer
// needs to render GET /v1/services/{service_id}/domains. It mirrors
// ServiceVariableReader — it composes ServiceRepository and
// ServiceDomainRepository through a short-lived read-only transaction
// (Store.Read), so the tenant-scoping guarantees the repositories
// prove in their integration tests are inherited for free, and every
// cross-tenant or unknown service_id surfaces as a deterministic
// apierr.NotFound rather than an empty list.
type ServiceDomainReader struct {
	store    *Store
	services *ServiceRepository
	domains  *ServiceDomainRepository
}

// NewServiceDomainReader builds a ServiceDomainReader over store. It
// returns an error for a nil store so a misconfigured adapter fails
// at construction rather than on its first request.
func NewServiceDomainReader(s *Store) (*ServiceDomainReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &ServiceDomainReader{
		store:    s,
		services: NewServiceRepository(),
		domains:  NewServiceDomainRepository(),
	}, nil
}

// ListServiceDomainsInput is the typed input shape
// ServiceDomainReader.ListDomains accepts. OrganizationID is always
// taken from the authenticated principal's home org at the httpapi
// layer (never from caller-controlled request input), and ServiceID
// is always taken from the path parameter; both surface here as
// plain strings so the tenant-scoped existence check that defends
// the boundary cannot be bypassed by a zero value.
type ListServiceDomainsInput struct {
	OrganizationID string
	ServiceID      string
}

// ServiceDomains is the typed response of ServiceDomainReader.ListDomains:
// the service id the domains belong to (echoed back so a caller can
// distinguish a multi-resource batch in a future domains-stream
// endpoint even though today's GET addresses exactly one service) and
// the domains themselves in deterministic order. An empty Domains
// slice with a populated ServiceID means the service exists, is owned
// by the tenant, and has no domain rows — never disguised as a
// NotFound.
type ServiceDomains struct {
	ServiceID string
	Domains   []ServiceDomain
}

// ListDomains returns the domain rows for the service identified by
// (organizationID, serviceID), reading them inside a short-lived
// read-only transaction. The read is tenant scoped at both legs: it
// Gets the service first so a cross-tenant or unknown service_id
// surfaces as a deterministic apierr.NotFound — never as an empty
// list, which would invite an agent to believe the service exists
// with no domains. A live service with no domains is then a
// deterministic empty slice. A datastore failure is propagated as
// its own typed error.
func (r *ServiceDomainReader) ListDomains(ctx context.Context, in ListServiceDomainsInput) (ServiceDomains, error) {
	var svcID string
	var domains []ServiceDomain
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		svc, getErr := r.services.GetByID(ctx, q, in.OrganizationID, in.ServiceID)
		if getErr != nil {
			return getErr
		}
		svcID = svc.ID
		list, listErr := r.domains.ListByService(ctx, q, in.OrganizationID, in.ServiceID)
		if listErr != nil {
			return listErr
		}
		domains = list
		return nil
	})
	if err != nil {
		return ServiceDomains{}, err
	}
	return ServiceDomains{ServiceID: svcID, Domains: domains}, nil
}
