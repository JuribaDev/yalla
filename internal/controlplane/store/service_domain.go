package store

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
	"github.com/jackc/pgx/v5"
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

// Insert writes a new service-scoped domain row inside tx. The caller
// must already have confirmed the parent service exists under
// (organizationID, serviceID) — Insert relies on the table's composite
// FK (organization_id, service_id) -> services (organization_id, id) as
// the database-side belt-and-braces, so a foreign-tenant or unknown
// service id would surface here as a typed mapWriteError rather than a
// raw constraint name. A duplicate (hostname, path) tuple is rejected
// by the table's UNIQUE constraint and mapped to a typed
// apierr.Conflict with a stable, value-free message — the customer-
// facing reason never echoes the submitted hostname or path. Any other
// driver error surfaces as the typed apierr.StoreUnavailable.
//
// version, created_at, and updated_at are owned by the database
// (defaults + triggers from migration 0023), so they are NOT supplied
// by the caller; Insert returns the persisted row with those fields
// populated so the audit record and the wire response can name the
// row's authoritative state.
func (r *ServiceDomainRepository) Insert(ctx context.Context, tx *Tx, d ServiceDomain) (ServiceDomain, error) {
	if tx == nil {
		return ServiceDomain{}, apierr.Internal(errors.New("store: ServiceDomainRepository.Insert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO service_domains
		    (id, organization_id, service_id, hostname, path, port, https, certificate_type)
		  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		  RETURNING `+serviceDomainColumns,
		d.ID, d.OrganizationID, d.ServiceID, d.Hostname, d.Path, d.Port, d.HTTPS, d.CertificateType)
	created, err := scanServiceDomain(row)
	if err != nil {
		return ServiceDomain{}, mapWriteError(err, "a service domain with this hostname and path already exists")
	}
	return created, nil
}

// GetByID returns the service-domain row identified by (organizationID,
// serviceID, domainID), or apierr.NotFound when no row matches the
// tenant-scoped predicate. The query filters on organization_id first
// so a cross-tenant or unknown (service_id, domain_id) tuple matches
// no rows even when a domain with the same id exists in another
// tenant — the response is never an oracle that confirms another
// organization's domain ids. A raw driver error surfaces as the typed
// apierr.StoreUnavailable.
func (r *ServiceDomainRepository) GetByID(ctx context.Context, q Querier, organizationID, serviceID, domainID string) (ServiceDomain, error) {
	row := q.QueryRow(ctx,
		`SELECT `+serviceDomainColumns+`
		   FROM service_domains
		  WHERE organization_id = $1 AND service_id = $2 AND id = $3`,
		organizationID, serviceID, domainID)
	d, err := scanServiceDomain(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceDomain{}, apierr.NotFound("service domain", domainID)
	}
	if err != nil {
		return ServiceDomain{}, apierr.StoreUnavailable(err)
	}
	return d, nil
}

// Update rewrites a service_domains row in place — hostname, path,
// port, https, and certificate_type are the updatable columns; the
// parent (organization_id, service_id) tuple is structural identity
// and cannot be reparented through this endpoint. The row's version
// column is owned by the service_domains_bump_version trigger from
// migration 0023 — Update never writes it itself, the trigger bumps
// it on every successful UPDATE.
//
// When ifMatchVersion is nil the predicate matches on
// (organization_id, service_id, id) alone — next-write-wins. When
// ifMatchVersion is non-nil the predicate also requires
// version = *ifMatchVersion, so a concurrent writer landing between
// the caller's read and this write is rejected as a typed
// apierr.ConflictStale carrying the row's authoritative version. The
// disambiguation between "row missing" and "version stale" runs
// through classifyServiceDomainConcurrencyMiss so the caller learns
// which precondition actually failed.
//
// A (hostname, path) already taken by another service-domain row
// anywhere in the cluster violates UNIQUE (hostname, path) and
// surfaces through mapWriteError as a deterministic apierr.Conflict —
// never a 500 leaking the constraint name. The repository is
// tenant-scoped at the SQL predicate: a cross-tenant
// (organization_id, service_id, id) tuple matches no row even when a
// domain with the same id exists in another tenant.
func (r *ServiceDomainRepository) Update(ctx context.Context, tx *Tx, d ServiceDomain, ifMatchVersion *int64) (ServiceDomain, error) {
	if tx == nil {
		return ServiceDomain{}, apierr.Internal(errors.New("store: ServiceDomainRepository.Update called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`UPDATE service_domains
			    SET hostname = $4, path = $5, port = $6, https = $7, certificate_type = $8
			  WHERE organization_id = $1 AND service_id = $2 AND id = $3
			 RETURNING `+serviceDomainColumns,
			d.OrganizationID, d.ServiceID, d.ID, d.Hostname, d.Path, d.Port, d.HTTPS, d.CertificateType)
	} else {
		row = tx.QueryRow(ctx,
			`UPDATE service_domains
			    SET hostname = $4, path = $5, port = $6, https = $7, certificate_type = $8
			  WHERE organization_id = $1 AND service_id = $2 AND id = $3 AND version = $9
			 RETURNING `+serviceDomainColumns,
			d.OrganizationID, d.ServiceID, d.ID, d.Hostname, d.Path, d.Port, d.HTTPS, d.CertificateType, *ifMatchVersion)
	}
	updated, err := scanServiceDomain(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return ServiceDomain{}, apierr.NotFound("service domain", d.ID)
		}
		return ServiceDomain{}, classifyServiceDomainConcurrencyMiss(ctx, tx, d.OrganizationID, d.ServiceID, d.ID, *ifMatchVersion)
	}
	if err != nil {
		return ServiceDomain{}, mapWriteError(err, "a service domain with this hostname and path already exists")
	}
	return updated, nil
}

// classifyServiceDomainConcurrencyMiss disambiguates the two reasons a
// version-checked UPDATE matched no rows: the domain was deleted
// (reported as NotFound for parity with the unchecked path) or the
// caller's view of the version is stale (reported as
// apierr.ConflictStale carrying the row's authoritative version). The
// read runs on the same *Tx as the failed write so the version it
// reports is consistent with the predicate that just rejected.
func classifyServiceDomainConcurrencyMiss(ctx context.Context, tx *Tx, organizationID, serviceID, domainID string, ifMatchVersion int64) error {
	r := NewServiceDomainRepository()
	current, err := r.GetByID(ctx, tx, organizationID, serviceID, domainID)
	if err != nil {
		return err
	}
	if current.Version == ifMatchVersion {
		return apierr.Internal(errors.New("store: ServiceDomainRepository.Update saw the same version after a no-row UPDATE"))
	}
	return apierr.ConflictStale(current.Version)
}

// DeleteByID removes the service_domains row identified by
// (organizationID, serviceID, domainID) and returns the deleted row as
// it stood at the moment of removal so the caller can render it onto
// the wire and the audit record can name the row that was destroyed.
// service_domains has no soft-delete column — a public-facing route is
// a routing artefact, not a continuing audit-trail tie that must
// outlive the resource, so the row is removed outright. The delete is
// tenant scoped: the predicate filters on organization_id first so a
// cross-tenant or unknown (service_id, domain_id) tuple matches no
// rows even when a domain with the same id exists in another tenant,
// and the response is never an oracle that confirms another
// organization's domain ids.
//
// When ifMatchVersion is nil the predicate matches on
// (organization_id, service_id, id) alone — next-write-wins. When it
// is non-nil the predicate ALSO requires version = *ifMatchVersion so
// a concurrent writer landing between the caller's read and this
// delete is rejected with a typed apierr.ConflictStale carrying the
// row's authoritative version. The pointer indirection distinguishes
// "caller did not supply a precondition" from "caller supplied
// version 0", which is impossible by schema CHECK and must not
// silently behave like the unchecked path. A no-row delete with a
// non-nil precondition disambiguates through classifyServiceDomain
// ConcurrencyMiss into either NotFound (row really is gone) or
// ConflictStale (version moved under the caller's feet).
func (r *ServiceDomainRepository) DeleteByID(ctx context.Context, tx *Tx, organizationID, serviceID, domainID string, ifMatchVersion *int64) (ServiceDomain, error) {
	if tx == nil {
		return ServiceDomain{}, apierr.Internal(errors.New("store: ServiceDomainRepository.DeleteByID called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`DELETE FROM service_domains
			  WHERE organization_id = $1 AND service_id = $2 AND id = $3
			 RETURNING `+serviceDomainColumns,
			organizationID, serviceID, domainID)
	} else {
		row = tx.QueryRow(ctx,
			`DELETE FROM service_domains
			  WHERE organization_id = $1 AND service_id = $2 AND id = $3 AND version = $4
			 RETURNING `+serviceDomainColumns,
			organizationID, serviceID, domainID, *ifMatchVersion)
	}
	deleted, err := scanServiceDomain(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return ServiceDomain{}, apierr.NotFound("service domain", domainID)
		}
		return ServiceDomain{}, classifyServiceDomainConcurrencyMiss(ctx, tx, organizationID, serviceID, domainID, *ifMatchVersion)
	}
	if err != nil {
		return ServiceDomain{}, apierr.StoreUnavailable(err)
	}
	return deleted, nil
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

// serviceDomainCreateAction is the immutable audit-event Action string
// emitted when a service domain is created. The constant lives in the
// store layer because the audit event is written from the same *Tx as
// the desired-state row.
const serviceDomainCreateAction = "domain.create"

// serviceDomainUpdateAction is the immutable audit-event Action string
// emitted when a service domain is updated. The constant lives in the
// store layer because the audit event is written from the same *Tx as
// the desired-state row.
const serviceDomainUpdateAction = "domain.update"

// serviceDomainDeleteAction is the immutable audit-event Action string
// emitted when a service domain is deleted. The constant lives in the
// store layer because the audit event is written from the same *Tx as
// the desired-state row.
const serviceDomainDeleteAction = "domain.delete"

// serviceDomainCertificateType* enumerate the closed TLS-issuance
// taxonomy the service_domains table's certificate_type CHECK confines.
// The constants live in the store layer because
// validateCreateServiceDomainInput compares against them before any
// database work; the CHECK in migration 0023 is the database-side
// belt-and-braces that rejects an out-of-set value even if the
// application layer ever forgets.
const (
	ServiceDomainCertificateLetsEncrypt = "lets-encrypt"
	ServiceDomainCertificateCustom      = "custom"
	ServiceDomainCertificateNone        = "none"
)

// serviceDomainDefaultPath is the path applied when the caller does not
// supply one; the table's default is the same, so a domain that names
// only a hostname routes the bare path.
const serviceDomainDefaultPath = "/"

// serviceDomainMaxPathLen bounds a service-domain path. It is the same
// repository-relative path bound the validate package's Path uses, with
// the addition that an absolute leading "/" is required (a service-
// domain path is a URL path, not a repository path).
const serviceDomainMaxPathLen = validate.MaxPathLen

// CreateServiceDomainInput is the unvalidated input to
// ServiceDomainService.Create. OrganizationID, ServiceID, DomainID,
// Hostname, Path, Port, HTTPS, and CertificateType are the caller-
// supplied resource fields; the Actor* and correlation fields describe
// the authenticated principal performing the create and are recorded
// verbatim on the audit event. They are plain strings so the store
// layer takes no build dependency on the policy or telemetry packages
// — the httpapi handler, which already holds the resolved principal
// and the request correlation, fills them in.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. ServiceID is sourced from the {service_id} PATH
// parameter, and the create unit of work re-reads the parent service
// under (OrganizationID, ServiceID) before any write — a cross-tenant
// or unknown service_id surfaces as a deterministic apierr.NotFound
// rather than a 500 or a silent success.
//
// Path is optional: an empty string is treated as the table's default
// "/" so a caller that names only a hostname routes the bare path.
// HTTPS and CertificateType carry their schema defaults (true and
// "lets-encrypt") when the caller leaves them at their zero values
// for booleans and empty strings respectively.
type CreateServiceDomainInput struct {
	OrganizationID  string
	ServiceID       string
	DomainID        string
	Hostname        string
	Path            string
	Port            int
	HTTPS           bool
	CertificateType string
	ActorID         string
	ActorKind       string
	ActorOrgID      string
	RequestID       string
	CorrelationID   string
}

// ServiceDomainService is the reference unit-of-work orchestrator for
// the create-service-domain transaction pattern. Create composes — in
// this fixed order, inside one transaction — a parent-service existence
// check, an in-transaction authorization check, the desired-state
// write, and the immutable audit record. Because every step shares the
// *Tx opened by Store.Write, a failure in any step rolls back every
// other step: the authorization and audit checks are impossible to
// bypass, and a domain row is never persisted without its audit trail.
//
// The httpapi RequireAuth middleware is the authoritative authorization
// gate for action domain.create (service-scoped via serviceIDResolver).
// The store-layer Authorize call is defense-in-depth against a grant
// change that landed between the HTTP authorize and the desired-state
// write — it runs on the same *Tx as the write so the in-transaction
// policy view sees exactly the state the row commits against.
//
// Service domains consume the "domains" quota dimension (BE-0329): every
// Create reserves one unit on the QuotaReserver in the SAME transaction
// as the authorization check, the desired-state write, and the audit
// append, so an organization that exhausts the dimension cannot half-
// write a row whose quota reservation rolled back. The worker-driven
// per-organization wildcard / custom-cert provisioning job lands in a
// later story; this dimension is the desired-state cap that bounds how
// many domain rows a tenant can persist before any of that runs.
type ServiceDomainService struct {
	store    *Store
	services *ServiceRepository
	domains  *ServiceDomainRepository
	authz    Authorizer
	quota    QuotaReserver
	audit    AuditAppender
}

// NewServiceDomainService wires a ServiceDomainService from its
// dependencies. It returns a typed error if any dependency is nil, so a
// misconfigured service fails at construction rather than on its first
// request.
func NewServiceDomainService(s *Store, services *ServiceRepository, domains *ServiceDomainRepository, authz Authorizer, quota QuotaReserver, audit AuditAppender) (*ServiceDomainService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case services == nil:
		return nil, errors.New("store: nil service repository")
	case domains == nil:
		return nil, errors.New("store: nil service domain repository")
	case authz == nil:
		return nil, errors.New("store: nil authorizer")
	case quota == nil:
		return nil, errors.New("store: nil quota reserver")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &ServiceDomainService{
		store:    s,
		services: services,
		domains:  domains,
		authz:    authz,
		quota:    quota,
		audit:    audit,
	}, nil
}

// Create validates in, then runs the create-domain unit of work inside
// one transaction: confirm the parent service exists under
// (OrganizationID, ServiceID), authorize, write the domain row, append
// the immutable audit record. Validation runs before the transaction
// is opened, so an invalid request never touches the database. Every
// failure after that point — a missing parent service, a denied
// authorization decision, a (hostname, path) conflict, or a failed
// audit append — rolls the whole transaction back, so the domain row
// is never persisted without its audit trail and the checks can never
// be skipped.
//
// The parent-service Get is tenant-scoped — it filters by
// organization_id first — so a cross-tenant or unknown service_id
// surfaces as a deterministic apierr.NotFound. This is the same
// boundary GET /v1/services/{service_id}/domains inherits, so a foreign
// service_id reaches the persistence layer with the principal's home
// organization id and is reported as 404 here just as it is on the
// read side, never disguised as a 403 that would confirm the foreign
// service's existence.
func (svc *ServiceDomainService) Create(ctx context.Context, in CreateServiceDomainInput) (ServiceDomain, error) {
	row, err := validateCreateServiceDomainInput(in)
	if err != nil {
		return ServiceDomain{}, err
	}

	// The audit record is filed under the actor's home organization —
	// the tenant the principal authenticated into — while its resource
	// id names the domain that was created. A missing actor
	// organization is a wiring error (an authenticated request always
	// carries one), not client input, so it is reported as Internal
	// rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return ServiceDomain{}, apierr.Internal(errors.New("store: ServiceDomainService.Create requires an actor organization for the audit record"))
	}

	var created ServiceDomain
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Parent service existence is tenant-scoped: a cross-tenant or
		// unknown service_id surfaces as a deterministic
		// apierr.NotFound, never a 500 or a silent success. The check
		// runs first so the in-tx authorize and the Insert do not have
		// to guess whether the parent exists.
		if _, getErr := svc.services.GetByID(ctx, tx, row.OrganizationID, row.ServiceID); getErr != nil {
			return getErr
		}
		// Defense-in-depth: the HTTP RequireAuth middleware already
		// authorized action domain.create against the (home org,
		// service_id) resource the path names. The in-transaction
		// Authorize is a redundant check whose real adapter reads
		// grant rows from the same *Tx as the desired-state write —
		// so a grant change that landed between the HTTP authorize
		// and this point still cannot let the write through.
		if err := svc.authz.Authorize(ctx, tx, serviceDomainCreateAction, row.OrganizationID); err != nil {
			return err
		}
		// Quota reservation (BE-0329): reserve one unit on the
		// "domains" dimension before the Insert. The reservation runs
		// inside the same *Tx as the Insert and the audit append, so a
		// rejected reservation rolls the whole unit of work back and a
		// tenant whose dimension is exhausted never persists a domain
		// row. The Checker locks the tenant's usage counter row FOR
		// UPDATE for hard-enforced limits, so concurrent Creates
		// serialise on the counter and can never over-allocate.
		if err := svc.quota.Reserve(ctx, tx, row.OrganizationID, string(QuotaResourceDomains)); err != nil {
			return err
		}
		inserted, err := svc.domains.Insert(ctx, tx, row)
		if err != nil {
			return err
		}
		event := AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         serviceDomainCreateAction,
			ResourceKind:   string(domain.KindServiceDomain),
			ResourceID:     inserted.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for domain.create",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			// The service_id, hostname, path, port, https flag, and
			// certificate_type are structural identifiers / routing
			// metadata / closed-taxonomy enums — none carries secret
			// material (the actual certificate material is held by the
			// worker / Dokploy layer and never round-trips through this
			// table) — so they are safe to record verbatim as audit
			// context.
			Metadata: map[string]string{
				"service_id":       inserted.ServiceID,
				"hostname":         inserted.Hostname,
				"path":             inserted.Path,
				"certificate_type": inserted.CertificateType,
			},
		}
		if _, err := svc.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		created = inserted
		return nil
	})
	if txErr != nil {
		return ServiceDomain{}, txErr
	}
	return created, nil
}

// validateCreateServiceDomainInput checks in and returns the
// ServiceDomain row it would map to. Field-level validation uses the
// shared validate.Collector so a single request rejecting on more than
// one field surfaces every violation in one typed apierr.InvalidInput.
// A submitted value never appears in a violation reason — a host or
// path that ended up in the wrong field cannot leak through the
// validation error.
func validateCreateServiceDomainInput(in CreateServiceDomainInput) (ServiceDomain, error) {
	c := validate.New()

	orgID := strings.TrimSpace(in.OrganizationID)
	validate.ID(c, "organization_id", orgID, domain.KindOrganization)

	serviceID := strings.TrimSpace(in.ServiceID)
	validate.ID(c, "service_id", serviceID, domain.KindService)

	domainID := strings.TrimSpace(in.DomainID)
	validate.ID(c, "id", domainID, domain.KindServiceDomain)

	// Wildcard hostnames require a per-organization feature flag the
	// store layer cannot resolve here. Until the wildcard story lands,
	// validate.Domain rejects them. A future story that admits
	// wildcards will resolve the option from the organization's
	// feature flags / quota at the httpapi layer before calling.
	hostname := strings.ToLower(strings.TrimSpace(in.Hostname))
	validate.Domain(c, "hostname", hostname, validate.DomainOptions{})

	path := strings.TrimSpace(in.Path)
	if path == "" {
		path = serviceDomainDefaultPath
	}
	validateServiceDomainPath(c, "path", path)

	if in.Port < 1 || in.Port > 65535 {
		c.Add("port", "must be between 1 and 65535")
	}

	certificateType := strings.TrimSpace(in.CertificateType)
	if certificateType == "" {
		certificateType = ServiceDomainCertificateLetsEncrypt
	}
	switch certificateType {
	case ServiceDomainCertificateLetsEncrypt, ServiceDomainCertificateCustom, ServiceDomainCertificateNone:
	default:
		c.Add("certificate_type", `must be one of "lets-encrypt", "custom", or "none"`)
	}

	if err := c.Err(); err != nil {
		return ServiceDomain{}, err
	}

	return ServiceDomain{
		ID:              domainID,
		OrganizationID:  orgID,
		ServiceID:       serviceID,
		Hostname:        hostname,
		Path:            path,
		Port:            in.Port,
		HTTPS:           in.HTTPS,
		CertificateType: certificateType,
	}, nil
}

// validateServiceDomainPath validates a URL path bound to a service
// domain. A service-domain path is an absolute URL path (always begins
// with "/"), parses cleanly as a URL path, contains no control bytes,
// and stays within serviceDomainMaxPathLen. The submitted value is
// never echoed in the violation reason.
func validateServiceDomainPath(c *validate.Collector, field, value string) {
	if value == "" {
		c.Add(field, "must not be blank")
		return
	}
	if len(value) > serviceDomainMaxPathLen {
		c.Addf(field, "must be at most %d characters", serviceDomainMaxPathLen)
		return
	}
	if !strings.HasPrefix(value, "/") {
		c.Add(field, "must start with a leading \"/\"")
		return
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			c.Add(field, "must not contain control characters")
			return
		}
	}
	if _, err := url.Parse("http://example.com" + value); err != nil {
		c.Add(field, "must be a valid URL path")
	}
}

// UpdateServiceDomainInput is the unvalidated input to
// ServiceDomainService.Update. OrganizationID identifies the tenant
// the domain belongs to; ServiceID names the parent service; DomainID
// names the row to update. Hostname, Path, Port, HTTPS, and
// CertificateType are optional pointers: a nil pointer means the
// caller did not include the field and it is left unchanged, which is
// what makes the operation a partial update. The Actor* and
// correlation fields describe the authenticated principal performing
// the update and are recorded verbatim on the audit event.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. ServiceID and DomainID are sourced from the PATH
// parameters; the update unit of work reads the current row under
// (OrganizationID, ServiceID, DomainID) before any mutation, so a
// cross-tenant or unknown tuple surfaces as a deterministic
// apierr.NotFound rather than a 500 or a silent success.
//
// IfMatchVersion is the optional optimistic-concurrency precondition:
// when non-nil, the update succeeds only if the row's current version
// equals *IfMatchVersion at write time, otherwise it returns a typed
// apierr.ConflictStale carrying the row's authoritative version. The
// httpapi layer fills it from the request's If-Match header. A nil
// pointer disables the check (next-write-wins). The pointer
// indirection distinguishes "caller did not supply a precondition"
// from "caller supplied version 0", which is impossible by schema
// CHECK and must not silently behave like the unchecked path.
//
// Reparenting onto another service is intentionally NOT in this
// input: a service domain belongs to exactly one service for its
// lifetime, and reparenting is a deliberate operation that would
// belong to a different endpoint behind a different action constant —
// never a partial update.
type UpdateServiceDomainInput struct {
	OrganizationID  string
	ServiceID       string
	DomainID        string
	Hostname        *string
	Path            *string
	Port            *int
	HTTPS           *bool
	CertificateType *string
	IfMatchVersion  *int64
	ActorID         string
	ActorKind       string
	ActorOrgID      string
	RequestID       string
	CorrelationID   string
}

// serviceDomainUpdate is the validated, normalised form of an
// UpdateServiceDomainInput produced by buildServiceDomainUpdate. The
// fields are pointers so an absent field (caller did not supply it) is
// distinguishable from a deliberate zero value, and the fields slice
// records — in caller-submission order, deduplicated by construction
// — the stable wire names of the columns that the patch will write,
// which is what the audit metadata records as updated_fields.
type serviceDomainUpdate struct {
	hostname        *string
	path            *string
	port            *int
	https           *bool
	certificateType *string
	fields          []string
}

// buildServiceDomainUpdate validates every supplied field on in and
// returns the normalised serviceDomainUpdate it would persist, or a
// typed apierr.InvalidInput naming every failed field (never echoing
// the submitted values). A patch that names no updatable field is
// itself a validation failure — a mutation that changes nothing is a
// client error, not a silent success.
func buildServiceDomainUpdate(in UpdateServiceDomainInput) (serviceDomainUpdate, error) {
	var (
		change serviceDomainUpdate
		c      = validate.New()
	)

	if in.Hostname != nil {
		change.fields = append(change.fields, "hostname")
		hostname := strings.ToLower(strings.TrimSpace(*in.Hostname))
		preCount := len(c.Violations())
		validate.Domain(c, "hostname", hostname, validate.DomainOptions{})
		if len(c.Violations()) == preCount {
			change.hostname = &hostname
		}
	}

	if in.Path != nil {
		change.fields = append(change.fields, "path")
		path := strings.TrimSpace(*in.Path)
		if path == "" {
			path = serviceDomainDefaultPath
		}
		preCount := len(c.Violations())
		validateServiceDomainPath(c, "path", path)
		if len(c.Violations()) == preCount {
			change.path = &path
		}
	}

	if in.Port != nil {
		change.fields = append(change.fields, "port")
		if *in.Port < 1 || *in.Port > 65535 {
			c.Add("port", "must be between 1 and 65535")
		} else {
			port := *in.Port
			change.port = &port
		}
	}

	if in.HTTPS != nil {
		change.fields = append(change.fields, "https")
		https := *in.HTTPS
		change.https = &https
	}

	if in.CertificateType != nil {
		change.fields = append(change.fields, "certificate_type")
		certificateType := strings.TrimSpace(*in.CertificateType)
		switch certificateType {
		case ServiceDomainCertificateLetsEncrypt, ServiceDomainCertificateCustom, ServiceDomainCertificateNone:
			change.certificateType = &certificateType
		default:
			c.Add("certificate_type", `must be one of "lets-encrypt", "custom", or "none"`)
		}
	}

	if len(change.fields) == 0 {
		c.Add("hostname", "at least one of hostname, path, port, https, or certificate_type must be provided")
	}

	if err := c.Err(); err != nil {
		return serviceDomainUpdate{}, err
	}
	return change, nil
}

// Update validates in, then runs the update-domain unit of work inside
// one transaction: read the current row under (OrganizationID,
// ServiceID, DomainID), optionally enforce the If-Match precondition,
// apply the caller-supplied fields, write the row back, append the
// immutable audit record. Validation of every supplied field runs
// before the transaction is opened, so an invalid request never
// touches the database. A patch that names no updatable field is
// itself a validation failure — a mutation that changes nothing is a
// client error, not a silent success. A blank
// OrganizationID/ServiceID/DomainID is a typed validation failure
// raised before the transaction is opened. The repository is tenant
// scoped: a cross-tenant {service_id} or {domain_id} reaches the
// persistence layer with the principal's home organization id and is
// reported as a typed apierr.NotFound, never another tenant's row. A
// (hostname, path) tuple that collides with another row anywhere in
// the cluster rolls the whole transaction back as a typed Conflict,
// so a duplicate domain row and an orphaned audit record are both
// impossible.
//
// Authorization for domain.update is enforced at the HTTP boundary by
// RequireAuth against the (home organization, service_id) resource
// the path names — the store layer never runs an in-transaction
// Authorize for the update path because the HTTP gate is
// authoritative and the in-transaction Authorizer is reserved for
// Create (the create-time race against grant changes during a quota
// reservation).
func (svc *ServiceDomainService) Update(ctx context.Context, in UpdateServiceDomainInput) (ServiceDomain, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return ServiceDomain{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	serviceID := strings.TrimSpace(in.ServiceID)
	if serviceID == "" {
		return ServiceDomain{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must not be blank",
		})
	}
	domainID := strings.TrimSpace(in.DomainID)
	if domainID == "" {
		return ServiceDomain{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "id",
			Reason: "must not be blank",
		})
	}

	change, err := buildServiceDomainUpdate(in)
	if err != nil {
		return ServiceDomain{}, err
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return ServiceDomain{}, apierr.Internal(errors.New("store: ServiceDomainService.Update requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         serviceDomainUpdateAction,
		ResourceKind:   string(domain.KindServiceDomain),
		ResourceID:     domainID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for domain.update",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// updated_fields names which fields the patch changed — stable
		// wire names, never the submitted values — so the audit trail
		// records the shape of the mutation without carrying any input
		// verbatim. The service_id is recorded verbatim because it is a
		// structural identifier, never secret material.
		Metadata: map[string]string{
			"service_id":     serviceID,
			"updated_fields": strings.Join(change.fields, ","),
		},
	}

	var updated ServiceDomain
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		current, getErr := svc.domains.GetByID(ctx, tx, organizationID, serviceID, domainID)
		if getErr != nil {
			return getErr
		}
		// A pre-check before the write surfaces the stale-version
		// conflict against the row the caller actually targets — even
		// when no other field on the patch happens to differ from the
		// current row, in which case the version-checked UPDATE would
		// itself succeed trivially without the trigger needing to fire.
		// The repository still re-checks the version under WHERE so a
		// concurrent writer landing between the read and the write is
		// also rejected.
		if in.IfMatchVersion != nil && current.Version != *in.IfMatchVersion {
			return apierr.ConflictStale(current.Version)
		}
		desired := current
		if change.hostname != nil {
			desired.Hostname = *change.hostname
		}
		if change.path != nil {
			desired.Path = *change.path
		}
		if change.port != nil {
			desired.Port = *change.port
		}
		if change.https != nil {
			desired.HTTPS = *change.https
		}
		if change.certificateType != nil {
			desired.CertificateType = *change.certificateType
		}
		row, updErr := svc.domains.Update(ctx, tx, desired, in.IfMatchVersion)
		if updErr != nil {
			return updErr
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		updated = row
		return nil
	})
	if txErr != nil {
		return ServiceDomain{}, txErr
	}
	return updated, nil
}

// DeleteServiceDomainInput is the typed input shape
// ServiceDomainService.Delete accepts. OrganizationID identifies the
// tenant the domain belongs to and is always taken from the
// authenticated principal's home org at the httpapi layer (never from
// caller-controlled request input). ServiceID and DomainID name the
// service_domains row to remove and are always taken from path
// parameters at the httpapi layer.
//
// IfMatchVersion is the optional optimistic-concurrency precondition:
// when non-nil, the delete succeeds only if the row's current version
// equals *IfMatchVersion at write time, otherwise it returns a typed
// apierr.ConflictStale carrying the row's authoritative version. The
// httpapi layer fills it from the request's If-Match header. A nil
// pointer disables the check (next-write-wins). The pointer
// indirection distinguishes "caller did not supply a precondition"
// from "caller supplied version 0", which is impossible by schema
// CHECK and must not silently behave like the unchecked path.
//
// A DELETE has no body, so no mutable-field shape lives on this
// struct — the only path-parameter validation the service performs is
// that none of OrganizationID, ServiceID, or DomainID is blank. The
// Actor* and correlation fields describe the authenticated principal
// performing the deletion and are recorded verbatim on the audit
// event; they are plain strings so the store layer takes no build
// dependency on the policy or telemetry packages — the httpapi
// handler, which already holds the resolved principal and the request
// correlation, fills them in.
type DeleteServiceDomainInput struct {
	OrganizationID string
	ServiceID      string
	DomainID       string
	IfMatchVersion *int64
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// Delete runs the delete-domain unit of work inside one transaction:
// remove the service_domains row identified by (OrganizationID,
// ServiceID, DomainID), optionally enforce the If-Match precondition,
// and append the immutable audit record. Validation of the input
// shape (path identifiers, actor org) runs before the transaction is
// opened, so an obviously invalid request never touches the database.
//
// service_domains has no soft-delete column — a public-facing
// hostname route is a routing artefact, not a continuing audit-trail
// tie that must outlive the resource, so the row is removed outright.
// The returned snapshot is the row exactly as it stood at the moment
// of removal so the caller can confirm what was deleted. The HTTP
// layer projects the snapshot through the same wire-shape every other
// service-domain endpoint uses; the row carries no credential
// material (the certificate_type column names the issuance behavior
// only — the actual certificate material is held by the worker /
// Dokploy layer and never round-trips through this table).
//
// Tenant scoping is enforced at the persistence layer: the DELETE
// predicate filters on organization_id first, so a cross-tenant or
// unknown {service_id, domain_id} tuple matches no rows and the
// service surfaces it as a deterministic apierr.NotFound. The audit
// record is rolled back with the missed delete so an audit trail can
// never name a deletion that did not happen. Any database constraint
// violation rolls the whole transaction back as a typed
// apierr.Conflict.
//
// Authorization for domain.delete is enforced at the HTTP boundary by
// RequireAuth against the (home organization, service_id) resource
// the path names — the store layer never runs an in-transaction
// Authorize for the delete path because the HTTP gate is
// authoritative and the in-transaction Authorizer is reserved for
// Create (the create-time race against grant changes during a quota
// reservation).
//
// The audit event is filed under the actor's home organization (the
// tenant the principal authenticated into) with
// resource_kind=service_domain and resource_id={domain_id}. Metadata
// records the structural identifiers (service_id, hostname, path,
// certificate_type) verbatim — none carries secret material, so they
// are safe to record as audit context — and never includes any
// caller-supplied request-body field (a DELETE has none).
func (svc *ServiceDomainService) Delete(ctx context.Context, in DeleteServiceDomainInput) (ServiceDomain, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return ServiceDomain{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	serviceID := strings.TrimSpace(in.ServiceID)
	if serviceID == "" {
		return ServiceDomain{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must not be blank",
		})
	}
	domainID := strings.TrimSpace(in.DomainID)
	if domainID == "" {
		return ServiceDomain{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "id",
			Reason: "must not be blank",
		})
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return ServiceDomain{}, apierr.Internal(errors.New("store: ServiceDomainService.Delete requires an actor organization for the audit record"))
	}

	var deleted ServiceDomain
	if txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		row, delErr := svc.domains.DeleteByID(ctx, tx, organizationID, serviceID, domainID, in.IfMatchVersion)
		if delErr != nil {
			return delErr
		}

		event := AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         serviceDomainDeleteAction,
			ResourceKind:   string(domain.KindServiceDomain),
			ResourceID:     row.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for domain.delete",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			// The service_id, hostname, path, and certificate_type are
			// structural identifiers / routing metadata / closed-taxonomy
			// enums — none carries secret material — so they are safe to
			// record verbatim as audit context. The deleted row's
			// version is the row's last authoritative version before
			// removal; useful for forensics and idempotency analysis.
			Metadata: map[string]string{
				"service_id":       row.ServiceID,
				"hostname":         row.Hostname,
				"path":             row.Path,
				"certificate_type": row.CertificateType,
				"version":          strconv.FormatInt(row.Version, 10),
			},
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		deleted = row
		return nil
	}); txErr != nil {
		return ServiceDomain{}, txErr
	}
	return deleted, nil
}
