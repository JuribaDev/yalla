package store

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
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
// Service domains do not yet have a quota (the worker-driven
// per-organization wildcard / custom-cert quota lands in a later
// provisioning story) and do not yet enqueue a provisioning job — the
// domain row is the source of truth, and the Dokploy reconciler will
// project it as part of the broader service-reconcile loop. When the
// dedicated worker story lands, the orchestrator will gain JobEnqueuer
// and QuotaReserver dependencies the same way ServiceService did,
// alongside the worker's contract tests.
type ServiceDomainService struct {
	store    *Store
	services *ServiceRepository
	domains  *ServiceDomainRepository
	authz    Authorizer
	audit    AuditAppender
}

// NewServiceDomainService wires a ServiceDomainService from its
// dependencies. It returns a typed error if any dependency is nil, so a
// misconfigured service fails at construction rather than on its first
// request.
func NewServiceDomainService(s *Store, services *ServiceRepository, domains *ServiceDomainRepository, authz Authorizer, audit AuditAppender) (*ServiceDomainService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case services == nil:
		return nil, errors.New("store: nil service repository")
	case domains == nil:
		return nil, errors.New("store: nil service domain repository")
	case authz == nil:
		return nil, errors.New("store: nil authorizer")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &ServiceDomainService{
		store:    s,
		services: services,
		domains:  domains,
		authz:    authz,
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
