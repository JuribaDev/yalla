package store

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// The action, job kind, and quota resource a service creation composes
// against. They are duplicated as plain strings here on purpose: the
// policy action catalog, the durable job table, and the quota schema
// are private to their own packages, and the store layer must not take
// a build dependency on them. The HTTP layer and the reference
// Authorizer / JobEnqueuer / QuotaReserver adapters own those
// constants; the store layer keeps only the narrow port interfaces
// (Authorizer, QuotaReserver, JobEnqueuer, AuditAppender) declared on
// the project service.
const (
	serviceCreateAction = "service.create"
	serviceProvisionJob = "service.provision"
	// serviceDisplayNameMaxLen bounds a human-authored service display
	// name, in runes. It mirrors the environment / project display-name
	// bounds and exists so an unbounded string can never reach the
	// database.
	serviceDisplayNameMaxLen = 200
)

// ServiceKind* enumerate the closed Dokploy service taxonomy the
// services table's kind CHECK confines. The constants live in the
// store layer because validateCreateServiceInput compares against them
// before any database work; the kind CHECK in migration 0002 is the
// database-side belt-and-braces that rejects an out-of-set value even
// if the application layer ever forgets.
const (
	ServiceKindApplication = "application"
	ServiceKindDatabase    = "database"
	ServiceKindCompose     = "compose"
)

// CreateServiceInput is the unvalidated input to ServiceService.Create.
// OrganizationID, EnvironmentID, ServiceID, Slug, DisplayName, and
// Kind are the caller-supplied resource fields; the Actor* and
// correlation fields describe the authenticated principal performing
// the create and are recorded verbatim on the audit event. They are
// plain strings so the store layer takes no build dependency on the
// policy or telemetry packages — the httpapi handler, which already
// holds the resolved principal and the request correlation, fills them
// in.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. EnvironmentID is sourced from the {environment_id}
// PATH parameter, and the create unit of work re-reads the parent
// environment under (OrganizationID, EnvironmentID) before any write —
// a cross-tenant or unknown environment_id surfaces as a deterministic
// apierr.NotFound rather than a 500 or a silent success, and the
// parent's project_id is derived from the persisted environment row
// rather than from caller input so the child can never land in another
// project even if the request were tampered with on the wire.
type CreateServiceInput struct {
	OrganizationID string
	EnvironmentID  string
	ServiceID      string
	Slug           string
	DisplayName    string
	Kind           string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// ServiceService is the reference unit-of-work orchestrator for the
// service-create transaction pattern. Create composes — in this fixed
// order, inside one transaction — a parent-environment existence
// check, an in-transaction authorization check, a quota reservation,
// the desired-state write, the provisioning-job enqueue, and the
// immutable audit record. Because every step shares the *Tx opened by
// Store.Write, a failure in any step rolls back every other step: the
// authorization, quota, and audit checks are impossible to bypass, and
// desired state is never persisted without its provisioning job or its
// audit trail.
//
// The httpapi RequireAuth middleware is the authoritative
// authorization gate for action service.create (environment-scoped via
// environmentIDResolver). The store-layer Authorize call is
// defense-in-depth against a grant change that landed between the HTTP
// authorize and the quota reservation — it runs on the same *Tx as
// the write so the in-transaction policy view sees exactly the state
// the row commits against.
type ServiceService struct {
	store        *Store
	projects     *ProjectRepository
	environments *EnvironmentRepository
	services     *ServiceRepository
	authz        Authorizer
	quota        QuotaReserver
	jobs         JobEnqueuer
	audit        AuditAppender
}

// NewServiceService wires a ServiceService from its dependencies. It
// returns a typed error if any dependency is nil, so a misconfigured
// service fails at construction rather than on its first request.
func NewServiceService(s *Store, projects *ProjectRepository, environments *EnvironmentRepository, services *ServiceRepository, authz Authorizer, quota QuotaReserver, jobs JobEnqueuer, audit AuditAppender) (*ServiceService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case projects == nil:
		return nil, errors.New("store: nil project repository")
	case environments == nil:
		return nil, errors.New("store: nil environment repository")
	case services == nil:
		return nil, errors.New("store: nil service repository")
	case authz == nil:
		return nil, errors.New("store: nil authorizer")
	case quota == nil:
		return nil, errors.New("store: nil quota reserver")
	case jobs == nil:
		return nil, errors.New("store: nil job enqueuer")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &ServiceService{
		store:        s,
		projects:     projects,
		environments: environments,
		services:     services,
		authz:        authz,
		quota:        quota,
		jobs:         jobs,
		audit:        audit,
	}, nil
}

// Create validates in, then runs the create-service unit of work
// inside one transaction: confirm the parent environment exists under
// (OrganizationID, EnvironmentID) — and learn its parent project_id
// from the persisted row, never from caller input — authorize, reserve
// quota, write the service row, enqueue the provisioning job, append
// the immutable audit record. Validation runs before the transaction
// is opened, so an invalid request never touches the database. Every
// failure after that point — a missing parent environment, a denied
// authorization decision, an exhausted quota, a slug conflict, a
// failed provisioning-job enqueue, or a failed audit append — rolls
// the whole transaction back, so the service row is never persisted
// without its job and audit trail and the checks can never be skipped.
//
// The parent-environment Get is tenant-scoped — it filters by
// organization_id first — so a cross-tenant or unknown environment_id
// surfaces as a deterministic apierr.NotFound. This is the same
// boundary GET /v1/environments/{environment_id}/services inherits, so
// a foreign environment_id reaches the persistence layer with the
// principal's home organization id and is reported as 404 here just
// as it is on the read side, never disguised as a 403 that would
// confirm the foreign environment's existence.
func (svc *ServiceService) Create(ctx context.Context, in CreateServiceInput) (Service, error) {
	service, err := validateCreateServiceInput(in)
	if err != nil {
		return Service{}, err
	}

	// The audit record is filed under the actor's home organization —
	// the tenant the principal authenticated into — while its resource
	// id names the service that was created. A missing actor
	// organization is a wiring error (an authenticated request always
	// carries one), not client input, so it is reported as Internal
	// rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Service{}, apierr.Internal(errors.New("store: ServiceService.Create requires an actor organization for the audit record"))
	}

	var created Service
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Parent environment existence is tenant-scoped: a cross-tenant
		// or unknown environment_id surfaces as a deterministic
		// apierr.NotFound, never a 500 or a silent success. The check
		// runs first so the quota reservation and the in-tx authorize
		// do not have to guess whether the parent exists. The
		// project_id leg of the new service row is taken from the
		// PERSISTED environment row — never from caller input — so the
		// child cannot accidentally land in another project even if a
		// later request body field tried to redirect it.
		env, getErr := svc.environments.GetByID(ctx, tx, service.OrganizationID, service.EnvironmentID)
		if getErr != nil {
			return getErr
		}
		service.ProjectID = env.ProjectID
		// Defense-in-depth: the HTTP RequireAuth middleware already
		// authorized action service.create against the (home org,
		// environment_id) resource the path names. The in-transaction
		// Authorize is a redundant check whose real adapter reads
		// grant rows from the same *Tx as the desired-state write —
		// so a grant change that landed between the HTTP authorize
		// and this point still cannot let the write through.
		if err := svc.authz.Authorize(ctx, tx, serviceCreateAction, service.OrganizationID); err != nil {
			return err
		}
		if err := svc.quota.Reserve(ctx, tx, service.OrganizationID, string(QuotaResourceServices)); err != nil {
			return err
		}
		row, err := svc.services.Insert(ctx, tx, service)
		if err != nil {
			return err
		}
		if err := svc.jobs.Enqueue(ctx, tx, service.OrganizationID, serviceProvisionJob, row.ID); err != nil {
			return err
		}
		event := AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         serviceCreateAction,
			ResourceKind:   string(domain.KindService),
			ResourceID:     row.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for service.create",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			// The slug, environment_id, project_id, and kind are
			// structural identifiers / closed-taxonomy enums — none
			// carries secret material — so they are safe to record
			// verbatim as audit context.
			Metadata: map[string]string{
				"slug":           row.Slug,
				"kind":           row.Kind,
				"environment_id": row.EnvironmentID,
				"project_id":     row.ProjectID,
			},
		}
		if _, err := svc.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		created = row
		return nil
	})
	if txErr != nil {
		return Service{}, txErr
	}
	return created, nil
}

// validateCreateServiceInput checks in and returns the Service row it
// would map to. The kind is validated against the closed Dokploy
// taxonomy ("application", "database", "compose") before any database
// work — a value outside that set is a typed 400 with a stable field
// violation, not a 500 leaking the database CHECK constraint name.
// ProjectID is intentionally NOT validated here: the parent
// environment's project_id is the source of truth, and Create fills
// the field from the persisted environment row inside the
// transaction.
func validateCreateServiceInput(in CreateServiceInput) (Service, error) {
	var violations []apierr.FieldViolation

	orgID := strings.TrimSpace(in.OrganizationID)
	if id, err := domain.ParseID(orgID); err != nil || id.Kind() != domain.KindOrganization {
		violations = append(violations, apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization id",
		})
	}

	environmentID := strings.TrimSpace(in.EnvironmentID)
	if id, err := domain.ParseID(environmentID); err != nil || id.Kind() != domain.KindEnvironment {
		violations = append(violations, apierr.FieldViolation{
			Field:  "environment_id",
			Reason: "must be a valid environment id",
		})
	}

	serviceID := strings.TrimSpace(in.ServiceID)
	if id, err := domain.ParseID(serviceID); err != nil || id.Kind() != domain.KindService {
		violations = append(violations, apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must be a valid service id",
		})
	}

	slug, err := domain.ParseSlug(in.Slug)
	if err != nil {
		violations = append(violations, apierr.FieldViolation{
			Field:  "slug",
			Reason: "must be a canonical slug",
		})
	}

	displayName, dnViolation := validateServiceDisplayName(in.DisplayName)
	if dnViolation != nil {
		violations = append(violations, *dnViolation)
	}

	kind, kindViolation := validateServiceKind(in.Kind)
	if kindViolation != nil {
		violations = append(violations, *kindViolation)
	}

	if len(violations) > 0 {
		return Service{}, apierr.InvalidInput(violations...)
	}
	return Service{
		ID:             serviceID,
		OrganizationID: orgID,
		EnvironmentID:  environmentID,
		Slug:           slug.String(),
		DisplayName:    displayName,
		Kind:           kind,
	}, nil
}

// validateServiceDisplayName trims and validates a human-authored
// service display name. It returns the trimmed value and a nil
// violation when the name is acceptable, or the zero value and a
// typed FieldViolation naming the display_name field — never the
// submitted value — otherwise.
func validateServiceDisplayName(raw string) (string, *apierr.FieldViolation) {
	displayName := strings.TrimSpace(raw)
	switch {
	case displayName == "":
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must not be blank"}
	case !utf8.ValidString(displayName):
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must be valid UTF-8"}
	case containsControlRune(displayName):
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must not contain control characters"}
	case utf8.RuneCountInString(displayName) > serviceDisplayNameMaxLen:
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "exceeds the maximum length"}
	}
	return displayName, nil
}

// validateServiceKind confines kind to the closed Dokploy taxonomy.
// The match is exact and case-sensitive, mirroring the database CHECK
// constraint in migration 0002. The returned violation names only the
// field, never the offending value (a future agent might construct an
// adversarial kind, and a redacted-by-default violation is safer).
func validateServiceKind(raw string) (string, *apierr.FieldViolation) {
	kind := strings.TrimSpace(raw)
	switch kind {
	case ServiceKindApplication, ServiceKindDatabase, ServiceKindCompose:
		return kind, nil
	}
	return "", &apierr.FieldViolation{
		Field:  "kind",
		Reason: "must be one of \"application\", \"database\", or \"compose\"",
	}
}
