package store

import (
	"context"
	"errors"
	"strings"
	"time"
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
	serviceCreateAction  = "service.create"
	serviceUpdateAction  = "service.update"
	serviceDeleteAction  = "service.delete"
	serviceRestoreAction = "service.restore"
	// serviceRestartAction is the immutable audit-event Action string
	// emitted by every service restart. It matches the wire-level
	// action constant the policy engine authorizes (service.restart),
	// so an auditor reading the audit row can pivot to the policy
	// matrix tests that pin the authorization contract of the same
	// action without translating between two vocabularies.
	serviceRestartAction = "service.restart"
	// serviceStopAction is the immutable audit-event Action string
	// emitted by every service stop. It matches the wire-level action
	// constant the policy engine authorizes (service.stop), so an
	// auditor reading the audit row can pivot to the policy matrix
	// tests that pin the authorization contract of the same action
	// without translating between two vocabularies.
	serviceStopAction = "service.stop"
	// serviceStartAction is the immutable audit-event Action string
	// emitted by every service start. It matches the wire-level action
	// constant the policy engine authorizes (service.start), so an
	// auditor reading the audit row can pivot to the policy matrix
	// tests that pin the authorization contract of the same action
	// without translating between two vocabularies.
	serviceStartAction  = "service.start"
	serviceProvisionJob = "service.provision"
	// serviceRestartJob is the durable-job kind enqueued by the
	// restart unit of work. The worker reads this kind to dispatch a
	// Dokploy-side restart of the named service. The kind is stable
	// public job-schema contract — every operator-facing log line,
	// metric, and dashboard groups by it.
	serviceRestartJob = "service.restart"
	// serviceStopJob is the durable-job kind enqueued by the stop unit
	// of work. The worker reads this kind to dispatch a Dokploy-side
	// stop of the named service. The kind is stable public
	// job-schema contract — every operator-facing log line, metric,
	// and dashboard groups by it.
	serviceStopJob = "service.stop"
	// serviceStartJob is the durable-job kind enqueued by the start
	// unit of work. The worker reads this kind to dispatch a
	// Dokploy-side start of the named service, bringing the
	// already-persisted desired state back up. The kind is stable
	// public job-schema contract — every operator-facing log line,
	// metric, and dashboard groups by it.
	serviceStartJob = "service.start"
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
		// Per-subtype quota: the "applications" dimension counts ONLY
		// services in the application taxonomy member. Compose and
		// database services do not consume this dimension and are
		// counted by their own per-subtype quotas (BE-0327 / BE-0328).
		// The reservation runs in the SAME transaction as the
		// services-dimension reservation and the desired-state write,
		// so an organization that exhausts either dimension cannot
		// half-write a service row whose other dimension passed —
		// every failure after this point rolls the whole unit of
		// work back together.
		if service.Kind == ServiceKindApplication {
			if err := svc.quota.Reserve(ctx, tx, service.OrganizationID, string(QuotaResourceApplications)); err != nil {
				return err
			}
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

// UpdateServiceInput is the unvalidated input to ServiceService.Update.
// OrganizationID identifies the tenant the service belongs to;
// ServiceID names the service to update. Slug and DisplayName are
// optional: a nil pointer means the caller did not include the field
// and it is left unchanged, which is what makes the operation a
// partial update. The Actor* and correlation fields describe the
// authenticated principal performing the update and are recorded
// verbatim on the audit event. They are plain strings so the store
// layer takes no build dependency on the policy or telemetry packages
// — the httpapi handler, which already holds the resolved principal
// and the request correlation, fills them in.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. ServiceID is sourced from the {service_id} PATH
// parameter; the update unit of work reads the current row under
// (OrganizationID, ServiceID) before any mutation, so a cross-tenant
// or unknown service_id surfaces as a deterministic apierr.NotFound
// rather than a 500 or a silent success.
//
// IfMatchVersion is the optional optimistic-concurrency precondition:
// when non-nil, the update succeeds only if the row's current version
// equals *IfMatchVersion at write time, otherwise it returns a typed
// apierr.ConflictStale carrying the row's authoritative version. The
// httpapi layer fills it from the request's If-Match header. A nil
// pointer disables the check (next-write-wins, the legacy behaviour).
// The pointer indirection is deliberate: it distinguishes "caller did
// not supply a precondition" from "caller supplied version 0", which
// is impossible by schema CHECK and must not silently behave like the
// unchecked path.
//
// Kind, parent project_id, and parent environment_id are intentionally
// NOT in this input: kind is closed Dokploy taxonomy and cannot be
// changed once provisioning has been told what to build, and
// reparenting a service onto another project or environment is a
// separate, deliberate operation that would belong to a different
// endpoint behind a different action constant — never a partial
// update.
type UpdateServiceInput struct {
	OrganizationID string
	ServiceID      string
	Slug           *string
	DisplayName    *string
	IfMatchVersion *int64
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// serviceUpdate is the validated, normalised form of an
// UpdateServiceInput produced by buildServiceUpdate. The fields are
// pointers so an absent field (caller did not supply it) is
// distinguishable from a deliberate zero value, and the fields slice
// records — in caller-submission order, deduplicated by construction
// — the stable wire names of the columns that the patch will write,
// which is what the audit metadata records as updated_fields.
type serviceUpdate struct {
	slug        *string
	displayName *string
	fields      []string
}

// buildServiceUpdate validates every supplied field on in and returns
// the normalised serviceUpdate it would persist, or a typed
// apierr.InvalidInput naming every failed field (never echoing the
// submitted values). A patch that names no updatable field is itself
// a validation failure — a mutation that changes nothing is a client
// error, not a silent success.
func buildServiceUpdate(in UpdateServiceInput) (serviceUpdate, error) {
	var (
		change     serviceUpdate
		violations []apierr.FieldViolation
	)

	if in.Slug != nil {
		change.fields = append(change.fields, "slug")
		slug, slugErr := domain.ParseSlug(*in.Slug)
		if slugErr != nil {
			violations = append(violations, apierr.FieldViolation{
				Field:  "slug",
				Reason: "must be a canonical slug",
			})
		} else {
			normalized := slug.String()
			change.slug = &normalized
		}
	}

	if in.DisplayName != nil {
		change.fields = append(change.fields, "display_name")
		displayName, dnViolation := validateServiceDisplayName(*in.DisplayName)
		if dnViolation != nil {
			violations = append(violations, *dnViolation)
		} else {
			change.displayName = &displayName
		}
	}

	if len(change.fields) == 0 {
		violations = append(violations, apierr.FieldViolation{
			Field:  "slug",
			Reason: "at least one of slug or display_name must be provided",
		})
	}

	if len(violations) > 0 {
		return serviceUpdate{}, apierr.InvalidInput(violations...)
	}
	return change, nil
}

// Update validates in, then runs the update-service unit of work
// inside one transaction: read the current row, optionally enforce the
// If-Match precondition, apply the caller-supplied fields, write the
// row back, append the immutable audit record. Validation of every
// supplied field runs before the transaction is opened, so an invalid
// request never touches the database. A patch that names no updatable
// field is itself a validation failure — a mutation that changes
// nothing is a client error, not a silent success. A blank
// OrganizationID/ServiceID is a typed validation failure raised
// before the transaction is opened. The repository is tenant scoped:
// a cross-tenant {service_id} reaches the persistence layer with the
// principal's home organization id and is reported as a typed
// apierr.NotFound, never another tenant's row. A slug that collides
// with another service in the same environment rolls the whole
// transaction back as a typed Conflict, so a duplicate service and
// an orphaned audit record are both impossible.
//
// Authorization for service.update is enforced at the HTTP boundary
// by RequireAuth against the (home organization, service_id) resource
// the path names — the store layer never runs an in-transaction
// Authorize for the update path because the HTTP gate is
// authoritative and the in-transaction Authorizer is reserved for
// Create (the create-time race against grant changes during a quota
// reservation).
func (svc *ServiceService) Update(ctx context.Context, in UpdateServiceInput) (Service, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	serviceID := strings.TrimSpace(in.ServiceID)
	if serviceID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must not be blank",
		})
	}

	change, err := buildServiceUpdate(in)
	if err != nil {
		return Service{}, err
	}

	// The audit record is filed under the actor's home organization —
	// the tenant the principal authenticated into — while its resource
	// id names the service that was updated. A missing actor
	// organization is a wiring error (an authenticated request always
	// carries one), not client input, so it is reported as Internal
	// rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Service{}, apierr.Internal(errors.New("store: ServiceService.Update requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         serviceUpdateAction,
		ResourceKind:   string(domain.KindService),
		ResourceID:     serviceID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for service.update",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// updated_fields names which fields the patch changed — stable
		// wire names, never the submitted values — so the audit trail
		// records the shape of the mutation without carrying any input
		// verbatim.
		Metadata: map[string]string{"updated_fields": strings.Join(change.fields, ",")},
	}

	var updated Service
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		current, getErr := svc.services.GetByID(ctx, tx, organizationID, serviceID)
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
		if change.slug != nil {
			desired.Slug = *change.slug
		}
		if change.displayName != nil {
			desired.DisplayName = *change.displayName
		}
		row, updErr := svc.services.Update(ctx, tx, desired, in.IfMatchVersion)
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
		return Service{}, txErr
	}
	return updated, nil
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

// DeleteServiceInput is the input to ServiceService.ScheduleDeletion.
// OrganizationID identifies the tenant the service belongs to;
// ServiceID names the service to schedule for teardown. The Actor* and
// correlation fields describe the authenticated principal performing
// the deletion and are recorded verbatim on the audit event. They are
// plain strings so the store layer takes no build dependency on the
// policy or telemetry packages — the httpapi handler, which already
// holds the resolved principal and the request correlation, fills them
// in.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. ServiceID is sourced from the {service_id} PATH
// parameter; the scheduling unit of work reads the current row under
// (OrganizationID, ServiceID) before any mutation, so a cross-tenant
// or unknown service_id surfaces as a deterministic apierr.NotFound
// rather than a 500 or a silent success.
//
// IfMatchVersion is the optional optimistic-concurrency precondition:
// when non-nil, the scheduling succeeds only if the row's current
// version equals *IfMatchVersion at write time, otherwise it returns
// a typed apierr.ConflictStale carrying the row's authoritative
// version. The httpapi layer fills it from the request's If-Match
// header. A nil pointer disables the check (next-write-wins, the
// legacy behaviour). The pointer indirection is deliberate: it
// distinguishes "caller did not supply a precondition" from "caller
// supplied version 0", which is impossible by schema CHECK and must
// not silently behave like the unchecked path.
type DeleteServiceInput struct {
	OrganizationID string
	ServiceID      string
	IfMatchVersion *int64
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// ScheduleDeletion schedules the service named by (in.OrganizationID,
// in.ServiceID) for teardown, inside one transaction: read the current
// row, optionally enforce the If-Match precondition, reject a service
// already scheduled, stamp deletion_scheduled_at, append the audit
// event. A blank OrganizationID or ServiceID is a typed validation
// failure raised before the transaction is opened. A {service_id}
// with no row inside the tenant is the typed NotFound the repository
// produces, and a service whose deletion was already scheduled rolls
// the whole transaction back as a typed Conflict — so an audit record
// can never name a deletion that did not change the resource's state.
//
// Authorization for service.delete is enforced at the HTTP boundary
// by RequireAuth against the (home organization, service_id) resource
// the path names — the store layer never runs an in-transaction
// Authorize for the delete path because the HTTP gate is
// authoritative and the in-transaction Authorizer is reserved for
// Create (the create-time race against grant changes during a quota
// reservation).
//
// This is a soft, scheduled deletion: it records the intent and
// stamps the timestamp. The destructive teardown — the worker that
// retires the Dokploy object backing the service and eventually
// removes the row and its audit log — is a later worker story, so the
// service row and its audit trail still exist after this returns.
func (svc *ServiceService) ScheduleDeletion(ctx context.Context, in DeleteServiceInput) (Service, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	serviceID := strings.TrimSpace(in.ServiceID)
	if serviceID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must not be blank",
		})
	}

	// The audit record is filed under the actor's home organization —
	// the tenant the principal authenticated into — while its resource
	// id names the service that was scheduled for deletion. A missing
	// actor organization is a wiring error (an authenticated request
	// always carries one), not client input, so it is reported as
	// Internal rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Service{}, apierr.Internal(errors.New("store: ServiceService.ScheduleDeletion requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         serviceDeleteAction,
		ResourceKind:   string(domain.KindService),
		ResourceID:     serviceID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for service.delete",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
	}

	var scheduled Service
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		current, getErr := svc.services.GetByID(ctx, tx, organizationID, serviceID)
		if getErr != nil {
			return getErr
		}
		// The version pre-check surfaces a stale If-Match BEFORE the
		// already-scheduled check, so the caller learns "your view of
		// the version is stale" instead of an already-scheduled
		// message that might race with a concurrent edit they did not
		// see.
		if in.IfMatchVersion != nil && current.Version != *in.IfMatchVersion {
			return apierr.ConflictStale(current.Version)
		}
		if current.DeletionScheduledAt != nil {
			// Scheduling teardown for a service already scheduled for
			// teardown changes nothing: the caller's view of the
			// resource lifecycle is stale, so it is a typed Conflict,
			// not a silent success that would write a misleading audit
			// record.
			return apierr.Conflict("service deletion is already scheduled")
		}
		row, updErr := svc.services.ScheduleDeletion(ctx, tx, organizationID, serviceID, in.IfMatchVersion)
		if updErr != nil {
			return updErr
		}
		// deletion_scheduled_at is database-assigned (now()); record the
		// resolved timestamp — a non-secret value — as audit context so
		// the trail captures exactly when teardown was scheduled.
		if row.DeletionScheduledAt != nil {
			event.Metadata = map[string]string{
				"deletion_scheduled_at": row.DeletionScheduledAt.UTC().Format(time.RFC3339Nano),
			}
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		scheduled = row
		return nil
	})
	if txErr != nil {
		return Service{}, txErr
	}
	return scheduled, nil
}

// RestoreServiceInput is the input to ServiceService.Restore.
// OrganizationID identifies the tenant the service belongs to;
// ServiceID names the service to restore from soft-deletion. The
// Actor* and correlation fields describe the authenticated principal
// performing the restore and are recorded verbatim on the audit
// event. They are plain strings so the store layer takes no build
// dependency on the policy or telemetry packages — the httpapi
// handler, which already holds the resolved principal and the request
// correlation, fills them in.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. ServiceID is sourced from the {service_id} PATH
// parameter; the restore unit of work reads the current row under
// (OrganizationID, ServiceID) before any mutation, so a cross-tenant
// or unknown service_id surfaces as a deterministic apierr.NotFound
// rather than a 500 or a silent success.
//
// IfMatchVersion is the optional optimistic-concurrency precondition:
// when non-nil, the restore succeeds only if the row's current
// version equals *IfMatchVersion at write time, otherwise it returns
// a typed apierr.ConflictStale carrying the row's authoritative
// version. The httpapi layer fills it from the request's If-Match
// header. A nil pointer disables the check (next-write-wins, the
// legacy behaviour). The pointer indirection is deliberate: it
// distinguishes "caller did not supply a precondition" from "caller
// supplied version 0", which is impossible by schema CHECK and must
// not silently behave like the unchecked path.
type RestoreServiceInput struct {
	OrganizationID string
	ServiceID      string
	IfMatchVersion *int64
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// Restore clears the deletion_scheduled_at stamp on the service named
// by (in.OrganizationID, in.ServiceID) inside one transaction: read
// the current row, optionally enforce the If-Match precondition,
// reject a service that is not currently scheduled for deletion,
// clear the stamp, append the audit event. A blank OrganizationID or
// ServiceID is a typed validation failure raised before the
// transaction is opened. A {service_id} with no row inside the
// tenant is the typed NotFound the repository produces, and a
// service whose deletion was never scheduled rolls the whole
// transaction back as a typed Conflict — so an audit record can
// never name a restore that did not change the resource's state.
//
// Authorization for service.restore is enforced at the HTTP boundary
// by RequireAuth against the (home organization, service_id) resource
// the path names — the store layer never runs an in-transaction
// Authorize for the restore path because the HTTP gate is
// authoritative and the in-transaction Authorizer is reserved for
// Create (the create-time race against grant changes during a quota
// reservation).
//
// Restore is the inverse of ScheduleDeletion: it clears the
// soft-delete stamp so the service is live again. The destructive
// teardown the scheduled deletion would have caused has not yet
// run — it is a later worker story that watches
// deletion_scheduled_at — so restoring before teardown returns the
// service to live state with its environments, services, and audit
// trail intact.
func (svc *ServiceService) Restore(ctx context.Context, in RestoreServiceInput) (Service, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	serviceID := strings.TrimSpace(in.ServiceID)
	if serviceID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must not be blank",
		})
	}

	// The audit record is filed under the actor's home organization —
	// the tenant the principal authenticated into — while its resource
	// id names the service that was restored. A missing actor
	// organization is a wiring error (an authenticated request always
	// carries one), not client input, so it is reported as Internal
	// rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Service{}, apierr.Internal(errors.New("store: ServiceService.Restore requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         serviceRestoreAction,
		ResourceKind:   string(domain.KindService),
		ResourceID:     serviceID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for service.restore",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
	}

	var restored Service
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		current, getErr := svc.services.GetByID(ctx, tx, organizationID, serviceID)
		if getErr != nil {
			return getErr
		}
		// The version pre-check surfaces a stale If-Match BEFORE the
		// not-scheduled check, so the caller learns "your view of the
		// version is stale" instead of a not-scheduled message that
		// might race with a concurrent restore they did not see.
		if in.IfMatchVersion != nil && current.Version != *in.IfMatchVersion {
			return apierr.ConflictStale(current.Version)
		}
		if current.DeletionScheduledAt == nil {
			// Restoring a service that was never scheduled for deletion
			// changes nothing: the caller's view of the resource
			// lifecycle is stale, so it is a typed Conflict, not a
			// silent success that would write a misleading audit
			// record.
			return apierr.Conflict("service is not scheduled for deletion")
		}
		// Record the deletion_scheduled_at the restore cleared as
		// audit context — a non-secret timestamp — so the trail
		// captures what state the resource was in BEFORE the restore.
		// It is captured from the current row, not the input, so a
		// caller cannot inject arbitrary metadata through the audit
		// field.
		event.Metadata = map[string]string{
			"deletion_scheduled_at": current.DeletionScheduledAt.UTC().Format(time.RFC3339Nano),
		}
		row, updErr := svc.services.Restore(ctx, tx, organizationID, serviceID, in.IfMatchVersion)
		if updErr != nil {
			return updErr
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		restored = row
		return nil
	})
	if txErr != nil {
		return Service{}, txErr
	}
	return restored, nil
}

// RestartServiceInput is the input to ServiceService.Restart.
// OrganizationID identifies the tenant the service belongs to;
// ServiceID names the service to restart. The Actor* and correlation
// fields describe the authenticated principal performing the restart
// and are recorded verbatim on the audit event. They are plain
// strings so the store layer takes no build dependency on the policy
// or telemetry packages — the httpapi handler, which already holds
// the resolved principal and the request correlation, fills them in.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. ServiceID is sourced from the {service_id} PATH
// parameter; the restart unit of work reads the current row under
// (OrganizationID, ServiceID) before any mutation, so a cross-tenant
// or unknown service_id surfaces as a deterministic apierr.NotFound
// rather than a 500 or a silent success.
//
// The restart request carries no caller-supplied body fields beyond
// the path parameter: a restart is a fire-and-forget signal that
// targets the entire service. The provisioning job that mirrors the
// restart into Dokploy is enqueued by the unit of work — it cannot be
// redirected, batched, or scheduled by the caller.
type RestartServiceInput struct {
	OrganizationID string
	ServiceID      string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// Restart records customer intent to restart the service named by
// (in.OrganizationID, in.ServiceID) and enqueues the durable
// provisioning job that mirrors the restart into Dokploy. The unit of
// work runs inside one transaction: confirm the parent service exists
// under (OrganizationID, ServiceID), reject a service that is already
// scheduled for deletion, re-authorize action service.restart against
// the parent service's organization on the same *Tx (defense-in-depth
// against a grant change that landed between the HTTP authorize and
// the desired-state write), enqueue the provisioning job, and append
// the immutable audit record. Because every step shares the *Tx, a
// failure in any of them rolls the others back: a partial restart and
// an orphaned audit row are both impossible, and the restart audit
// record can never exist without its provisioning job.
//
// The parent-service Get is tenant-scoped — it filters by
// organization_id first — so a cross-tenant or unknown service_id
// surfaces as a deterministic apierr.NotFound. A service that has
// already been scheduled for teardown cannot accept new operations: a
// restart job would race the soft-delete worker and either succeed
// against a half-torn-down service or fail mid-flight. Refuse the
// restart at the boundary with a deterministic 409 rather than emit
// a job whose outcome is undefined.
//
// Restart writes NO new row to the services table — the service row's
// desired state does not change. The persistence side effects are the
// provisioning_jobs row that the worker will execute and the immutable
// audit_events row that records the actor and the (organization_id,
// service_id, project_id, environment_id) the operation targeted.
func (svc *ServiceService) Restart(ctx context.Context, in RestartServiceInput) (Service, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	serviceID := strings.TrimSpace(in.ServiceID)
	if serviceID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must not be blank",
		})
	}

	// The audit record is filed under the actor's home organization —
	// the tenant the principal authenticated into — while its resource
	// id names the service that was restarted. A missing actor
	// organization is a wiring error (an authenticated request always
	// carries one), not client input, so it is reported as Internal
	// rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Service{}, apierr.Internal(errors.New("store: ServiceService.Restart requires an actor organization for the audit record"))
	}
	actorID := strings.TrimSpace(in.ActorID)
	if actorID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "requested_by",
			Reason: "must not be blank",
		})
	}

	var restarted Service
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Parent-service existence is tenant-scoped: a cross-tenant or
		// unknown service_id surfaces as the typed apierr.NotFound the
		// repository produces, never a 500 or a silent success.
		parent, getErr := svc.services.GetByID(ctx, tx, organizationID, serviceID)
		if getErr != nil {
			return getErr
		}
		// A service that has already been scheduled for teardown
		// cannot accept new operations: a restart job would race the
		// soft-delete worker and either succeed against a half-torn-
		// down service or fail mid-flight. Refuse at the boundary with
		// a deterministic 409 rather than emit a job whose outcome is
		// undefined.
		if parent.DeletionScheduledAt != nil {
			return apienvelopeServiceScheduledForDeletionConflict()
		}

		// Defense-in-depth: the HTTP RequireAuth middleware already
		// authorized action service.restart against the (home org,
		// service_id) resource the path names. The in-transaction
		// Authorize is a redundant check whose real adapter reads
		// grant rows from the same *Tx as the desired-state write —
		// so a grant change that landed between the HTTP authorize
		// and this point still cannot let the write through.
		if err := svc.authz.Authorize(ctx, tx, serviceRestartAction, organizationID); err != nil {
			return err
		}

		// The provisioning job and the audit record commit atomically
		// with the in-tx authorize. Every JobEnqueuer adapter pins the
		// job's organization_id to the service's tenant, so a job
		// cannot reference another tenant's service.
		if err := svc.jobs.Enqueue(ctx, tx, parent.OrganizationID, serviceRestartJob, parent.ID); err != nil {
			return err
		}
		event := AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        actorID,
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         serviceRestartAction,
			ResourceKind:   string(domain.KindService),
			ResourceID:     parent.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for service.restart",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			// The structural identifiers are non-secret and safe to
			// record verbatim — a future support reader sees the
			// service, its environment, and its project context. There
			// is no caller-supplied free-form text on the restart
			// path, so no field needs to flow through the output
			// redactor before persistence.
			Metadata: map[string]string{
				"service_id":     parent.ID,
				"environment_id": parent.EnvironmentID,
				"project_id":     parent.ProjectID,
			},
		}
		if _, err := svc.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		restarted = parent
		return nil
	})
	if txErr != nil {
		return Service{}, txErr
	}
	return restarted, nil
}

// apienvelopeServiceScheduledForDeletionConflict is the typed 409 the
// restart unit of work returns when the parent service has already
// been scheduled for soft-delete. It is a function rather than a
// package-level apierr value so each call site produces a fresh
// error with its own stack capture and so callers cannot accidentally
// mutate shared state.
func apienvelopeServiceScheduledForDeletionConflict() error {
	return apierr.Conflict("the service is scheduled for deletion and cannot accept new operations")
}

// StopServiceInput is the input to ServiceService.Stop. OrganizationID
// identifies the tenant the service belongs to; ServiceID names the
// service to stop. The Actor* and correlation fields describe the
// authenticated principal performing the stop and are recorded
// verbatim on the audit event. They are plain strings so the store
// layer takes no build dependency on the policy or telemetry packages
// — the httpapi handler, which already holds the resolved principal
// and the request correlation, fills them in.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. ServiceID is sourced from the {service_id} PATH
// parameter; the stop unit of work reads the current row under
// (OrganizationID, ServiceID) before any mutation, so a cross-tenant
// or unknown service_id surfaces as a deterministic apierr.NotFound
// rather than a 500 or a silent success.
//
// The stop request carries no caller-supplied body fields beyond the
// path parameter: a stop is a fire-and-forget signal that targets the
// entire service. The provisioning job that mirrors the stop into
// Dokploy is enqueued by the unit of work — it cannot be redirected,
// batched, or scheduled by the caller.
type StopServiceInput struct {
	OrganizationID string
	ServiceID      string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// Stop records customer intent to stop the service named by
// (in.OrganizationID, in.ServiceID) and enqueues the durable
// provisioning job that mirrors the stop into Dokploy. The unit of
// work runs inside one transaction: confirm the parent service exists
// under (OrganizationID, ServiceID), reject a service that is already
// scheduled for deletion, re-authorize action service.stop against
// the parent service's organization on the same *Tx (defense-in-depth
// against a grant change that landed between the HTTP authorize and
// the desired-state write), enqueue the provisioning job, and append
// the immutable audit record. Because every step shares the *Tx, a
// failure in any of them rolls the others back: a partial stop and
// an orphaned audit row are both impossible, and the stop audit
// record can never exist without its provisioning job.
//
// The parent-service Get is tenant-scoped — it filters by
// organization_id first — so a cross-tenant or unknown service_id
// surfaces as a deterministic apierr.NotFound. A service that has
// already been scheduled for teardown cannot accept new operations: a
// stop job would race the soft-delete worker. Refuse the stop at the
// boundary with a deterministic 409 rather than emit a job whose
// outcome is undefined.
//
// Stop writes NO new row to the services table — the service row's
// desired state does not change (a stopped service can be started
// again without recreating it). The persistence side effects are the
// provisioning_jobs row that the worker will execute and the immutable
// audit_events row that records the actor and the (organization_id,
// service_id, project_id, environment_id) the operation targeted.
func (svc *ServiceService) Stop(ctx context.Context, in StopServiceInput) (Service, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	serviceID := strings.TrimSpace(in.ServiceID)
	if serviceID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must not be blank",
		})
	}

	// The audit record is filed under the actor's home organization —
	// the tenant the principal authenticated into — while its resource
	// id names the service that was stopped. A missing actor
	// organization is a wiring error (an authenticated request always
	// carries one), not client input, so it is reported as Internal
	// rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Service{}, apierr.Internal(errors.New("store: ServiceService.Stop requires an actor organization for the audit record"))
	}
	actorID := strings.TrimSpace(in.ActorID)
	if actorID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "requested_by",
			Reason: "must not be blank",
		})
	}

	var stopped Service
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Parent-service existence is tenant-scoped: a cross-tenant or
		// unknown service_id surfaces as the typed apierr.NotFound the
		// repository produces, never a 500 or a silent success.
		parent, getErr := svc.services.GetByID(ctx, tx, organizationID, serviceID)
		if getErr != nil {
			return getErr
		}
		// A service that has already been scheduled for teardown
		// cannot accept new operations: a stop job would race the
		// soft-delete worker. Refuse at the boundary with a
		// deterministic 409 rather than emit a job whose outcome is
		// undefined.
		if parent.DeletionScheduledAt != nil {
			return apienvelopeServiceScheduledForDeletionConflict()
		}

		// Defense-in-depth: the HTTP RequireAuth middleware already
		// authorized action service.stop against the (home org,
		// service_id) resource the path names. The in-transaction
		// Authorize is a redundant check whose real adapter reads
		// grant rows from the same *Tx as the desired-state write —
		// so a grant change that landed between the HTTP authorize
		// and this point still cannot let the write through.
		if err := svc.authz.Authorize(ctx, tx, serviceStopAction, organizationID); err != nil {
			return err
		}

		// The provisioning job and the audit record commit atomically
		// with the in-tx authorize. Every JobEnqueuer adapter pins the
		// job's organization_id to the service's tenant, so a job
		// cannot reference another tenant's service.
		if err := svc.jobs.Enqueue(ctx, tx, parent.OrganizationID, serviceStopJob, parent.ID); err != nil {
			return err
		}
		event := AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        actorID,
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         serviceStopAction,
			ResourceKind:   string(domain.KindService),
			ResourceID:     parent.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for service.stop",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			// The structural identifiers are non-secret and safe to
			// record verbatim — a future support reader sees the
			// service, its environment, and its project context. There
			// is no caller-supplied free-form text on the stop path,
			// so no field needs to flow through the output redactor
			// before persistence.
			Metadata: map[string]string{
				"service_id":     parent.ID,
				"environment_id": parent.EnvironmentID,
				"project_id":     parent.ProjectID,
			},
		}
		if _, err := svc.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		stopped = parent
		return nil
	})
	if txErr != nil {
		return Service{}, txErr
	}
	return stopped, nil
}

// StartServiceInput is the input to ServiceService.Start.
// OrganizationID identifies the tenant the service belongs to;
// ServiceID names the service to start. The Actor* and correlation
// fields describe the authenticated principal performing the start
// and are recorded verbatim on the audit event. They are plain
// strings so the store layer takes no build dependency on the policy
// or telemetry packages — the httpapi handler, which already holds
// the resolved principal and the request correlation, fills them in.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. ServiceID is sourced from the {service_id} PATH
// parameter; the start unit of work reads the current row under
// (OrganizationID, ServiceID) before any mutation, so a cross-tenant
// or unknown service_id surfaces as a deterministic apierr.NotFound
// rather than a 500 or a silent success.
//
// The start request carries no caller-supplied body fields beyond the
// path parameter: a start is a fire-and-forget signal that targets
// the entire service. The provisioning job that mirrors the start
// into Dokploy is enqueued by the unit of work — it cannot be
// redirected, batched, or scheduled by the caller.
type StartServiceInput struct {
	OrganizationID string
	ServiceID      string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// Start records customer intent to start the service named by
// (in.OrganizationID, in.ServiceID) and enqueues the durable
// provisioning job that mirrors the start into Dokploy. The unit of
// work runs inside one transaction: confirm the parent service exists
// under (OrganizationID, ServiceID), reject a service that is already
// scheduled for deletion, re-authorize action service.start against
// the parent service's organization on the same *Tx (defense-in-depth
// against a grant change that landed between the HTTP authorize and
// the desired-state write), enqueue the provisioning job, and append
// the immutable audit record. Because every step shares the *Tx, a
// failure in any of them rolls the others back: a partial start and
// an orphaned audit row are both impossible, and the start audit
// record can never exist without its provisioning job.
//
// The parent-service Get is tenant-scoped — it filters by
// organization_id first — so a cross-tenant or unknown service_id
// surfaces as a deterministic apierr.NotFound. A service that has
// already been scheduled for teardown cannot accept new operations: a
// start job would race the soft-delete worker. Refuse the start at
// the boundary with a deterministic 409 rather than emit a job whose
// outcome is undefined.
//
// Start writes NO new row to the services table — the service row's
// desired state does not change (the worker brings the already-
// persisted desired state back up). The persistence side effects are
// the provisioning_jobs row that the worker will execute and the
// immutable audit_events row that records the actor and the
// (organization_id, service_id, project_id, environment_id) the
// operation targeted.
func (svc *ServiceService) Start(ctx context.Context, in StartServiceInput) (Service, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	serviceID := strings.TrimSpace(in.ServiceID)
	if serviceID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must not be blank",
		})
	}

	// The audit record is filed under the actor's home organization —
	// the tenant the principal authenticated into — while its resource
	// id names the service that was started. A missing actor
	// organization is a wiring error (an authenticated request always
	// carries one), not client input, so it is reported as Internal
	// rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Service{}, apierr.Internal(errors.New("store: ServiceService.Start requires an actor organization for the audit record"))
	}
	actorID := strings.TrimSpace(in.ActorID)
	if actorID == "" {
		return Service{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "requested_by",
			Reason: "must not be blank",
		})
	}

	var started Service
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Parent-service existence is tenant-scoped: a cross-tenant or
		// unknown service_id surfaces as the typed apierr.NotFound the
		// repository produces, never a 500 or a silent success.
		parent, getErr := svc.services.GetByID(ctx, tx, organizationID, serviceID)
		if getErr != nil {
			return getErr
		}
		// A service that has already been scheduled for teardown
		// cannot accept new operations: a start job would race the
		// soft-delete worker. Refuse at the boundary with a
		// deterministic 409 rather than emit a job whose outcome is
		// undefined.
		if parent.DeletionScheduledAt != nil {
			return apienvelopeServiceScheduledForDeletionConflict()
		}

		// Defense-in-depth: the HTTP RequireAuth middleware already
		// authorized action service.start against the (home org,
		// service_id) resource the path names. The in-transaction
		// Authorize is a redundant check whose real adapter reads
		// grant rows from the same *Tx as the desired-state write —
		// so a grant change that landed between the HTTP authorize
		// and this point still cannot let the write through.
		if err := svc.authz.Authorize(ctx, tx, serviceStartAction, organizationID); err != nil {
			return err
		}

		// The provisioning job and the audit record commit atomically
		// with the in-tx authorize. Every JobEnqueuer adapter pins the
		// job's organization_id to the service's tenant, so a job
		// cannot reference another tenant's service.
		if err := svc.jobs.Enqueue(ctx, tx, parent.OrganizationID, serviceStartJob, parent.ID); err != nil {
			return err
		}
		event := AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        actorID,
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         serviceStartAction,
			ResourceKind:   string(domain.KindService),
			ResourceID:     parent.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for service.start",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			// The structural identifiers are non-secret and safe to
			// record verbatim — a future support reader sees the
			// service, its environment, and its project context. There
			// is no caller-supplied free-form text on the start path,
			// so no field needs to flow through the output redactor
			// before persistence.
			Metadata: map[string]string{
				"service_id":     parent.ID,
				"environment_id": parent.EnvironmentID,
				"project_id":     parent.ProjectID,
			},
		}
		if _, err := svc.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		started = parent
		return nil
	})
	if txErr != nil {
		return Service{}, txErr
	}
	return started, nil
}
