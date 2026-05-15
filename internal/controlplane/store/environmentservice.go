package store

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// The action, job kind, and quota resource an environment creation
// composes against. They are duplicated as plain strings here on
// purpose: the policy action catalog, the durable job table, and the
// quota schema are private to their own packages, and the store layer
// must not take a build dependency on them. The HTTP layer and the
// reference Authorizer/JobEnqueuer adapters own those constants; the
// store layer keeps only the port interfaces (Authorizer,
// QuotaReserver, JobEnqueuer, AuditAppender) declared on the project
// service.
const (
	environmentCreateAction = "environment.create"
	environmentProvisionJob = "environment.provision"
	// environmentDisplayNameMaxLen bounds a human-authored environment
	// display name, in runes. It mirrors the project display-name bound
	// and exists so an unbounded string can never reach the database.
	environmentDisplayNameMaxLen = 200
)

// CreateEnvironmentInput is the unvalidated input to
// EnvironmentService.Create. OrganizationID, ProjectID, EnvironmentID,
// Slug, and DisplayName are the caller-supplied resource fields; the
// Actor* and correlation fields describe the authenticated principal
// performing the create and are recorded verbatim on the audit event.
// They are plain strings so the store layer takes no build dependency
// on the policy or telemetry packages — the httpapi handler, which
// already holds the resolved principal and the request correlation,
// fills them in.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. ProjectID is sourced from the {project_id} PATH
// parameter, and the create unit of work re-checks that the project
// exists in (OrganizationID, ProjectID) before any write — a
// cross-tenant or unknown project surfaces as a deterministic
// apierr.NotFound rather than a 500 or a silent success.
type CreateEnvironmentInput struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	Slug           string
	DisplayName    string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// EnvironmentService is the reference unit-of-work orchestrator for the
// environment-create transaction pattern. Create composes — in this
// fixed order, inside one transaction — a project-existence check, an
// in-transaction authorization check, a quota reservation, the
// desired-state write, the provisioning-job enqueue, and the immutable
// audit record. Because every step shares the *Tx opened by
// Store.Write, a failure in any step rolls back every other step: the
// authorization, quota, and audit checks are impossible to bypass,
// and desired state is never persisted without its provisioning job
// or its audit trail.
//
// The httpapi RequireAuth middleware is the authoritative authorization
// gate for action environment.create (project-scoped via
// projectIDResolver). The store-layer Authorize call is defense-in-depth
// against a grant change that landed between the HTTP authorize and
// the quota reservation — it runs on the same *Tx as the write so the
// in-transaction policy view sees exactly the state the row commits
// against.
type EnvironmentService struct {
	store        *Store
	projects     *ProjectRepository
	environments *EnvironmentRepository
	authz        Authorizer
	quota        QuotaReserver
	jobs         JobEnqueuer
	audit        AuditAppender
}

// NewEnvironmentService wires an EnvironmentService from its
// dependencies. It returns a typed error if any dependency is nil, so
// a misconfigured service fails at construction rather than on its
// first request.
func NewEnvironmentService(s *Store, projects *ProjectRepository, environments *EnvironmentRepository, authz Authorizer, quota QuotaReserver, jobs JobEnqueuer, audit AuditAppender) (*EnvironmentService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case projects == nil:
		return nil, errors.New("store: nil project repository")
	case environments == nil:
		return nil, errors.New("store: nil environment repository")
	case authz == nil:
		return nil, errors.New("store: nil authorizer")
	case quota == nil:
		return nil, errors.New("store: nil quota reserver")
	case jobs == nil:
		return nil, errors.New("store: nil job enqueuer")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &EnvironmentService{
		store:        s,
		projects:     projects,
		environments: environments,
		authz:        authz,
		quota:        quota,
		jobs:         jobs,
		audit:        audit,
	}, nil
}

// Create validates in, then runs the create-environment unit of work
// inside one transaction: confirm the parent project exists under
// (OrganizationID, ProjectID), authorize, reserve quota, write the
// environment row, enqueue the provisioning job, append the immutable
// audit record. Validation runs before the transaction is opened, so
// an invalid request never touches the database. Every failure after
// that point — a missing parent project, a denied authorization
// decision, an exhausted quota, a slug conflict, a failed
// provisioning-job enqueue, or a failed audit append — rolls the whole
// transaction back, so the environment row is never persisted without
// its job and audit trail and the checks can never be skipped.
//
// The parent-project Get is tenant-scoped — it filters by
// organization_id first — so a cross-tenant or unknown project_id
// surfaces as a deterministic apierr.NotFound. This is the same
// boundary GET /v1/projects/{project_id}/environments inherits, so a
// foreign project_id reaches the persistence layer with the
// principal's home organization id and is reported as 404 here just
// as it is on the read side, never disguised as a 403 that would
// confirm the foreign project's existence.
func (svc *EnvironmentService) Create(ctx context.Context, in CreateEnvironmentInput) (Environment, error) {
	environment, err := validateCreateEnvironmentInput(in)
	if err != nil {
		return Environment{}, err
	}

	// The audit record is filed under the actor's home organization —
	// the tenant the principal authenticated into — while its resource
	// id names the environment that was created. A missing actor
	// organization is a wiring error (an authenticated request always
	// carries one), not client input, so it is reported as Internal
	// rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Environment{}, apierr.Internal(errors.New("store: EnvironmentService.Create requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         environmentCreateAction,
		ResourceKind:   string(domain.KindEnvironment),
		ResourceID:     environment.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for environment.create",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// The slug is a canonical [a-z0-9-] identifier and the
		// project_id is a structural id — neither carries secret
		// material — so they are safe to record verbatim as audit
		// context.
		Metadata: map[string]string{
			"slug":       environment.Slug,
			"project_id": environment.ProjectID,
		},
	}

	var created Environment
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Project existence is tenant-scoped: a cross-tenant or unknown
		// project_id surfaces as a deterministic apierr.NotFound, never
		// a 500 or a silent success. The check runs first so the
		// quota reservation and the in-tx authorize do not have to
		// guess whether the parent exists.
		if _, getErr := svc.projects.Get(ctx, tx, environment.OrganizationID, environment.ProjectID); getErr != nil {
			return getErr
		}
		// Defense-in-depth: the HTTP RequireAuth middleware already
		// authorized action environment.create against the (home org,
		// project_id) resource the path names. The in-transaction
		// Authorize is a redundant check whose real adapter reads
		// grant rows from the same *Tx as the desired-state write —
		// so a grant change that landed between the HTTP authorize
		// and this point still cannot let the write through.
		if err := svc.authz.Authorize(ctx, tx, environmentCreateAction, environment.OrganizationID); err != nil {
			return err
		}
		if err := svc.quota.Reserve(ctx, tx, environment.OrganizationID, string(QuotaResourceEnvironments)); err != nil {
			return err
		}
		row, err := svc.environments.Insert(ctx, tx, environment)
		if err != nil {
			return err
		}
		if err := svc.jobs.Enqueue(ctx, tx, environment.OrganizationID, environmentProvisionJob, row.ID); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		created = row
		return nil
	})
	if txErr != nil {
		return Environment{}, txErr
	}
	return created, nil
}

// validateCreateEnvironmentInput checks in and returns the Environment
// row it would persist. It is split out from Create so the validation
// rules are unit testable without a database, and so an invalid
// request is rejected before a transaction is ever opened. On failure
// it returns a typed apierr.InvalidInput carrying stable field paths —
// never the submitted values — so the rejection can name the offending
// field without leaking input.
func validateCreateEnvironmentInput(in CreateEnvironmentInput) (Environment, error) {
	var violations []apierr.FieldViolation

	orgID := strings.TrimSpace(in.OrganizationID)
	if id, err := domain.ParseID(orgID); err != nil || id.Kind() != domain.KindOrganization {
		violations = append(violations, apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization id",
		})
	}

	projectID := strings.TrimSpace(in.ProjectID)
	if id, err := domain.ParseID(projectID); err != nil || id.Kind() != domain.KindProject {
		violations = append(violations, apierr.FieldViolation{
			Field:  "project_id",
			Reason: "must be a valid project id",
		})
	}

	environmentID := strings.TrimSpace(in.EnvironmentID)
	if id, err := domain.ParseID(environmentID); err != nil || id.Kind() != domain.KindEnvironment {
		violations = append(violations, apierr.FieldViolation{
			Field:  "environment_id",
			Reason: "must be a valid environment id",
		})
	}

	slug, err := domain.ParseSlug(in.Slug)
	if err != nil {
		violations = append(violations, apierr.FieldViolation{
			Field:  "slug",
			Reason: "must be a canonical slug",
		})
	}

	displayName, dnViolation := validateEnvironmentDisplayName(in.DisplayName)
	if dnViolation != nil {
		violations = append(violations, *dnViolation)
	}

	if len(violations) > 0 {
		return Environment{}, apierr.InvalidInput(violations...)
	}
	return Environment{
		ID:             environmentID,
		OrganizationID: orgID,
		ProjectID:      projectID,
		Slug:           slug.String(),
		DisplayName:    displayName,
	}, nil
}

// validateEnvironmentDisplayName trims and validates a human-authored
// environment display name. It returns the trimmed value and a nil
// violation when the name is acceptable, or the zero value and a typed
// FieldViolation naming the display_name field — never the submitted
// value — otherwise.
func validateEnvironmentDisplayName(raw string) (string, *apierr.FieldViolation) {
	displayName := strings.TrimSpace(raw)
	switch {
	case displayName == "":
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must not be blank"}
	case !utf8.ValidString(displayName):
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must be valid UTF-8"}
	case containsControlRune(displayName):
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must not contain control characters"}
	case utf8.RuneCountInString(displayName) > environmentDisplayNameMaxLen:
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "exceeds the maximum length"}
	}
	return displayName, nil
}
