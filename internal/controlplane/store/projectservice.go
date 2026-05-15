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

// Authorizer decides whether the current principal may perform an action
// against an organization scope. The store layer depends only on this narrow
// port; the real RBAC engine lands in internal/controlplane/policy. Authorize
// receives the same Querier as the surrounding unit of work, so a policy
// decision that reads grant rows sees exactly the state the write commits
// against. A denied decision is returned as a typed apierr.Forbidden error.
type Authorizer interface {
	Authorize(ctx context.Context, q Querier, action, organizationID string) error
}

// QuotaReserver reserves quota for a resource within an organization. The
// store layer depends only on this narrow port; the real quota service lands
// in internal/controlplane/quota. Reserve receives the *Tx of the surrounding
// unit of work, so the reservation it records commits or rolls back atomically
// with the resource it guards. An exhausted limit is returned as a typed
// apierr.QuotaExceeded error.
type QuotaReserver interface {
	Reserve(ctx context.Context, tx *Tx, organizationID, resource string) error
}

// JobEnqueuer enqueues a durable provisioning job. The store layer depends
// only on this narrow port; the real durable job queue lands in
// internal/controlplane/jobs. Enqueue receives the *Tx of the surrounding unit
// of work, so the job row commits atomically with the desired-state write —
// the system can never persist a resource without its provisioning job, or a
// job without its resource.
type JobEnqueuer interface {
	Enqueue(ctx context.Context, tx *Tx, organizationID, jobKind, resourceID string) error
}

// The action, job kind, and quota resource a project creation composes
// against. They are duplicated as plain strings here on purpose: the policy
// action catalog, the quota schema, and the durable job table are later
// stories, and the store layer must not take a build dependency on them. When
// those packages land they own these constants; the store layer keeps only
// the port interfaces above.
const (
	projectCreateAction  = "project.create"
	projectUpdateAction  = "project.update"
	projectDeleteAction  = "project.delete"
	projectProvisionJob  = "project.provision"
	projectQuotaResource = "projects"
	// projectDisplayNameMaxLen bounds a human-authored project display name,
	// in runes. It mirrors the organization display-name bound and exists so
	// an unbounded string can never reach the database.
	projectDisplayNameMaxLen = 200
)

// CreateProjectInput is the unvalidated input to ProjectService.Create.
// OrganizationID, ProjectID, Slug, and DisplayName are the caller-supplied
// resource fields; the Actor* and correlation fields describe the
// authenticated principal performing the create and are recorded verbatim on
// the audit event. They are plain strings so the store layer takes no build
// dependency on the policy or telemetry packages — the httpapi handler, which
// already holds the resolved principal and the request correlation, fills
// them in.
type CreateProjectInput struct {
	OrganizationID string
	ProjectID      string
	Slug           string
	DisplayName    string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// UpdateProjectInput is the unvalidated input to ProjectService.Update.
// OrganizationID identifies the tenant the project belongs to; ProjectID
// names the project to update. Slug and DisplayName are optional: a nil
// pointer means the caller did not include the field and it is left
// unchanged, which is what makes the operation a partial update. The
// Actor* and correlation fields describe the authenticated principal
// performing the update and are recorded verbatim on the audit event. They
// are plain strings so the store layer takes no build dependency on the
// policy or telemetry packages — the httpapi handler, which already holds
// the resolved principal and the request correlation, fills them in.
//
// IfMatchVersion is the optional optimistic-concurrency precondition: when
// non-nil, the update succeeds only if the row's current version equals
// *IfMatchVersion at write time, otherwise it returns a typed
// apierr.ConflictStale carrying the row's authoritative version. The httpapi
// layer fills it from the request's If-Match header. A nil pointer disables
// the check (next-write-wins, the legacy behaviour). The pointer indirection
// is deliberate: it distinguishes "caller did not supply a precondition"
// from "caller supplied version 0", which is impossible by schema CHECK and
// must not silently behave like the unchecked path.
type UpdateProjectInput struct {
	OrganizationID string
	ProjectID      string
	Slug           *string
	DisplayName    *string
	IfMatchVersion *int64
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// DeleteProjectInput is the input to ProjectService.ScheduleDeletion.
// OrganizationID identifies the tenant the project belongs to; ProjectID
// names the project to schedule for teardown. The Actor* and correlation
// fields describe the authenticated principal performing the deletion and
// are recorded verbatim on the audit event. They are plain strings so the
// store layer takes no build dependency on the policy or telemetry packages
// — the httpapi handler, which already holds the resolved principal and the
// request correlation, fills them in.
//
// IfMatchVersion enforces optimistic concurrency for scheduling deletion,
// with the same semantics as on UpdateProjectInput.
type DeleteProjectInput struct {
	OrganizationID string
	ProjectID      string
	IfMatchVersion *int64
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// ProjectService is the reference unit-of-work orchestrator for the repository
// transaction pattern. Create composes — in this fixed order, inside one
// transaction — an authorization check, a quota reservation, the desired-state
// write, the provisioning-job enqueue, and the immutable audit record.
// Because every step shares the *Tx opened by Store.Write, a failure in any
// step rolls back every other step: the authorization, quota, and audit
// checks are impossible to bypass, and desired state is never persisted
// without its provisioning job or its audit trail.
type ProjectService struct {
	store *Store
	repo  *ProjectRepository
	authz Authorizer
	quota QuotaReserver
	jobs  JobEnqueuer
	audit AuditAppender
}

// NewProjectService wires a ProjectService from its dependencies. It returns a
// typed error if any dependency is nil, so a misconfigured service fails at
// construction rather than on its first request.
func NewProjectService(s *Store, repo *ProjectRepository, authz Authorizer, quota QuotaReserver, jobs JobEnqueuer, audit AuditAppender) (*ProjectService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case repo == nil:
		return nil, errors.New("store: nil project repository")
	case authz == nil:
		return nil, errors.New("store: nil authorizer")
	case quota == nil:
		return nil, errors.New("store: nil quota reserver")
	case jobs == nil:
		return nil, errors.New("store: nil job enqueuer")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &ProjectService{store: s, repo: repo, authz: authz, quota: quota, jobs: jobs, audit: audit}, nil
}

// Create validates in, then runs the create-project unit of work inside one
// transaction: authorize, reserve quota, write the project row, enqueue the
// provisioning job, append the immutable audit record. Validation runs before
// the transaction is opened, so an invalid request never touches the database.
// Every failure after that point — a denied authorization decision, an
// exhausted quota, a slug conflict, a failed provisioning-job enqueue, or a
// failed audit append — rolls the whole transaction back, so the project row
// is never persisted without its job and audit trail and the checks can never
// be skipped.
func (svc *ProjectService) Create(ctx context.Context, in CreateProjectInput) (Project, error) {
	project, err := validateCreateProjectInput(in)
	if err != nil {
		return Project{}, err
	}

	// The audit record is filed under the actor's home organization — the
	// tenant the principal authenticated into — while its resource id names
	// the project that was created. A missing actor organization is a wiring
	// error (an authenticated request always carries one), not client input,
	// so it is reported as Internal rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Project{}, apierr.Internal(errors.New("store: ProjectService.Create requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         projectCreateAction,
		ResourceKind:   string(domain.KindProject),
		ResourceID:     project.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for project.create",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// The slug is a canonical [a-z0-9-] identifier — it carries no secret
		// material — so it is safe to record verbatim as audit context.
		Metadata: map[string]string{"slug": project.Slug},
	}

	var created Project
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if err := svc.authz.Authorize(ctx, tx, projectCreateAction, project.OrganizationID); err != nil {
			return err
		}
		if err := svc.quota.Reserve(ctx, tx, project.OrganizationID, projectQuotaResource); err != nil {
			return err
		}
		row, err := svc.repo.Insert(ctx, tx, project)
		if err != nil {
			return err
		}
		if err := svc.jobs.Enqueue(ctx, tx, project.OrganizationID, projectProvisionJob, row.ID); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		created = row
		return nil
	})
	if txErr != nil {
		return Project{}, txErr
	}
	return created, nil
}

// Update validates in, then runs the update-project unit of work inside one
// transaction: read the current row, optionally enforce the If-Match
// precondition, apply the caller-supplied fields, write the row back,
// append the immutable audit record. Validation of every supplied field
// runs before the transaction is opened, so an invalid request never
// touches the database. A patch that names no updatable field is itself a
// validation failure — a mutation that changes nothing is a client error,
// not a silent success. A blank OrganizationID/ProjectID is a typed
// validation failure raised before the transaction is opened. The
// repository is tenant scoped: a cross-tenant {project_id} reaches the
// persistence layer with the principal's home organization id and is
// reported as a typed apierr.NotFound, never another tenant's row. A slug
// that collides with another project in the same organization rolls the
// whole transaction back as a typed Conflict, so a duplicate project and
// an orphaned audit record are both impossible.
//
// Authorization for project.update is enforced at the HTTP boundary by
// RequireAuth against the (home organization, project_id) resource the
// path names — the store layer never runs an in-transaction Authorize for
// the update path because the HTTP gate is authoritative and the
// in-transaction Authorizer is reserved for Create (the create-time race
// against grant changes during a quota reservation).
func (svc *ProjectService) Update(ctx context.Context, in UpdateProjectInput) (Project, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return Project{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	projectID := strings.TrimSpace(in.ProjectID)
	if projectID == "" {
		return Project{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "project_id",
			Reason: "must not be blank",
		})
	}

	change, err := buildProjectUpdate(in)
	if err != nil {
		return Project{}, err
	}

	// The audit record is filed under the actor's home organization — the
	// tenant the principal authenticated into — while its resource id names
	// the project that was updated. A missing actor organization is a
	// wiring error (an authenticated request always carries one), not
	// client input, so it is reported as Internal rather than a validation
	// failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Project{}, apierr.Internal(errors.New("store: ProjectService.Update requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         projectUpdateAction,
		ResourceKind:   string(domain.KindProject),
		ResourceID:     projectID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for project.update",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// updated_fields names which fields the patch changed — stable wire
		// names, never the submitted values — so the audit trail records
		// the shape of the mutation without carrying any input verbatim.
		Metadata: map[string]string{"updated_fields": strings.Join(change.fields, ",")},
	}

	var updated Project
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		current, getErr := svc.repo.Get(ctx, tx, organizationID, projectID)
		if getErr != nil {
			return getErr
		}
		// A pre-check before the write surfaces the stale-version conflict
		// against the row the caller actually targets — even when no other
		// field on the patch happens to differ from the current row, in
		// which case the version-checked UPDATE would itself succeed
		// trivially without the trigger needing to fire. The repository
		// still re-checks the version under WHERE so a concurrent writer
		// landing between the read and the write is also rejected.
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
		row, updErr := svc.repo.Update(ctx, tx, desired, in.IfMatchVersion)
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
		return Project{}, txErr
	}
	return updated, nil
}

// validateCreateProjectInput checks in and returns the Project row it would
// persist. It is split out from Create so the validation rules are unit
// testable without a database, and so an invalid request is rejected before a
// transaction is ever opened. On failure it returns a typed apierr.InvalidInput
// carrying stable field paths — never the submitted values — so the rejection
// can name the offending field without leaking input.
func validateCreateProjectInput(in CreateProjectInput) (Project, error) {
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

	slug, err := domain.ParseSlug(in.Slug)
	if err != nil {
		violations = append(violations, apierr.FieldViolation{
			Field:  "slug",
			Reason: "must be a canonical slug",
		})
	}

	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		violations = append(violations, apierr.FieldViolation{
			Field:  "display_name",
			Reason: "must not be empty",
		})
	}

	if len(violations) > 0 {
		return Project{}, apierr.InvalidInput(violations...)
	}
	return Project{
		ID:             projectID,
		OrganizationID: orgID,
		Slug:           slug.String(),
		DisplayName:    displayName,
	}, nil
}

// projectUpdate is the validated, normalised form of an UpdateProjectInput:
// the fields the caller asked to change, already parsed and trimmed. A nil
// pointer means "leave this field unchanged". fields lists the stable wire
// names of every field present in the patch, in declaration order, for the
// audit record.
type projectUpdate struct {
	slug        *string
	displayName *string
	fields      []string
}

// buildProjectUpdate validates the caller-supplied fields of in and returns
// the normalised patch. It is split out from Update so the validation rules
// are unit testable without a database, and so an invalid request is
// rejected before a transaction is ever opened. A patch that names no
// updatable field is itself a validation failure. On failure it returns a
// typed apierr.InvalidInput carrying stable field paths — never the
// submitted values.
func buildProjectUpdate(in UpdateProjectInput) (projectUpdate, error) {
	var (
		change     projectUpdate
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
		displayName, dnViolation := validateProjectDisplayName(*in.DisplayName)
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
		return projectUpdate{}, apierr.InvalidInput(violations...)
	}
	return change, nil
}

// validateProjectDisplayName trims and validates a human-authored project
// display name. It returns the trimmed value and a nil violation when the
// name is acceptable, or the zero value and a typed FieldViolation naming
// the display_name field — never the submitted value — otherwise.
func validateProjectDisplayName(raw string) (string, *apierr.FieldViolation) {
	displayName := strings.TrimSpace(raw)
	switch {
	case displayName == "":
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must not be blank"}
	case !utf8.ValidString(displayName):
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must be valid UTF-8"}
	case containsControlRune(displayName):
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must not contain control characters"}
	case utf8.RuneCountInString(displayName) > projectDisplayNameMaxLen:
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "exceeds the maximum length"}
	}
	return displayName, nil
}

// ScheduleDeletion schedules the project named by (in.OrganizationID,
// in.ProjectID) for teardown, inside one transaction: read the current row,
// optionally enforce the If-Match precondition, reject a project already
// scheduled, stamp deletion_scheduled_at, append the audit event. A blank
// OrganizationID or ProjectID is a typed validation failure raised before
// the transaction is opened. A {project_id} with no row inside the tenant
// is the typed NotFound the repository produces, and a project whose
// deletion was already scheduled rolls the whole transaction back as a
// typed Conflict — so an audit record can never name a deletion that did
// not change the resource's state.
//
// Authorization for project.delete is enforced at the HTTP boundary by
// RequireAuth against the (home organization, project_id) resource the
// path names — the store layer never runs an in-transaction Authorize for
// the delete path because the HTTP gate is authoritative and the
// in-transaction Authorizer is reserved for Create (the create-time race
// against grant changes during a quota reservation).
//
// This is a soft, scheduled deletion: it records the intent and stamps the
// timestamp. The destructive teardown — the ON DELETE CASCADE that removes
// environments, services, and the audit log under the project — is a later
// worker story, so the project row and its audit trail still exist after
// this returns.
func (svc *ProjectService) ScheduleDeletion(ctx context.Context, in DeleteProjectInput) (Project, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return Project{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	projectID := strings.TrimSpace(in.ProjectID)
	if projectID == "" {
		return Project{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "project_id",
			Reason: "must not be blank",
		})
	}

	// The audit record is filed under the actor's home organization — the
	// tenant the principal authenticated into — while its resource id names
	// the project that was scheduled for deletion. A missing actor
	// organization is a wiring error (an authenticated request always
	// carries one), not client input, so it is reported as Internal rather
	// than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Project{}, apierr.Internal(errors.New("store: ProjectService.ScheduleDeletion requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         projectDeleteAction,
		ResourceKind:   string(domain.KindProject),
		ResourceID:     projectID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for project.delete",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
	}

	var scheduled Project
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		current, getErr := svc.repo.Get(ctx, tx, organizationID, projectID)
		if getErr != nil {
			return getErr
		}
		// The version pre-check surfaces a stale If-Match BEFORE the
		// already-scheduled check, so the caller learns "your view of the
		// version is stale" instead of an already-scheduled message that
		// might race with a concurrent edit they did not see.
		if in.IfMatchVersion != nil && current.Version != *in.IfMatchVersion {
			return apierr.ConflictStale(current.Version)
		}
		if current.DeletionScheduledAt != nil {
			// Scheduling teardown for a project already scheduled for
			// teardown changes nothing: the caller's view of the resource
			// lifecycle is stale, so it is a typed Conflict, not a silent
			// success that would write a misleading audit record.
			return apierr.Conflict("project deletion is already scheduled")
		}
		row, updErr := svc.repo.ScheduleDeletion(ctx, tx, organizationID, projectID, in.IfMatchVersion)
		if updErr != nil {
			return updErr
		}
		// deletion_scheduled_at is database-assigned (now()); record the
		// resolved timestamp — a non-secret value — as audit context so the
		// trail captures exactly when teardown was scheduled.
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
		return Project{}, txErr
	}
	return scheduled, nil
}
