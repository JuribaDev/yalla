package store

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// The action and resource kind an organization creation composes against. They
// are duplicated as plain strings here on purpose: the policy action catalog
// is owned by internal/controlplane/policy, and the store layer must not take a
// build dependency on it. The HTTP authorization middleware authorizes the same
// action before the handler is reached; the value recorded here is the audit
// trail of the decision, kept in sync by the policy matrix tests.
const (
	organizationCreateAction = "organization.create"
	organizationUpdateAction = "organization.update"
	organizationDeleteAction = "organization.delete"
	// organizationProvisionJob is the durable-job kind enqueued when a new
	// Yalla organization needs a Dokploy organization mapping. It is kept as a
	// plain string so the store layer stays decoupled from the jobs package.
	organizationProvisionJob = "ensure_dokploy_organization"
	// organizationDisplayNameMaxLen bounds a human-authored organization
	// display name, in runes. It is the same order of magnitude as every other
	// display-name bound in the system and exists so an unbounded string can
	// never reach the database.
	organizationDisplayNameMaxLen = 200
)

// CreateOrganizationInput is the unvalidated input to OrganizationService.Create.
// Slug and DisplayName are the caller-supplied resource fields; the Actor* and
// correlation fields describe the authenticated principal performing the create
// and are recorded verbatim on the audit event. They are plain strings so the
// store layer takes no build dependency on the policy or telemetry packages —
// the httpapi handler, which already holds the resolved principal and the
// request correlation, fills them in.
type CreateOrganizationInput struct {
	Slug          string
	DisplayName   string
	ActorID       string
	ActorKind     string
	ActorOrgID    string
	RequestID     string
	CorrelationID string
}

// UpdateOrganizationInput is the unvalidated input to OrganizationService.Update.
// OrganizationID names the organization to update. Slug and DisplayName are
// optional: a nil pointer means the caller did not include the field and it is
// left unchanged, which is what makes the operation a partial update. The
// Actor* and correlation fields describe the authenticated principal performing
// the update and are recorded verbatim on the audit event. They are plain
// strings so the store layer takes no build dependency on the policy or
// telemetry packages — the httpapi handler, which already holds the resolved
// principal and the request correlation, fills them in.
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
type UpdateOrganizationInput struct {
	OrganizationID string
	Slug           *string
	DisplayName    *string
	IfMatchVersion *int64
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// DeleteOrganizationInput is the input to OrganizationService.ScheduleDeletion.
// OrganizationID names the organization to schedule for teardown. The Actor*
// and correlation fields describe the authenticated principal performing the
// deletion and are recorded verbatim on the audit event. They are plain strings
// so the store layer takes no build dependency on the policy or telemetry
// packages — the httpapi handler, which already holds the resolved principal
// and the request correlation, fills them in.
//
// IfMatchVersion enforces optimistic concurrency for scheduling deletion,
// with the same semantics as on UpdateOrganizationInput.
type DeleteOrganizationInput struct {
	OrganizationID string
	IfMatchVersion *int64
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// AuditAppender records one immutable audit event inside the unit of work. The
// store layer depends only on this narrow port; *AuditRepository satisfies it.
// Append receives the *Tx of the surrounding unit of work, so the audit record
// commits or rolls back atomically with the mutation it describes — a created
// organization can never exist without its audit trail, and an audit record is
// never written for a create that rolled back.
type AuditAppender interface {
	Append(ctx context.Context, tx *Tx, e AuditEvent) (AuditEvent, error)
}

// OrganizationService is the unit-of-work orchestrator for creating, updating,
// and scheduling the deletion of organizations. Create composes — in a fixed
// order, inside one transaction — the desired-state write, the durable
// provisioning job, and the immutable audit record. Update and
// ScheduleDeletion compose the desired-state mutation and audit record the
// same way. Because every step shares the *Tx opened by Store.Write, a failure
// in any step rolls the others back: an organization is never persisted without
// its provisioning intent and audit trail.
type OrganizationService struct {
	store *Store
	orgs  *OrganizationRepository
	jobs  JobEnqueuer
	audit AuditAppender
}

// NewOrganizationService wires an OrganizationService from its dependencies. It
// returns a typed error if any dependency is nil, so a misconfigured service
// fails at construction rather than on its first request.
func NewOrganizationService(s *Store, orgs *OrganizationRepository, jobs JobEnqueuer, audit AuditAppender) (*OrganizationService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case orgs == nil:
		return nil, errors.New("store: nil organization repository")
	case jobs == nil:
		return nil, errors.New("store: nil job enqueuer")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &OrganizationService{store: s, orgs: orgs, jobs: jobs, audit: audit}, nil
}

// Create validates in, then runs the create-organization unit of work inside
// one transaction: write the organization row, enqueue the provisioning job,
// append the audit event. Validation runs before the transaction is opened, so
// an invalid request never touches the database. A slug that collides with an
// existing organization rolls the whole transaction back as a typed Conflict,
// so a duplicate organization, orphaned provisioning job, and orphaned audit
// record are all impossible.
func (svc *OrganizationService) Create(ctx context.Context, in CreateOrganizationInput) (Organization, error) {
	org, err := buildOrganizationToCreate(in)
	if err != nil {
		return Organization{}, err
	}

	// The audit record is filed under the actor's home organization — the
	// tenant the principal authenticated into — while its resource id names
	// the organization that was created. A missing actor organization is a
	// wiring error (an authenticated request always carries one), not client
	// input, so it is reported as Internal rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Organization{}, apierr.Internal(errors.New("store: OrganizationService.Create requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         organizationCreateAction,
		ResourceKind:   string(domain.KindOrganization),
		ResourceID:     org.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for organization.create",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// The slug is a canonical [a-z0-9-] identifier — it carries no secret
		// material — so it is safe to record verbatim as audit context.
		Metadata: map[string]string{"slug": org.Slug},
	}

	var created Organization
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		row, insErr := svc.orgs.Insert(ctx, tx, org)
		if insErr != nil {
			return insErr
		}
		if err := svc.jobs.Enqueue(ctx, tx, EnqueueJobInput{
			OrganizationID: row.ID,
			JobKind:        organizationProvisionJob,
			ResourceID:     row.ID,
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
		}); err != nil {
			return err
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		created = row
		return nil
	})
	if txErr != nil {
		return Organization{}, txErr
	}
	return created, nil
}

// Update validates in, then runs the update-organization unit of work inside
// one transaction: read the current row, apply the caller-supplied fields,
// write the row back, append the audit event. Validation of every supplied
// field runs before the transaction is opened, so an invalid request never
// touches the database. A patch that names no updatable field is itself a
// validation failure — a mutation that changes nothing is a client error, not
// a silent success. An {org_id} with no row is the typed NotFound the
// repository produces, and a slug that collides with another organization
// rolls the whole transaction back as a typed Conflict, so a duplicate
// organization and an orphaned audit record are both impossible.
func (svc *OrganizationService) Update(ctx context.Context, in UpdateOrganizationInput) (Organization, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return Organization{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}

	change, err := buildOrganizationUpdate(in)
	if err != nil {
		return Organization{}, err
	}

	// The audit record is filed under the actor's home organization — the
	// tenant the principal authenticated into — while its resource id names
	// the organization that was updated. A missing actor organization is a
	// wiring error (an authenticated request always carries one), not client
	// input, so it is reported as Internal rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Organization{}, apierr.Internal(errors.New("store: OrganizationService.Update requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         organizationUpdateAction,
		ResourceKind:   string(domain.KindOrganization),
		ResourceID:     organizationID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for organization.update",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// updated_fields names which fields the patch changed — stable wire
		// names, never the submitted values — so the audit trail records the
		// shape of the mutation without carrying any input verbatim.
		Metadata: map[string]string{"updated_fields": strings.Join(change.fields, ",")},
	}

	var updated Organization
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		current, getErr := svc.orgs.Get(ctx, tx, organizationID)
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
		row, updErr := svc.orgs.Update(ctx, tx, desired, in.IfMatchVersion)
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
		return Organization{}, txErr
	}
	return updated, nil
}

// ScheduleDeletion schedules the organization named by in.OrganizationID for
// teardown, inside one transaction: read the current row, reject a row already
// scheduled, stamp deletion_scheduled_at, append the audit event. A blank
// organization id is a typed validation failure raised before the transaction
// is opened. An {org_id} with no row is the typed NotFound the repository
// produces, and an organization whose deletion was already scheduled rolls the
// whole transaction back as a typed Conflict — so an audit record can never
// name a deletion that did not change the resource's state.
//
// This is a soft, scheduled deletion: it records the intent and stamps the
// timestamp. The destructive teardown — the ON DELETE CASCADE that removes
// projects, environments, services, and the audit log — is a later worker
// story, so the organization row and its audit trail still exist after this
// returns.
func (svc *OrganizationService) ScheduleDeletion(ctx context.Context, in DeleteOrganizationInput) (Organization, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return Organization{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}

	// The audit record is filed under the actor's home organization — the
	// tenant the principal authenticated into — while its resource id names
	// the organization that was scheduled for deletion. A missing actor
	// organization is a wiring error (an authenticated request always carries
	// one), not client input, so it is reported as Internal rather than a
	// validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Organization{}, apierr.Internal(errors.New("store: OrganizationService.ScheduleDeletion requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         organizationDeleteAction,
		ResourceKind:   string(domain.KindOrganization),
		ResourceID:     organizationID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for organization.delete",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
	}

	var scheduled Organization
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		current, getErr := svc.orgs.Get(ctx, tx, organizationID)
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
			// Scheduling teardown for an organization already scheduled for
			// teardown changes nothing: the caller's view of the resource
			// lifecycle is stale, so it is a typed Conflict, not a silent
			// success that would write a misleading audit record.
			return apierr.Conflict("organization deletion is already scheduled")
		}
		row, updErr := svc.orgs.ScheduleDeletion(ctx, tx, organizationID, in.IfMatchVersion)
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
		return Organization{}, txErr
	}
	return scheduled, nil
}

// buildOrganizationToCreate validates in and returns the Organization row it
// would persist, with a freshly minted, non-guessable id. It is split out from
// Create so the validation rules are unit testable without a database, and so
// an invalid request is rejected before a transaction is ever opened. On
// failure it returns a typed apierr.InvalidInput carrying stable field paths —
// never the submitted values — so the rejection can name the offending field
// without leaking input.
func buildOrganizationToCreate(in CreateOrganizationInput) (Organization, error) {
	var violations []apierr.FieldViolation

	slug, slugErr := domain.ParseSlug(in.Slug)
	if slugErr != nil {
		violations = append(violations, apierr.FieldViolation{
			Field:  "slug",
			Reason: "must be a canonical slug",
		})
	}

	displayName, dnViolation := validateOrganizationDisplayName(in.DisplayName)
	if dnViolation != nil {
		violations = append(violations, *dnViolation)
	}

	if len(violations) > 0 {
		return Organization{}, apierr.InvalidInput(violations...)
	}

	id, err := domain.NewID(domain.KindOrganization)
	if err != nil {
		// A crypto/rand failure is an environment fault, not client input.
		return Organization{}, apierr.Internal(err)
	}

	return Organization{
		ID:          id.String(),
		Slug:        slug.String(),
		DisplayName: displayName,
	}, nil
}

// organizationUpdate is the validated, normalised form of an
// UpdateOrganizationInput: the fields the caller asked to change, already
// parsed and trimmed. A nil pointer means "leave this field unchanged". fields
// lists the stable wire names of every field present in the patch, in
// declaration order, for the audit record.
type organizationUpdate struct {
	slug        *string
	displayName *string
	fields      []string
}

// buildOrganizationUpdate validates the caller-supplied fields of in and
// returns the normalised patch. It is split out from Update so the validation
// rules are unit testable without a database, and so an invalid request is
// rejected before a transaction is ever opened. A patch that names no updatable
// field is itself a validation failure. On failure it returns a typed
// apierr.InvalidInput carrying stable field paths — never the submitted values.
func buildOrganizationUpdate(in UpdateOrganizationInput) (organizationUpdate, error) {
	var (
		change     organizationUpdate
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
		displayName, dnViolation := validateOrganizationDisplayName(*in.DisplayName)
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
		return organizationUpdate{}, apierr.InvalidInput(violations...)
	}
	return change, nil
}

// validateOrganizationDisplayName trims and validates a human-authored
// organization display name. It returns the trimmed value and a nil violation
// when the name is acceptable, or the zero value and a typed FieldViolation
// naming the display_name field — never the submitted value — otherwise.
func validateOrganizationDisplayName(raw string) (string, *apierr.FieldViolation) {
	displayName := strings.TrimSpace(raw)
	switch {
	case displayName == "":
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must not be blank"}
	case !utf8.ValidString(displayName):
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must be valid UTF-8"}
	case containsControlRune(displayName):
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "must not contain control characters"}
	case utf8.RuneCountInString(displayName) > organizationDisplayNameMaxLen:
		return "", &apierr.FieldViolation{Field: "display_name", Reason: "exceeds the maximum length"}
	}
	return displayName, nil
}

// containsControlRune reports whether s contains any Unicode control character
// (which includes NUL, tab, newline, and carriage return).
func containsControlRune(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
