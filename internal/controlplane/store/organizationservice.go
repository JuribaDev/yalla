package store

import (
	"context"
	"errors"
	"strings"
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

// AuditAppender records one immutable audit event inside the unit of work. The
// store layer depends only on this narrow port; *AuditRepository satisfies it.
// Append receives the *Tx of the surrounding unit of work, so the audit record
// commits or rolls back atomically with the mutation it describes — a created
// organization can never exist without its audit trail, and an audit record is
// never written for a create that rolled back.
type AuditAppender interface {
	Append(ctx context.Context, tx *Tx, e AuditEvent) (AuditEvent, error)
}

// OrganizationService is the unit-of-work orchestrator for creating
// organizations. Create composes — in this fixed order, inside one transaction
// — the desired-state write and the immutable audit record. Because both steps
// share the *Tx opened by Store.Write, a failure in either rolls the other
// back: an organization is never persisted without its audit event.
//
// It enqueues no provisioning job: an organization is the tenant root of
// Yalla's source-of-truth hierarchy, and the worker that mirrors it into
// Dokploy is driven by a later story.
type OrganizationService struct {
	store *Store
	orgs  *OrganizationRepository
	audit AuditAppender
}

// NewOrganizationService wires an OrganizationService from its dependencies. It
// returns a typed error if any dependency is nil, so a misconfigured service
// fails at construction rather than on its first request.
func NewOrganizationService(s *Store, orgs *OrganizationRepository, audit AuditAppender) (*OrganizationService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case orgs == nil:
		return nil, errors.New("store: nil organization repository")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &OrganizationService{store: s, orgs: orgs, audit: audit}, nil
}

// Create validates in, then runs the create-organization unit of work inside
// one transaction: write the organization row, append the audit event.
// Validation runs before the transaction is opened, so an invalid request
// never touches the database. A slug that collides with an existing
// organization rolls the whole transaction back as a typed Conflict, so a
// duplicate organization and an orphaned audit record are both impossible.
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

	displayName := strings.TrimSpace(in.DisplayName)
	switch {
	case displayName == "":
		violations = append(violations, apierr.FieldViolation{
			Field:  "display_name",
			Reason: "must not be blank",
		})
	case !utf8.ValidString(displayName):
		violations = append(violations, apierr.FieldViolation{
			Field:  "display_name",
			Reason: "must be valid UTF-8",
		})
	case containsControlRune(displayName):
		violations = append(violations, apierr.FieldViolation{
			Field:  "display_name",
			Reason: "must not contain control characters",
		})
	case utf8.RuneCountInString(displayName) > organizationDisplayNameMaxLen:
		violations = append(violations, apierr.FieldViolation{
			Field:  "display_name",
			Reason: "exceeds the maximum length",
		})
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
