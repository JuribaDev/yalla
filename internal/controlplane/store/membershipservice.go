package store

import (
	"context"
	"errors"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// The policy action a membership add records on its audit event. It is
// duplicated as a plain string here on purpose: the policy action catalog is
// owned by internal/controlplane/policy, and the store layer must not take a
// build dependency on it. The HTTP authorization middleware authorizes the
// same action before the handler is reached; the value recorded here is the
// audit trail of the decision, kept in sync by the policy matrix tests.
const membersManageAction = "members.manage"

// membershipAllowedRoles is the set of organization-wide roles the
// memberships.role CHECK constraint permits. The HTTP layer rejects any
// other value before this layer is reached, but the white-box validator
// guards it as defence-in-depth so an unrecognised role can never reach the
// database.
var membershipAllowedRoles = map[string]struct{}{
	"owner":  {},
	"admin":  {},
	"member": {},
}

// AddMembershipInput is the unvalidated input to MembershipService.Add.
// OrganizationID names the organization to add the member to. UserID names
// the existing global user being added, and Role is the organization-wide
// role to grant. The Actor* and correlation fields describe the authenticated
// principal performing the add and are recorded verbatim on the audit event.
// They are plain strings so the store layer takes no build dependency on the
// policy or telemetry packages — the httpapi handler, which already holds the
// resolved principal and the request correlation, fills them in.
type AddMembershipInput struct {
	OrganizationID string
	UserID         string
	Role           string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// MembershipService is the unit-of-work orchestrator for adding members to an
// organization. Add composes — in a fixed order, inside one transaction — the
// existence checks for the organization and the user, the desired-state write
// (the memberships row), and the immutable audit record. Because every step
// shares the *Tx opened by Store.Write, a failure in any rolls the others
// back: a member is never persisted without its audit event, and an audit
// event is never written for a member that was not.
//
// It enqueues no provisioning job: a membership is a Yalla-source-of-truth
// concept; Dokploy has no notion of who is a member of a tenant.
type MembershipService struct {
	store       *Store
	orgs        *OrganizationRepository
	memberships *MembershipRepository
	audit       AuditAppender
}

// NewMembershipService wires a MembershipService from its dependencies. It
// returns a typed error if any dependency is nil, so a misconfigured service
// fails at construction rather than on its first request.
func NewMembershipService(s *Store, orgs *OrganizationRepository, memberships *MembershipRepository, audit AuditAppender) (*MembershipService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case orgs == nil:
		return nil, errors.New("store: nil organization repository")
	case memberships == nil:
		return nil, errors.New("store: nil membership repository")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &MembershipService{store: s, orgs: orgs, memberships: memberships, audit: audit}, nil
}

// Add validates in, then runs the add-membership unit of work inside one
// transaction: confirm the organization exists, confirm the user exists,
// insert the memberships row, append the audit event. Validation runs before
// the transaction is opened, so an invalid request never touches the
// database. A missing organization or user is the typed NotFound the
// existence checks produce, and a user that is already a member rolls the
// whole transaction back as a typed Conflict — so a duplicate membership and
// an orphaned audit record are both impossible.
func (svc *MembershipService) Add(ctx context.Context, in AddMembershipInput) (OrganizationMember, error) {
	organizationID, userID, role, err := validateMembershipAdd(in)
	if err != nil {
		return OrganizationMember{}, err
	}

	// The audit record is filed under the actor's home organization — the
	// tenant the principal authenticated into — while its resource id names
	// the membership target (the user being added). A missing actor
	// organization is a wiring error (an authenticated request always carries
	// one), not client input, so it is reported as Internal rather than a
	// validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return OrganizationMember{}, apierr.Internal(errors.New("store: MembershipService.Add requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         membersManageAction,
		ResourceKind:   string(domain.KindUser),
		ResourceID:     userID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for members.manage",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// organization_id is the target tenant of the add (which may differ
		// from the actor's home organization for a support principal); the
		// role is one of the three CHECK-constrained values and carries no
		// secret material, so both are safe to record verbatim.
		Metadata: map[string]string{
			"organization_id": organizationID,
			"role":            role,
		},
	}

	var added OrganizationMember
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, getErr := svc.orgs.Get(ctx, tx, organizationID); getErr != nil {
			return getErr
		}
		exists, userErr := svc.memberships.UserExists(ctx, tx, userID)
		if userErr != nil {
			return userErr
		}
		if !exists {
			return apierr.NotFound("user", userID)
		}
		row, insErr := svc.memberships.Insert(ctx, tx, organizationID, userID, role)
		if insErr != nil {
			return insErr
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		added = row
		return nil
	})
	if txErr != nil {
		return OrganizationMember{}, txErr
	}
	return added, nil
}

// validateMembershipAdd validates the caller-supplied fields of in and returns
// the trimmed, normalised values for the unit of work. It is split out from
// Add so the validation rules are unit testable without a database, and so an
// invalid request is rejected before a transaction is ever opened. On
// failure it returns a typed apierr.InvalidInput carrying stable field paths
// — never the submitted values — so the rejection can name the offending
// field without leaking input.
func validateMembershipAdd(in AddMembershipInput) (organizationID, userID, role string, err error) {
	organizationID = strings.TrimSpace(in.OrganizationID)
	userID = strings.TrimSpace(in.UserID)
	role = strings.TrimSpace(in.Role)

	var violations []apierr.FieldViolation
	if organizationID == "" {
		violations = append(violations, apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	// user_id is treated as an opaque identifier: the caller passes a value
	// they already have, so it cannot be minted here and we cannot demand the
	// strict domain.ParseID format that NewID emits — older test fixtures and
	// any legitimately stored id whose suffix predates the current format
	// would otherwise be rejected here. We require only the kind prefix that
	// every user id carries; format strictness is the job of internal/
	// controlplane/domain when an id is minted, and existence is enforced
	// inside the transaction by the users-table check.
	if userID == "" || !strings.HasPrefix(userID, string(domain.KindUser)+"_") {
		violations = append(violations, apierr.FieldViolation{
			Field:  "user_id",
			Reason: "must be a valid user identifier",
		})
	}
	switch {
	case role == "":
		violations = append(violations, apierr.FieldViolation{
			Field:  "role",
			Reason: "must not be blank",
		})
	default:
		if _, ok := membershipAllowedRoles[role]; !ok {
			violations = append(violations, apierr.FieldViolation{
				Field:  "role",
				Reason: "must be one of owner, admin, or member",
			})
		}
	}
	if len(violations) > 0 {
		return "", "", "", apierr.InvalidInput(violations...)
	}
	return organizationID, userID, role, nil
}
