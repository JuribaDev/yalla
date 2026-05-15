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
//
// membersManageAction is the action recorded for every membership mutation
// (add, role change) — both go through the same policy gate.
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

// UpdateMembershipInput is the unvalidated input to MembershipService.UpdateMember.
// OrganizationID and UserID name the membership row to update. Role is the
// new organization-wide role to assign. The Actor* and correlation fields
// describe the authenticated principal performing the change and are recorded
// verbatim on the audit event. They are plain strings so the store layer
// takes no build dependency on the policy or telemetry packages — the
// httpapi handler, which already holds the resolved principal and the
// request correlation, fills them in.
//
// PATCH semantics: today's contract is that the role is the only mutable
// field on a membership. A future story may broaden the patch surface (e.g.
// grants) — when that lands, every new field is a separate optional pointer
// and a patch that names no field is rejected as InvalidInput, mirroring the
// organization PATCH pattern. Until then a missing/blank role is itself a
// validation failure: a no-op patch is a client error, not a silent success.
type UpdateMembershipInput struct {
	OrganizationID string
	UserID         string
	Role           string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// RemoveMembershipInput is the unvalidated input to MembershipService.Remove.
// OrganizationID and UserID name the membership row to remove. The Actor*
// and correlation fields describe the authenticated principal performing the
// removal and are recorded verbatim on the audit event. They are plain
// strings so the store layer takes no build dependency on the policy or
// telemetry packages — the httpapi handler, which already holds the resolved
// principal and the request correlation, fills them in.
//
// Removing a membership is a hard delete: the row is dropped and the
// destructive write is paired with an immutable audit record inside one
// transaction. There is no soft-delete tombstone — the trail of "who
// removed whom" is the audit row, not a residual membership row.
type RemoveMembershipInput struct {
	OrganizationID string
	UserID         string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// MembershipService is the unit-of-work orchestrator for adding members to an
// organization, updating their role, and removing them. Add composes — in a
// fixed order, inside one transaction — the existence checks for the
// organization and the user, the desired-state write (the memberships row),
// and the immutable audit record. UpdateMember composes — in a fixed order,
// inside one transaction — the existence check for the (organization, user)
// membership, the role update (which atomically bumps role_version), and the
// immutable audit record. Remove composes — in a fixed order, inside one
// transaction — the existence check for the (organization, user) membership,
// the DELETE of the memberships row, and the immutable audit record. Because
// every step shares the *Tx opened by Store.Write, a failure in any rolls
// the others back: a member is never persisted, re-roled, or removed without
// its audit event, and an audit event is never written for a mutation that
// did not happen.
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

// UpdateMember validates in, then runs the update-membership unit of work
// inside one transaction: confirm the membership exists, write the new role
// (which atomically bumps role_version, sweeping every outstanding session
// for the member), append the audit event. Validation runs before the
// transaction is opened, so an invalid request never touches the database. A
// missing membership — including the wrong-organization-for-this-user case —
// is the typed NotFound the repository produces; the audit record is rolled
// back with it, so an audit trail can never name a mutation that did not
// happen.
//
// The audit record is filed under the actor's home organization (the tenant
// the principal authenticated into) while its resource id names the user
// whose role was changed. metadata captures the target tenant, the new role,
// and the previous role — all non-secret values — so the trail records
// exactly what the mutation did without leaking input.
func (svc *MembershipService) UpdateMember(ctx context.Context, in UpdateMembershipInput) (OrganizationMember, error) {
	organizationID, userID, role, err := validateMembershipUpdate(in)
	if err != nil {
		return OrganizationMember{}, err
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return OrganizationMember{}, apierr.Internal(errors.New("store: MembershipService.UpdateMember requires an actor organization for the audit record"))
	}

	var updated OrganizationMember
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Read the current row inside the same transaction so the audit
		// record can name the previous role and so a missing membership is
		// reported as NotFound (404) without relying on the UPDATE's no-rows
		// path. The read is tenant scoped: a user id paired with the wrong
		// organization simply does not match, so a cross-tenant member_id
		// can never reveal another tenant's membership through this layer.
		current, getErr := svc.memberships.GetMember(ctx, tx, organizationID, userID)
		if getErr != nil {
			return getErr
		}

		row, updErr := svc.memberships.UpdateRole(ctx, tx, organizationID, userID, role)
		if updErr != nil {
			return updErr
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
			// organization_id is the target tenant of the update; previous_role
			// and role are CHECK-constrained values and carry no secret
			// material, so all three are safe to record verbatim.
			Metadata: map[string]string{
				"organization_id": organizationID,
				"previous_role":   current.Role,
				"role":            role,
			},
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		updated = row
		return nil
	})
	if txErr != nil {
		return OrganizationMember{}, txErr
	}
	return updated, nil
}

// validateMembershipUpdate validates the caller-supplied fields of in and
// returns the trimmed, normalised values for the update unit of work. It is
// split out from UpdateMember so the validation rules are unit testable
// without a database, and so an invalid request is rejected before a
// transaction is ever opened. On failure it returns a typed
// apierr.InvalidInput carrying stable field paths — never the submitted
// values — so the rejection can name the offending field without leaking
// input.
func validateMembershipUpdate(in UpdateMembershipInput) (organizationID, userID, role string, err error) {
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
	// member_id is treated as an opaque identifier the caller already has, so
	// the rules mirror validateMembershipAdd: require the user-kind prefix as
	// a defensive guard and let the in-transaction existence check enforce
	// the rest. Format strictness is the job of internal/controlplane/domain
	// when an id is minted; the auth/HTTP layer's earlier 403/404 also
	// shields this layer from arbitrary cross-tenant probes.
	if userID == "" || !strings.HasPrefix(userID, string(domain.KindUser)+"_") {
		violations = append(violations, apierr.FieldViolation{
			Field:  "member_id",
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

// Remove validates in, then runs the remove-membership unit of work inside
// one transaction: confirm the membership exists, delete the memberships
// row, append the audit event. Validation runs before the transaction is
// opened, so an invalid request never touches the database. A missing
// membership — including the wrong-organization-for-this-user case — is the
// typed NotFound the repository produces; the audit record is rolled back
// with it, so an audit trail can never name a removal that did not happen.
//
// The audit record is filed under the actor's home organization (the tenant
// the principal authenticated into) while its resource id names the user
// whose membership was removed. metadata captures the target tenant and the
// role the member held at removal time — both non-secret values — so the
// trail records exactly what was undone without leaking input.
//
// Remove returns the OrganizationMember as it was *immediately before* the
// delete: the existence read inside the transaction, projected through the
// same wire shape every other membership endpoint uses. This lets the HTTP
// layer render a deterministic terminal view (the membership that was
// removed) rather than a bare 204, mirroring the organization scheduled-
// deletion contract where the response carries the resource just past the
// state change. The row no longer exists by the time this returns; the
// returned OrganizationMember is the audit-grade record of what was
// removed.
func (svc *MembershipService) Remove(ctx context.Context, in RemoveMembershipInput) (OrganizationMember, error) {
	organizationID, userID, err := validateMembershipRemove(in)
	if err != nil {
		return OrganizationMember{}, err
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return OrganizationMember{}, apierr.Internal(errors.New("store: MembershipService.Remove requires an actor organization for the audit record"))
	}

	var removed OrganizationMember
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Read the current row inside the same transaction so the audit
		// record can name the role the member held at removal time and so a
		// missing membership is reported as NotFound (404) without relying
		// on the DELETE's no-rows path. The read is tenant scoped: a user
		// id paired with the wrong organization simply does not match, so a
		// cross-tenant member_id can never reveal another tenant's
		// membership through this layer.
		current, getErr := svc.memberships.GetMember(ctx, tx, organizationID, userID)
		if getErr != nil {
			return getErr
		}

		if delErr := svc.memberships.Delete(ctx, tx, organizationID, userID); delErr != nil {
			return delErr
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
			// organization_id is the target tenant of the removal; role is a
			// CHECK-constrained value and carries no secret material, so both
			// are safe to record verbatim. The role captured here is the role
			// the member held at removal time — the audit trail of what was
			// undone, not a forward-looking value.
			Metadata: map[string]string{
				"organization_id": organizationID,
				"role":            current.Role,
			},
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		removed = current
		return nil
	})
	if txErr != nil {
		return OrganizationMember{}, txErr
	}
	return removed, nil
}

// validateMembershipRemove validates the caller-supplied identifiers of in
// and returns the trimmed, normalised values for the remove unit of work. It
// is split out from Remove so the validation rules are unit testable without
// a database, and so an invalid request is rejected before a transaction is
// ever opened. On failure it returns a typed apierr.InvalidInput carrying
// stable field paths — never the submitted values — so the rejection can
// name the offending field without leaking input.
func validateMembershipRemove(in RemoveMembershipInput) (organizationID, userID string, err error) {
	organizationID = strings.TrimSpace(in.OrganizationID)
	userID = strings.TrimSpace(in.UserID)

	var violations []apierr.FieldViolation
	if organizationID == "" {
		violations = append(violations, apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	// member_id is treated as an opaque identifier the caller already has,
	// so the rules mirror validateMembershipUpdate: require the user-kind
	// prefix as a defensive guard and let the in-transaction existence
	// check enforce the rest. Format strictness is the job of internal/
	// controlplane/domain when an id is minted; the auth/HTTP layer's
	// earlier 403/404 also shields this layer from arbitrary cross-tenant
	// probes.
	if userID == "" || !strings.HasPrefix(userID, string(domain.KindUser)+"_") {
		violations = append(violations, apierr.FieldViolation{
			Field:  "member_id",
			Reason: "must be a valid user identifier",
		})
	}
	if len(violations) > 0 {
		return "", "", apierr.InvalidInput(violations...)
	}
	return organizationID, userID, nil
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
