package store

import (
	"context"
	"errors"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// Membership is the source-of-truth representation of a row in the memberships
// table: the join between a user and an organization, carrying the user's
// organization-wide role and the role/revocation version.
//
// RoleVersion is the counter that backs version-based session revocation. A
// human session token (internal/controlplane/auth) embeds the RoleVersion it
// was minted with; the auth layer rejects a token whose embedded version no
// longer matches this row, so a single increment — on a role change or a
// forced sign-out — invalidates every outstanding session for the member at
// once, without a denylist. It is the persistence-layer shape; HTTP request
// and response shapes are the job of the httpapi layer.
type Membership struct {
	OrganizationID string
	UserID         string
	Role           string
	RoleVersion    int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// MembershipRepository is the persistence layer for organization memberships.
// It follows the repository pattern used across the store package: reads
// accept a Querier and are tenant scoped by organization_id before user id, so
// a user id paired with another organization simply does not match and a
// cross-tenant id can never reveal another organization's membership.
type MembershipRepository struct{}

// NewMembershipRepository returns a MembershipRepository.
func NewMembershipRepository() *MembershipRepository { return &MembershipRepository{} }

// membershipColumns is the column list returned by every memberships query, in
// the order scanMembership expects.
const membershipColumns = `organization_id, user_id, role, role_version, created_at, updated_at`

// scanMembership scans one memberships row, in membershipColumns order, into a
// Membership.
func scanMembership(row pgx.Row) (Membership, error) {
	var m Membership
	err := row.Scan(&m.OrganizationID, &m.UserID, &m.Role, &m.RoleVersion, &m.CreatedAt, &m.UpdatedAt)
	return m, err
}

// Get returns the membership of userID within organizationID. The query is
// tenant scoped: it filters by organization_id first, so a user id that has no
// membership in this organization simply does not match and is reported as
// NotFound — a cross-tenant id can never reveal another organization's
// membership. It is the read the auth layer uses to resolve a session token's
// current role/revocation version.
func (r *MembershipRepository) Get(ctx context.Context, q Querier, organizationID, userID string) (Membership, error) {
	row := q.QueryRow(ctx,
		`SELECT `+membershipColumns+`
		 FROM memberships
		 WHERE organization_id = $1 AND user_id = $2`,
		organizationID, userID)
	m, err := scanMembership(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, apierr.NotFound("membership", userID)
	}
	if err != nil {
		return Membership{}, apierr.StoreUnavailable(err)
	}
	return m, nil
}

// Insert writes a new memberships row inside tx, joins it with the member's
// global user identity, and returns the persisted OrganizationMember —
// including the database-assigned role_version, timestamps, and the user's
// email and display name. It requires a *Tx — not a bare Querier — so a
// membership can never be created outside the transaction that also carries
// its audit record.
//
// role_version is left to the schema default (1): a freshly added member
// starts at version 1, the same monotonic-positive counter that backs
// session-token revocation for human members.
//
// A constraint violation is reported as a typed apierr.Conflict: the caller's
// view of the resource lifecycle is stale. The service layer pre-checks both
// organization and user existence before this call, so a violation at this
// layer can only be the primary-key duplicate — the user is already a member
// of the organization. A non-violation driver error surfaces as
// apierr.StoreUnavailable through mapWriteError. The raw driver error, which
// may name the constraint, is preserved only as the wrapped cause for
// server-side logging and never reaches the user-facing message.
func (r *MembershipRepository) Insert(ctx context.Context, tx *Tx, organizationID, userID, role string) (OrganizationMember, error) {
	if tx == nil {
		return OrganizationMember{}, apierr.Internal(errors.New("store: MembershipRepository.Insert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`WITH inserted AS (
		     INSERT INTO memberships (organization_id, user_id, role)
		     VALUES ($1, $2, $3)
		     RETURNING organization_id, user_id, role, role_version, created_at, updated_at
		 )
		 SELECT i.organization_id, i.user_id, i.role, i.role_version, i.created_at, i.updated_at, u.email, u.display_name
		   FROM inserted i
		   JOIN users u ON u.id = i.user_id`,
		organizationID, userID, role)
	m, err := scanOrganizationMember(row)
	if err != nil {
		return OrganizationMember{}, mapWriteError(err, "the user is already a member of this organization")
	}
	return m, nil
}

// UpdateRole writes a new role for the (organizationID, userID) membership
// inside tx, atomically bumps the row's role_version, joins the result with
// the member's global user identity, and returns the persisted
// OrganizationMember. It requires a *Tx — not a bare Querier — so a role
// change can never be persisted outside the transaction that also carries its
// audit record.
//
// role_version is incremented in the same statement that overwrites role:
// internal/controlplane/auth mints human session tokens that embed the
// role_version they were issued with and the auth middleware rejects a token
// whose embedded version no longer matches the current row, so a single
// monotonic increment here invalidates every outstanding session for the
// member at once — without a denylist. Bumping the version on every successful
// role change is what makes the revocation invariant honest; callers that do
// not want a session sweep should not call UpdateRole at all.
//
// The query is tenant scoped — it filters on (organization_id, user_id) — so a
// user id paired with the wrong organization simply does not match and is
// reported as the typed apierr.NotFound the GET endpoint uses, never disguised
// as a 5xx and never revealing whether another tenant has that member. A
// driver error that is not a missing row surfaces as apierr.StoreUnavailable
// through mapWriteError; the membership has no schema constraint a role change
// could realistically violate (the role CHECK is enforced by validateMembershipRoleUpdate
// before this layer is reached), so a Conflict here is always reported through
// the generic mapWriteError contract.
func (r *MembershipRepository) UpdateRole(ctx context.Context, tx *Tx, organizationID, userID, role string) (OrganizationMember, error) {
	if tx == nil {
		return OrganizationMember{}, apierr.Internal(errors.New("store: MembershipRepository.UpdateRole called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`WITH updated AS (
		     UPDATE memberships
		        SET role         = $3,
		            role_version = role_version + 1
		      WHERE organization_id = $1 AND user_id = $2
		     RETURNING organization_id, user_id, role, role_version, created_at, updated_at
		 )
		 SELECT u_m.organization_id, u_m.user_id, u_m.role, u_m.role_version,
		        u_m.created_at, u_m.updated_at, u.email, u.display_name
		   FROM updated u_m
		   JOIN users u ON u.id = u_m.user_id`,
		organizationID, userID, role)
	m, err := scanOrganizationMember(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationMember{}, apierr.NotFound("membership", userID)
	}
	if err != nil {
		return OrganizationMember{}, mapWriteError(err, "the membership cannot be updated")
	}
	return m, nil
}

// UserExists reports whether userID names a row in the global users table. It
// is the membership service's pre-check before INSERT: a missing user is
// surfaced as the typed apierr.NotFound a caller can read, instead of relying
// on a foreign-key constraint violation collapsing into a generic Conflict at
// the INSERT site. It accepts a Querier so it works against an open write
// transaction.
func (r *MembershipRepository) UserExists(ctx context.Context, q Querier, userID string) (bool, error) {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists); err != nil {
		return false, apierr.StoreUnavailable(err)
	}
	return exists, nil
}

// OrganizationMember is a memberships row joined with the member's global user
// identity: the shape GET /v1/organizations/{org_id}/members needs. It carries
// the organization-wide role and lifecycle timestamps from the memberships
// table plus the user's email and display name from the global users table,
// so the httpapi layer can render a useful member list without a second
// lookup. It is the persistence-layer shape; the HTTP wire shape is the job
// of the httpapi layer. It carries no credential material — a membership row
// stores a role, never a secret.
type OrganizationMember struct {
	Membership
	Email           string
	UserDisplayName string
}

// organizationMemberColumns is the column list returned by ListByOrganization,
// in the order scanOrganizationMember expects. It joins the memberships row
// (aliased m) with the global users identity row (aliased u).
const organizationMemberColumns = `m.organization_id, m.user_id, m.role, m.role_version, m.created_at, m.updated_at, u.email, u.display_name`

// scanOrganizationMember scans one ListByOrganization row, in
// organizationMemberColumns order, into an OrganizationMember.
func scanOrganizationMember(row pgx.Row) (OrganizationMember, error) {
	var m OrganizationMember
	err := row.Scan(
		&m.OrganizationID, &m.UserID, &m.Role, &m.RoleVersion,
		&m.CreatedAt, &m.UpdatedAt, &m.Email, &m.UserDisplayName,
	)
	return m, err
}

// GetMember returns the membership of userID within organizationID, joined
// with the member's global user identity — the shape GET
// /v1/organizations/{org_id}/members/{member_id} needs. The query is tenant
// scoped: it filters by organization_id first, so a user id paired with the
// wrong organization simply does not match and is reported as the typed
// apierr.NotFound (with the user id, never the organization id, as the
// surfaced identifier) — a cross-tenant member_id can never reveal another
// organization's membership. It accepts a Querier so it works against a
// read-only transaction or an open write transaction.
//
// The JOIN is INNER because the memberships.user_id foreign key guarantees a
// matching users row for every membership; a missing user is therefore a
// schema invariant violation, surfaced as the typed apierr.StoreUnavailable
// every other repository read produces, never disguised as a not-found.
func (r *MembershipRepository) GetMember(ctx context.Context, q Querier, organizationID, userID string) (OrganizationMember, error) {
	row := q.QueryRow(ctx,
		`SELECT `+organizationMemberColumns+`
		   FROM memberships m
		   JOIN users u ON u.id = m.user_id
		  WHERE m.organization_id = $1 AND m.user_id = $2`,
		organizationID, userID)
	m, err := scanOrganizationMember(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationMember{}, apierr.NotFound("membership", userID)
	}
	if err != nil {
		return OrganizationMember{}, apierr.StoreUnavailable(err)
	}
	return m, nil
}

// ListByOrganization returns every membership of organizationID, joined with
// each member's global user identity, ordered deterministically by creation
// time then user id so the response is stable for a given set of rows. The
// query is tenant scoped: it filters by organization_id, so it can only ever
// return the memberships of the organization named — a cross-tenant id simply
// matches no rows and yields an empty list, never another organization's
// members. It accepts a Querier so it works against a read-only transaction
// or an open write transaction. The return is always a non-nil slice so
// callers can iterate it without a nil check; a datastore failure surfaces
// as the typed apierr.StoreUnavailable error every other repository read
// produces, never disguised as an empty result.
func (r *MembershipRepository) ListByOrganization(ctx context.Context, q Querier, organizationID string) ([]OrganizationMember, error) {
	rows, err := q.Query(ctx,
		`SELECT `+organizationMemberColumns+`
		   FROM memberships m
		   JOIN users u ON u.id = m.user_id
		  WHERE m.organization_id = $1
		  ORDER BY m.created_at, m.user_id`,
		organizationID)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	members := make([]OrganizationMember, 0)
	for rows.Next() {
		m, scanErr := scanOrganizationMember(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		members = append(members, m)
	}
	if rows.Err() != nil {
		return nil, apierr.StoreUnavailable(rows.Err())
	}
	return members, nil
}

// MembershipReader is the store-backed read adapter for the membership list
// surface: the persistence surface the httpapi layer needs to render
// GET /v1/organizations/{org_id}/members. It mirrors OrganizationReader — it
// composes the MembershipRepository rather than issuing its own SQL, so the
// tenant-scoping guarantees the repository proves in its integration tests
// are inherited for free, and every method opens its own short-lived read
// transaction through Store.Read.
type MembershipReader struct {
	store       *Store
	memberships *MembershipRepository
}

// NewMembershipReader builds a MembershipReader over store. It returns an
// error for a nil store so a misconfigured adapter fails at construction
// rather than on its first request.
func NewMembershipReader(s *Store) (*MembershipReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &MembershipReader{store: s, memberships: NewMembershipRepository()}, nil
}

// ListMembers returns every membership of organizationID, joined with each
// member's global user identity, reading them inside a short-lived read-only
// transaction. The read is tenant scoped: a cross-tenant id simply matches no
// rows and yields an empty list, never another organization's members. A
// datastore failure is propagated as its own typed error.
func (r *MembershipReader) ListMembers(ctx context.Context, organizationID string) ([]OrganizationMember, error) {
	var members []OrganizationMember
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var listErr error
		members, listErr = r.memberships.ListByOrganization(ctx, q, organizationID)
		return listErr
	})
	if err != nil {
		return nil, err
	}
	return members, nil
}

// GetMember returns the membership of userID within organizationID, joined
// with the member's global user identity, reading it inside a short-lived
// read-only transaction. The read is tenant scoped: a user id paired with
// the wrong organization simply does not match and is reported as the typed
// apierr.NotFound, so a cross-tenant member_id can never reveal another
// organization's membership. A datastore failure is propagated as its own
// typed error.
func (r *MembershipReader) GetMember(ctx context.Context, organizationID, userID string) (OrganizationMember, error) {
	var member OrganizationMember
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var getErr error
		member, getErr = r.memberships.GetMember(ctx, q, organizationID, userID)
		return getErr
	})
	if err != nil {
		return OrganizationMember{}, err
	}
	return member, nil
}
