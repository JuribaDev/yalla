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
