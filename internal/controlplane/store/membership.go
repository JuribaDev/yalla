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
