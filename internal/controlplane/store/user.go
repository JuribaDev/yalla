package store

import (
	"context"
	"errors"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// User is the source-of-truth representation of a row in the users table —
// the global human identity record. It is the persistence-layer shape; HTTP
// request and response shapes are the job of the httpapi layer.
//
// users is a global identity table. A user is linked to organizations through
// memberships, never owned by one organization directly, so the row carries
// no organization_id. Deleting an organization cascades through projects,
// environments, services, memberships, and dokploy_refs but leaves users rows
// intact. Tenant-scoped reads must therefore go through a verified parent
// join — see GetInOrganization.
//
// Email is stored in a case-insensitive citext column with a UNIQUE
// constraint: "Ada@Example.com" and "ada@example.com" cannot both exist, and
// either lookup returns the same row. The repository preserves whatever
// casing the caller persisted; equality is the schema's job.
type User struct {
	ID          string
	Email       string
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UserRepository is the persistence layer for the users table. It follows the
// repository pattern used across the store package: reads accept a Querier so
// they run against a read-only transaction or an open write transaction,
// every statement is fully parameterized, and a missing row is reported as a
// typed apierr.NotFound rather than a bare pgx.ErrNoRows.
//
// users is a global identity table, so a bare Get is scoped by the row's own
// id — there is no parent organization_id to filter by first. Callers that
// need to confine a read to a single tenant (the policy default) go through
// GetInOrganization, which JOINs the row against memberships so a user
// outside the organization is reported as NotFound just like an unknown id.
//
// The repository is stateless; the constructor exists so call sites depend on
// a value rather than a bare struct literal.
type UserRepository struct{}

// NewUserRepository returns a UserRepository.
func NewUserRepository() *UserRepository { return &UserRepository{} }

// userColumns is the column list returned by every users query, in the order
// scanUser expects.
const userColumns = `id, email, display_name, created_at, updated_at`

// Get returns the user identified by userID. A missing id is reported as a
// typed NotFound — the same shape any other unknown id produces, so a caller
// can never tell "no such user" apart from "a user you cannot see". The
// caller is responsible for only ever passing a user id the authenticated
// principal is authorized to see; that authorization decision is the policy
// engine's job and is made before this repository is reached.
func (r *UserRepository) Get(ctx context.Context, q Querier, userID string) (User, error) {
	row := q.QueryRow(ctx,
		`SELECT `+userColumns+`
		 FROM users
		 WHERE id = $1`,
		userID)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, apierr.NotFound("user", userID)
	}
	if err != nil {
		return User{}, apierr.StoreUnavailable(err)
	}
	return u, nil
}

// GetByEmail returns the user identified by email. Email is stored in a
// citext column with a UNIQUE constraint, so the lookup is case-insensitive
// and at most one row can match. A missing email is reported as a typed
// NotFound; this is the lookup the auth layer uses to translate a sign-in
// identifier into a persisted identity, so a non-existent email and a wrong
// password must be indistinguishable from outside — this read returns the
// same NotFound shape any other unknown id produces.
func (r *UserRepository) GetByEmail(ctx context.Context, q Querier, email string) (User, error) {
	row := q.QueryRow(ctx,
		`SELECT `+userColumns+`
		 FROM users
		 WHERE email = $1`,
		email)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, apierr.NotFound("user", email)
	}
	if err != nil {
		return User{}, apierr.StoreUnavailable(err)
	}
	return u, nil
}

// GetInOrganization returns the user identified by userID only when they are
// a member of organizationID. The query JOINs users against memberships and
// filters on organization_id first, so a user that has no membership in this
// organization simply does not match and is reported as NotFound — the same
// shape an unknown id produces, so a cross-tenant id can never reveal another
// organization's roster. It is the tenant-scoped read the httpapi layer uses
// before rendering a user under GET /v1/organizations/{org}/members/{user}.
func (r *UserRepository) GetInOrganization(ctx context.Context, q Querier, organizationID, userID string) (User, error) {
	row := q.QueryRow(ctx,
		`SELECT u.id, u.email, u.display_name, u.created_at, u.updated_at
		 FROM users u
		 JOIN memberships m ON m.user_id = u.id
		 WHERE m.organization_id = $1 AND u.id = $2`,
		organizationID, userID)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, apierr.NotFound("user", userID)
	}
	if err != nil {
		return User{}, apierr.StoreUnavailable(err)
	}
	return u, nil
}

// Insert writes a new user row inside tx and returns the persisted row,
// including the database-assigned timestamps. It requires a *Tx — not a bare
// Querier — so a user can never be created outside the transaction that also
// carries its audit record. An email that collides with an existing user is
// reported as a typed Conflict; the raw driver error, which may name the
// constraint, is preserved only as the wrapped cause for server-side logging
// and never reaches the user-facing message.
func (r *UserRepository) Insert(ctx context.Context, tx *Tx, u User) (User, error) {
	if tx == nil {
		return User{}, apierr.Internal(errors.New("store: UserRepository.Insert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO users (id, email, display_name)
		 VALUES ($1, $2, $3)
		 RETURNING `+userColumns,
		u.ID, u.Email, u.DisplayName)
	created, err := scanUser(row)
	if err != nil {
		return User{}, mapWriteError(err, "a user with this email already exists")
	}
	return created, nil
}

// Update writes new email and display_name values for the user identified by
// u.ID inside tx and returns the persisted row, including the
// trigger-refreshed updated_at timestamp. It requires a *Tx — not a bare
// Querier — so a user can never be updated outside the transaction that also
// carries its audit record. A missing id is reported as a typed NotFound —
// the same shape any other unknown id produces, so a caller can never tell
// "no such user" apart from "a user you cannot see". An email that collides
// with another user is reported as a typed Conflict; the raw driver error,
// which may name the constraint, is preserved only as the wrapped cause for
// server-side logging and never reaches the user-facing message.
//
// The users table has no version column — the global identity row is
// authoritative under the user's own control, and the
// session-token-revocation counter that protects organization-scoped
// authorization lives on memberships.role_version, not here.
func (r *UserRepository) Update(ctx context.Context, tx *Tx, u User) (User, error) {
	if tx == nil {
		return User{}, apierr.Internal(errors.New("store: UserRepository.Update called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`UPDATE users
		    SET email = $2, display_name = $3
		  WHERE id = $1
		 RETURNING `+userColumns,
		u.ID, u.Email, u.DisplayName)
	updated, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, apierr.NotFound("user", u.ID)
	}
	if err != nil {
		return User{}, mapWriteError(err, "a user with this email already exists")
	}
	return updated, nil
}

// Delete removes the user identified by userID inside tx. It requires a *Tx
// — not a bare Querier — so a user can never be deleted outside the
// transaction that also carries its audit record. A missing id is reported
// as a typed NotFound — the same shape any other unknown id produces, so a
// caller can never tell "no such user" apart from "a user you cannot see".
//
// memberships(user_id) is ON DELETE CASCADE, so the user's organization
// memberships disappear in the same statement; api_keys.created_by is
// ON DELETE SET NULL, so historical key rows survive but their authorship
// pointer is cleared. The teardown is therefore atomic with the audit
// record that this transaction also carries.
func (r *UserRepository) Delete(ctx context.Context, tx *Tx, userID string) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: UserRepository.Delete called with a nil transaction"))
	}
	tag, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return apierr.StoreUnavailable(err)
	}
	if tag.RowsAffected() == 0 {
		return apierr.NotFound("user", userID)
	}
	return nil
}

// scanUser scans one users row in userColumns order.
func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

// UserReader is the store-backed read adapter for user resources: the
// persistence surface the httpapi layer needs to render
// GET /v1/users/{user_id}. It mirrors OrganizationReader — it composes the
// UserRepository rather than issuing its own SQL, so the typed-error and
// (where applicable) tenant-scoping guarantees the repository proves in its
// integration tests are inherited for free, and every method opens its own
// short-lived read transaction through Store.Read.
type UserReader struct {
	store *Store
	users *UserRepository
}

// NewUserReader builds a UserReader over store. It returns an error for a nil
// store so a misconfigured adapter fails at construction rather than on its
// first request.
func NewUserReader(s *Store) (*UserReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &UserReader{store: s, users: NewUserRepository()}, nil
}

// GetUser returns the user identified by userID, reading it inside a
// short-lived read-only transaction. A missing id is the typed NotFound the
// repository produces; a datastore failure is propagated as its own typed
// error and never disguised as a not-found.
func (r *UserReader) GetUser(ctx context.Context, userID string) (User, error) {
	var u User
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var getErr error
		u, getErr = r.users.Get(ctx, q, userID)
		return getErr
	})
	if err != nil {
		return User{}, err
	}
	return u, nil
}

// GetUserInOrganization returns the user identified by userID only when they
// are a member of organizationID, reading inside a short-lived read-only
// transaction. The tenant-scoping is the repository's join; a non-member
// surfaces as the typed NotFound an unknown id would produce.
func (r *UserReader) GetUserInOrganization(ctx context.Context, organizationID, userID string) (User, error) {
	var u User
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var getErr error
		u, getErr = r.users.GetInOrganization(ctx, q, organizationID, userID)
		return getErr
	})
	if err != nil {
		return User{}, err
	}
	return u, nil
}
