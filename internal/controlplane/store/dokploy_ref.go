package store

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// YallaKind is the closed-set kind of the Yalla resource a dokploy_refs row
// names through its (organization_id, yalla_id) tuple. The string values
// match the dokploy_refs.yalla_kind CHECK constraint verbatim and are public
// compatibility contract for the worker side of the mapping.
type YallaKind string

const (
	// YallaKindOrganization names the organizations row that owns the
	// mapping. Used when Dokploy itself models a per-tenant top-level
	// container.
	YallaKindOrganization YallaKind = "organization"
	// YallaKindProject names a projects row.
	YallaKindProject YallaKind = "project"
	// YallaKindEnvironment names an environments row.
	YallaKindEnvironment YallaKind = "environment"
	// YallaKindService names a services row — the most common case, since
	// every customer-facing application/database/compose unit ultimately
	// resolves to a Dokploy application or database.
	YallaKindService YallaKind = "service"
)

// String returns the kind's stable string value, matching the database
// CHECK constraint verbatim.
func (k YallaKind) String() string { return string(k) }

// DokployResource is the closed-set kind of the Dokploy object a
// dokploy_refs row maps a Yalla resource onto. The string values match the
// dokploy_refs.dokploy_resource CHECK constraint verbatim and are public
// compatibility contract for the worker side of the mapping.
type DokployResource string

const (
	// DokployResourceOrganization names a Dokploy organization-equivalent
	// container.
	DokployResourceOrganization DokployResource = "organization"
	// DokployResourceProject names a Dokploy project.
	DokployResourceProject DokployResource = "project"
	// DokployResourceEnvironment names a Dokploy environment.
	DokployResourceEnvironment DokployResource = "environment"
	// DokployResourceApplication names a Dokploy application (a service
	// rendered as an image, git, or drop artifact).
	DokployResourceApplication DokployResource = "application"
	// DokployResourceCompose names a Dokploy compose stack.
	DokployResourceCompose DokployResource = "compose"
	// DokployResourceDatabase names a Dokploy managed database
	// (postgres/mysql/mariadb/mongo/redis).
	DokployResourceDatabase DokployResource = "database"
	// DokployResourceDomain names a Dokploy domain attached to a service.
	// A single service may own multiple domains.
	DokployResourceDomain DokployResource = "domain"
	// DokployResourceBackup names a Dokploy backup configuration. A single
	// service may own multiple backups.
	DokployResourceBackup DokployResource = "backup"
)

// String returns the resource's stable string value, matching the database
// CHECK constraint verbatim.
func (d DokployResource) String() string { return string(d) }

// dokployRefListMaxRows caps how many dokploy_refs rows a single list call
// returns, so an unbounded query can never be issued by accident; an HTTP
// layer that wants pagination later will add an explicit offset or cursor
// parameter rather than relax this ceiling.
const dokployRefListMaxRows = 500

// DokployRef is the source-of-truth representation of a row in the
// dokploy_refs table — one polymorphic mapping from a Yalla resource
// (identified by (organization_id, yalla_kind, yalla_id)) to a Dokploy
// object (identified by (dokploy_resource, dokploy_id), globally unique).
// The mapping table cannot use a single foreign-key column because the
// target row's table varies; the organization_id FK keeps every row
// tenant-scoped regardless, and the two UNIQUE constraints make duplicate
// mappings and Dokploy-object reuse structurally unrepresentable.
//
// The struct carries no credential material: dokploy_id is an opaque
// identifier minted by Dokploy (not a token), and no other field stores
// secrets, API keys, cookies, or rendered environment variable values.
//
// There is no Version field: migration 0011's comment about covering
// dokploy_refs "for parity" was aspirational — the migration's ALTER
// statements only touch organizations, projects, environments, and
// services. The repository surface exposes no row-level Update method
// either; the mapping has no customer-mutable column, every column is
// part of the row identity or a database-owned timestamp. If a future
// worker story needs a remap surface it can land both the column (via a
// new migration) and the Update method together; this story deliberately
// scopes the "optimistic versioning where applicable" acceptance criterion
// to "not applicable here" rather than build an unused write path.
type DokployRef struct {
	ID              int64
	OrganizationID  string
	YallaKind       YallaKind
	YallaID         string
	DokployResource DokployResource
	DokployID       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// LogValue keeps a stray slog record that captures a DokployRef safe. The
// row carries no secrets, but LogValue still narrows the slog projection so
// a panic stack trace or debug log record cannot inadvertently widen the
// surface beyond the structural identifiers and the closed-set kinds.
func (r DokployRef) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int64("id", r.ID),
		slog.String("organization_id", r.OrganizationID),
		slog.String("yalla_kind", r.YallaKind.String()),
		slog.String("yalla_id", r.YallaID),
		slog.String("dokploy_resource", r.DokployResource.String()),
		slog.String("dokploy_id", r.DokployID),
	)
}

// dokployRefColumns is the SELECT projection used by every read in this
// repository. Keeping it as a single string keeps the column list in
// lockstep with scanDokployRef.
const dokployRefColumns = `id, organization_id, yalla_kind, yalla_id,
	dokploy_resource, dokploy_id, created_at, updated_at`

// DokployRefRepository is the persistence half of the dokploy_refs surface.
// Every read and every write is tenant-scoped: the organization_id leg of
// the predicate is non-optional, so a missing or cross-tenant id matches no
// rows — never another tenant's mapping. The repository is stateless; the
// constructor exists so call sites depend on a value rather than a bare
// struct literal.
//
// Mutating methods (Insert, Delete) require a *Tx so the mapping write
// commits or rolls back atomically with the lifecycle operation that
// triggered it (typically the worker's reconciliation transaction that
// also writes audit_events and updates the service's desired_state). Read
// methods accept a Querier so they work against either a standalone
// read-only transaction or an open write transaction without changing the
// signature.
type DokployRefRepository struct{}

// NewDokployRefRepository returns a stateless DokployRefRepository.
func NewDokployRefRepository() *DokployRefRepository { return &DokployRefRepository{} }

// Insert persists ref as a new dokploy_refs row inside tx and returns the
// committed row (including the database-assigned id, created_at, and
// updated_at). The id column is GENERATED ALWAYS AS IDENTITY so the
// caller MUST NOT supply one; ref.ID is ignored and overwritten with the
// minted value. A blank YallaKind or DokployResource is rejected as a
// programming error at the application boundary — the closed sets are
// small and the database CHECK is the authoritative belt-and-braces.
//
// The schema enforces the tenant invariant — the organization_id FK
// references organizations(id) so a row can never sit under a foreign
// organization — and the closed-set CHECKs reject an unknown yalla_kind or
// dokploy_resource. Duplicate mappings (either the same Dokploy object
// being claimed twice through UNIQUE (dokploy_resource, dokploy_id) or the
// same (organization_id, yalla_id, dokploy_resource, dokploy_id) tuple
// being inserted twice) surface as the typed apierr.Conflict mapWriteError
// produces; the raw constraint name never leaks into the user-facing
// message.
func (r *DokployRefRepository) Insert(ctx context.Context, tx *Tx, ref DokployRef) (DokployRef, error) {
	if tx == nil {
		return DokployRef{}, apierr.Internal(errors.New("store: DokployRefRepository.Insert called with a nil transaction"))
	}
	if ref.YallaKind == "" {
		return DokployRef{}, apierr.Internal(errors.New("store: DokployRefRepository.Insert called with a blank yalla_kind"))
	}
	if ref.DokployResource == "" {
		return DokployRef{}, apierr.Internal(errors.New("store: DokployRefRepository.Insert called with a blank dokploy_resource"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO dokploy_refs
		   (organization_id, yalla_kind, yalla_id, dokploy_resource, dokploy_id)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING `+dokployRefColumns,
		ref.OrganizationID, ref.YallaKind.String(), ref.YallaID,
		ref.DokployResource.String(), ref.DokployID)
	inserted, err := scanDokployRef(row)
	if err != nil {
		return DokployRef{}, mapWriteError(err, "a dokploy mapping with this yalla resource, dokploy resource, or dokploy id already exists")
	}
	return inserted, nil
}

// Get returns the single dokploy_refs row identified by (organizationID,
// id), tenant-scoped at the SQL predicate. The composite predicate is
// non-optional: a missing or cross-tenant organizationID matches no row
// even when a mapping with the same id exists in another tenant — the
// response is never an oracle that reveals another organization's mapping
// ids. A row that does not exist surfaces as the typed apierr.NotFound,
// never as a 500 leaking the cause; the not-found payload names only the
// mapping id the caller already supplied.
func (r *DokployRefRepository) Get(ctx context.Context, q Querier, organizationID string, id int64) (DokployRef, error) {
	row := q.QueryRow(ctx,
		`SELECT `+dokployRefColumns+`
		   FROM dokploy_refs
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, id)
	ref, err := scanDokployRef(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return DokployRef{}, apierr.NotFound("dokploy_ref", dokployRefIDString(id))
	}
	if err != nil {
		return DokployRef{}, apierr.StoreUnavailable(err)
	}
	return ref, nil
}

// GetByDokployTarget returns the single dokploy_refs row whose Dokploy
// target tuple is (dokployResource, dokployID), scoped to organizationID.
// The schema's UNIQUE (dokploy_resource, dokploy_id) is global — Dokploy
// object identity is global — but the read is still tenant-scoped at the
// SQL predicate so the response can never be an oracle for the existence
// of a Dokploy object owned by a foreign tenant. A row that does not exist
// surfaces as the typed apierr.NotFound; the not-found payload names only
// the dokploy_id the caller already supplied so no other-tenant identifier
// can leak.
func (r *DokployRefRepository) GetByDokployTarget(ctx context.Context, q Querier, organizationID string, dokployResource DokployResource, dokployID string) (DokployRef, error) {
	if dokployResource == "" {
		return DokployRef{}, apierr.Internal(errors.New("store: DokployRefRepository.GetByDokployTarget called with a blank dokploy_resource"))
	}
	row := q.QueryRow(ctx,
		`SELECT `+dokployRefColumns+`
		   FROM dokploy_refs
		  WHERE organization_id = $1
		    AND dokploy_resource = $2
		    AND dokploy_id = $3`,
		organizationID, dokployResource.String(), dokployID)
	ref, err := scanDokployRef(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return DokployRef{}, apierr.NotFound("dokploy_ref", dokployID)
	}
	if err != nil {
		return DokployRef{}, apierr.StoreUnavailable(err)
	}
	return ref, nil
}

// ListByYallaResource returns every dokploy_refs row attached to the Yalla
// resource identified by (organizationID, yallaKind, yallaID), ordered
// deterministically by (dokploy_resource ASC, dokploy_id ASC, id ASC). The
// query is tenant scoped at the SQL predicate so a cross-tenant tuple
// matches no rows and yields an empty slice. The result is always a
// non-nil slice (possibly empty) so callers can iterate it without a nil
// check. The query is bounded by dokployRefListMaxRows.
//
// This method does NOT verify the parent Yalla row exists; callers that
// need to distinguish "Yalla resource missing" from "Yalla resource has no
// Dokploy mappings yet" must Get the parent first.
func (r *DokployRefRepository) ListByYallaResource(ctx context.Context, q Querier, organizationID string, yallaKind YallaKind, yallaID string) ([]DokployRef, error) {
	if yallaKind == "" {
		return nil, apierr.Internal(errors.New("store: DokployRefRepository.ListByYallaResource called with a blank yalla_kind"))
	}
	rows, err := q.Query(ctx,
		`SELECT `+dokployRefColumns+`
		   FROM dokploy_refs
		  WHERE organization_id = $1
		    AND yalla_kind = $2
		    AND yalla_id = $3
		  ORDER BY dokploy_resource ASC, dokploy_id ASC, id ASC
		  LIMIT $4`,
		organizationID, yallaKind.String(), yallaID, dokployRefListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]DokployRef, 0)
	for rows.Next() {
		ref, scanErr := scanDokployRef(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// ListByOrganization returns every dokploy_refs row owned by
// organizationID, ordered deterministically by (yalla_kind ASC, yalla_id
// ASC, dokploy_resource ASC, dokploy_id ASC, id ASC). The query is tenant
// scoped at the SQL predicate so a cross-tenant id can never reveal
// another organization's mappings. The result is always a non-nil slice
// (possibly empty) and the query is bounded by dokployRefListMaxRows.
func (r *DokployRefRepository) ListByOrganization(ctx context.Context, q Querier, organizationID string) ([]DokployRef, error) {
	rows, err := q.Query(ctx,
		`SELECT `+dokployRefColumns+`
		   FROM dokploy_refs
		  WHERE organization_id = $1
		  ORDER BY yalla_kind ASC, yalla_id ASC,
		           dokploy_resource ASC, dokploy_id ASC, id ASC
		  LIMIT $2`,
		organizationID, dokployRefListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]DokployRef, 0)
	for rows.Next() {
		ref, scanErr := scanDokployRef(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, ref)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// Delete removes the row identified by (organizationID, id). The query is
// tenant scoped at the SQL predicate: a cross-tenant id matches no rows
// and the method reports apierr.NotFound via the RowsAffected() == 0 path
// — the same idempotent-tag pattern api_keys.Revoke and
// APIKeyScopeRepository.Delete use. A successful delete returns nil; the
// caller does not need the prior row body because every mutation has
// already audited the identity it removed.
func (r *DokployRefRepository) Delete(ctx context.Context, tx *Tx, organizationID string, id int64) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: DokployRefRepository.Delete called with a nil transaction"))
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM dokploy_refs
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, id)
	if err != nil {
		return apierr.StoreUnavailable(err)
	}
	if tag.RowsAffected() == 0 {
		return apierr.NotFound("dokploy_ref", dokployRefIDString(id))
	}
	return nil
}

// dokployRefIDString renders the bigint id as a decimal string for the
// not-found payload. The dokploy_refs PK is the only int64 id surfaced by
// the store package so far (every other resource uses an opaque text id),
// so we render it inline rather than introduce a strconv import indirection.
func dokployRefIDString(id int64) string {
	if id == 0 {
		return "0"
	}
	negative := id < 0
	if negative {
		id = -id
	}
	var buf [20]byte
	pos := len(buf)
	for id > 0 {
		pos--
		buf[pos] = byte('0' + id%10)
		id /= 10
	}
	if negative {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// scanDokployRef scans one dokploy_refs row in dokployRefColumns order.
func scanDokployRef(row scanRow) (DokployRef, error) {
	var (
		r                  DokployRef
		yallaKindStr       string
		dokployResourceStr string
	)
	if err := row.Scan(
		&r.ID,
		&r.OrganizationID,
		&yallaKindStr,
		&r.YallaID,
		&dokployResourceStr,
		&r.DokployID,
		&r.CreatedAt,
		&r.UpdatedAt,
	); err != nil {
		return DokployRef{}, err
	}
	r.YallaKind = YallaKind(yallaKindStr)
	r.DokployResource = DokployResource(dokployResourceStr)
	return r, nil
}
