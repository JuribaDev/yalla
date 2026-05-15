package store

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
)

// OrganizationVariable is a single organization-scoped environment variable
// — the lowest-precedence layer of the Organization -> Project ->
// Environment -> Service variable hierarchy the Dokploy renderer composes.
//
// Value is the literal value the variable carries. The repository returns it
// verbatim from the database; the HTTP layer redacts secret values before
// projection onto the wire, and the audit layer redacts every value
// regardless of is_secret before persisting it in audit metadata. The
// LogValue method below makes log records that accidentally carry an
// OrganizationVariable safe by structurally hiding the value at the slog
// boundary as a second line of defence — a panic stack trace or a debug
// log that captures the struct cannot leak the literal.
type OrganizationVariable struct {
	ID             string
	OrganizationID string
	Key            string
	Value          string
	IsSecret       bool
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// LogValue redacts every variable value at the slog boundary so a stray
// log record that captures an OrganizationVariable cannot leak the literal.
// Non-secret values reach the wire through the HTTP projection (which has
// its own explicit redaction policy); logs always see the sentinel.
func (v OrganizationVariable) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", v.ID),
		slog.String("organization_id", v.OrganizationID),
		slog.String("key", v.Key),
		slog.String("value", output.Sentinel),
		slog.Bool("is_secret", v.IsSecret),
		slog.Int64("version", v.Version),
	)
}

// organizationVariableColumns is the SELECT projection used by every read
// in this repository. Keeping it as a single string keeps the column list
// in lockstep with scanOrganizationVariable.
const organizationVariableColumns = `id, organization_id, key, value, is_secret, version, created_at, updated_at`

// organizationVariableListMaxRows caps how many rows a single
// ListByOrganization call returns. An unbounded query can never be issued
// by accident; an HTTP layer that wants pagination later will add an
// explicit offset or cursor parameter rather than relax this ceiling.
const organizationVariableListMaxRows = 500

// OrganizationVariableRepository is the persistence half of the
// organization-variables surface. Every read is tenant-scoped: the
// organization_id leg of the predicate is non-optional, so a missing or
// cross-tenant id simply matches no rows and yields an empty list — never
// another tenant's variables.
type OrganizationVariableRepository struct{}

// NewOrganizationVariableRepository builds a stateless
// OrganizationVariableRepository.
func NewOrganizationVariableRepository() *OrganizationVariableRepository {
	return &OrganizationVariableRepository{}
}

// ListByOrganization returns every organization-scoped variable owned by
// organizationID, in deterministic (key ASC, id ASC) order so an agent
// observing the response sees a stable ordering across calls. The read is
// tenant-scoped at the SQL predicate, so a cross-tenant id matches no
// rows. A raw driver error surfaces as the typed apierr.StoreUnavailable
// — the cause is wrapped for logging only, never leaked into the
// customer-facing message.
func (r *OrganizationVariableRepository) ListByOrganization(ctx context.Context, q Querier, organizationID string) ([]OrganizationVariable, error) {
	rows, err := q.Query(ctx,
		`SELECT `+organizationVariableColumns+`
		   FROM organization_variables
		  WHERE organization_id = $1
		  ORDER BY key ASC, id ASC
		  LIMIT $2`,
		organizationID, organizationVariableListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	var out []OrganizationVariable
	for rows.Next() {
		v, scanErr := scanOrganizationVariable(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// Upsert inserts or updates the (organization_id, key) row carrying value /
// is_secret. The (organization_id, key) UNIQUE constraint from migration
// 0012 is the conflict target, so an existing row keeps its id and bumps
// version through the bump_version trigger; a new row uses the caller-
// supplied id (already minted by the service layer through
// domain.NewID(KindOrganizationVariable) so the id is non-guessable and
// tenant-anonymous). The returned OrganizationVariable reflects the
// committed state — its id is the row's stable id (the existing id for an
// update, the freshly minted one for an insert), its version is the
// post-trigger version, and its updated_at is the moment the row
// persisted.
//
// The tenant predicate is non-optional: organization_id is part of the
// upsert key, so a cross-tenant smuggling attempt at this seam either
// matches an existing (organization_id, key) pair owned by the supplied
// organization (the intended idempotent overwrite) or inserts a fresh row
// scoped to that organization — never another tenant's data. Validation
// of organizationID, key, and value happens in the service layer before a
// transaction is opened; this method assumes its inputs already cleared
// validate.EnvVars.
//
// A foreign-key violation (organizationID does not exist) and the table's
// CHECK constraints both surface as apierr.Conflict through mapWriteError;
// any other driver error surfaces as apierr.StoreUnavailable. The raw
// driver error is wrapped as the cause for server-side logging only and
// never reaches the user-facing message — so a customer-facing 409 here
// never echoes value content.
func (r *OrganizationVariableRepository) Upsert(ctx context.Context, tx *Tx, id, organizationID, key, value string, isSecret bool) (OrganizationVariable, error) {
	if tx == nil {
		return OrganizationVariable{}, apierr.Internal(errors.New("store: OrganizationVariableRepository.Upsert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO organization_variables (id, organization_id, key, value, is_secret)
		     VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (organization_id, key) DO UPDATE
		    SET value     = EXCLUDED.value,
		        is_secret = EXCLUDED.is_secret
		RETURNING `+organizationVariableColumns,
		id, organizationID, key, value, isSecret)
	v, err := scanOrganizationVariable(row)
	if err != nil {
		return OrganizationVariable{}, mapWriteError(err, "the organization variable could not be saved")
	}
	return v, nil
}

// DeleteByOrganizationExceptKeys removes every organization_variables row
// owned by organizationID whose key is not in keepKeys. It is the
// counterpart of Upsert in the bulk-replace unit of work: Upsert applies
// every variable the caller wants to keep, and this method drops the rest
// — so the post-condition is "the tenant's variables == exactly the
// caller-supplied set". keepKeys MAY be empty (the caller asked to clear
// every organization-scoped variable); the SQL predicate is written so
// `key <> ALL($2)` is true for every row when the array is empty,
// producing a deterministic full clear.
//
// The tenant predicate is non-optional: organization_id is part of the
// WHERE clause, so a cross-tenant id matches no rows and deletes nothing —
// never another tenant's data. Validation of organizationID and the keep
// list happens in the service layer; this method assumes the caller
// already produced a deduplicated, validated list of POSIX env-var names.
func (r *OrganizationVariableRepository) DeleteByOrganizationExceptKeys(ctx context.Context, tx *Tx, organizationID string, keepKeys []string) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: OrganizationVariableRepository.DeleteByOrganizationExceptKeys called with a nil transaction"))
	}
	if keepKeys == nil {
		keepKeys = []string{}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM organization_variables
		  WHERE organization_id = $1
		    AND key <> ALL($2)`,
		organizationID, keepKeys); err != nil {
		return mapWriteError(err, "the organization variables could not be reconciled")
	}
	return nil
}

// scanRow is the minimal Scan interface pgx.Row and pgx.Rows both satisfy.
// Keeping the scanner generic over both lets ListByOrganization and a
// future Get share the projection.
type scanRow interface {
	Scan(dest ...any) error
}

// scanOrganizationVariable scans one row into an OrganizationVariable. The
// column order must match organizationVariableColumns above.
func scanOrganizationVariable(row scanRow) (OrganizationVariable, error) {
	var v OrganizationVariable
	if err := row.Scan(
		&v.ID,
		&v.OrganizationID,
		&v.Key,
		&v.Value,
		&v.IsSecret,
		&v.Version,
		&v.CreatedAt,
		&v.UpdatedAt,
	); err != nil {
		return OrganizationVariable{}, err
	}
	return v, nil
}
