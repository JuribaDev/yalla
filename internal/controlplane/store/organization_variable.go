package store

import (
	"context"
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
