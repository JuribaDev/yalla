package store

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
)

// EnvironmentVariable is a single environment-scoped environment variable —
// the third-from-lowest precedence layer of the
// Organization -> Project -> Environment -> Service variable hierarchy the
// Dokploy renderer composes. An environment-scoped variable shadows any
// project-scoped variable of the same key for services inside the
// environment, which in turn shadows the organization-scoped variable of
// the same key.
//
// Value is the literal value the variable carries. The repository returns
// it verbatim from the database; the HTTP layer redacts secret values
// before projection onto the wire, and a future audit layer redacts every
// value regardless of is_secret before persisting it in audit metadata.
// The LogValue method below makes log records that accidentally carry an
// EnvironmentVariable safe by structurally hiding the value at the slog
// boundary as a second line of defence — a panic stack trace or a debug
// log that captures the struct cannot leak the literal.
type EnvironmentVariable struct {
	ID             string
	OrganizationID string
	EnvironmentID  string
	Key            string
	Value          string
	IsSecret       bool
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// LogValue redacts every variable value at the slog boundary so a stray
// log record that captures an EnvironmentVariable cannot leak the literal.
// Non-secret values reach the wire through the HTTP projection (which has
// its own explicit redaction policy); logs always see the sentinel.
func (v EnvironmentVariable) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", v.ID),
		slog.String("organization_id", v.OrganizationID),
		slog.String("environment_id", v.EnvironmentID),
		slog.String("key", v.Key),
		slog.String("value", output.Sentinel),
		slog.Bool("is_secret", v.IsSecret),
		slog.Int64("version", v.Version),
	)
}

// environmentVariableColumns is the SELECT projection used by every read in
// this repository. Keeping it as a single string keeps the column list in
// lockstep with scanEnvironmentVariable.
const environmentVariableColumns = `id, organization_id, environment_id, key, value, is_secret, version, created_at, updated_at`

// environmentVariableListMaxRows caps how many rows a single
// ListByEnvironment call returns. An unbounded query can never be issued
// by accident; an HTTP layer that wants pagination later will add an
// explicit offset or cursor parameter rather than relax this ceiling.
const environmentVariableListMaxRows = 500

// EnvironmentVariableRepository is the persistence half of the
// environment-variables surface. Every read is tenant-scoped: the
// organization_id and environment_id legs of the predicate are
// non-optional, so a missing or cross-tenant id simply matches no rows
// and yields an empty list — never another tenant's variables. The
// repository is stateless; the constructor exists so call sites depend
// on a value rather than a bare struct literal.
type EnvironmentVariableRepository struct{}

// NewEnvironmentVariableRepository builds a stateless
// EnvironmentVariableRepository.
func NewEnvironmentVariableRepository() *EnvironmentVariableRepository {
	return &EnvironmentVariableRepository{}
}

// ListByEnvironment returns every environment-scoped variable owned by
// (organizationID, environmentID), in deterministic (key ASC, id ASC)
// order so an agent observing the response sees a stable ordering across
// calls. The read is tenant-scoped at the SQL predicate, so a
// cross-tenant (organization, environment) tuple matches no rows. A raw
// driver error surfaces as the typed apierr.StoreUnavailable — the cause
// is wrapped for logging only, never leaked into the customer-facing
// message.
//
// This method does NOT verify the environment exists; callers that need
// to distinguish "environment missing" from "environment has no
// variables" must Get the environment first (the
// EnvironmentVariableReader adapter does so in the same short-lived
// transaction).
func (r *EnvironmentVariableRepository) ListByEnvironment(ctx context.Context, q Querier, organizationID, environmentID string) ([]EnvironmentVariable, error) {
	rows, err := q.Query(ctx,
		`SELECT `+environmentVariableColumns+`
		   FROM environment_variables
		  WHERE organization_id = $1 AND environment_id = $2
		  ORDER BY key ASC, id ASC
		  LIMIT $3`,
		organizationID, environmentID, environmentVariableListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]EnvironmentVariable, 0)
	for rows.Next() {
		v, scanErr := scanEnvironmentVariable(rows)
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

// scanEnvironmentVariable scans one environment_variables row in
// environmentVariableColumns order.
func scanEnvironmentVariable(row scanRow) (EnvironmentVariable, error) {
	var v EnvironmentVariable
	if err := row.Scan(
		&v.ID,
		&v.OrganizationID,
		&v.EnvironmentID,
		&v.Key,
		&v.Value,
		&v.IsSecret,
		&v.Version,
		&v.CreatedAt,
		&v.UpdatedAt,
	); err != nil {
		return EnvironmentVariable{}, err
	}
	return v, nil
}

// EnvironmentVariableReader is the store-backed read adapter for the
// environment-variables surface: the persistence surface the httpapi
// layer needs to render GET /v1/environments/{environment_id}/variables.
// It mirrors ProjectVariableReader — it composes EnvironmentRepository
// and EnvironmentVariableRepository through a short-lived read-only
// transaction (Store.Read), so the tenant-scoping guarantees the
// repositories prove in their integration tests are inherited for free,
// and every cross-tenant or unknown environment_id surfaces as a
// deterministic apierr.NotFound rather than an empty list.
type EnvironmentVariableReader struct {
	store        *Store
	environments *EnvironmentRepository
	variables    *EnvironmentVariableRepository
}

// NewEnvironmentVariableReader builds an EnvironmentVariableReader over
// store. It returns an error for a nil store so a misconfigured adapter
// fails at construction rather than on its first request.
func NewEnvironmentVariableReader(s *Store) (*EnvironmentVariableReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &EnvironmentVariableReader{
		store:        s,
		environments: NewEnvironmentRepository(),
		variables:    NewEnvironmentVariableRepository(),
	}, nil
}

// ListEnvironmentVariables returns every environment-scoped variable
// owned by (organizationID, environmentID), reading them inside a
// short-lived read-only transaction. The read is tenant scoped at both
// legs: it Gets the environment first so a cross-tenant or unknown
// environment_id surfaces as a deterministic apierr.NotFound — never as
// an empty list, which would invite an agent to believe the environment
// exists with no variables. A live environment with no variables is
// then a deterministic empty slice. A datastore failure is propagated
// as its own typed error.
//
// Variable values reach this layer verbatim from the database. The HTTP
// layer is the wire redaction chokepoint (secret values become the
// redaction sentinel; non-secret values project verbatim). A future
// audit layer will be the audit-metadata redaction chokepoint (every
// value redacted regardless of is_secret). The store does not redact at
// persistence — a future write path needs to round-trip values losslessly
// — but every consumer that surfaces values is required to redact, and
// EnvironmentVariable.LogValue redacts at the slog boundary as a second
// line of defence.
func (r *EnvironmentVariableReader) ListEnvironmentVariables(ctx context.Context, organizationID, environmentID string) ([]EnvironmentVariable, error) {
	var vars []EnvironmentVariable
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, getErr := r.environments.GetByID(ctx, q, organizationID, environmentID); getErr != nil {
			return getErr
		}
		list, listErr := r.variables.ListByEnvironment(ctx, q, organizationID, environmentID)
		if listErr != nil {
			return listErr
		}
		vars = list
		return nil
	})
	if err != nil {
		return nil, err
	}
	return vars, nil
}
