package store

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
)

// ServiceVariable is a single service-scoped environment variable — the
// highest-precedence (lowest-level) layer of the
// Organization -> Project -> Environment -> Service variable hierarchy the
// Dokploy renderer composes. A service-scoped variable shadows the
// environment-, project-, and organization-scoped variables of the same
// key for that service only.
//
// Value is the literal value the variable carries. The repository returns
// it verbatim from the database; the HTTP layer redacts secret values
// before projection onto the wire, and a future audit layer redacts every
// value regardless of is_secret before persisting it in audit metadata.
// The LogValue method below makes log records that accidentally carry a
// ServiceVariable safe by structurally hiding the value at the slog
// boundary as a second line of defence — a panic stack trace or a debug
// log that captures the struct cannot leak the literal.
type ServiceVariable struct {
	ID             string
	OrganizationID string
	ServiceID      string
	Key            string
	Value          string
	IsSecret       bool
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// LogValue redacts every variable value at the slog boundary so a stray
// log record that captures a ServiceVariable cannot leak the literal.
// Non-secret values reach the wire through the HTTP projection (which has
// its own explicit redaction policy); logs always see the sentinel.
func (v ServiceVariable) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", v.ID),
		slog.String("organization_id", v.OrganizationID),
		slog.String("service_id", v.ServiceID),
		slog.String("key", v.Key),
		slog.String("value", output.Sentinel),
		slog.Bool("is_secret", v.IsSecret),
		slog.Int64("version", v.Version),
	)
}

// serviceVariableColumns is the SELECT projection used by every read in
// this repository. Keeping it as a single string keeps the column list in
// lockstep with scanServiceVariable.
const serviceVariableColumns = `id, organization_id, service_id, key, value, is_secret, version, created_at, updated_at`

// serviceVariableListMaxRows caps how many rows a single ListByService
// call returns. An unbounded query can never be issued by accident; an
// HTTP layer that wants pagination later will add an explicit offset or
// cursor parameter rather than relax this ceiling.
const serviceVariableListMaxRows = 500

// ServiceVariableRepository is the persistence half of the service-
// variables surface. Every read is tenant-scoped: the organization_id
// and service_id legs of the predicate are non-optional, so a missing
// or cross-tenant id simply matches no rows and yields an empty list —
// never another tenant's variables. The repository is stateless; the
// constructor exists so call sites depend on a value rather than a
// bare struct literal.
type ServiceVariableRepository struct{}

// NewServiceVariableRepository builds a stateless ServiceVariableRepository.
func NewServiceVariableRepository() *ServiceVariableRepository {
	return &ServiceVariableRepository{}
}

// ListByService returns every service-scoped variable owned by
// (organizationID, serviceID), in deterministic (key ASC, id ASC) order
// so an agent observing the response sees a stable ordering across
// calls. The read is tenant-scoped at the SQL predicate, so a
// cross-tenant (organization, service) tuple matches no rows. A raw
// driver error surfaces as the typed apierr.StoreUnavailable — the
// cause is wrapped for logging only, never leaked into the customer-
// facing message.
//
// This method does NOT verify the service exists; callers that need to
// distinguish "service missing" from "service has no variables" must
// Get the service first (the ServiceVariableReader adapter does so in
// the same short-lived transaction).
func (r *ServiceVariableRepository) ListByService(ctx context.Context, q Querier, organizationID, serviceID string) ([]ServiceVariable, error) {
	rows, err := q.Query(ctx,
		`SELECT `+serviceVariableColumns+`
		   FROM service_variables
		  WHERE organization_id = $1 AND service_id = $2
		  ORDER BY key ASC, id ASC
		  LIMIT $3`,
		organizationID, serviceID, serviceVariableListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]ServiceVariable, 0)
	for rows.Next() {
		v, scanErr := scanServiceVariable(rows)
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

// scanServiceVariable scans one service_variables row in
// serviceVariableColumns order.
func scanServiceVariable(row scanRow) (ServiceVariable, error) {
	var v ServiceVariable
	if err := row.Scan(
		&v.ID,
		&v.OrganizationID,
		&v.ServiceID,
		&v.Key,
		&v.Value,
		&v.IsSecret,
		&v.Version,
		&v.CreatedAt,
		&v.UpdatedAt,
	); err != nil {
		return ServiceVariable{}, err
	}
	return v, nil
}

// ServiceVariableReader is the store-backed read adapter for the
// service-variables surface: the persistence surface the httpapi layer
// needs to render GET /v1/services/{service_id}/variables. It mirrors
// EnvironmentVariableReader — it composes ServiceRepository and
// ServiceVariableRepository through a short-lived read-only transaction
// (Store.Read), so the tenant-scoping guarantees the repositories prove
// in their integration tests are inherited for free, and every
// cross-tenant or unknown service_id surfaces as a deterministic
// apierr.NotFound rather than an empty list.
type ServiceVariableReader struct {
	store     *Store
	services  *ServiceRepository
	variables *ServiceVariableRepository
}

// NewServiceVariableReader builds a ServiceVariableReader over store. It
// returns an error for a nil store so a misconfigured adapter fails at
// construction rather than on its first request.
func NewServiceVariableReader(s *Store) (*ServiceVariableReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &ServiceVariableReader{
		store:     s,
		services:  NewServiceRepository(),
		variables: NewServiceVariableRepository(),
	}, nil
}

// ListServiceVariables returns every service-scoped variable owned by
// (organizationID, serviceID), reading them inside a short-lived
// read-only transaction. The read is tenant scoped at both legs: it
// Gets the service first so a cross-tenant or unknown service_id
// surfaces as a deterministic apierr.NotFound — never as an empty
// list, which would invite an agent to believe the service exists
// with no variables. A live service with no variables is then a
// deterministic empty slice. A datastore failure is propagated as its
// own typed error.
//
// Variable values reach this layer verbatim from the database. The
// HTTP layer is the wire redaction chokepoint (secret values become
// the redaction sentinel; non-secret values project verbatim). A
// future audit layer will be the audit-metadata redaction chokepoint
// (every value redacted regardless of is_secret). The store does not
// redact at persistence — a future write path needs to round-trip
// values losslessly — but every consumer that surfaces values is
// required to redact, and ServiceVariable.LogValue redacts at the
// slog boundary as a second line of defence.
func (r *ServiceVariableReader) ListServiceVariables(ctx context.Context, organizationID, serviceID string) ([]ServiceVariable, error) {
	var vars []ServiceVariable
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, getErr := r.services.GetByID(ctx, q, organizationID, serviceID); getErr != nil {
			return getErr
		}
		list, listErr := r.variables.ListByService(ctx, q, organizationID, serviceID)
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
