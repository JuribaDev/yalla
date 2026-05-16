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

// Upsert inserts or updates the (organization_id, service_id, key) row
// carrying value / is_secret. The (organization_id, service_id, key)
// UNIQUE constraint from migration 0021 is the conflict target, so an
// existing row keeps its id and bumps version through the bump_version
// trigger; a new row uses the caller-supplied id (already minted by the
// service layer through domain.NewID(KindServiceVariable) so the id is
// non-guessable and tenant-anonymous). The returned ServiceVariable
// reflects the committed state — its id is the row's stable id (the
// existing id for an update, the freshly minted one for an insert), its
// version is the post-trigger version, and its updated_at is the moment
// the row persisted.
//
// The tenant predicate is non-optional: organization_id AND service_id
// are part of the upsert key, so a cross-tenant smuggling attempt at this
// seam either matches an existing (organization_id, service_id, key)
// tuple owned by the supplied tenant (the intended idempotent overwrite)
// or inserts a fresh row scoped to that tenant — never another tenant's
// data. Validation of organizationID, serviceID, key, and value happens
// in the service layer before a transaction is opened; this method
// assumes its inputs already cleared the same shape checks the PUT
// endpoint enforces.
//
// A foreign-key violation (organizationID/serviceID does not exist) and
// the table's CHECK constraints both surface as apierr.Conflict through
// mapWriteError; any other driver error surfaces as
// apierr.StoreUnavailable. The raw driver error is wrapped as the cause
// for server-side logging only and never reaches the user-facing message
// — so a customer-facing 409 here never echoes value content.
func (r *ServiceVariableRepository) Upsert(ctx context.Context, tx *Tx, id, organizationID, serviceID, key, value string, isSecret bool) (ServiceVariable, error) {
	if tx == nil {
		return ServiceVariable{}, apierr.Internal(errors.New("store: ServiceVariableRepository.Upsert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO service_variables (id, organization_id, service_id, key, value, is_secret)
		     VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (organization_id, service_id, key) DO UPDATE
		    SET value     = EXCLUDED.value,
		        is_secret = EXCLUDED.is_secret
		RETURNING `+serviceVariableColumns,
		id, organizationID, serviceID, key, value, isSecret)
	v, err := scanServiceVariable(row)
	if err != nil {
		return ServiceVariable{}, mapWriteError(err, "the service variable could not be saved")
	}
	return v, nil
}

// DeleteByServiceExceptKeys removes every service_variables row owned by
// (organizationID, serviceID) whose key is not in keepKeys. It is the
// counterpart of Upsert in the bulk-replace unit of work: Upsert applies
// every variable the caller wants to keep, and this method drops the
// rest — so the post-condition is "the service's variables == exactly
// the caller-supplied set". keepKeys MAY be empty (the caller asked to
// clear every service-scoped variable); the SQL predicate is written so
// `key <> ALL($3)` is true for every row when the array is empty,
// producing a deterministic full clear.
//
// The tenant predicate is non-optional: organization_id AND service_id
// are part of the WHERE clause, so a cross-tenant tuple matches no rows
// and deletes nothing — never another tenant's data. Validation of
// organizationID, serviceID, and the keep list happens in the service
// layer; this method assumes the caller already produced a
// deduplicated, validated list of POSIX env-var names.
func (r *ServiceVariableRepository) DeleteByServiceExceptKeys(ctx context.Context, tx *Tx, organizationID, serviceID string, keepKeys []string) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: ServiceVariableRepository.DeleteByServiceExceptKeys called with a nil transaction"))
	}
	if keepKeys == nil {
		keepKeys = []string{}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM service_variables
		  WHERE organization_id = $1
		    AND service_id      = $2
		    AND key <> ALL($3)`,
		organizationID, serviceID, keepKeys); err != nil {
		return mapWriteError(err, "the service variables could not be reconciled")
	}
	return nil
}

// serviceVariablesWriteAction is the action recorded on the audit event
// emitted by every service-variables replace. It matches the wire-level
// action constant the policy engine authorizes (env.write), so an
// audit reader can correlate the audit event back to the API surface
// that produced it without a translation table.
const serviceVariablesWriteAction = "env.write"

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
