package store

import (
	"context"
	"errors"
)

// OrganizationVariableReader is the store-backed read adapter for the
// organization-variables surface: the persistence surface the httpapi layer
// needs to render GET /v1/organizations/{org_id}/variables. It mirrors
// UsageReader and AuditEventReader — it composes the
// OrganizationVariableRepository rather than issuing its own SQL, so the
// tenant-scoping guarantees the repository proves in its integration tests
// are inherited for free, and every method opens its own short-lived
// read transaction through Store.Read.
type OrganizationVariableReader struct {
	store *Store
	repo  *OrganizationVariableRepository
}

// NewOrganizationVariableReader builds an OrganizationVariableReader over
// store. The constructor returns an error for a nil store so a misconfigured
// adapter fails at construction rather than on its first request.
func NewOrganizationVariableReader(s *Store) (*OrganizationVariableReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &OrganizationVariableReader{store: s, repo: NewOrganizationVariableRepository()}, nil
}

// ListByOrganization returns every organization-scoped variable owned by
// organizationID, in deterministic order (key ASC, id ASC). The read runs
// inside a short-lived read-only transaction so it cannot smuggle a
// mutation past Store.Write. The read is tenant-scoped at the repository:
// a cross-tenant id simply matches no rows and yields an empty list, never
// another organization's variables.
//
// Variable values reach this layer verbatim from the database. The HTTP
// layer is the wire redaction chokepoint (secret values become the
// redaction sentinel; non-secret values project verbatim). The audit
// layer is the audit-metadata redaction chokepoint (every value is
// redacted regardless of is_secret). The store does not redact at
// persistence — a future write path needs to round-trip values losslessly
// — but every consumer that surfaces values is required to redact, and
// OrganizationVariable.LogValue redacts at the slog boundary as a second
// line of defence.
func (r *OrganizationVariableReader) ListByOrganization(ctx context.Context, organizationID string) ([]OrganizationVariable, error) {
	var vars []OrganizationVariable
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var listErr error
		vars, listErr = r.repo.ListByOrganization(ctx, q, organizationID)
		return listErr
	})
	if err != nil {
		return nil, err
	}
	return vars, nil
}
