package store

import (
	"context"
	"errors"
)

// AuditEventReader is the store-backed read adapter for the audit-events
// surface: the persistence surface the httpapi layer needs to render
// GET /v1/organizations/{org_id}/audit-events. It mirrors UsageReader and
// LimitsReader — it composes the AuditRepository rather than issuing its
// own SQL, so the tenant-scoping guarantees the repository proves in its
// integration tests are inherited for free, and every method opens its
// own short-lived read transaction through Store.Read.
type AuditEventReader struct {
	store *Store
	repo  *AuditRepository
}

// NewAuditEventReader builds an AuditEventReader over store. The
// constructor returns an error for a nil store so a misconfigured adapter
// fails at construction rather than on its first request.
func NewAuditEventReader(s *Store) (*AuditEventReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &AuditEventReader{store: s, repo: NewAuditRepository()}, nil
}

// ListByOrganization returns the most recent audit events for
// organizationID, newest first, capped at limit (clamped to a sane
// maximum at the repository, and to that maximum when limit is
// non-positive). The read runs inside a short-lived read-only transaction
// so it cannot smuggle a mutation past Store.Write. The read is tenant
// scoped at the repository: a cross-tenant id simply matches no rows and
// yields an empty list, never another organization's audit trail.
//
// Metadata, IP address, and user agent are already redacted by the time
// they reach this layer — the audit.Auditor redacts every value before
// AuditRepository.Append persists the row — so projecting them onto the
// wire is structurally safe: no secret can reach this method.
func (r *AuditEventReader) ListByOrganization(ctx context.Context, organizationID string, limit int) ([]AuditEvent, error) {
	var events []AuditEvent
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var listErr error
		events, listErr = r.repo.ListByOrganization(ctx, q, organizationID, limit)
		return listErr
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}
