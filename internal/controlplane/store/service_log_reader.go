package store

import (
	"context"
	"errors"
	"time"
)

// ServiceLogLine is one entry in a service log read response. The
// shape is the stable, source-of-truth-agnostic structural row that
// the httpapi service-logs payload projects onto the wire as-is
// (modulo JSON tag naming) — no pointer-typed fields, no embedded
// interfaces, no Dokploy-specific identifiers. The httpapi-layer
// wire DTO depends on these field names being stable, so adding a
// new field is a strictly forward-compatible operation; renaming or
// removing one is a wire break.
//
// Stream is the channel the line came from. The closed set the
// httpapi-layer documents is "stdout", "stderr", and "system" — a
// future Dokploy-fetcher adapter MUST keep producing values from
// this closed set (or extend it explicitly) so an agent reading the
// payload can branch on the value without escape-decoding it.
// Message is the literal byte content of the log line as Dokploy
// emitted it — never re-rendered with secrets, since this
// adapter never reads database-resident secret material; any
// rendered-environment redaction is the Dokploy-fetcher adapter's
// responsibility when it lands.
type ServiceLogLine struct {
	OccurredAt time.Time
	Stream     string
	Message    string
}

// ServiceLogs is the typed response of ServiceLogReader.ListLogs: the
// service id the lines belong to (echoed back so a caller can
// distinguish a multi-resource batch in a future log-stream endpoint
// even though today's GET addresses exactly one service) and the
// lines themselves in occurrence order (oldest first). An empty
// Lines slice with a populated ServiceID means the service exists,
// is owned by the tenant, and has no log lines available — never
// disguised as a NotFound.
type ServiceLogs struct {
	ServiceID string
	Lines     []ServiceLogLine
}

// ListServiceLogsInput is the typed input shape ServiceLogReader.ListLogs
// accepts. The shape is closed — no pointer-typed fields, no embedded
// interfaces — so a callsite that builds it cannot accidentally smuggle
// a caller-controlled organization id past the tenant boundary by
// nilling out a pointer. OrganizationID is always taken from the
// authenticated principal's home org at the httpapi layer (never from
// caller-controlled request input), and ServiceID is always taken from
// the path parameter; both surface here as plain strings so the
// tenant-scoped existence check that defends the boundary cannot be
// bypassed by a zero value.
//
// Limit clamps the number of lines returned. The httpapi layer
// rejects malformed, non-positive, and larger-than-ceiling values
// before any call reaches this struct, so a Limit < 1 here is a
// wiring error rather than a client error; the adapter defends
// against it by returning an internal error rather than reading
// unbounded.
type ListServiceLogsInput struct {
	OrganizationID string
	ServiceID      string
	Limit          int
}

// ServiceLogReader is the store-backed read adapter for the service
// logs surface: the persistence surface the httpapi layer needs to
// render GET /v1/services/{service_id}/logs. The current adapter is
// the placeholder shape — it performs the tenant-scoped service
// existence check inside a short-lived read-only transaction (Store.Read),
// so a cross-tenant or unknown service_id surfaces as a deterministic
// apierr.NotFound at the parent existence check, and returns an empty
// Lines slice for every service that exists in the principal's home
// tenant.
//
// The real log fetcher — a Dokploy-driven adapter that round-trips
// through the typed internal Dokploy client and surfaces lines from
// the running container — lands with the service provisioning worker
// stories (BE-0301+). Until then, the placeholder ensures the
// HTTP-layer authorization gate, the tenant boundary, and the wire
// contract (yalla.output.v1 envelope, stable JSON shape) are all
// production-grade — only the log content itself is a deterministic
// empty slice. This is the same shape noopJobEnqueuer carries for
// provisioning: the boundary is real, the placeholder side-effect is
// a no-op, and the customer-facing contract never disguises an
// "unfetched" line set as a tenant-isolation failure.
type ServiceLogReader struct {
	store    *Store
	services *ServiceRepository
}

// NewServiceLogReader builds a ServiceLogReader over store. It returns
// an error rather than panicking on a nil store so the caller (the
// API boot path) can surface the wiring mistake as a typed startup
// failure, mirroring NewServiceReader's contract.
func NewServiceLogReader(s *Store) (*ServiceLogReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &ServiceLogReader{
		store:    s,
		services: NewServiceRepository(),
	}, nil
}

// ListLogs returns the log lines for the service identified by
// (organizationID, serviceID), reading them inside a short-lived
// read-only transaction. The read is tenant-scoped at the SQL leg
// (the same existence check ServiceReader.GetService runs), so a
// cross-tenant or unknown service_id surfaces as a deterministic
// apierr.NotFound — never as another tenant's id echoed back, and
// never as an empty success that would mask a tenant-isolation
// failure. A live service in the principal's own tenant returns an
// empty Lines slice with the service id populated; the real Dokploy
// log fetcher lands in a later worker story.
//
// A datastore failure is propagated as its own typed error. A
// Limit < 1 is rejected as a typed internal error — the httpapi
// layer is responsible for clamping the caller-supplied value before
// it reaches the adapter, so reaching this branch with a non-positive
// limit is a wiring mistake.
func (r *ServiceLogReader) ListLogs(ctx context.Context, in ListServiceLogsInput) (ServiceLogs, error) {
	if in.Limit < 1 {
		return ServiceLogs{}, errors.New("store: ListServiceLogsInput.Limit must be positive")
	}
	var svcID string
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		svc, getErr := r.services.GetByID(ctx, q, in.OrganizationID, in.ServiceID)
		if getErr != nil {
			return getErr
		}
		svcID = svc.ID
		return nil
	})
	if err != nil {
		return ServiceLogs{}, err
	}
	return ServiceLogs{ServiceID: svcID, Lines: nil}, nil
}
