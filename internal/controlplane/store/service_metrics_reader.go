package store

import (
	"context"
	"errors"
	"time"
)

// ServiceMetricSample is one point in a service metric read response.
// The shape is the stable, source-of-truth-agnostic structural row
// that the httpapi service-metrics payload projects onto the wire
// as-is (modulo JSON tag naming) — no pointer-typed fields, no
// embedded interfaces, no Dokploy- or Traefik-specific identifiers.
// The httpapi-layer wire DTO depends on these field names being
// stable, so adding a new field is a strictly forward-compatible
// operation; renaming or removing one is a wire break.
//
// Name is the metric label this point came from. The closed set the
// httpapi-layer documents mirrors the usage-metric ladder
// (BE-0583..BE-0598) — http_requests, http_response_bytes,
// http_rps_peak_1m, latency_p95_ms, container_cpu_millicore_seconds,
// container_memory_mb_hours, and so on — a future Traefik- or
// Dokploy-fetcher adapter MUST keep producing values from a
// well-known set (or extend it explicitly) so an agent reading the
// payload can branch on the value without escape-decoding it. Value
// is the numeric sample as the source adapter emitted it; Unit is
// the unit of measure (count, byte, ms, millicore_seconds, mb_hours,
// gb_month, …) so an agent does not have to infer it from the name.
//
// The metrics surface is operational, not billing-grade: usage_counters
// and the billing reconciliation worker (BE-0569 / BE-0580) remain
// the authoritative source for invoiceable totals. The httpapi-layer
// payload is a customer-visible read-through of recently observed
// samples and never doubles as the billing oracle.
type ServiceMetricSample struct {
	Name       string
	OccurredAt time.Time
	Value      float64
	Unit       string
}

// ServiceMetrics is the typed response of ServiceMetricsReader.ListMetrics:
// the service id the samples belong to (echoed back so a caller can
// distinguish a multi-resource batch in a future metrics-stream
// endpoint even though today's GET addresses exactly one service) and
// the samples themselves in occurrence order (oldest first). An empty
// Samples slice with a populated ServiceID means the service exists,
// is owned by the tenant, and has no recorded samples available —
// never disguised as a NotFound.
type ServiceMetrics struct {
	ServiceID string
	Samples   []ServiceMetricSample
}

// ListServiceMetricsInput is the typed input shape
// ServiceMetricsReader.ListMetrics accepts. The shape is closed — no
// pointer-typed fields, no embedded interfaces — so a callsite that
// builds it cannot accidentally smuggle a caller-controlled
// organization id past the tenant boundary by nilling out a pointer.
// OrganizationID is always taken from the authenticated principal's
// home org at the httpapi layer (never from caller-controlled request
// input), and ServiceID is always taken from the path parameter;
// both surface here as plain strings so the tenant-scoped existence
// check that defends the boundary cannot be bypassed by a zero value.
//
// Limit clamps the number of samples returned. The httpapi layer
// rejects malformed, non-positive, and larger-than-ceiling values
// before any call reaches this struct, so a Limit < 1 here is a
// wiring error rather than a client error; the adapter defends
// against it by returning an internal error rather than reading
// unbounded.
type ListServiceMetricsInput struct {
	OrganizationID string
	ServiceID      string
	Limit          int
}

// ServiceMetricsReader is the store-backed read adapter for the
// service metrics surface: the persistence surface the httpapi layer
// needs to render GET /v1/services/{service_id}/metrics. The current
// adapter is the placeholder shape — it performs the tenant-scoped
// service existence check inside a short-lived read-only transaction
// (Store.Read), so a cross-tenant or unknown service_id surfaces as
// a deterministic apierr.NotFound at the parent existence check, and
// returns an empty Samples slice for every service that exists in
// the principal's home tenant.
//
// The real metrics source — a Traefik- or Dokploy-driven adapter
// that round-trips through the typed internal Dokploy client and
// surfaces samples attributed to the running service — lands with
// the metrics source adapter stories (BE-0571, BE-0573) and the
// usage_counters aggregation (BE-0569). Until then, the placeholder
// ensures the HTTP-layer authorization gate, the tenant boundary,
// and the wire contract (yalla.output.v1 envelope, stable JSON
// shape) are all production-grade — only the sample content itself
// is a deterministic empty slice. This is the same shape
// ServiceLogReader carries for logs and noopJobEnqueuer carries for
// provisioning: the boundary is real, the placeholder side-effect
// is a no-op, and the customer-facing contract never disguises an
// "unfetched" sample set as a tenant-isolation failure.
type ServiceMetricsReader struct {
	store    *Store
	services *ServiceRepository
}

// NewServiceMetricsReader builds a ServiceMetricsReader over store.
// It returns an error rather than panicking on a nil store so the
// caller (the API boot path) can surface the wiring mistake as a
// typed startup failure, mirroring NewServiceLogReader's contract.
func NewServiceMetricsReader(s *Store) (*ServiceMetricsReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &ServiceMetricsReader{
		store:    s,
		services: NewServiceRepository(),
	}, nil
}

// ListMetrics returns the metric samples for the service identified
// by (organizationID, serviceID), reading them inside a short-lived
// read-only transaction. The read is tenant-scoped at the SQL leg
// (the same existence check ServiceReader.GetService runs), so a
// cross-tenant or unknown service_id surfaces as a deterministic
// apierr.NotFound — never as another tenant's id echoed back, and
// never as an empty success that would mask a tenant-isolation
// failure. A live service in the principal's own tenant returns an
// empty Samples slice with the service id populated; the real
// metrics source lands in a later worker story.
//
// A datastore failure is propagated as its own typed error. A
// Limit < 1 is rejected as a typed internal error — the httpapi
// layer is responsible for clamping the caller-supplied value before
// it reaches the adapter, so reaching this branch with a non-positive
// limit is a wiring mistake.
func (r *ServiceMetricsReader) ListMetrics(ctx context.Context, in ListServiceMetricsInput) (ServiceMetrics, error) {
	if in.Limit < 1 {
		return ServiceMetrics{}, errors.New("store: ListServiceMetricsInput.Limit must be positive")
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
		return ServiceMetrics{}, err
	}
	return ServiceMetrics{ServiceID: svcID, Samples: nil}, nil
}
