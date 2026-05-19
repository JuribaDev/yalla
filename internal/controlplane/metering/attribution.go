package metering

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
)

// TraefikAttributionSource identifies how a Traefik sample was mapped to a
// Yalla service. The values are persisted into usage-event metadata by later
// ingestion layers, so keep them stable.
type TraefikAttributionSource string

const (
	// TraefikAttributionSourceLabel means an explicit Yalla service label
	// carried the service id.
	TraefikAttributionSourceLabel TraefikAttributionSource = "traefik_label"
	// TraefikAttributionSourceName means the service id was recovered from a
	// deterministic Dokploy or Traefik service name.
	TraefikAttributionSourceName TraefikAttributionSource = "dokploy_name"
)

// TraefikAttributionConfidence records whether the mapping came from an
// explicit Yalla label or a recovered deterministic service name.
type TraefikAttributionConfidence string

const (
	// TraefikAttributionConfidenceHigh is used for explicit Yalla labels.
	TraefikAttributionConfidenceHigh TraefikAttributionConfidence = "high"
	// TraefikAttributionConfidenceMedium is used for deterministic name
	// recovery.
	TraefikAttributionConfidenceMedium TraefikAttributionConfidence = "medium"
)

// TraefikQuarantineReason explains why a source sample must not become a
// billing-grade usage event automatically.
type TraefikQuarantineReason string

const (
	// TraefikQuarantineMissingRef means the sample looked managed but had no
	// source-of-truth Dokploy mapping.
	TraefikQuarantineMissingRef TraefikQuarantineReason = "missing_ref"
	// TraefikQuarantineDeletedService means the mapped Yalla service is
	// terminally deleted.
	TraefikQuarantineDeletedService TraefikQuarantineReason = "deleted_service"
	// TraefikQuarantineUnmanagedResource means no Yalla identifier could be
	// recovered from the sample.
	TraefikQuarantineUnmanagedResource TraefikQuarantineReason = "unmanaged_resource"
)

var (
	// ErrTraefikAttributionNotFound means a sample looked like a Yalla-managed
	// service but no live dokploy_refs/services mapping resolved it.
	ErrTraefikAttributionNotFound = errors.New("metering: traefik attribution mapping not found")
	// ErrTraefikUnmanagedResource means a sample does not carry a Yalla label
	// or deterministic service id and should be quarantined as unmanaged.
	ErrTraefikUnmanagedResource = errors.New("metering: traefik sample is not a managed Yalla resource")
)

// TraefikResolveInput is the stable lookup contract between attribution logic
// and the store-backed dokploy_refs resolver.
type TraefikResolveInput struct {
	ServiceID string
	Service   string
	Labels    map[string]string
}

// TraefikResourceAttribution is the tenant/resource scope resolved for one
// Traefik service sample.
type TraefikResourceAttribution struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	Source         TraefikAttributionSource
	Confidence     TraefikAttributionConfidence
	Deleted        bool
}

// TraefikServiceResolver resolves extracted Traefik service identifiers to
// Yalla source-of-truth resources.
type TraefikServiceResolver interface {
	ResolveTraefikService(context.Context, TraefikResolveInput) (TraefikResourceAttribution, error)
}

// TraefikAttributionInput groups source samples collected over a bounded
// window.
type TraefikAttributionInput struct {
	Samples []TraefikMetricSample
}

// AttributedTraefikSample is safe to convert into a usage event: it carries
// the complete tenant scope and the original normalized source sample.
type AttributedTraefikSample struct {
	TraefikMetricSample
	OrganizationID    string
	ProjectID         string
	EnvironmentID     string
	ServiceID         string
	AttributionSource TraefikAttributionSource
	Confidence        TraefikAttributionConfidence
	Metadata          map[string]string
}

// QuarantinedTraefikSample is intentionally not billable until reviewed or a
// later attribution replay can resolve it.
type QuarantinedTraefikSample struct {
	Sample TraefikMetricSample
	Reason TraefikQuarantineReason
}

// TraefikAttributionResult splits samples into billable and quarantined sets.
type TraefikAttributionResult struct {
	Attributed  []AttributedTraefikSample
	Quarantined []QuarantinedTraefikSample
}

// TraefikAttributor maps normalized source samples to Yalla tenant resources.
type TraefikAttributor struct {
	resolver TraefikServiceResolver
}

// NewTraefikAttributor builds a Traefik attribution layer over resolver.
func NewTraefikAttributor(resolver TraefikServiceResolver) *TraefikAttributor {
	return &TraefikAttributor{resolver: resolver}
}

// Attribute resolves each sample independently. Unknown, deleted, and
// unmanaged samples are quarantined and never silently dropped or billed.
func (a *TraefikAttributor) Attribute(ctx context.Context, in TraefikAttributionInput) (TraefikAttributionResult, error) {
	if a == nil || a.resolver == nil {
		return TraefikAttributionResult{}, errors.New("metering: nil TraefikServiceResolver")
	}
	result := TraefikAttributionResult{
		Attributed:  []AttributedTraefikSample{},
		Quarantined: []QuarantinedTraefikSample{},
	}
	for _, sample := range in.Samples {
		candidate := traefikServiceCandidate(sample)
		if candidate.serviceID == "" {
			result.Quarantined = append(result.Quarantined, QuarantinedTraefikSample{
				Sample: sample,
				Reason: TraefikQuarantineUnmanagedResource,
			})
			continue
		}
		attr, err := a.resolver.ResolveTraefikService(ctx, TraefikResolveInput{
			ServiceID: candidate.serviceID,
			Service:   sample.Service,
			Labels:    copyStringMap(sample.Labels),
		})
		if errors.Is(err, ErrTraefikUnmanagedResource) {
			result.Quarantined = append(result.Quarantined, QuarantinedTraefikSample{Sample: sample, Reason: TraefikQuarantineUnmanagedResource})
			continue
		}
		if errors.Is(err, ErrTraefikAttributionNotFound) {
			result.Quarantined = append(result.Quarantined, QuarantinedTraefikSample{Sample: sample, Reason: TraefikQuarantineMissingRef})
			continue
		}
		if err != nil {
			return TraefikAttributionResult{}, err
		}
		if attr.Deleted {
			result.Quarantined = append(result.Quarantined, QuarantinedTraefikSample{Sample: sample, Reason: TraefikQuarantineDeletedService})
			continue
		}
		if attr.Source == "" {
			attr.Source = candidate.source
		}
		if attr.Confidence == "" {
			attr.Confidence = candidate.confidence
		}
		result.Attributed = append(result.Attributed, AttributedTraefikSample{
			TraefikMetricSample: sample,
			OrganizationID:      attr.OrganizationID,
			ProjectID:           attr.ProjectID,
			EnvironmentID:       attr.EnvironmentID,
			ServiceID:           attr.ServiceID,
			AttributionSource:   attr.Source,
			Confidence:          attr.Confidence,
			Metadata:            traefikAttributionMetadata(sample, attr),
		})
	}
	return result, nil
}

type traefikCandidate struct {
	serviceID  string
	source     TraefikAttributionSource
	confidence TraefikAttributionConfidence
}

var traefikServiceIDPattern = regexp.MustCompile(`\bsvc[_-][A-Za-z0-9][A-Za-z0-9_-]*`)

func traefikServiceCandidate(sample TraefikMetricSample) traefikCandidate {
	for _, key := range []string{"yalla_service_id", "yalla.service.id", "service_id", "com.yalla.service_id"} {
		if value := strings.TrimSpace(sample.Labels[key]); value != "" {
			return traefikCandidate{
				serviceID:  normalizeServiceID(value),
				source:     TraefikAttributionSourceLabel,
				confidence: TraefikAttributionConfidenceHigh,
			}
		}
	}
	for _, value := range traefikNameCandidates(sample) {
		if serviceID := recoverServiceID(value); serviceID != "" {
			return traefikCandidate{
				serviceID:  serviceID,
				source:     TraefikAttributionSourceName,
				confidence: TraefikAttributionConfidenceMedium,
			}
		}
	}
	return traefikCandidate{}
}

func traefikNameCandidates(sample TraefikMetricSample) []string {
	values := []string{sample.Service}
	keys := make([]string, 0, len(sample.Labels))
	for key := range sample.Labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch strings.ToLower(key) {
		case "appname", "app_name", "service", "service_name", "traefik_service", "container_name", "com.dokploy.appname":
			values = append(values, sample.Labels[key])
		}
	}
	return values
}

func recoverServiceID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	match := traefikServiceIDPattern.FindString(value)
	if match == "" {
		return ""
	}
	return normalizeServiceID(match)
}

func normalizeServiceID(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "svc-") {
		return "svc_" + strings.TrimPrefix(value, "svc-")
	}
	return value
}

func traefikAttributionMetadata(sample TraefikMetricSample, attr TraefikResourceAttribution) map[string]string {
	out := map[string]string{
		"attribution_source":     string(attr.Source),
		"attribution_confidence": string(attr.Confidence),
		"traefik_service":        sample.Service,
	}
	if sample.QueryVersion != "" {
		out["query_version"] = sample.QueryVersion
	}
	if sample.RawSampleChecksum != "" {
		out["raw_sample_checksum"] = sample.RawSampleChecksum
	}
	if sample.Status != "" {
		out["status"] = sample.Status
	}
	if sample.Bucket != "" {
		out["bucket"] = sample.Bucket
	}
	return out
}
