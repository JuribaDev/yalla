package metering

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
)

// ContainerAttributionSource identifies how a container sample was mapped to a
// Yalla service.
type ContainerAttributionSource string

const (
	// ContainerAttributionSourceLabel means an explicit Yalla service label
	// carried the service id.
	ContainerAttributionSourceLabel ContainerAttributionSource = "container_label"
	// ContainerAttributionSourceName means the service id was recovered from a
	// deterministic container or pod name.
	ContainerAttributionSourceName ContainerAttributionSource = "container_name"
)

// ContainerAttributionConfidence records whether attribution came from an
// explicit label or name recovery.
type ContainerAttributionConfidence string

const (
	// ContainerAttributionConfidenceHigh is used for explicit Yalla labels.
	ContainerAttributionConfidenceHigh ContainerAttributionConfidence = "high"
	// ContainerAttributionConfidenceMedium is used for deterministic name
	// recovery.
	ContainerAttributionConfidenceMedium ContainerAttributionConfidence = "medium"
)

// ContainerQuarantineReason explains why a container source sample must not
// become billing-grade usage automatically.
type ContainerQuarantineReason string

const (
	// ContainerQuarantineMissingRef means the sample looked managed but had no
	// source-of-truth mapping.
	ContainerQuarantineMissingRef ContainerQuarantineReason = "missing_ref"
	// ContainerQuarantineDeletedService means the mapped Yalla service is
	// terminally deleted.
	ContainerQuarantineDeletedService ContainerQuarantineReason = "deleted_service"
	// ContainerQuarantineUnmanagedResource means no Yalla identifier could be
	// recovered from the sample.
	ContainerQuarantineUnmanagedResource ContainerQuarantineReason = "unmanaged_resource"
)

var (
	// ErrContainerAttributionNotFound means a sample looked like a
	// Yalla-managed service but no live mapping resolved it.
	ErrContainerAttributionNotFound = errors.New("metering: container attribution mapping not found")
	// ErrContainerUnmanagedResource means a sample does not carry a Yalla label
	// or deterministic service id and should be quarantined as unmanaged.
	ErrContainerUnmanagedResource = errors.New("metering: container sample is not a managed Yalla resource")
)

// ContainerResolveInput is the stable lookup contract between attribution
// logic and a store-backed service resolver.
type ContainerResolveInput struct {
	ServiceID   string
	ContainerID string
	Labels      map[string]string
}

// ContainerResourceAttribution is the tenant/resource scope resolved for one
// container sample.
type ContainerResourceAttribution struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	Source         ContainerAttributionSource
	Confidence     ContainerAttributionConfidence
	Deleted        bool
}

// ContainerServiceResolver resolves extracted service identifiers to Yalla
// source-of-truth resources.
type ContainerServiceResolver interface {
	ResolveContainerService(context.Context, ContainerResolveInput) (ContainerResourceAttribution, error)
}

// ContainerAttributionInput groups source samples collected over a bounded
// window.
type ContainerAttributionInput struct {
	Samples []ContainerMetricSample
}

// QuarantinedContainerSample is intentionally not billable until reviewed or a
// later attribution replay can resolve it.
type QuarantinedContainerSample struct {
	Sample ContainerMetricSample
	Reason ContainerQuarantineReason
}

// ContainerAttributionResult splits samples into billable and quarantined sets.
type ContainerAttributionResult struct {
	Attributed  []AttributedContainerSample
	Quarantined []QuarantinedContainerSample
}

// ContainerAttributor maps normalized source samples to Yalla tenant resources.
type ContainerAttributor struct {
	resolver ContainerServiceResolver
}

// NewContainerAttributor builds a container attribution layer over resolver.
func NewContainerAttributor(resolver ContainerServiceResolver) *ContainerAttributor {
	return &ContainerAttributor{resolver: resolver}
}

// Attribute resolves each sample independently. Unknown, deleted, and
// unmanaged samples are quarantined and never silently billed.
func (a *ContainerAttributor) Attribute(ctx context.Context, in ContainerAttributionInput) (ContainerAttributionResult, error) {
	if a == nil || a.resolver == nil {
		return ContainerAttributionResult{}, errors.New("metering: nil ContainerServiceResolver")
	}
	result := ContainerAttributionResult{
		Attributed:  []AttributedContainerSample{},
		Quarantined: []QuarantinedContainerSample{},
	}
	for _, sample := range in.Samples {
		candidate := containerServiceCandidate(sample)
		if candidate.serviceID == "" {
			result.Quarantined = append(result.Quarantined, QuarantinedContainerSample{Sample: sample, Reason: ContainerQuarantineUnmanagedResource})
			continue
		}
		attr, err := a.resolver.ResolveContainerService(ctx, ContainerResolveInput{
			ServiceID:   candidate.serviceID,
			ContainerID: sample.ContainerID,
			Labels:      copyStringMap(sample.Labels),
		})
		if errors.Is(err, ErrContainerUnmanagedResource) {
			result.Quarantined = append(result.Quarantined, QuarantinedContainerSample{Sample: sample, Reason: ContainerQuarantineUnmanagedResource})
			continue
		}
		if errors.Is(err, ErrContainerAttributionNotFound) {
			result.Quarantined = append(result.Quarantined, QuarantinedContainerSample{Sample: sample, Reason: ContainerQuarantineMissingRef})
			continue
		}
		if err != nil {
			return ContainerAttributionResult{}, err
		}
		if attr.Deleted {
			result.Quarantined = append(result.Quarantined, QuarantinedContainerSample{Sample: sample, Reason: ContainerQuarantineDeletedService})
			continue
		}
		if attr.Source == "" {
			attr.Source = candidate.source
		}
		if attr.Confidence == "" {
			attr.Confidence = candidate.confidence
		}
		result.Attributed = append(result.Attributed, AttributedContainerSample{
			ContainerMetricSample: sample,
			OrganizationID:        attr.OrganizationID,
			ProjectID:             attr.ProjectID,
			EnvironmentID:         attr.EnvironmentID,
			ServiceID:             attr.ServiceID,
			Metadata:              containerAttributionMetadata(attr),
		})
	}
	return result, nil
}

type containerCandidate struct {
	serviceID  string
	source     ContainerAttributionSource
	confidence ContainerAttributionConfidence
}

var containerServiceIDPattern = regexp.MustCompile(`\bsvc[_-][A-Za-z0-9][A-Za-z0-9_-]*`)

func containerServiceCandidate(sample ContainerMetricSample) containerCandidate {
	for _, key := range []string{"yalla_service_id", "yalla.service.id", "service_id", "com.yalla.service_id", "io.yalla.service_id"} {
		if value := strings.TrimSpace(sample.Labels[key]); value != "" {
			return containerCandidate{
				serviceID:  normalizeServiceID(value),
				source:     ContainerAttributionSourceLabel,
				confidence: ContainerAttributionConfidenceHigh,
			}
		}
	}
	for _, value := range containerNameCandidates(sample) {
		if serviceID := recoverContainerServiceID(value); serviceID != "" {
			return containerCandidate{
				serviceID:  serviceID,
				source:     ContainerAttributionSourceName,
				confidence: ContainerAttributionConfidenceMedium,
			}
		}
	}
	return containerCandidate{}
}

func containerNameCandidates(sample ContainerMetricSample) []string {
	values := []string{sample.ContainerID}
	keys := make([]string, 0, len(sample.Labels))
	for key := range sample.Labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch strings.ToLower(key) {
		case "container", "container_name", "pod", "pod_name", "name", "app", "appname", "com.dokploy.appname":
			values = append(values, sample.Labels[key])
		}
	}
	return values
}

func recoverContainerServiceID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	match := containerServiceIDPattern.FindString(value)
	return normalizeServiceID(match)
}

func containerAttributionMetadata(attr ContainerResourceAttribution) map[string]string {
	metadata := map[string]string{
		"attribution_source":     string(attr.Source),
		"attribution_confidence": string(attr.Confidence),
	}
	return metadata
}
