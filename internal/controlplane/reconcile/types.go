package reconcile

import (
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// DriftKind classifies a divergence between desired and actual state.
//
// The set is closed: a planner action is exactly one of these three kinds,
// and Repairer-vs-Reviewer-vs-Unmanaged dispatch hinges on the kind alone.
type DriftKind string

const (
	// DriftSafe drift can be auto-repaired: converging actual back to desired
	// is reversible and cannot cause data loss.
	DriftSafe DriftKind = "safe"
	// DriftDangerous drift cannot be auto-repaired without potential data
	// loss or hiding a compromise. The engine records a ReviewEvent instead.
	DriftDangerous DriftKind = "dangerous"
	// DriftUnmanaged classifies a Dokploy resource that has no Yalla
	// counterpart. The engine records it via UnmanagedRecorder and never
	// exposes it to customers by default.
	DriftUnmanaged DriftKind = "unmanaged"
)

// Valid reports whether k is one of the recognised drift kinds.
func (k DriftKind) Valid() bool {
	switch k {
	case DriftSafe, DriftDangerous, DriftUnmanaged:
		return true
	default:
		return false
	}
}

// ActionType names the operation a single Plan action represents.
type ActionType string

const (
	// ActionUpdateEnvVar repairs a divergent env var on a managed service.
	ActionUpdateEnvVar ActionType = "update_env_var"
	// ActionEnsureDomain re-binds a managed domain whose host matches desired
	// but is missing from actual state.
	ActionEnsureDomain ActionType = "ensure_domain"
	// ActionRemoveExtraEnvVar removes an unmanaged env var from a managed
	// service: the key isn't in desired and is therefore drift.
	ActionRemoveExtraEnvVar ActionType = "remove_extra_env_var"
	// ActionUpdateBuildConfig repairs a managed service whose Dokploy build
	// settings drifted from Yalla's desired state.
	ActionUpdateBuildConfig ActionType = "update_build_config"
	// ActionReviewMissingService records that a managed service has vanished
	// from Dokploy.
	ActionReviewMissingService ActionType = "review_missing_service"
	// ActionReviewMissingDatabase records that a managed database service has
	// vanished from Dokploy.
	ActionReviewMissingDatabase ActionType = "review_missing_database"
	// ActionReviewRenamedDomain records that a known domain's host on Dokploy
	// no longer matches desired.
	ActionReviewRenamedDomain ActionType = "review_renamed_domain"
	// ActionReviewServiceTypeChange records that a managed service's type has
	// changed on Dokploy.
	ActionReviewServiceTypeChange ActionType = "review_service_type_change"
	// ActionMarkUnmanaged records a Dokploy resource without a Yalla
	// counterpart.
	ActionMarkUnmanaged ActionType = "mark_unmanaged"
)

// DriftReason is the stable, value-free classification a planner emits for an
// Action, a ReviewEvent, or an UnmanagedResource. Reasons name *what* was
// detected (matching the test-case vocabulary) and never the input value, so
// secrets can be carried through diffs/logs/audits safely.
type DriftReason string

const (
	// ReasonEnvVarChanged is emitted when a desired env var's value differs
	// from the actual value on Dokploy. Never carries the value itself.
	ReasonEnvVarChanged DriftReason = "env_var_changed"
	// ReasonEnvVarMissing is emitted when a desired env var is absent on
	// Dokploy.
	ReasonEnvVarMissing DriftReason = "env_var_missing"
	// ReasonEnvVarExtra is emitted when Dokploy carries an env var the
	// desired state does not.
	ReasonEnvVarExtra DriftReason = "env_var_extra"
	// ReasonBuildConfigChanged is emitted when a managed service's build
	// settings differ from source of truth. Never carries the branch,
	// commit, image, artifact URL, or path itself.
	ReasonBuildConfigChanged DriftReason = "build_config_changed"
	// ReasonDomainMissing is emitted when a desired domain is absent on
	// Dokploy.
	ReasonDomainMissing DriftReason = "domain_missing"
	// ReasonDomainRenamed is emitted when a known domain ID exists on Dokploy
	// but its host no longer matches desired.
	ReasonDomainRenamed DriftReason = "domain_renamed"
	// ReasonServiceMissing is emitted when a managed application/compose
	// service is absent on Dokploy.
	ReasonServiceMissing DriftReason = "service_missing"
	// ReasonDatabaseMissing is emitted when a managed database service is
	// absent on Dokploy.
	ReasonDatabaseMissing DriftReason = "database_missing"
	// ReasonServiceTypeChanged is emitted when a known service's type
	// differs between desired and actual.
	ReasonServiceTypeChanged DriftReason = "service_type_changed"
	// ReasonResourceUnmanaged is emitted for a Dokploy resource that has no
	// Yalla counterpart.
	ReasonResourceUnmanaged DriftReason = "resource_unmanaged"
)

// ResourceLevel names which level of the hierarchy a drift refers to. It is
// used by unmanaged-resource records and by review events so an operator can
// page through review queues at the right depth.
type ResourceLevel string

// The canonical resource levels. Every UnmanagedResource and ReviewEvent
// names exactly one of these so triage queues can page by hierarchy depth.
const (
	LevelOrganization ResourceLevel = "organization"
	LevelProject      ResourceLevel = "project"
	LevelEnvironment  ResourceLevel = "environment"
	LevelService      ResourceLevel = "service"
	LevelDomain       ResourceLevel = "domain"
)

// ServiceRef locates a service in both the Yalla and Dokploy hierarchies. It
// is the minimum identification a Repairer or ReviewRecorder needs to act on
// the right resource.
type ServiceRef struct {
	OrganizationID domain.ID
	ProjectID      domain.ID
	EnvironmentID  domain.ID
	ServiceID      domain.ID
	// DokployServiceID is the resolved Dokploy service ID. Empty when the
	// service has never been provisioned.
	DokployServiceID string
}

// DomainRef locates a managed domain.
type DomainRef struct {
	Service  ServiceRef
	DomainID domain.ID
	// DokployDomainID is the resolved Dokploy domain ID. Empty when the
	// domain has never been provisioned.
	DokployDomainID string
}

// DesiredEnvVar is the source-of-truth env var the engine compares against
// actual state. Secret reports whether the value is sensitive; the engine
// treats secret and non-secret values identically for diff purposes, but
// downstream Repairer adapters can route secrets through their secret store.
type DesiredEnvVar struct {
	Key    string
	Value  string
	Secret bool
}

// DesiredDomain is the source-of-truth domain entry.
type DesiredDomain struct {
	ID    domain.ID
	Host  string
	HTTPS bool
	// DokployID is the recorded Dokploy domain ID, or empty when the domain
	// has never been provisioned.
	DokployID string
}

// DesiredService is the source-of-truth shape for one managed service.
type DesiredService struct {
	ID    domain.ID
	Label string
	Type  dokploy.ServiceType
	// Build is the source-of-truth build configuration for application and
	// compose services. It is ignored for database services.
	Build dokploy.BuildSettings
	// Engine is the database engine; required when Type is ServiceDatabase
	// and ignored otherwise.
	Engine string
	// DokployID is the recorded Dokploy service ID, or empty when not yet
	// provisioned. A service whose DokployID is empty is treated as
	// not-yet-provisioned, not as drift.
	DokployID string
	EnvVars   []DesiredEnvVar
	Domains   []DesiredDomain
}

// DesiredEnvironment is the source-of-truth shape for one environment under a
// project.
type DesiredEnvironment struct {
	ID        domain.ID
	Label     string
	DokployID string
	Services  []DesiredService
}

// DesiredProject is the source-of-truth shape for one project under an
// organization.
type DesiredProject struct {
	ID           domain.ID
	Label        string
	DokployID    string
	Environments []DesiredEnvironment
}

// DesiredOrganization is the full source-of-truth view of an organization.
type DesiredOrganization struct {
	ID    domain.ID
	Label string
	// DokployID is the Dokploy organization the tenant provisions into.
	// In shared mode this is the shared internal org ID; in dedicated mode it
	// is the recorded org ID for the tenant. Empty when the organization has
	// never been provisioned.
	DokployID string
	Projects  []DesiredProject
}

// ActualEnvVar is one env var read from Dokploy. Value is included so the
// engine can detect changed values; downstream callers must never log or
// audit it directly.
type ActualEnvVar struct {
	Key   string
	Value string
}

// ActualDomain is one domain read from Dokploy.
type ActualDomain struct {
	DokployID string
	Host      string
	HTTPS     bool
}

// ActualService is one service read from Dokploy.
type ActualService struct {
	DokployID string
	Name      string
	Type      dokploy.ServiceType
	Build     dokploy.BuildSettings
	Engine    string
	EnvVars   []ActualEnvVar
	Domains   []ActualDomain
}

// ActualEnvironment is one environment read from Dokploy.
type ActualEnvironment struct {
	DokployID string
	Name      string
	Services  []ActualService
}

// ActualProject is one project read from Dokploy.
type ActualProject struct {
	DokployID    string
	Name         string
	Environments []ActualEnvironment
}

// ActualOrganization is the full actual-state view of an organization,
// limited to the Dokploy organization the tenant provisions into.
type ActualOrganization struct {
	DokployID string
	Projects  []ActualProject
}

// UnmanagedResource records a Dokploy resource that has no Yalla counterpart.
// It is the payload the engine hands to UnmanagedRecorder.
type UnmanagedResource struct {
	OrganizationID    domain.ID
	Level             ResourceLevel
	DokployResourceID string
	// ParentDokployID, when set, locates the unmanaged resource inside the
	// hierarchy without exposing it to a customer (a project ID is the
	// parent of an environment, and so on).
	ParentDokployID string
	// Type is the service kind for service-level unmanaged resources; empty
	// at higher levels.
	Type dokploy.ServiceType
	// Reason is always ReasonResourceUnmanaged for unmanaged records but is
	// included for symmetry with ReviewEvent.
	Reason DriftReason
}

// ReviewEvent records dangerous drift the engine refuses to auto-repair. The
// payload is the minimum context a human operator needs to triage the drift,
// and never contains a value or other secret-shaped data.
type ReviewEvent struct {
	OrganizationID domain.ID
	Level          ResourceLevel
	Reason         DriftReason
	Service        ServiceRef
	// Domain is set for domain-level review events.
	Domain DomainRef
	// EnvVarKey is set for env-var-level review events; it is a key, never a
	// value.
	EnvVarKey string
}

// trimmedID returns id with surrounding whitespace removed.
func trimmedID(id domain.ID) domain.ID { return domain.ID(strings.TrimSpace(string(id))) }
