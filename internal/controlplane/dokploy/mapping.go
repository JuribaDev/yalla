package dokploy

import (
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// The Yalla* types below are the source-of-truth hierarchy shapes the Mapper
// consumes. They are intentionally minimal projections of the persistence-layer
// records: the Mapper needs only the canonical Yalla ID, the human label that
// seeds a deterministic Dokploy name, the parent linkage, and the
// already-recorded Dokploy ID (empty until the resource has been provisioned
// once). Threading the recorded Dokploy ID through is what makes every produced
// intent idempotent against Yalla's source of truth.

// YallaOrganization is the source-of-truth shape for a Yalla organization — the
// tenant root of the hierarchy.
type YallaOrganization struct {
	// ID is the canonical Yalla organization ID (org_...). Required.
	ID domain.ID
	// Label is the human-authored organization name; it seeds the deterministic
	// Dokploy resource name. A blank or unusable label falls back to the
	// resource kind, so a valid ID always yields a name.
	Label string
	// DokployID is the Dokploy organization ID already recorded for this
	// organization, or empty when it has not been provisioned yet. When set,
	// the produced intent fetches and verifies rather than creates.
	DokployID string
}

// YallaProject is the source-of-truth shape for a Yalla project within an
// organization.
type YallaProject struct {
	// ID is the canonical Yalla project ID (proj_...). Required.
	ID domain.ID
	// OrganizationID is the canonical Yalla ID of the owning organization
	// (org_...). Required; it asserts the parent linkage is well formed.
	OrganizationID domain.ID
	// Label seeds the deterministic Dokploy resource name.
	Label string
	// DokployID is the recorded Dokploy project ID, or empty when not yet
	// provisioned.
	DokployID string
}

// YallaEnvironment is the source-of-truth shape for a Yalla environment within
// a project.
type YallaEnvironment struct {
	// ID is the canonical Yalla environment ID (env_...). Required.
	ID domain.ID
	// ProjectID is the canonical Yalla ID of the owning project (proj_...).
	// Required; it asserts the parent linkage is well formed.
	ProjectID domain.ID
	// Label seeds the deterministic Dokploy resource name.
	Label string
	// DokployID is the recorded Dokploy environment ID, or empty when not yet
	// provisioned.
	DokployID string
}

// YallaService is the source-of-truth shape for a Yalla service within an
// environment.
type YallaService struct {
	// ID is the canonical Yalla service ID (svc_...). Required.
	ID domain.ID
	// EnvironmentID is the canonical Yalla ID of the owning environment
	// (env_...). Required; it asserts the parent linkage is well formed.
	EnvironmentID domain.ID
	// Label seeds the deterministic Dokploy resource name.
	Label string
	// Type selects which kind of Dokploy resource backs the service: a
	// long-running application, a Docker Compose stack, or a managed database.
	// Required.
	Type ServiceType
	// Engine is the database engine (for example "postgres"); required when
	// Type is ServiceDatabase and ignored otherwise.
	Engine string
	// DokployID is the recorded Dokploy service ID, or empty when not yet
	// provisioned.
	DokployID string
}

// Mapper translates Yalla's source-of-truth hierarchy
// (organization -> project -> environment -> service) into the Dokploy
// provisioning intents that the typed Client consumes. It mirrors Dokploy's own
// model: a Yalla organization maps to a Dokploy organization, a project to a
// Dokploy project, an environment to a Dokploy environment, and a service to a
// Dokploy application, compose stack, or database.
//
// The Mapper is pure: it performs no I/O, holds no Dokploy credentials, and is
// safe for concurrent use. It validates every input locally — a malformed Yalla
// ID, a broken parent linkage, or an invalid service type is reported as a
// typed apierr.InvalidInput with stable field paths and never echoes the
// submitted value.
//
// Provisioning is inherently top-down: a child intent needs its parent's
// Dokploy ID, which is only known after the parent has been ensured. The
// per-level methods therefore take the parent's resolved Dokploy ID explicitly,
// so the worker ensures each level, records the returned Dokploy ID, and feeds
// it into the next level.
//
// Construct a Mapper with NewMapper.
type Mapper struct {
	sharedOrganizationID string
}

// MapperOption configures a Mapper.
type MapperOption func(*Mapper)

// WithSharedOrganization configures the Mapper to map every Yalla organization
// into one shared internal Dokploy organization rather than a dedicated Dokploy
// organization per tenant. This is the fallback for Dokploy deployments that do
// not support multi-organization isolation; Yalla's own policy engine remains
// authoritative for tenant isolation in that mode. A blank id is ignored.
func WithSharedOrganization(dokployOrganizationID string) MapperOption {
	return func(m *Mapper) {
		m.sharedOrganizationID = strings.TrimSpace(dokployOrganizationID)
	}
}

// NewMapper returns a Mapper. With no options it maps each Yalla organization to
// a dedicated Dokploy organization; pass WithSharedOrganization to use a single
// shared Dokploy organization instead.
func NewMapper(opts ...MapperOption) *Mapper {
	m := &Mapper{}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// SharesOrganization reports whether the Mapper maps every tenant into one
// shared internal Dokploy organization.
func (m *Mapper) SharesOrganization() bool { return m.sharedOrganizationID != "" }

// OrganizationTarget is the result of mapping a Yalla organization: it resolves
// which Dokploy organization the tenant provisions into.
type OrganizationTarget struct {
	// Shared reports whether the tenant uses the shared internal Dokploy
	// organization (WithSharedOrganization) rather than a dedicated one.
	Shared bool
	// DokployID is the Dokploy organization ID when it is already known: the
	// configured shared organization in shared mode, or the previously-recorded
	// dedicated organization ID. It is empty in dedicated mode when the Dokploy
	// organization has not been provisioned yet — the worker learns it by
	// running EnsureInput and then feeds it into Mapper.Project.
	DokployID string
	// EnsureInput is the intent that makes the dedicated Dokploy organization
	// exist. It is nil in shared mode, where there is no per-tenant Dokploy
	// organization to ensure.
	EnsureInput *EnsureOrganizationInput
}

// Organization maps a Yalla organization to its Dokploy organization target. In
// dedicated mode it returns an EnsureOrganizationInput carrying a deterministic
// Dokploy name (and the recorded Dokploy ID as ExistingID, so the intent is
// idempotent). In shared mode it resolves directly to the configured shared
// Dokploy organization ID and EnsureInput is nil.
func (m *Mapper) Organization(org YallaOrganization) (OrganizationTarget, error) {
	var violations []apierr.FieldViolation
	validYallaID(&violations, "organization.id", org.ID, domain.KindOrganization)
	if len(violations) > 0 {
		return OrganizationTarget{}, apierr.InvalidInput(violations...)
	}
	if m.sharedOrganizationID != "" {
		return OrganizationTarget{Shared: true, DokployID: m.sharedOrganizationID}, nil
	}
	name, err := domain.DokployName(org.Label, org.ID)
	if err != nil {
		// org.ID has already passed ParseID, so DokployName cannot fail on its
		// account — this is a defensive contract assertion, not a user error.
		return OrganizationTarget{}, apierr.Internal(err)
	}
	existing := strings.TrimSpace(org.DokployID)
	return OrganizationTarget{
		DokployID: existing,
		EnsureInput: &EnsureOrganizationInput{
			ExistingID: existing,
			Name:       name,
		},
	}, nil
}

// Project maps a Yalla project to the Dokploy project intent. dokployOrganizationID
// is the resolved Dokploy organization ID of the parent (OrganizationTarget.DokployID
// in shared mode, or the ID recorded after running OrganizationTarget.EnsureInput).
func (m *Mapper) Project(dokployOrganizationID string, proj YallaProject) (EnsureProjectInput, error) {
	var violations []apierr.FieldViolation
	requireDokployParent(&violations, "dokploy_organization_id", dokployOrganizationID)
	validYallaID(&violations, "project.id", proj.ID, domain.KindProject)
	validYallaID(&violations, "project.organization_id", proj.OrganizationID, domain.KindOrganization)
	if len(violations) > 0 {
		return EnsureProjectInput{}, apierr.InvalidInput(violations...)
	}
	name, err := domain.DokployName(proj.Label, proj.ID)
	if err != nil {
		return EnsureProjectInput{}, apierr.Internal(err)
	}
	return EnsureProjectInput{
		ExistingID:     strings.TrimSpace(proj.DokployID),
		OrganizationID: strings.TrimSpace(dokployOrganizationID),
		Name:           name,
	}, nil
}

// Environment maps a Yalla environment to the Dokploy environment intent.
// dokployProjectID is the resolved Dokploy project ID of the parent (the ID
// recorded after running the parent project's EnsureProjectInput).
func (m *Mapper) Environment(dokployProjectID string, env YallaEnvironment) (EnsureEnvironmentInput, error) {
	var violations []apierr.FieldViolation
	requireDokployParent(&violations, "dokploy_project_id", dokployProjectID)
	validYallaID(&violations, "environment.id", env.ID, domain.KindEnvironment)
	validYallaID(&violations, "environment.project_id", env.ProjectID, domain.KindProject)
	if len(violations) > 0 {
		return EnsureEnvironmentInput{}, apierr.InvalidInput(violations...)
	}
	name, err := domain.DokployName(env.Label, env.ID)
	if err != nil {
		return EnsureEnvironmentInput{}, apierr.Internal(err)
	}
	return EnsureEnvironmentInput{
		ExistingID: strings.TrimSpace(env.DokployID),
		ProjectID:  strings.TrimSpace(dokployProjectID),
		Name:       name,
	}, nil
}

// Service maps a Yalla service to the Dokploy service intent, routing by
// Type to a Dokploy application, compose stack, or database. dokployEnvironmentID
// is the resolved Dokploy environment ID of the parent. A database service must
// carry an Engine; the engine is dropped for non-database services.
func (m *Mapper) Service(dokployEnvironmentID string, svc YallaService) (EnsureServiceInput, error) {
	var violations []apierr.FieldViolation
	requireDokployParent(&violations, "dokploy_environment_id", dokployEnvironmentID)
	validYallaID(&violations, "service.id", svc.ID, domain.KindService)
	validYallaID(&violations, "service.environment_id", svc.EnvironmentID, domain.KindEnvironment)
	if !svc.Type.Valid() {
		violations = append(violations, apierr.FieldViolation{
			Field:  "service.type",
			Reason: "must be application, compose, or database",
		})
	}
	engine := strings.TrimSpace(svc.Engine)
	if svc.Type == ServiceDatabase && engine == "" {
		violations = append(violations, apierr.FieldViolation{
			Field:  "service.engine",
			Reason: "required for database services",
		})
	}
	if len(violations) > 0 {
		return EnsureServiceInput{}, apierr.InvalidInput(violations...)
	}
	name, err := domain.DokployName(svc.Label, svc.ID)
	if err != nil {
		return EnsureServiceInput{}, apierr.Internal(err)
	}
	in := EnsureServiceInput{
		ExistingID:    strings.TrimSpace(svc.DokployID),
		EnvironmentID: strings.TrimSpace(dokployEnvironmentID),
		Name:          name,
		Type:          svc.Type,
	}
	if svc.Type == ServiceDatabase {
		in.Engine = engine
	}
	return in, nil
}

// validYallaID appends a field violation to violations when id is not a
// canonical Yalla ID of the wanted kind. It never echoes the submitted id, so
// the resulting error is safe for client envelopes, logs, and audit metadata.
func validYallaID(violations *[]apierr.FieldViolation, field string, id domain.ID, want domain.Kind) {
	if _, err := domain.ParseID(string(id)); err != nil {
		*violations = append(*violations, apierr.FieldViolation{
			Field: field, Reason: "must be a valid resource id",
		})
		return
	}
	if id.Kind() != want {
		*violations = append(*violations, apierr.FieldViolation{
			Field: field, Reason: "must be a " + want.String() + " id",
		})
	}
}

// requireDokployParent appends a field violation to violations when value — the
// parent resource's resolved Dokploy ID — is blank.
func requireDokployParent(violations *[]apierr.FieldViolation, field, value string) {
	if strings.TrimSpace(value) == "" {
		*violations = append(*violations, apierr.FieldViolation{
			Field: field, Reason: "required",
		})
	}
}
