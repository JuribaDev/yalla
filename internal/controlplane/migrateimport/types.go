package migrateimport

import (
	"context"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// ResourceLevel names which level of the hierarchy a PlanItem refers to. The
// set is closed; Plan and Apply switch on it to dispatch persistence.
type ResourceLevel string

// The canonical resource levels recognised by the importer. They mirror the
// reconcile package's own ResourceLevel values so triage tooling can address
// the same hierarchy depths uniformly.
const (
	LevelOrganization ResourceLevel = "organization"
	LevelProject      ResourceLevel = "project"
	LevelEnvironment  ResourceLevel = "environment"
	LevelService      ResourceLevel = "service"
)

// Valid reports whether l is one of the recognised resource levels.
func (l ResourceLevel) Valid() bool {
	switch l {
	case LevelOrganization, LevelProject, LevelEnvironment, LevelService:
		return true
	default:
		return false
	}
}

// ItemStatus is the disposition the planner assigned to a PlanItem. Apply
// dispatches on it; every status other than StatusReady is a skip.
type ItemStatus string

const (
	// StatusReady means Apply will attempt to persist the item: the owner is
	// assigned, the parent is known (or also about to be imported), the
	// resource type is supported, and no name collision was detected.
	StatusReady ItemStatus = "ready"
	// StatusPendingOwner means the operator has not supplied an explicit
	// OwnerAssignment for this Dokploy organization, so no resource under it
	// may become customer-visible. The item is listed for review and Apply
	// always skips it.
	StatusPendingOwner ItemStatus = "pending_owner"
	// StatusSkipDuplicate means a Yalla resource with the proposed slug
	// already exists under the resolved parent and is *not* linked to this
	// Dokploy resource. Apply skips it; the operator reconciles manually.
	StatusSkipDuplicate ItemStatus = "skip_duplicate"
	// StatusSkipMissingParent means the resolved parent has no Yalla
	// counterpart in this plan and no pre-existing linked record. Apply
	// cannot honour an orphaned child.
	StatusSkipMissingParent ItemStatus = "skip_missing_parent"
	// StatusSkipUnsupported means the Dokploy service type is not one Yalla
	// supports (application / compose / database).
	StatusSkipUnsupported ItemStatus = "skip_unsupported_type"
	// StatusSkipAlreadyImported means a Yalla row already records the same
	// Dokploy resource ID. Apply skips it as an idempotent no-op.
	StatusSkipAlreadyImported ItemStatus = "skip_already_imported"
)

// Valid reports whether s is one of the recognised item statuses.
func (s ItemStatus) Valid() bool {
	switch s {
	case StatusReady, StatusPendingOwner, StatusSkipDuplicate,
		StatusSkipMissingParent, StatusSkipUnsupported, StatusSkipAlreadyImported:
		return true
	default:
		return false
	}
}

// ItemReason is the stable, value-free classification code attached to each
// PlanItem. Reasons name *what* was detected, never the input value, so the
// Plan is safe to render into an audit-friendly JSON envelope.
type ItemReason string

const (
	// ReasonReadyToImport accompanies StatusReady.
	ReasonReadyToImport ItemReason = "ready_to_import"
	// ReasonExplicitOwnerMissing accompanies StatusPendingOwner.
	ReasonExplicitOwnerMissing ItemReason = "explicit_owner_missing"
	// ReasonDuplicateName accompanies StatusSkipDuplicate.
	ReasonDuplicateName ItemReason = "duplicate_name_in_parent"
	// ReasonMissingParentImport accompanies StatusSkipMissingParent.
	ReasonMissingParentImport ItemReason = "missing_parent_import"
	// ReasonUnsupportedServiceType accompanies StatusSkipUnsupported.
	ReasonUnsupportedServiceType ItemReason = "unsupported_service_type"
	// ReasonAlreadyLinked accompanies StatusSkipAlreadyImported.
	ReasonAlreadyLinked ItemReason = "already_linked"
)

// Snapshot is the live Dokploy view the Scanner returns: the organization
// being imported plus every project, environment, and service under it. The
// importer treats Snapshot as untrusted input from the perspective of name
// sanitisation, but trusts the parent linkage as the source-of-truth view of
// Dokploy at scan time.
type Snapshot struct {
	// Organization is the Dokploy organization being imported.
	Organization SnapshotOrganization
	// Projects belong to the organization. The slice is in the order the
	// Scanner returned them; the planner sorts deterministically before
	// emitting PlanItems.
	Projects []SnapshotProject
	// Environments belong to one of the projects. The planner skips children
	// whose parent is missing from Projects.
	Environments []SnapshotEnvironment
	// Services belong to one of the environments. The planner skips children
	// whose parent is missing from Environments.
	Services []SnapshotService
}

// SnapshotOrganization is the Dokploy organization root of a Snapshot.
type SnapshotOrganization struct {
	// DokployID is the Dokploy organization ID; required.
	DokployID string
	// Name is the human-authored Dokploy organization name; required.
	Name string
}

// SnapshotProject is one Dokploy project under SnapshotOrganization.
type SnapshotProject struct {
	// DokployID is the Dokploy project ID; required.
	DokployID string
	// DokployOrganizationID is the parent Dokploy organization ID; required
	// and used to filter out children scanned from a different organization.
	DokployOrganizationID string
	// Name is the human-authored Dokploy project name; required.
	Name string
}

// SnapshotEnvironment is one Dokploy environment under a SnapshotProject.
type SnapshotEnvironment struct {
	// DokployID is the Dokploy environment ID; required.
	DokployID string
	// DokployProjectID is the parent Dokploy project ID; required.
	DokployProjectID string
	// Name is the human-authored Dokploy environment name; required.
	Name string
}

// SnapshotService is one Dokploy service under a SnapshotEnvironment.
type SnapshotService struct {
	// DokployID is the Dokploy service ID; required.
	DokployID string
	// DokployEnvironmentID is the parent Dokploy environment ID; required.
	DokployEnvironmentID string
	// Name is the human-authored Dokploy service name; required.
	Name string
	// Type is the raw Dokploy service type ("application", "compose",
	// "database", or any unsupported value). The planner classifies an
	// unsupported value as StatusSkipUnsupported rather than failing.
	Type string
	// Engine is the database engine when Type is "database"; ignored
	// otherwise.
	Engine string
}

// OwnerAssignment is the operator's explicit declaration that a Dokploy
// organization belongs to a Yalla organization. The planner only marks an
// item StatusReady when an assignment is supplied; without it, every item is
// StatusPendingOwner and stays out of Apply.
type OwnerAssignment struct {
	// DokployOrganizationID is the Dokploy organization the assignment binds.
	// Must match Snapshot.Organization.DokployID; mismatches cause the planner
	// to treat the assignment as absent.
	DokployOrganizationID string
	// YallaOrganizationID is the existing Yalla organization that will own
	// every imported resource under DokployOrganizationID.
	YallaOrganizationID domain.ID
}

// IsAssigned reports whether o carries a non-blank Yalla organization ID and
// Dokploy organization ID. The planner uses this to short-circuit to
// StatusPendingOwner without exposing the partial value.
func (o OwnerAssignment) IsAssigned() bool {
	return strings.TrimSpace(o.DokployOrganizationID) != "" &&
		strings.TrimSpace(string(o.YallaOrganizationID)) != ""
}

// PlanItem is one ordered entry in a Plan. It is value-free for sensitive
// content: env vars, secrets, tokens, and other secret-shaped fields never
// reach a PlanItem. JSON serialisation is stable: every field is named, no
// pointer-cycle is possible, and the Plan is safe to render into a
// yalla.output.v1 envelope by the eventual admin import endpoint.
type PlanItem struct {
	// Level names which level of the hierarchy this item refers to.
	Level ResourceLevel `json:"level"`
	// Status is the disposition the planner assigned. Apply switches on it.
	Status ItemStatus `json:"status"`
	// Reason is the stable, value-free classification code.
	Reason ItemReason `json:"reason"`
	// DokployResourceID is the Dokploy ID of the resource being imported.
	DokployResourceID string `json:"dokploy_resource_id"`
	// DokployParentID is the Dokploy ID of the resource's parent, or empty at
	// the organization level.
	DokployParentID string `json:"dokploy_parent_id,omitempty"`
	// ProposedSlug is the canonical Yalla slug derived from the Dokploy
	// resource name. Always non-empty and ValidateSlug-clean for StatusReady;
	// may be empty when normalisation rejected the source name.
	ProposedSlug string `json:"proposed_slug,omitempty"`
	// ProposedDisplay is the human display name the importer will write. It
	// is the Dokploy resource name as-supplied; the persistence layer trims
	// and bounds it.
	ProposedDisplay string `json:"proposed_display,omitempty"`
	// ServiceType is set on service-level items and carries the raw Dokploy
	// type string. The planner uses it to detect StatusSkipUnsupported; the
	// repository uses it to dispatch CreateService.
	ServiceType string `json:"service_type,omitempty"`
	// Engine is set on service-level items that name a database engine.
	Engine string `json:"engine,omitempty"`
	// YallaParentID is the resolved Yalla ID of the parent resource. It is
	// set when the parent is a pre-existing Yalla row (already linked, or the
	// owner assignment itself for organization-level children).
	YallaParentID domain.ID `json:"yalla_parent_id,omitempty"`
	// ExistingYallaID is the Yalla ID of a row that already records this
	// Dokploy resource (StatusSkipAlreadyImported) or that collides on slug
	// under the parent (StatusSkipDuplicate). Empty otherwise.
	ExistingYallaID domain.ID `json:"existing_yalla_id,omitempty"`
}

// Plan is the deterministic, ordered list of items the importer would persist.
// It is the pure output of Importer.Plan and the sole input to Importer.Apply.
type Plan struct {
	// DokployOrganizationID is the organization the plan was scanned for.
	DokployOrganizationID string `json:"dokploy_organization_id"`
	// YallaOrganizationID is the resolved owner. Empty when no OwnerAssignment
	// was supplied — every item in the plan is then StatusPendingOwner.
	YallaOrganizationID domain.ID `json:"yalla_organization_id,omitempty"`
	// Items is the ordered list of plan entries. Ordering is deterministic:
	// hierarchy-first (organization, project, environment, service), then
	// Dokploy parent ID, then Dokploy resource ID.
	Items []PlanItem `json:"items"`
}

// ReadyItems returns the subset of Items whose Status is StatusReady, in the
// Plan's own order. This is the iteration target of Apply.
func (p Plan) ReadyItems() []PlanItem {
	out := make([]PlanItem, 0, len(p.Items))
	for _, item := range p.Items {
		if item.Status == StatusReady {
			out = append(out, item)
		}
	}
	return out
}

// IsEmpty reports whether the plan contains no items at all (an empty
// Snapshot, not "no ready items").
func (p Plan) IsEmpty() bool { return len(p.Items) == 0 }

// Failure is one per-item failure recorded during Apply. The error is
// preserved for logging and retry decisions; its message has already been
// scrubbed by the importer's Redactor before being placed here.
type Failure struct {
	Item PlanItem
	Err  error
}

// Result is the outcome of one Apply. It records counts for telemetry and the
// list of per-item failures.
type Result struct {
	// Imported is the number of items the Repository accepted.
	Imported int
	// Skipped is the number of non-ready items the plan asked Apply to step
	// over (StatusPendingOwner, StatusSkipDuplicate, etc.).
	Skipped int
	// Failures collects the per-item failures from Repository calls.
	Failures []Failure
}

// ExistingOrganization is the minimal Yalla organization view the Repository
// returns when the importer asks whether the owner is real.
type ExistingOrganization struct {
	ID domain.ID
}

// ExistingProject is the minimal Yalla project view the Repository returns
// when the importer probes for a slug collision or a pre-existing Dokploy
// link.
type ExistingProject struct {
	ID domain.ID
	// DokployID is the Dokploy project ID this row is linked to, or empty
	// when the row has no Dokploy link yet (an unlinked duplicate).
	DokployID string
}

// ExistingEnvironment mirrors ExistingProject at the environment level.
type ExistingEnvironment struct {
	ID        domain.ID
	ProjectID domain.ID
	DokployID string
}

// ExistingService mirrors ExistingProject at the service level.
type ExistingService struct {
	ID            domain.ID
	EnvironmentID domain.ID
	DokployID     string
}

// CreateProjectInput is the payload the Repository receives for a project
// import.
type CreateProjectInput struct {
	OrganizationID domain.ID
	Slug           string
	DisplayName    string
	DokployID      string
}

// CreateEnvironmentInput is the payload the Repository receives for an
// environment import.
type CreateEnvironmentInput struct {
	ProjectID   domain.ID
	Slug        string
	DisplayName string
	DokployID   string
}

// CreateServiceInput is the payload the Repository receives for a service
// import.
type CreateServiceInput struct {
	EnvironmentID domain.ID
	Slug          string
	DisplayName   string
	Type          string
	Engine        string
	DokployID     string
}

// Scanner is the port the importer uses to read the live Dokploy snapshot. A
// Dokploy-backed adapter lives outside this package; tests supply a fake.
type Scanner interface {
	// Scan returns the live Snapshot for the given Dokploy organization. A
	// blank or unknown organization is reported as a typed apierr.* error.
	Scan(ctx context.Context, dokployOrganizationID string) (Snapshot, error)
}

// Repository is the port the importer uses to read and write the
// source-of-truth hierarchy. A store-backed adapter lives outside this
// package; tests supply a fake.
//
// Every Find* method returns apierr.NotFound when the row does not exist.
// Other failures are returned as their catalogued apierr.* code (an
// uncatalogued error is upgraded to apierr.StoreUnavailable by the importer
// before being surfaced).
type Repository interface {
	// FindOrganization returns the Yalla organization or apierr.NotFound.
	FindOrganization(ctx context.Context, id domain.ID) (ExistingOrganization, error)

	// FindProjectByDokployID returns the Yalla project linked to dokployID
	// under organizationID, or apierr.NotFound.
	FindProjectByDokployID(ctx context.Context, organizationID domain.ID, dokployID string) (ExistingProject, error)
	// FindProjectBySlug returns the Yalla project with slug under
	// organizationID, or apierr.NotFound.
	FindProjectBySlug(ctx context.Context, organizationID domain.ID, slug string) (ExistingProject, error)
	// CreateProject persists a project import and returns the new Yalla ID.
	CreateProject(ctx context.Context, in CreateProjectInput) (domain.ID, error)

	// FindEnvironmentByDokployID returns the Yalla environment linked to
	// dokployID under projectID, or apierr.NotFound.
	FindEnvironmentByDokployID(ctx context.Context, projectID domain.ID, dokployID string) (ExistingEnvironment, error)
	// FindEnvironmentBySlug returns the Yalla environment with slug under
	// projectID, or apierr.NotFound.
	FindEnvironmentBySlug(ctx context.Context, projectID domain.ID, slug string) (ExistingEnvironment, error)
	// CreateEnvironment persists an environment import and returns the new
	// Yalla ID.
	CreateEnvironment(ctx context.Context, in CreateEnvironmentInput) (domain.ID, error)

	// FindServiceByDokployID returns the Yalla service linked to dokployID
	// under environmentID, or apierr.NotFound.
	FindServiceByDokployID(ctx context.Context, environmentID domain.ID, dokployID string) (ExistingService, error)
	// FindServiceBySlug returns the Yalla service with slug under
	// environmentID, or apierr.NotFound.
	FindServiceBySlug(ctx context.Context, environmentID domain.ID, slug string) (ExistingService, error)
	// CreateService persists a service import and returns the new Yalla ID.
	CreateService(ctx context.Context, in CreateServiceInput) (domain.ID, error)
}
