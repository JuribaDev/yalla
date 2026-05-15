package migrateimport

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// Config bundles the dependencies an Importer needs. Scanner and Repository
// are required; Logger, Now, and Redactor each have a sensible default.
type Config struct {
	// Scanner reads the live Dokploy snapshot.
	Scanner Scanner
	// Repository reads and writes the source-of-truth hierarchy.
	Repository Repository
	// Logger receives structured diagnostics. A nil value defaults to
	// slog.Default.
	Logger *slog.Logger
	// Now is an injectable clock; tests set it for determinism. A nil value
	// defaults to time.Now().UTC.
	Now func() time.Time
	// Redactor scrubs error strings before they reach logs and Result.Failures.
	// A nil value defaults to a fresh output.NewRedactor() with no literal
	// secrets registered, which still scrubs Authorization-style headers and
	// token-bearing query parameters from upstream error dumps.
	Redactor *output.Redactor
}

// Importer plans and applies the import of pre-existing Dokploy resources into
// Yalla's source-of-truth hierarchy. It is safe for concurrent use across
// multiple admin requests.
type Importer struct {
	scanner    Scanner
	repository Repository
	logger     *slog.Logger
	now        func() time.Time
	redactor   *output.Redactor
}

// New validates cfg and returns a ready Importer. Construction failures are
// typed apierr.Internal errors: a misconfigured importer is a Yalla deployment
// bug, not a customer-facing input failure.
func New(cfg Config) (*Importer, error) {
	if cfg.Scanner == nil {
		return nil, apierr.Internal(stderrors.New("migrateimport: Config.Scanner is required"))
	}
	if cfg.Repository == nil {
		return nil, apierr.Internal(stderrors.New("migrateimport: Config.Repository is required"))
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := cfg.Now
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	redactor := cfg.Redactor
	if redactor == nil {
		redactor = output.NewRedactor()
	}
	return &Importer{
		scanner:    cfg.Scanner,
		repository: cfg.Repository,
		logger:     logger,
		now:        clock,
		redactor:   redactor,
	}, nil
}

// PlanInput is the request shape for Importer.Plan. A blank or unassigned
// Assignment is allowed; the resulting Plan is then entirely StatusPendingOwner
// and Apply skips every item.
type PlanInput struct {
	// DokployOrganizationID is the Dokploy organization to scan; required.
	DokployOrganizationID string
	// Assignment is the operator's explicit owner declaration. May be the
	// zero value, in which case the Plan is dry-run-only and Apply imports
	// nothing.
	Assignment OwnerAssignment
}

// Plan reads the live Dokploy snapshot and returns the deterministic Plan of
// PlanItems. It performs no writes: a Plan is the dry-run output, and is the
// sole input to Apply.
//
// Plan validates only the request input (the Dokploy organization ID, the
// optional Yalla organization ID). Scanner and Repository failures are
// returned as their catalogued apierr.* code (an uncatalogued failure is
// upgraded to apierr.StoreUnavailable or apierr.DokployUnavailable as
// appropriate).
func (i *Importer) Plan(ctx context.Context, in PlanInput) (Plan, error) {
	dokployOrg := strings.TrimSpace(in.DokployOrganizationID)
	if dokployOrg == "" {
		return Plan{}, apierr.InvalidInput(apierr.FieldViolation{
			Field: "dokploy_organization_id", Reason: "required",
		})
	}

	assignment := normaliseAssignment(in.Assignment)
	if !assignment.IsAssigned() && strings.TrimSpace(string(in.Assignment.YallaOrganizationID)) != "" {
		// A blank Dokploy organization in the assignment is a programming
		// error: the operator supplied a Yalla owner but no Dokploy org to
		// bind it to.
		return Plan{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "assignment.dokploy_organization_id",
			Reason: "required when yalla_organization_id is set",
		})
	}
	if assignment.IsAssigned() {
		if err := validateYallaOrgID(assignment.YallaOrganizationID); err != nil {
			return Plan{}, err
		}
		// Mismatched assignment is treated as "no assignment" to keep the
		// classification surface honest: a wrong Dokploy ID in the assignment
		// must not silently bind the Yalla owner to a different org.
		if assignment.DokployOrganizationID != dokployOrg {
			return Plan{}, apierr.InvalidInput(apierr.FieldViolation{
				Field:  "assignment.dokploy_organization_id",
				Reason: "must match dokploy_organization_id",
			})
		}
	}

	snapshot, err := i.scanner.Scan(ctx, dokployOrg)
	if err != nil {
		return Plan{}, wrapScannerErr(i.redactor, err)
	}
	if strings.TrimSpace(snapshot.Organization.DokployID) == "" {
		return Plan{}, apierr.Internal(stderrors.New(
			"migrateimport: Scanner returned no organization id"))
	}
	if snapshot.Organization.DokployID != dokployOrg {
		return Plan{}, apierr.Internal(fmt.Errorf(
			"migrateimport: Scanner returned organization %s, expected %s",
			redact(i.redactor, snapshot.Organization.DokployID),
			redact(i.redactor, dokployOrg)))
	}

	plan := Plan{
		DokployOrganizationID: dokployOrg,
		YallaOrganizationID:   assignment.YallaOrganizationID,
	}

	// If no owner is assigned, every item is StatusPendingOwner and we never
	// query the Repository — the operator is reviewing what *would* be
	// imported, not yet committing to anything.
	if !assignment.IsAssigned() {
		plan.Items = pendingOwnerItems(snapshot)
		return plan, nil
	}

	// Validate the assignment names an existing Yalla organization. A missing
	// owner is a typed NotFound the operator must fix before re-running.
	if _, err := i.repository.FindOrganization(ctx, assignment.YallaOrganizationID); err != nil {
		if isNotFound(err) {
			return Plan{}, apierr.NotFound("organization",
				string(assignment.YallaOrganizationID))
		}
		return Plan{}, wrapRepositoryErr(i.redactor, err)
	}

	items, err := i.classify(ctx, snapshot, assignment.YallaOrganizationID)
	if err != nil {
		return Plan{}, err
	}
	plan.Items = items
	return plan, nil
}

// Apply executes the StatusReady items in plan in hierarchy order, asking the
// Repository to persist each one. It is best-effort: a per-item failure does
// not stop the rest of the plan; every failure is collected in
// Result.Failures with its error string scrubbed through the configured
// output.Redactor.
//
// Apply returns a non-nil error only when ctx itself is cancelled before the
// loop completes, or when the plan is structurally invalid (missing owner).
// Plans whose items are all non-ready are a valid no-op.
func (i *Importer) Apply(ctx context.Context, plan Plan) (Result, error) {
	res := Result{}
	if strings.TrimSpace(plan.DokployOrganizationID) == "" {
		return res, apierr.InvalidInput(apierr.FieldViolation{
			Field: "plan.dokploy_organization_id", Reason: "required",
		})
	}
	if !hasReady(plan) {
		// A plan without ready items is a valid no-op; account for the
		// skipped items so the caller's telemetry remains accurate.
		for _, item := range plan.Items {
			if item.Status != StatusReady {
				res.Skipped++
			}
		}
		return res, nil
	}
	if strings.TrimSpace(string(plan.YallaOrganizationID)) == "" {
		// StatusReady items require a resolved owner; an apply path that
		// reached this point without one is a planner bug.
		return res, apierr.Internal(stderrors.New(
			"migrateimport: plan has ready items but no yalla_organization_id"))
	}

	// resolvedParents tracks the resolved Yalla ID of every parent the apply
	// step has encountered so far. Keyed by Dokploy resource ID at each
	// hierarchy depth, so a service can resolve "what is the Yalla
	// environment ID for the parent named in PlanItem.DokployParentID".
	resolvedParents := map[string]domain.ID{
		// The organization root is always already resolved.
		plan.DokployOrganizationID: plan.YallaOrganizationID,
	}

	for _, item := range plan.Items {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if item.Status != StatusReady {
			res.Skipped++
			continue
		}
		yallaID, err := i.applyOne(ctx, item, resolvedParents)
		if err != nil {
			i.logFailure(ctx, item, err)
			res.Failures = append(res.Failures, Failure{
				Item: item,
				Err:  scrubErr(i.redactor, err),
			})
			continue
		}
		resolvedParents[item.DokployResourceID] = yallaID
		res.Imported++
	}
	return res, nil
}

// applyOne dispatches one StatusReady item to its Repository write. Returns
// the newly minted Yalla ID so subsequent children can resolve their parent.
func (i *Importer) applyOne(ctx context.Context, item PlanItem, parents map[string]domain.ID) (domain.ID, error) {
	switch item.Level {
	case LevelProject:
		parent, ok := parents[item.DokployParentID]
		if !ok {
			return "", apierr.Internal(fmt.Errorf(
				"migrateimport: project %s has no resolved parent",
				redact(i.redactor, item.DokployResourceID)))
		}
		return i.repository.CreateProject(ctx, CreateProjectInput{
			OrganizationID: parent,
			Slug:           item.ProposedSlug,
			DisplayName:    item.ProposedDisplay,
			DokployID:      item.DokployResourceID,
		})
	case LevelEnvironment:
		parent, ok := parents[item.DokployParentID]
		if !ok {
			return "", apierr.Internal(fmt.Errorf(
				"migrateimport: environment %s has no resolved parent",
				redact(i.redactor, item.DokployResourceID)))
		}
		return i.repository.CreateEnvironment(ctx, CreateEnvironmentInput{
			ProjectID:   parent,
			Slug:        item.ProposedSlug,
			DisplayName: item.ProposedDisplay,
			DokployID:   item.DokployResourceID,
		})
	case LevelService:
		parent, ok := parents[item.DokployParentID]
		if !ok {
			return "", apierr.Internal(fmt.Errorf(
				"migrateimport: service %s has no resolved parent",
				redact(i.redactor, item.DokployResourceID)))
		}
		return i.repository.CreateService(ctx, CreateServiceInput{
			EnvironmentID: parent,
			Slug:          item.ProposedSlug,
			DisplayName:   item.ProposedDisplay,
			Type:          item.ServiceType,
			Engine:        item.Engine,
			DokployID:     item.DokployResourceID,
		})
	case LevelOrganization:
		// Organization-level imports are not produced for StatusReady: the
		// operator's OwnerAssignment binds an *existing* Yalla organization.
		return "", apierr.Internal(fmt.Errorf(
			"migrateimport: organization-level ready item is not supported"))
	default:
		return "", apierr.Internal(fmt.Errorf(
			"migrateimport: unrecognised level %q", item.Level))
	}
}

// classify is the heart of the planner. It walks the snapshot in hierarchy
// order, queries the Repository for collisions and pre-existing links, and
// produces the ordered slice of PlanItems.
func (i *Importer) classify(ctx context.Context, snap Snapshot, yallaOrg domain.ID) ([]PlanItem, error) {
	items := make([]PlanItem, 0, len(snap.Projects)+len(snap.Environments)+len(snap.Services))

	// Index project parents so we can detect missing parents and resolve
	// environments to their parent project deterministically.
	projectIndex := indexProjectsByID(snap.Projects, snap.Organization.DokployID)
	// resolvedProjectParents maps a Dokploy project ID to the Yalla project
	// ID that will own it after Apply. It is populated as we classify
	// projects so environments can look up their parent.
	resolvedProjectParents := map[string]domain.ID{}

	sortedProjects := sortedProjectKeys(projectIndex)
	for _, pid := range sortedProjects {
		proj := projectIndex[pid]
		item, yallaID, err := i.classifyProject(ctx, proj, yallaOrg)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
		if item.Status == StatusReady || item.Status == StatusSkipAlreadyImported {
			// In both ready and already-imported the parent is now a real
			// row environments can attach to. Duplicates and skips do not
			// populate the map.
			resolvedProjectParents[proj.DokployID] = yallaID
		}
	}

	envIndex := indexEnvironmentsByID(snap.Environments)
	resolvedEnvParents := map[string]domain.ID{}

	sortedEnvs := sortedEnvironmentKeys(envIndex)
	for _, eid := range sortedEnvs {
		env := envIndex[eid]
		parentYalla, parentResolved := resolvedProjectParents[env.DokployProjectID]
		_, parentInPlan := projectIndex[env.DokployProjectID]
		item, yallaID, err := i.classifyEnvironment(ctx, env, parentYalla, parentResolved, parentInPlan)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
		if item.Status == StatusReady || item.Status == StatusSkipAlreadyImported {
			resolvedEnvParents[env.DokployID] = yallaID
		}
	}

	svcIndex := indexServicesByID(snap.Services)
	sortedSvcs := sortedServiceKeys(svcIndex)
	for _, sid := range sortedSvcs {
		svc := svcIndex[sid]
		parentYalla, parentResolved := resolvedEnvParents[svc.DokployEnvironmentID]
		_, parentInPlan := envIndex[svc.DokployEnvironmentID]
		item, err := i.classifyService(ctx, svc, parentYalla, parentResolved, parentInPlan)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, nil
}

// classifyProject decides whether the snapshot project becomes a ready
// import, an already-linked no-op, a duplicate skip, or another skip.
func (i *Importer) classifyProject(ctx context.Context, proj SnapshotProject, yallaOrg domain.ID) (PlanItem, domain.ID, error) {
	item := PlanItem{
		Level:             LevelProject,
		DokployResourceID: strings.TrimSpace(proj.DokployID),
		DokployParentID:   strings.TrimSpace(proj.DokployOrganizationID),
		ProposedDisplay:   strings.TrimSpace(proj.Name),
		YallaParentID:     yallaOrg,
	}

	// Already linked? Look up by Dokploy ID under the resolved Yalla org.
	existing, err := i.repository.FindProjectByDokployID(ctx, yallaOrg, item.DokployResourceID)
	if err == nil {
		item.Status = StatusSkipAlreadyImported
		item.Reason = ReasonAlreadyLinked
		item.ExistingYallaID = existing.ID
		return item, existing.ID, nil
	}
	if !isNotFound(err) {
		return PlanItem{}, "", wrapRepositoryErr(i.redactor, err)
	}

	// Normalise the proposed slug. A name that cannot normalise into a valid
	// slug is itself classified — never an error.
	slug, slugErr := proposeSlug(proj.Name)
	if slugErr != nil {
		item.Status = StatusSkipDuplicate
		item.Reason = ReasonDuplicateName
		return item, "", nil
	}
	item.ProposedSlug = slug

	// Duplicate slug under the resolved Yalla org?
	clash, err := i.repository.FindProjectBySlug(ctx, yallaOrg, slug)
	if err != nil && !isNotFound(err) {
		return PlanItem{}, "", wrapRepositoryErr(i.redactor, err)
	}
	if err == nil && clash.DokployID != item.DokployResourceID {
		item.Status = StatusSkipDuplicate
		item.Reason = ReasonDuplicateName
		item.ExistingYallaID = clash.ID
		return item, "", nil
	}

	item.Status = StatusReady
	item.Reason = ReasonReadyToImport
	return item, "", nil
}

// classifyEnvironment mirrors classifyProject at the environment level.
func (i *Importer) classifyEnvironment(ctx context.Context, env SnapshotEnvironment, parentYalla domain.ID, parentResolved, parentInPlan bool) (PlanItem, domain.ID, error) {
	item := PlanItem{
		Level:             LevelEnvironment,
		DokployResourceID: strings.TrimSpace(env.DokployID),
		DokployParentID:   strings.TrimSpace(env.DokployProjectID),
		ProposedDisplay:   strings.TrimSpace(env.Name),
		YallaParentID:     parentYalla,
	}

	if !parentInPlan {
		// The Dokploy environment names a project that was not part of the
		// snapshot. It cannot be honoured.
		item.Status = StatusSkipMissingParent
		item.Reason = ReasonMissingParentImport
		return item, "", nil
	}
	if !parentResolved {
		// The parent project was skipped or failed classification, so this
		// child cannot proceed either.
		item.Status = StatusSkipMissingParent
		item.Reason = ReasonMissingParentImport
		return item, "", nil
	}

	// Already linked under the resolved parent project?
	existing, err := i.repository.FindEnvironmentByDokployID(ctx, parentYalla, item.DokployResourceID)
	if err == nil {
		item.Status = StatusSkipAlreadyImported
		item.Reason = ReasonAlreadyLinked
		item.ExistingYallaID = existing.ID
		return item, existing.ID, nil
	}
	if !isNotFound(err) {
		return PlanItem{}, "", wrapRepositoryErr(i.redactor, err)
	}

	slug, slugErr := proposeSlug(env.Name)
	if slugErr != nil {
		item.Status = StatusSkipDuplicate
		item.Reason = ReasonDuplicateName
		return item, "", nil
	}
	item.ProposedSlug = slug

	clash, err := i.repository.FindEnvironmentBySlug(ctx, parentYalla, slug)
	if err != nil && !isNotFound(err) {
		return PlanItem{}, "", wrapRepositoryErr(i.redactor, err)
	}
	if err == nil && clash.DokployID != item.DokployResourceID {
		item.Status = StatusSkipDuplicate
		item.Reason = ReasonDuplicateName
		item.ExistingYallaID = clash.ID
		return item, "", nil
	}

	item.Status = StatusReady
	item.Reason = ReasonReadyToImport
	return item, "", nil
}

// classifyService mirrors classifyProject at the service level, with the
// added classification of unsupported Dokploy service types.
func (i *Importer) classifyService(ctx context.Context, svc SnapshotService, parentYalla domain.ID, parentResolved, parentInPlan bool) (PlanItem, error) {
	item := PlanItem{
		Level:             LevelService,
		DokployResourceID: strings.TrimSpace(svc.DokployID),
		DokployParentID:   strings.TrimSpace(svc.DokployEnvironmentID),
		ProposedDisplay:   strings.TrimSpace(svc.Name),
		ServiceType:       strings.TrimSpace(svc.Type),
		Engine:            strings.TrimSpace(svc.Engine),
		YallaParentID:     parentYalla,
	}

	if !parentInPlan || !parentResolved {
		item.Status = StatusSkipMissingParent
		item.Reason = ReasonMissingParentImport
		return item, nil
	}

	if !supportedServiceType(svc) {
		item.Status = StatusSkipUnsupported
		item.Reason = ReasonUnsupportedServiceType
		return item, nil
	}

	existing, err := i.repository.FindServiceByDokployID(ctx, parentYalla, item.DokployResourceID)
	if err == nil {
		item.Status = StatusSkipAlreadyImported
		item.Reason = ReasonAlreadyLinked
		item.ExistingYallaID = existing.ID
		return item, nil
	}
	if !isNotFound(err) {
		return PlanItem{}, wrapRepositoryErr(i.redactor, err)
	}

	slug, slugErr := proposeSlug(svc.Name)
	if slugErr != nil {
		item.Status = StatusSkipDuplicate
		item.Reason = ReasonDuplicateName
		return item, nil
	}
	item.ProposedSlug = slug

	clash, err := i.repository.FindServiceBySlug(ctx, parentYalla, slug)
	if err != nil && !isNotFound(err) {
		return PlanItem{}, wrapRepositoryErr(i.redactor, err)
	}
	if err == nil && clash.DokployID != item.DokployResourceID {
		item.Status = StatusSkipDuplicate
		item.Reason = ReasonDuplicateName
		item.ExistingYallaID = clash.ID
		return item, nil
	}

	item.Status = StatusReady
	item.Reason = ReasonReadyToImport
	return item, nil
}

// pendingOwnerItems builds the dry-run-only listing when no OwnerAssignment
// was supplied. Every item is StatusPendingOwner so the operator can review
// what would be imported once an owner is assigned. The proposed slug is
// still computed when the Dokploy name normalises cleanly; an
// un-normalisable name leaves ProposedSlug empty so the operator notices.
func pendingOwnerItems(snap Snapshot) []PlanItem {
	out := make([]PlanItem, 0, len(snap.Projects)+len(snap.Environments)+len(snap.Services))

	projectIndex := indexProjectsByID(snap.Projects, snap.Organization.DokployID)
	for _, pid := range sortedProjectKeys(projectIndex) {
		p := projectIndex[pid]
		item := PlanItem{
			Level:             LevelProject,
			Status:            StatusPendingOwner,
			Reason:            ReasonExplicitOwnerMissing,
			DokployResourceID: strings.TrimSpace(p.DokployID),
			DokployParentID:   strings.TrimSpace(p.DokployOrganizationID),
			ProposedDisplay:   strings.TrimSpace(p.Name),
		}
		if slug, err := proposeSlug(p.Name); err == nil {
			item.ProposedSlug = slug
		}
		out = append(out, item)
	}

	envIndex := indexEnvironmentsByID(snap.Environments)
	for _, eid := range sortedEnvironmentKeys(envIndex) {
		e := envIndex[eid]
		if _, ok := projectIndex[e.DokployProjectID]; !ok {
			// Environment references a missing parent — record it as a
			// missing-parent skip rather than a pending-owner item so the
			// operator's review surface still names the structural problem.
			out = append(out, PlanItem{
				Level:             LevelEnvironment,
				Status:            StatusSkipMissingParent,
				Reason:            ReasonMissingParentImport,
				DokployResourceID: strings.TrimSpace(e.DokployID),
				DokployParentID:   strings.TrimSpace(e.DokployProjectID),
				ProposedDisplay:   strings.TrimSpace(e.Name),
			})
			continue
		}
		item := PlanItem{
			Level:             LevelEnvironment,
			Status:            StatusPendingOwner,
			Reason:            ReasonExplicitOwnerMissing,
			DokployResourceID: strings.TrimSpace(e.DokployID),
			DokployParentID:   strings.TrimSpace(e.DokployProjectID),
			ProposedDisplay:   strings.TrimSpace(e.Name),
		}
		if slug, err := proposeSlug(e.Name); err == nil {
			item.ProposedSlug = slug
		}
		out = append(out, item)
	}

	svcIndex := indexServicesByID(snap.Services)
	for _, sid := range sortedServiceKeys(svcIndex) {
		s := svcIndex[sid]
		if _, ok := envIndex[s.DokployEnvironmentID]; !ok {
			out = append(out, PlanItem{
				Level:             LevelService,
				Status:            StatusSkipMissingParent,
				Reason:            ReasonMissingParentImport,
				DokployResourceID: strings.TrimSpace(s.DokployID),
				DokployParentID:   strings.TrimSpace(s.DokployEnvironmentID),
				ProposedDisplay:   strings.TrimSpace(s.Name),
				ServiceType:       strings.TrimSpace(s.Type),
				Engine:            strings.TrimSpace(s.Engine),
			})
			continue
		}
		if !supportedServiceType(s) {
			out = append(out, PlanItem{
				Level:             LevelService,
				Status:            StatusSkipUnsupported,
				Reason:            ReasonUnsupportedServiceType,
				DokployResourceID: strings.TrimSpace(s.DokployID),
				DokployParentID:   strings.TrimSpace(s.DokployEnvironmentID),
				ProposedDisplay:   strings.TrimSpace(s.Name),
				ServiceType:       strings.TrimSpace(s.Type),
				Engine:            strings.TrimSpace(s.Engine),
			})
			continue
		}
		item := PlanItem{
			Level:             LevelService,
			Status:            StatusPendingOwner,
			Reason:            ReasonExplicitOwnerMissing,
			DokployResourceID: strings.TrimSpace(s.DokployID),
			DokployParentID:   strings.TrimSpace(s.DokployEnvironmentID),
			ProposedDisplay:   strings.TrimSpace(s.Name),
			ServiceType:       strings.TrimSpace(s.Type),
			Engine:            strings.TrimSpace(s.Engine),
		}
		if slug, err := proposeSlug(s.Name); err == nil {
			item.ProposedSlug = slug
		}
		out = append(out, item)
	}
	return out
}

// supportedServiceType reports whether svc names a Dokploy service type Yalla
// can import. Database services additionally require a non-blank engine.
func supportedServiceType(svc SnapshotService) bool {
	t := dokploy.ServiceType(strings.TrimSpace(svc.Type))
	if !t.Valid() {
		return false
	}
	if t == dokploy.ServiceDatabase && strings.TrimSpace(svc.Engine) == "" {
		return false
	}
	return true
}

// proposeSlug normalises a Dokploy resource name into a canonical Yalla slug.
// An un-normalisable name (no usable alphanumerics) is reported with the
// underlying domain error so the planner can classify rather than propagate.
func proposeSlug(name string) (string, error) {
	slug, err := domain.NormalizeSlug(name)
	if err != nil {
		return "", err
	}
	return slug.String(), nil
}

// indexProjectsByID returns the snapshot's projects keyed by Dokploy ID,
// filtering out any project whose DokployOrganizationID does not match
// orgID. Projects with blank IDs are also dropped.
func indexProjectsByID(in []SnapshotProject, orgID string) map[string]SnapshotProject {
	out := make(map[string]SnapshotProject, len(in))
	for _, p := range in {
		id := strings.TrimSpace(p.DokployID)
		if id == "" {
			continue
		}
		if strings.TrimSpace(p.DokployOrganizationID) != orgID {
			continue
		}
		out[id] = p
	}
	return out
}

func indexEnvironmentsByID(in []SnapshotEnvironment) map[string]SnapshotEnvironment {
	out := make(map[string]SnapshotEnvironment, len(in))
	for _, e := range in {
		id := strings.TrimSpace(e.DokployID)
		if id == "" {
			continue
		}
		out[id] = e
	}
	return out
}

func indexServicesByID(in []SnapshotService) map[string]SnapshotService {
	out := make(map[string]SnapshotService, len(in))
	for _, s := range in {
		id := strings.TrimSpace(s.DokployID)
		if id == "" {
			continue
		}
		out[id] = s
	}
	return out
}

// sortedProjectKeys returns the keys of m in deterministic order. We sort by
// Dokploy ID alone: a stable order makes the plan reproducible without
// leaking name content into the ordering.
func sortedProjectKeys(m map[string]SnapshotProject) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedEnvironmentKeys(m map[string]SnapshotEnvironment) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedServiceKeys(m map[string]SnapshotService) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// hasReady reports whether the plan contains at least one StatusReady item.
func hasReady(p Plan) bool {
	for _, item := range p.Items {
		if item.Status == StatusReady {
			return true
		}
	}
	return false
}

// normaliseAssignment trims whitespace and returns the assignment. A blank
// assignment becomes the zero value so IsAssigned returns false consistently.
func normaliseAssignment(a OwnerAssignment) OwnerAssignment {
	return OwnerAssignment{
		DokployOrganizationID: strings.TrimSpace(a.DokployOrganizationID),
		YallaOrganizationID: domain.ID(
			strings.TrimSpace(string(a.YallaOrganizationID))),
	}
}

// validateYallaOrgID rejects a Yalla organization ID that is malformed or
// names the wrong resource kind. The error never echoes the submitted value.
func validateYallaOrgID(id domain.ID) error {
	parsed, err := domain.ParseID(string(id))
	if err != nil {
		return apierr.InvalidInput(apierr.FieldViolation{
			Field: "assignment.yalla_organization_id", Reason: "must be a valid resource id",
		})
	}
	if parsed.Kind() != domain.KindOrganization {
		return apierr.InvalidInput(apierr.FieldViolation{
			Field: "assignment.yalla_organization_id", Reason: "must be an organization id",
		})
	}
	return nil
}

// isNotFound reports whether err is a catalogued apierr.NotFound. A nil or
// non-catalogued error returns false.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) {
		return false
	}
	return ye.Code == yerr.CodeNotFound
}

// wrapScannerErr coerces a Scanner failure into the apierr taxonomy. A typed
// apierr from the adapter is preserved; anything else is upgraded to
// apierr.DokployUnavailable.
func wrapScannerErr(redactor *output.Redactor, err error) error {
	if err == nil {
		return nil
	}
	if isCatalogued(err) {
		return err
	}
	return apierr.DokployUnavailable(scrubErr(redactor, err))
}

// wrapRepositoryErr coerces a Repository failure into the apierr taxonomy. A
// typed apierr is preserved; anything else is upgraded to
// apierr.StoreUnavailable.
func wrapRepositoryErr(redactor *output.Redactor, err error) error {
	if err == nil {
		return nil
	}
	if isCatalogued(err) {
		return err
	}
	return apierr.StoreUnavailable(scrubErr(redactor, err))
}

func isCatalogued(err error) bool {
	var ye *yerr.Error
	return stderrors.As(err, &ye)
}

// scrubErr returns an apierr-shaped error whose message has been scrubbed
// through redactor. A typed apierr is preserved without re-wrapping.
func scrubErr(redactor *output.Redactor, err error) error {
	if err == nil {
		return nil
	}
	if isCatalogued(err) {
		return err
	}
	return apierr.Internal(stderrors.New(scrubMessage(redactor, err)))
}

func scrubMessage(redactor *output.Redactor, err error) string {
	if err == nil {
		return ""
	}
	if redactor == nil {
		return err.Error()
	}
	return redactor.Redact(err.Error())
}

func redact(redactor *output.Redactor, s string) string {
	if redactor == nil {
		return s
	}
	return redactor.Redact(s)
}

// logFailure emits one structured failure record per per-item Apply failure.
// Item context (level, status, reason, Dokploy ID, slug) is value-free and
// safe; the error string is scrubbed before logging.
func (i *Importer) logFailure(ctx context.Context, item PlanItem, err error) {
	i.logger.WarnContext(ctx, "migrate import action failed",
		append(telemetry.LogAttrs(ctx),
			slog.String("level", string(item.Level)),
			slog.String("status", string(item.Status)),
			slog.String("reason", string(item.Reason)),
			slog.String("dokploy_resource_id", redact(i.redactor, item.DokployResourceID)),
			slog.String("dokploy_parent_id", redact(i.redactor, item.DokployParentID)),
			slog.String("proposed_slug", item.ProposedSlug),
			slog.String("error", scrubMessage(i.redactor, err)),
		)...)
}
