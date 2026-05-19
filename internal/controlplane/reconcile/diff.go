package reconcile

import (
	"sort"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Action is one item in a Plan. It is a tagged record describing what the
// engine wants to do (or refuses to do) about a single drift.
//
// Action is value-free: the Reason carries a stable classification code, never
// the input value. The engine never logs or audits values directly; it routes
// them through the Repairer port for safe drift only.
type Action struct {
	// Type names the operation.
	Type ActionType
	// Kind is the safety classification used to dispatch the action.
	Kind DriftKind
	// Reason is the stable, value-free classification code.
	Reason DriftReason
	// Service is set for service-, env-var-, and domain-level actions.
	Service ServiceRef
	// Domain is set for domain-level actions.
	Domain DomainRef
	// EnvVarKey is set for env-var-level actions. Never holds a value.
	EnvVarKey string
	// DesiredValue is the env-var value the Repairer should write. It is
	// only populated for ActionUpdateEnvVar (whose Kind is always DriftSafe)
	// and is consumed by the Repairer adapter; the planner, logger, audit,
	// and review path must not read this field for any other purpose.
	DesiredValue string
	// DesiredSecret records whether DesiredValue is secret. Used by the
	// Repairer to route to a secret store, never logged.
	DesiredSecret bool
	// DesiredBuild is set for ActionUpdateBuildConfig. It can contain
	// private repo refs or image/artifact locations and must only be consumed
	// by a Repairer adapter.
	DesiredBuild dokploy.BuildSettings
	// DesiredService is set for ActionEnsureService and review actions that
	// need to communicate the desired service shape downstream.
	DesiredService *DesiredService
	// DesiredDomain is set for ActionEnsureDomain.
	DesiredDomain *DesiredDomain
	// Unmanaged is set for ActionMarkUnmanaged.
	Unmanaged *UnmanagedResource
}

// Plan is the ordered list of actions the engine intends to apply. It is the
// pure output of Diff and the sole input to Apply. A Plan with no actions
// means actual converged on desired and nothing needs to happen.
type Plan struct {
	OrganizationID domain.ID
	Actions        []Action
}

// IsEmpty reports whether the plan contains no actions.
func (p Plan) IsEmpty() bool { return len(p.Actions) == 0 }

// SafeActions returns the subset of actions classified DriftSafe.
func (p Plan) SafeActions() []Action { return p.filter(DriftSafe) }

// DangerousActions returns the subset of actions classified DriftDangerous.
func (p Plan) DangerousActions() []Action { return p.filter(DriftDangerous) }

// UnmanagedActions returns the subset of actions classified DriftUnmanaged.
func (p Plan) UnmanagedActions() []Action { return p.filter(DriftUnmanaged) }

func (p Plan) filter(kind DriftKind) []Action {
	out := make([]Action, 0, len(p.Actions))
	for _, a := range p.Actions {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

// Diff is the pure planner: given a desired and actual snapshot of the same
// organization, Diff returns the ordered Plan of actions the engine should
// apply.
//
// The returned Plan is deterministic — actions are ordered by (project,
// environment, service, kind, reason, secondary key) so a test can assert on
// it without reaching for set semantics. Diff never panics on missing or
// extra resources; instead it emits the correct drift classification.
//
// Diff does not validate desired/actual structurally (call validate.* upstream
// when the data crosses a request boundary); it only classifies divergence.
// It never reads or echoes any env-var value into a Reason or other
// classification field — values reach Action only via DesiredValue, which is
// consumed by the Repairer adapter and never logged.
func Diff(desired DesiredOrganization, actual ActualOrganization) Plan {
	plan := Plan{OrganizationID: trimmedID(desired.ID)}

	// Resolve project lookup tables keyed by Dokploy ID so we can scan
	// desired top-down and detect missing/unmanaged in one pass.
	actualProjects := indexProjects(actual.Projects)
	seenProjects := make(map[string]struct{}, len(actualProjects))

	for _, dp := range desired.Projects {
		dokployProjectID := strings.TrimSpace(dp.DokployID)
		if dokployProjectID == "" {
			// Not yet provisioned: this is provisioning lag, not drift.
			continue
		}
		ap, ok := actualProjects[dokployProjectID]
		if !ok {
			// A managed project missing from Dokploy is dangerous: the
			// project might own data, downstreams, or domains we should not
			// resurrect blindly. The planner emits review actions per
			// service inside it so the operator has the right grain.
			emitMissingProjectReviews(&plan, desired.ID, dp)
			continue
		}
		seenProjects[dokployProjectID] = struct{}{}
		diffEnvironments(&plan, desired.ID, dp, ap)
	}

	// Anything in actual that desired did not claim is unmanaged.
	for _, ap := range actual.Projects {
		dokployProjectID := strings.TrimSpace(ap.DokployID)
		if dokployProjectID == "" {
			continue
		}
		if _, ok := seenProjects[dokployProjectID]; ok {
			continue
		}
		plan.Actions = append(plan.Actions, Action{
			Type:   ActionMarkUnmanaged,
			Kind:   DriftUnmanaged,
			Reason: ReasonResourceUnmanaged,
			Unmanaged: &UnmanagedResource{
				OrganizationID:    trimmedID(desired.ID),
				Level:             LevelProject,
				DokployResourceID: dokployProjectID,
				ParentDokployID:   strings.TrimSpace(actual.DokployID),
				Reason:            ReasonResourceUnmanaged,
			},
		})
		// Every service and domain inside an unmanaged project is also
		// unmanaged. Surfacing them lets the operator see the blast radius
		// before deciding to adopt or delete the project.
		emitUnmanagedDescendants(&plan, desired.ID, ap)
	}

	sortActions(plan.Actions)
	return plan
}

func indexProjects(projects []ActualProject) map[string]ActualProject {
	out := make(map[string]ActualProject, len(projects))
	for _, p := range projects {
		id := strings.TrimSpace(p.DokployID)
		if id == "" {
			continue
		}
		out[id] = p
	}
	return out
}

func indexEnvironments(envs []ActualEnvironment) map[string]ActualEnvironment {
	out := make(map[string]ActualEnvironment, len(envs))
	for _, e := range envs {
		id := strings.TrimSpace(e.DokployID)
		if id == "" {
			continue
		}
		out[id] = e
	}
	return out
}

func indexServices(svcs []ActualService) map[string]ActualService {
	out := make(map[string]ActualService, len(svcs))
	for _, s := range svcs {
		id := strings.TrimSpace(s.DokployID)
		if id == "" {
			continue
		}
		out[id] = s
	}
	return out
}

func diffEnvironments(plan *Plan, orgID domain.ID, dp DesiredProject, ap ActualProject) {
	actualEnvs := indexEnvironments(ap.Environments)
	seen := make(map[string]struct{}, len(actualEnvs))
	for _, de := range dp.Environments {
		dokployEnvID := strings.TrimSpace(de.DokployID)
		if dokployEnvID == "" {
			continue
		}
		ae, ok := actualEnvs[dokployEnvID]
		if !ok {
			emitMissingEnvironmentReviews(plan, orgID, dp, de)
			continue
		}
		seen[dokployEnvID] = struct{}{}
		diffServices(plan, orgID, dp, de, ae)
	}
	for _, ae := range ap.Environments {
		dokployEnvID := strings.TrimSpace(ae.DokployID)
		if dokployEnvID == "" {
			continue
		}
		if _, ok := seen[dokployEnvID]; ok {
			continue
		}
		plan.Actions = append(plan.Actions, Action{
			Type:   ActionMarkUnmanaged,
			Kind:   DriftUnmanaged,
			Reason: ReasonResourceUnmanaged,
			Unmanaged: &UnmanagedResource{
				OrganizationID:    trimmedID(orgID),
				Level:             LevelEnvironment,
				DokployResourceID: dokployEnvID,
				ParentDokployID:   strings.TrimSpace(ap.DokployID),
				Reason:            ReasonResourceUnmanaged,
			},
		})
		for _, svc := range ae.Services {
			plan.Actions = append(plan.Actions, unmanagedServiceAction(orgID, ae, svc))
		}
	}
}

func diffServices(plan *Plan, orgID domain.ID, dp DesiredProject, de DesiredEnvironment, ae ActualEnvironment) {
	actualSvcs := indexServices(ae.Services)
	seen := make(map[string]struct{}, len(actualSvcs))
	for _, ds := range de.Services {
		ref := ServiceRef{
			OrganizationID:   trimmedID(orgID),
			ProjectID:        trimmedID(dp.ID),
			EnvironmentID:    trimmedID(de.ID),
			ServiceID:        trimmedID(ds.ID),
			DokployServiceID: strings.TrimSpace(ds.DokployID),
		}
		if ref.DokployServiceID == "" {
			continue
		}
		as, ok := actualSvcs[ref.DokployServiceID]
		if !ok {
			plan.Actions = append(plan.Actions, missingServiceAction(ref, ds))
			continue
		}
		seen[ref.DokployServiceID] = struct{}{}
		diffService(plan, ref, ds, as)
	}
	for _, as := range ae.Services {
		dokployID := strings.TrimSpace(as.DokployID)
		if dokployID == "" {
			continue
		}
		if _, ok := seen[dokployID]; ok {
			continue
		}
		plan.Actions = append(plan.Actions, unmanagedServiceAction(orgID, ae, as))
	}
}

func diffService(plan *Plan, ref ServiceRef, ds DesiredService, as ActualService) {
	if ds.Type != as.Type {
		plan.Actions = append(plan.Actions, Action{
			Type:    ActionReviewServiceTypeChange,
			Kind:    DriftDangerous,
			Reason:  ReasonServiceTypeChanged,
			Service: ref,
		})
		// A type-changed service is a fundamental mismatch. Do not emit safe
		// repairs against a service whose kind we no longer trust.
		return
	}
	if ds.Type == dokploy.ServiceDatabase && normaliseEngine(ds.Engine) != normaliseEngine(as.Engine) {
		plan.Actions = append(plan.Actions, Action{
			Type:    ActionReviewServiceTypeChange,
			Kind:    DriftDangerous,
			Reason:  ReasonServiceTypeChanged,
			Service: ref,
		})
		// Database engine drift is a subtype mismatch. Do not apply safe
		// env/domain repairs against a database whose storage engine no
		// longer matches Yalla's source of truth.
		return
	}
	if ds.Type != dokploy.ServiceDatabase && normaliseRole(ds.Role) != "" && normaliseRole(ds.Role) != normaliseRole(as.Role) {
		plan.Actions = append(plan.Actions, Action{
			Type:    ActionReviewServiceRoleChange,
			Kind:    DriftDangerous,
			Reason:  ReasonServiceRoleChanged,
			Service: ref,
		})
		// Runtime role drift changes service semantics (for example worker
		// vs cron/web). Do not emit safe repairs against a service whose
		// runtime shape no longer matches Yalla's source of truth.
		return
	}
	diffBuild(plan, ref, ds, as)
	diffEnvVars(plan, ref, ds, as)
	if normaliseRole(ds.Role) != "" && normaliseRole(ds.Role) != string(dokploy.RoleWeb) {
		ds.Domains = nil
	}
	diffDomains(plan, ref, ds, as)
}

func diffBuild(plan *Plan, ref ServiceRef, ds DesiredService, as ActualService) {
	if ds.Type == dokploy.ServiceDatabase {
		return
	}
	desired := normaliseBuildForDiff(ds.Build)
	actual := normaliseBuildForDiff(as.Build)
	if desired == actual {
		return
	}
	plan.Actions = append(plan.Actions, Action{
		Type:         ActionUpdateBuildConfig,
		Kind:         DriftSafe,
		Reason:       ReasonBuildConfigChanged,
		Service:      ref,
		DesiredBuild: desired,
	})
}

func diffEnvVars(plan *Plan, ref ServiceRef, ds DesiredService, as ActualService) {
	desiredMap := make(map[string]DesiredEnvVar, len(ds.EnvVars))
	for _, e := range ds.EnvVars {
		key := strings.TrimSpace(e.Key)
		if key == "" {
			continue
		}
		desiredMap[key] = e
	}
	actualMap := make(map[string]ActualEnvVar, len(as.EnvVars))
	for _, e := range as.EnvVars {
		key := strings.TrimSpace(e.Key)
		if key == "" {
			continue
		}
		actualMap[key] = e
	}
	// Stable iteration: sort the union of keys.
	keys := unionKeys(desiredMap, actualMap)
	for _, key := range keys {
		dv, hasDesired := desiredMap[key]
		av, hasActual := actualMap[key]
		switch {
		case hasDesired && !hasActual:
			plan.Actions = append(plan.Actions, Action{
				Type:          ActionUpdateEnvVar,
				Kind:          DriftSafe,
				Reason:        ReasonEnvVarMissing,
				Service:       ref,
				EnvVarKey:     key,
				DesiredValue:  dv.Value,
				DesiredSecret: dv.Secret,
			})
		case !hasDesired && hasActual:
			plan.Actions = append(plan.Actions, Action{
				Type:      ActionRemoveExtraEnvVar,
				Kind:      DriftSafe,
				Reason:    ReasonEnvVarExtra,
				Service:   ref,
				EnvVarKey: key,
			})
		case hasDesired && hasActual && dv.Value != av.Value:
			plan.Actions = append(plan.Actions, Action{
				Type:          ActionUpdateEnvVar,
				Kind:          DriftSafe,
				Reason:        ReasonEnvVarChanged,
				Service:       ref,
				EnvVarKey:     key,
				DesiredValue:  dv.Value,
				DesiredSecret: dv.Secret,
			})
		}
	}
}

func diffDomains(plan *Plan, ref ServiceRef, ds DesiredService, as ActualService) {
	desiredByID := make(map[string]DesiredDomain)
	desiredByHost := make(map[string]DesiredDomain)
	for _, d := range ds.Domains {
		host := normaliseHost(d.Host)
		if host == "" {
			continue
		}
		desiredByHost[host] = d
		if id := strings.TrimSpace(d.DokployID); id != "" {
			desiredByID[id] = d
		}
	}
	actualByID := make(map[string]ActualDomain)
	actualByHost := make(map[string]ActualDomain)
	for _, d := range as.Domains {
		host := normaliseHost(d.Host)
		if host == "" {
			continue
		}
		actualByHost[host] = d
		if id := strings.TrimSpace(d.DokployID); id != "" {
			actualByID[id] = d
		}
	}

	// First pass: detect renamed-domain drift on every desired domain that
	// has a Dokploy ID we can pin against actual.
	for _, dd := range ds.Domains {
		dokployID := strings.TrimSpace(dd.DokployID)
		if dokployID == "" {
			continue
		}
		ad, ok := actualByID[dokployID]
		if !ok {
			continue
		}
		if normaliseHost(ad.Host) != normaliseHost(dd.Host) {
			plan.Actions = append(plan.Actions, Action{
				Type:    ActionReviewRenamedDomain,
				Kind:    DriftDangerous,
				Reason:  ReasonDomainRenamed,
				Service: ref,
				Domain: DomainRef{
					Service:         ref,
					DomainID:        trimmedID(dd.ID),
					DokployDomainID: dokployID,
				},
			})
		}
	}

	// Second pass: desired domain not represented in actual at all is a
	// safe ensure (re-bind) — unless we already flagged a rename for it.
	for _, dd := range ds.Domains {
		host := normaliseHost(dd.Host)
		dokployID := strings.TrimSpace(dd.DokployID)
		if dokployID != "" {
			if _, ok := actualByID[dokployID]; ok {
				continue // already handled in rename pass
			}
		}
		if _, ok := actualByHost[host]; ok {
			continue
		}
		desiredCopy := dd
		plan.Actions = append(plan.Actions, Action{
			Type:    ActionEnsureDomain,
			Kind:    DriftSafe,
			Reason:  ReasonDomainMissing,
			Service: ref,
			Domain: DomainRef{
				Service:         ref,
				DomainID:        trimmedID(dd.ID),
				DokployDomainID: dokployID,
			},
			DesiredDomain: &desiredCopy,
		})
	}

	// Third pass: actual domains the desired state does not claim (by ID or
	// host) are unmanaged.
	for _, ad := range as.Domains {
		host := normaliseHost(ad.Host)
		dokployID := strings.TrimSpace(ad.DokployID)
		if dokployID != "" {
			if _, ok := desiredByID[dokployID]; ok {
				continue
			}
		}
		if _, ok := desiredByHost[host]; ok {
			continue
		}
		plan.Actions = append(plan.Actions, Action{
			Type:   ActionMarkUnmanaged,
			Kind:   DriftUnmanaged,
			Reason: ReasonResourceUnmanaged,
			Unmanaged: &UnmanagedResource{
				OrganizationID:    ref.OrganizationID,
				Level:             LevelDomain,
				DokployResourceID: dokployID,
				ParentDokployID:   ref.DokployServiceID,
				Reason:            ReasonResourceUnmanaged,
			},
		})
	}
}

func missingServiceAction(ref ServiceRef, ds DesiredService) Action {
	desiredCopy := ds
	if ds.Type == dokploy.ServiceDatabase {
		return Action{
			Type:           ActionReviewMissingDatabase,
			Kind:           DriftDangerous,
			Reason:         ReasonDatabaseMissing,
			Service:        ref,
			DesiredService: &desiredCopy,
		}
	}
	return Action{
		Type:           ActionReviewMissingService,
		Kind:           DriftDangerous,
		Reason:         ReasonServiceMissing,
		Service:        ref,
		DesiredService: &desiredCopy,
	}
}

func unmanagedServiceAction(orgID domain.ID, ae ActualEnvironment, as ActualService) Action {
	return Action{
		Type:   ActionMarkUnmanaged,
		Kind:   DriftUnmanaged,
		Reason: ReasonResourceUnmanaged,
		Unmanaged: &UnmanagedResource{
			OrganizationID:    trimmedID(orgID),
			Level:             LevelService,
			DokployResourceID: strings.TrimSpace(as.DokployID),
			ParentDokployID:   strings.TrimSpace(ae.DokployID),
			Type:              as.Type,
			Reason:            ReasonResourceUnmanaged,
		},
	}
}

func emitMissingProjectReviews(plan *Plan, orgID domain.ID, dp DesiredProject) {
	for _, de := range dp.Environments {
		emitMissingEnvironmentReviews(plan, orgID, dp, de)
	}
}

func emitMissingEnvironmentReviews(plan *Plan, orgID domain.ID, dp DesiredProject, de DesiredEnvironment) {
	for _, ds := range de.Services {
		if strings.TrimSpace(ds.DokployID) == "" {
			continue
		}
		ref := ServiceRef{
			OrganizationID:   trimmedID(orgID),
			ProjectID:        trimmedID(dp.ID),
			EnvironmentID:    trimmedID(de.ID),
			ServiceID:        trimmedID(ds.ID),
			DokployServiceID: strings.TrimSpace(ds.DokployID),
		}
		plan.Actions = append(plan.Actions, missingServiceAction(ref, ds))
	}
}

func emitUnmanagedDescendants(plan *Plan, orgID domain.ID, ap ActualProject) {
	for _, ae := range ap.Environments {
		envID := strings.TrimSpace(ae.DokployID)
		if envID != "" {
			plan.Actions = append(plan.Actions, Action{
				Type:   ActionMarkUnmanaged,
				Kind:   DriftUnmanaged,
				Reason: ReasonResourceUnmanaged,
				Unmanaged: &UnmanagedResource{
					OrganizationID:    trimmedID(orgID),
					Level:             LevelEnvironment,
					DokployResourceID: envID,
					ParentDokployID:   strings.TrimSpace(ap.DokployID),
					Reason:            ReasonResourceUnmanaged,
				},
			})
		}
		for _, svc := range ae.Services {
			plan.Actions = append(plan.Actions, unmanagedServiceAction(orgID, ae, svc))
		}
	}
}

func unionKeys(desired map[string]DesiredEnvVar, actual map[string]ActualEnvVar) []string {
	seen := make(map[string]struct{}, len(desired)+len(actual))
	for k := range desired {
		seen[k] = struct{}{}
	}
	for k := range actual {
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func normaliseHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

func normaliseEngine(engine string) string {
	return strings.ToLower(strings.TrimSpace(engine))
}

func normaliseRole(role dokploy.ServiceRole) string {
	return strings.ToLower(strings.TrimSpace(string(role)))
}

func normaliseBuildForDiff(in dokploy.BuildSettings) dokploy.BuildSettings {
	out := dokploy.BuildSettings{
		Builder:        strings.TrimSpace(in.Builder),
		DockerfilePath: strings.TrimSpace(in.DockerfilePath),
		Image:          strings.TrimSpace(in.Image),
		GitBranch:      strings.TrimSpace(in.GitBranch),
		GitCommit:      strings.TrimSpace(in.GitCommit),
		ArtifactURL:    strings.TrimSpace(in.ArtifactURL),
	}
	if out.Builder == "" {
		out.Builder = dokploy.BuilderDockerfile
	}
	switch out.Builder {
	case dokploy.BuilderDockerfile:
		if out.DockerfilePath == "" {
			out.DockerfilePath = "Dockerfile"
		}
		out.Image = ""
		out.ArtifactURL = ""
	case dokploy.BuilderNixpacks:
		out.DockerfilePath = ""
		out.Image = ""
		out.ArtifactURL = ""
	case dokploy.BuilderImage:
		out.DockerfilePath = ""
		out.GitBranch = ""
		out.GitCommit = ""
		out.ArtifactURL = ""
	case dokploy.BuilderDropArtifact:
		out.DockerfilePath = ""
		out.Image = ""
		out.GitBranch = ""
		out.GitCommit = ""
	}
	return out
}

// sortActions enforces a stable, deterministic action ordering so tests can
// assert on the plan without using set semantics. The ordering is:
//
//  1. Project Dokploy ID (or empty for org-level)
//  2. Environment Dokploy ID
//  3. Service Dokploy ID
//  4. Drift kind (safe < dangerous < unmanaged) — repair before review
//  5. Reason
//  6. Secondary key (env var key, domain host, unmanaged Dokploy ID)
func sortActions(actions []Action) {
	sort.SliceStable(actions, func(i, j int) bool {
		ai, aj := actions[i], actions[j]
		if ai.Service.DokployServiceID != aj.Service.DokployServiceID {
			return ai.Service.DokployServiceID < aj.Service.DokployServiceID
		}
		if ai.Kind != aj.Kind {
			return kindRank(ai.Kind) < kindRank(aj.Kind)
		}
		if ai.Reason != aj.Reason {
			return ai.Reason < aj.Reason
		}
		if ai.EnvVarKey != aj.EnvVarKey {
			return ai.EnvVarKey < aj.EnvVarKey
		}
		hostI, hostJ := "", ""
		if ai.DesiredDomain != nil {
			hostI = normaliseHost(ai.DesiredDomain.Host)
		}
		if aj.DesiredDomain != nil {
			hostJ = normaliseHost(aj.DesiredDomain.Host)
		}
		if hostI != hostJ {
			return hostI < hostJ
		}
		unmanagedI, unmanagedJ := "", ""
		if ai.Unmanaged != nil {
			unmanagedI = ai.Unmanaged.DokployResourceID
		}
		if aj.Unmanaged != nil {
			unmanagedJ = aj.Unmanaged.DokployResourceID
		}
		return unmanagedI < unmanagedJ
	})
}

func kindRank(k DriftKind) int {
	switch k {
	case DriftSafe:
		return 0
	case DriftDangerous:
		return 1
	case DriftUnmanaged:
		return 2
	default:
		return 3
	}
}
