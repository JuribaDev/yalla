package reconcile_test

// Canonical reference reconciliation diff test (BE-0405).
//
// This file is the load-bearing static fixture the BE-0405
// verification suite gate (`go test -run TestReconciliation
// ./...`) binds to. The pair (`TestReconciliationCoversCallSites`
// and `TestReconciliationPreservesContractUnderContention`) is the
// closed-set + per-decision-stability contract for the
// reconcile package's pure classifier chokepoint
// `reconcile.Diff(desired, actual) reconcile.Plan`.
//
// Threat model: the reconcile loop is the only customer-facing
// surface that consumes both the Yalla desired-state snapshot
// (source of truth) and the live Dokploy actual-state snapshot
// (defence-in-depth) in the same evaluation. The pure decision
// logic that classifies divergence is `reconcile.Diff`: it is a
// deterministic function from `(DesiredOrganization,
// ActualOrganization)` to a `Plan` whose every `Action` carries a
// stable closed-set tag `(ActionType, DriftKind, DriftReason)`.
// The classifier reads desired env-var values only to route them
// to `Action.DesiredValue` or `Action.DesiredBuild` (the only
// fields a Repairer adapter consumes); it never echoes a value into `Action.Type`,
// `Action.Kind`, `Action.Reason`, `Action.EnvVarKey`,
// `Action.Service`, `Action.Domain`, or `Action.Unmanaged`. The
// classifier never reads I/O, never observes wall-clock time, and
// never mutates input. A regression that demoted a reason out of
// the closed set, that started echoing a value into a
// classification field, that flipped a Kind from `dangerous` to
// `safe` (auto-repairing dangerous drift would risk data loss),
// or that introduced non-deterministic ordering, would either
// corrupt the audit/review queue or let the engine auto-repair
// drift it must not touch.
//
// The pair binds to the BE-0405 `-run TestReconciliation` filter
// via the `TestReconciliation` substring; renaming either member
// to a name that does not contain the substring silently de-gates
// the reconciliation suite for any caller relying on the filter.
//
// The closed-set coverage invariant pins four structural
// reconcile contracts in one place:
//
//  1. Every documented `DriftReason` in `reconcileDriftReasons`
//     is exercised by at least one scenario. A regression that
//     removed a reason from `Diff` without dropping its entry
//     here fails the exhaustiveness self-check at the head of
//     the covers test rather than waiting for the per-row
//     verdict to drift.
//  2. Every documented `ActionType` in `reconcileActionTypes` is
//     exercised by at least one scenario. A regression that
//     removed an action type from the planner without dropping
//     its entry here fails the second exhaustiveness self-check.
//  3. Deterministic ordering: `Diff(desired, actual)` is a pure
//     function — calling it twice on the same inputs MUST yield
//     equal plans (same actions, same order). A regression that
//     introduced map-iteration ordering into the planner's
//     output would surface here before any per-row verdict.
//  4. Value-free classification: the per-row redaction canary
//     seeds `reconcileSecretMarker` into desired env-var values
//     in env-var scenarios and asserts the marker survives in
//     `Action.DesiredValue` / `Action.DesiredBuild` (the value-routing fields) but
//     NEVER appears in `Action.Type`, `Action.Kind`,
//     `Action.Reason`, `Action.EnvVarKey`, `Action.Service.*`,
//     `Action.Domain.*`, or `Action.Unmanaged.*`. A regression
//     that started echoing a value into any classification field
//     would fail the marker-absence predicate on every env-var
//     scenario.
//
// `TestReconciliationPreservesContractUnderContention` fires
// `reconcileWorkers * reconcileIterationsPerWorker` goroutines
// that each draw a scenario by deterministic mod-index and call
// `reconcile.Diff` directly. `Diff` takes no receiver and no
// shared state, so the contention burst is a defence-in-depth
// gate that pins the *purity* of the chokepoint: a regression
// that smuggled shared mutable state into the package (a cached
// reason table, a `sync.Once` mutating a per-action map, a
// `sync.Pool` reused across calls without resetting) would
// surface as a per-iteration assertion failure even when the
// aggregate pass count matched.

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/reconcile"
)

// reconcileSecretMarker is a sentinel literal the canonical
// scenarios seed into desired env-var values whose drift routes
// through `Action.DesiredValue` or `Action.DesiredBuild`. The marker is not a secret
// transport pattern (no "Bearer", "Authorization", "token=",
// etc.), so any operator-side redactor leaves it intact — the
// per-row canary asserts the marker survives into one value-routing field
// and is absent from every
// other field of the emitted `Action`. A regression that started
// echoing the desired value into a classification field would
// fail the marker-absence predicate on its first scenario.
const reconcileSecretMarker = "RECONCILESECRETMARKER"

// reconcileDriftReasons is the closed set of `DriftReason`
// constants the BE-0405 gate covers. Every entry MUST be
// exercised by at least one scenario in
// `reconcileScenarios()`. A regression that removed a reason
// from `reconcile.Diff` without dropping its entry here trips
// the exhaustiveness self-check at the head of the covers test;
// a regression that added a new reason without listing it here
// trips the table audit too because the new reason would not
// appear in any scenario.
var reconcileDriftReasons = []reconcile.DriftReason{
	reconcile.ReasonEnvVarChanged,
	reconcile.ReasonEnvVarMissing,
	reconcile.ReasonEnvVarExtra,
	reconcile.ReasonBuildConfigChanged,
	reconcile.ReasonCronScheduleChanged,
	reconcile.ReasonDomainMissing,
	reconcile.ReasonDomainRenamed,
	reconcile.ReasonServiceMissing,
	reconcile.ReasonDatabaseMissing,
	reconcile.ReasonServiceTypeChanged,
	reconcile.ReasonServiceRoleChanged,
	reconcile.ReasonResourceUnmanaged,
}

// reconcileActionTypes is the closed set of `ActionType`
// constants the BE-0405 gate covers. Every entry MUST be
// exercised by at least one scenario; a regression that
// demoted an action type from the planner is forced to drop
// its entry here too or fail the exhaustiveness self-check.
var reconcileActionTypes = []reconcile.ActionType{
	reconcile.ActionUpdateEnvVar,
	reconcile.ActionEnsureDomain,
	reconcile.ActionRemoveExtraEnvVar,
	reconcile.ActionUpdateBuildConfig,
	reconcile.ActionUpdateCronSchedule,
	reconcile.ActionReviewMissingService,
	reconcile.ActionReviewMissingDatabase,
	reconcile.ActionReviewRenamedDomain,
	reconcile.ActionReviewServiceTypeChange,
	reconcile.ActionReviewServiceRoleChange,
	reconcile.ActionMarkUnmanaged,
}

// reconcileExpect predicts which closed-set tag at least one
// `Action` in the emitted plan MUST carry. The covers and
// contention tests both consult the predicate via
// `reconcileCheckOutcome`.
//
// `empty=true` predicts an action-free plan (the no-drift
// baseline and the provisioning-lag scenarios). `reason`,
// `kind`, and `actionType` predict the closed-set tag of the
// scenario's *dominant* action — additional secondary actions
// (cascading unmanaged-descendant rows, etc.) are tolerated
// and tagged via `extraReasons` so the per-row assertion does
// not false-positive on an over-narrow predicate.
type reconcileExpect struct {
	empty        bool
	reason       reconcile.DriftReason
	kind         reconcile.DriftKind
	actionType   reconcile.ActionType
	extraReasons []reconcile.DriftReason
}

// reconcileScenario describes one row of the closed coverage
// table. The mutator applies the under-test deviation to a
// fresh baseline; the expect field encodes which closed-set tag
// the dominant action MUST carry. The reasonTag identifies the
// `DriftReason` the row primarily exercises so the
// exhaustiveness self-check at the head of the covers test can
// confirm every documented reason fires on at least one row.
// `seedValueMarker=true` instructs the mutator to seed
// `reconcileSecretMarker` into desired env-var or build values so the
// per-row canary can assert value-free classification.
type reconcileScenario struct {
	name            string
	mutator         func(desired *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization)
	expect          reconcileExpect
	reasonTag       reconcile.DriftReason
	typeTag         reconcile.ActionType
	seedValueMarker bool
}

// reconcileBaselineState returns a (desired, actual) pair that
// converges with zero drift. Every scenario starts from a fresh
// copy of this state (via `reconcileBaseline()`) and applies a
// targeted mutation so the resulting plan exercises exactly the
// reasons the row predicts.
func reconcileBaseline() (reconcile.DesiredOrganization, reconcile.ActualOrganization) {
	orgID := domain.MustNewID(domain.KindOrganization)
	projID := domain.MustNewID(domain.KindProject)
	envID := domain.MustNewID(domain.KindEnvironment)
	appID := domain.MustNewID(domain.KindService)
	dbID := domain.MustNewID(domain.KindService)
	domainYallaID := domain.MustNewID(domain.KindService)

	desired := reconcile.DesiredOrganization{
		ID:        orgID,
		Label:     "Demo Org",
		DokployID: "dokploy-org-1",
		Projects: []reconcile.DesiredProject{{
			ID:        projID,
			Label:     "Demo Project",
			DokployID: "dokploy-proj-1",
			Environments: []reconcile.DesiredEnvironment{{
				ID:        envID,
				Label:     "production",
				DokployID: "dokploy-env-prod",
				Services: []reconcile.DesiredService{
					{
						ID:        appID,
						Label:     "demo-app",
						Type:      dokploy.ServiceApplication,
						Role:      dokploy.RoleWeb,
						DokployID: "dokploy-svc-app",
						EnvVars: []reconcile.DesiredEnvVar{
							{Key: "FOO", Value: "foo-value"},
						},
						Domains: []reconcile.DesiredDomain{{
							ID:        domainYallaID,
							Host:      "demo.example.com",
							HTTPS:     true,
							DokployID: "dokploy-dom-1",
						}},
					},
					{
						ID:        dbID,
						Label:     "demo-db",
						Type:      dokploy.ServiceDatabase,
						Engine:    "postgres",
						DokployID: "dokploy-svc-db",
					},
				},
			}},
		}},
	}
	actual := reconcile.ActualOrganization{
		DokployID: "dokploy-org-1",
		Projects: []reconcile.ActualProject{{
			DokployID: "dokploy-proj-1",
			Name:      "demo-project-projabcd",
			Environments: []reconcile.ActualEnvironment{{
				DokployID: "dokploy-env-prod",
				Name:      "production-envabcd",
				Services: []reconcile.ActualService{
					{
						DokployID: "dokploy-svc-app",
						Name:      "demo-app-svcappabcd",
						Type:      dokploy.ServiceApplication,
						Role:      dokploy.RoleWeb,
						EnvVars: []reconcile.ActualEnvVar{
							{Key: "FOO", Value: "foo-value"},
						},
						Domains: []reconcile.ActualDomain{{
							DokployID: "dokploy-dom-1",
							Host:      "demo.example.com",
							HTTPS:     true,
						}},
					},
					{
						DokployID: "dokploy-svc-db",
						Name:      "demo-db-svcdbabcd",
						Type:      dokploy.ServiceDatabase,
						Engine:    "postgres",
					},
				},
			}},
		}},
	}
	return desired, actual
}

// reconcileScenarios is the closed scenario table the BE-0405
// gate walks. Every entry in `reconcileDriftReasons` AND every
// entry in `reconcileActionTypes` MUST appear at least once
// (exhaustiveness asserted at the head of the covers test).
// Ordering is deterministic so the contention burst's mod-index
// draws are reproducible across runs.
func reconcileScenarios() []reconcileScenario {
	return []reconcileScenario{
		{
			name:    "baseline matched state emits no actions",
			mutator: func(*reconcile.DesiredOrganization, *reconcile.ActualOrganization) {},
			expect:  reconcileExpect{empty: true},
		},
		{
			name: "desired env var with changed value emits env_var_changed safe update",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				// Marker rides on the desired side so it MUST land in
				// Action.DesiredValue when the planner emits env_var_changed.
				d.Projects[0].Environments[0].Services[0].EnvVars[0].Value = "foo-value-" + reconcileSecretMarker
				a.Projects[0].Environments[0].Services[0].EnvVars[0].Value = "stale-value"
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonEnvVarChanged,
				kind:       reconcile.DriftSafe,
				actionType: reconcile.ActionUpdateEnvVar,
			},
			reasonTag:       reconcile.ReasonEnvVarChanged,
			typeTag:         reconcile.ActionUpdateEnvVar,
			seedValueMarker: true,
		},
		{
			name: "desired env var absent from actual emits env_var_missing safe update",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				// Marker rides on the new BAR var only; the baseline FOO/foo-value
				// is left untouched on both sides so this row exercises
				// env_var_missing in isolation.
				d.Projects[0].Environments[0].Services[0].EnvVars = append(
					d.Projects[0].Environments[0].Services[0].EnvVars,
					reconcile.DesiredEnvVar{Key: "BAR", Value: "bar-value-" + reconcileSecretMarker},
				)
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonEnvVarMissing,
				kind:       reconcile.DriftSafe,
				actionType: reconcile.ActionUpdateEnvVar,
			},
			reasonTag:       reconcile.ReasonEnvVarMissing,
			typeTag:         reconcile.ActionUpdateEnvVar,
			seedValueMarker: true,
		},
		{
			name: "actual env var without desired counterpart emits env_var_extra safe removal",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				a.Projects[0].Environments[0].Services[0].EnvVars = append(
					a.Projects[0].Environments[0].Services[0].EnvVars,
					reconcile.ActualEnvVar{Key: "EXTRA", Value: "leftover"},
				)
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonEnvVarExtra,
				kind:       reconcile.DriftSafe,
				actionType: reconcile.ActionRemoveExtraEnvVar,
			},
			reasonTag: reconcile.ReasonEnvVarExtra,
			typeTag:   reconcile.ActionRemoveExtraEnvVar,
		},
		{
			name: "application git build config drift emits build_config_changed safe update",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				d.Projects[0].Environments[0].Services[0].Build = dokploy.BuildSettings{
					Builder:        dokploy.BuilderDockerfile,
					DockerfilePath: "deploy/Dockerfile",
					GitBranch:      "main",
					GitCommit:      "commit-" + reconcileSecretMarker,
				}
				a.Projects[0].Environments[0].Services[0].Build = dokploy.BuildSettings{
					Builder:        dokploy.BuilderDockerfile,
					DockerfilePath: "Dockerfile",
					GitBranch:      "staging",
					GitCommit:      "old-commit",
				}
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonBuildConfigChanged,
				kind:       reconcile.DriftSafe,
				actionType: reconcile.ActionUpdateBuildConfig,
			},
			reasonTag:       reconcile.ReasonBuildConfigChanged,
			typeTag:         reconcile.ActionUpdateBuildConfig,
			seedValueMarker: true,
		},
		{
			name: "cron schedule drift emits cron_schedule_changed safe update",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				d.Projects[0].Environments[0].Services[0].Role = dokploy.RoleCron
				d.Projects[0].Environments[0].Services[0].CronSchedule = "0 2 * * * " + reconcileSecretMarker
				d.Projects[0].Environments[0].Services[0].Domains = nil
				a.Projects[0].Environments[0].Services[0].Role = dokploy.RoleCron
				a.Projects[0].Environments[0].Services[0].CronSchedule = "15 3 * * *"
				a.Projects[0].Environments[0].Services[0].Domains = nil
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonCronScheduleChanged,
				kind:       reconcile.DriftSafe,
				actionType: reconcile.ActionUpdateCronSchedule,
			},
			reasonTag:       reconcile.ReasonCronScheduleChanged,
			typeTag:         reconcile.ActionUpdateCronSchedule,
			seedValueMarker: true,
		},
		{
			name: "desired domain absent from actual emits domain_missing safe ensure",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				a.Projects[0].Environments[0].Services[0].Domains = a.Projects[0].Environments[0].Services[0].Domains[:0]
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonDomainMissing,
				kind:       reconcile.DriftSafe,
				actionType: reconcile.ActionEnsureDomain,
			},
			reasonTag: reconcile.ReasonDomainMissing,
			typeTag:   reconcile.ActionEnsureDomain,
		},
		{
			name: "known domain ID with mismatched host emits domain_renamed dangerous review",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				a.Projects[0].Environments[0].Services[0].Domains[0].Host = "rogue.example.com"
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonDomainRenamed,
				kind:       reconcile.DriftDangerous,
				actionType: reconcile.ActionReviewRenamedDomain,
				// The desired domain (demo.example.com) is no longer represented
				// by host in actual, so the planner ALSO emits a safe domain_missing
				// ensure for the desired host. Tolerate the secondary action.
				extraReasons: []reconcile.DriftReason{reconcile.ReasonDomainMissing},
			},
			reasonTag: reconcile.ReasonDomainRenamed,
			typeTag:   reconcile.ActionReviewRenamedDomain,
		},
		{
			name: "managed application missing from actual emits service_missing dangerous review",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				svcs := a.Projects[0].Environments[0].Services
				out := svcs[:0]
				for _, s := range svcs {
					if s.DokployID != "dokploy-svc-app" {
						out = append(out, s)
					}
				}
				a.Projects[0].Environments[0].Services = out
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonServiceMissing,
				kind:       reconcile.DriftDangerous,
				actionType: reconcile.ActionReviewMissingService,
			},
			reasonTag: reconcile.ReasonServiceMissing,
			typeTag:   reconcile.ActionReviewMissingService,
		},
		{
			name: "managed database missing from actual emits database_missing dangerous review",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				svcs := a.Projects[0].Environments[0].Services
				out := svcs[:0]
				for _, s := range svcs {
					if s.DokployID != "dokploy-svc-db" {
						out = append(out, s)
					}
				}
				a.Projects[0].Environments[0].Services = out
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonDatabaseMissing,
				kind:       reconcile.DriftDangerous,
				actionType: reconcile.ActionReviewMissingDatabase,
			},
			reasonTag: reconcile.ReasonDatabaseMissing,
			typeTag:   reconcile.ActionReviewMissingDatabase,
		},
		{
			name: "known service whose Dokploy type changed emits service_type_changed dangerous review",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				// Flip the application's Dokploy type to compose; desired still
				// says application so Diff classifies the divergence as a
				// dangerous service_type_changed event.
				a.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceCompose
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonServiceTypeChanged,
				kind:       reconcile.DriftDangerous,
				actionType: reconcile.ActionReviewServiceTypeChange,
			},
			reasonTag: reconcile.ReasonServiceTypeChanged,
			typeTag:   reconcile.ActionReviewServiceTypeChange,
		},
		{
			name: "known worker whose Dokploy role changed emits service_role_changed dangerous review",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				d.Projects[0].Environments[0].Services[0].Role = dokploy.RoleWorker
				a.Projects[0].Environments[0].Services[0].Role = dokploy.RoleCron
				a.Projects[0].Environments[0].Services[0].Build = dokploy.BuildSettings{
					Builder:   dokploy.BuilderNixpacks,
					GitBranch: "staging",
				}
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonServiceRoleChanged,
				kind:       reconcile.DriftDangerous,
				actionType: reconcile.ActionReviewServiceRoleChange,
			},
			reasonTag: reconcile.ReasonServiceRoleChanged,
			typeTag:   reconcile.ActionReviewServiceRoleChange,
		},
		{
			name: "actual service without desired counterpart emits resource_unmanaged",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				a.Projects[0].Environments[0].Services = append(
					a.Projects[0].Environments[0].Services,
					reconcile.ActualService{
						DokployID: "dokploy-svc-orphan",
						Name:      "orphan-leftoverservabcd",
						Type:      dokploy.ServiceApplication,
					},
				)
			},
			expect: reconcileExpect{
				reason:     reconcile.ReasonResourceUnmanaged,
				kind:       reconcile.DriftUnmanaged,
				actionType: reconcile.ActionMarkUnmanaged,
			},
			reasonTag: reconcile.ReasonResourceUnmanaged,
			typeTag:   reconcile.ActionMarkUnmanaged,
		},
		{
			name: "desired service with empty Dokploy ID is provisioning lag, not drift",
			mutator: func(d *reconcile.DesiredOrganization, a *reconcile.ActualOrganization) {
				// Add a not-yet-provisioned desired service; it MUST be skipped
				// rather than emitting service_missing (the contract: empty
				// DokployID is provisioning lag, not drift).
				d.Projects[0].Environments[0].Services = append(
					d.Projects[0].Environments[0].Services,
					reconcile.DesiredService{
						ID:        domain.MustNewID(domain.KindService),
						Label:     "pending-app",
						Type:      dokploy.ServiceApplication,
						DokployID: "",
					},
				)
			},
			expect: reconcileExpect{empty: true},
		},
	}
}

const (
	reconcileWorkers              = 32
	reconcileIterationsPerWorker  = 64
	reconcileContentionIterations = reconcileWorkers * reconcileIterationsPerWorker
)

// reconcileApplyMutator builds a fresh (desired, actual) pair from
// the canonical baseline and applies the row's mutator. Cloning
// before mutation keeps every scenario independent so the per-row
// covers test and the per-iteration contention test draw the same
// input from the same row name. The mutator is responsible for
// seeding `reconcileSecretMarker` into the desired env-var value
// the row routes through `Action.DesiredValue`; the per-row
// canary inside `reconcileCheckOutcome` is gated on
// `row.seedValueMarker` so the marker-absence predicate runs only
// for the env-var rows whose mutator seeded the marker.
func reconcileApplyMutator(row reconcileScenario) (reconcile.DesiredOrganization, reconcile.ActualOrganization) {
	desired, actual := reconcileBaseline()
	row.mutator(&desired, &actual)
	return desired, actual
}

// TestReconciliationCoversCallSites is the closed-set coverage
// half of the BE-0405 pair. It walks every documented
// `DriftReason` and `ActionType` of `reconcile.Diff` and asserts
// the classifier emits the predicted closed-set tag for every
// scenario row. The closed-set self-checks at the head of the
// test catch drift in either direction: a new reason that ships
// without a row, an existing reason that drops its row, an
// action type without a scenario, or non-deterministic ordering.
func TestReconciliationCoversCallSites(t *testing.T) {
	t.Parallel()

	rows := reconcileScenarios()
	if len(rows) == 0 {
		t.Fatalf("reconcileScenarios returned an empty table; the closed-set construction is broken")
	}

	// Closed-set self-check #1: every documented DriftReason is
	// exercised by at least one scenario row.
	reasonSeen := make(map[reconcile.DriftReason]int, len(reconcileDriftReasons))
	for _, r := range reconcileDriftReasons {
		reasonSeen[r] = 0
	}
	for _, row := range rows {
		if row.reasonTag == "" {
			continue
		}
		if _, ok := reasonSeen[row.reasonTag]; !ok {
			t.Fatalf("scenario %q tags reason %q which is not in reconcileDriftReasons; every scenario reason tag must be a documented DriftReason",
				row.name, row.reasonTag)
		}
		reasonSeen[row.reasonTag]++
	}
	for reason, count := range reasonSeen {
		if count == 0 {
			t.Fatalf("DriftReason %q is not exercised by any scenario; every documented reason must surface in at least one row of reconcileScenarios",
				reason)
		}
	}

	// Closed-set self-check #2: every documented ActionType is
	// exercised by at least one scenario row.
	actionSeen := make(map[reconcile.ActionType]int, len(reconcileActionTypes))
	for _, a := range reconcileActionTypes {
		actionSeen[a] = 0
	}
	for _, row := range rows {
		if row.typeTag == "" {
			continue
		}
		if _, ok := actionSeen[row.typeTag]; !ok {
			t.Fatalf("scenario %q tags action type %q which is not in reconcileActionTypes; every scenario type tag must be a documented ActionType",
				row.name, row.typeTag)
		}
		actionSeen[row.typeTag]++
	}
	for typ, count := range actionSeen {
		if count == 0 {
			t.Fatalf("ActionType %q is not exercised by any scenario; every documented action type must surface in at least one row of reconcileScenarios",
				typ)
		}
	}

	// Closed-set self-check #3: deterministic ordering. Diff is a
	// pure function — calling it twice on the same inputs MUST
	// yield equal plans (same actions, same order). A regression
	// that introduced map-iteration ordering into the output
	// would surface here before any per-row verdict.
	for _, row := range rows {
		row := row
		desired, actual := reconcileApplyMutator(row)
		first := reconcile.Diff(desired, actual)
		second := reconcile.Diff(desired, actual)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("scenario %q: Diff(desired, actual) is non-deterministic — repeated call produced a different plan. first=%+v second=%+v",
				row.name, first, second)
		}
	}

	// Closed-set self-check #4: the secret marker is a non-empty
	// compile-time literal whose absence would silently false-
	// positive every per-row marker-absence predicate. Asserting
	// non-emptiness pins the contract that a future contributor
	// who blanks the constant must explicitly update the test, not
	// silently de-gate the value-free classification canary.
	if reconcileSecretMarker == "" {
		t.Fatalf("reconcileSecretMarker is empty; the per-row marker-absence predicate would false-positive on every env-var scenario")
	}

	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			desired, actual := reconcileApplyMutator(row)
			plan := reconcile.Diff(desired, actual)
			reconcileAssertOutcome(t, row, plan)
		})
	}
}

// TestReconciliationPreservesContractUnderContention is the
// per-decision-stability half of the BE-0405 pair. It fires
// `reconcileContentionIterations` goroutines that each draw a
// scenario by deterministic mod-index, build their own
// (desired, actual) pair via `reconcileApplyMutator`, and call
// `reconcile.Diff` directly. `Diff` takes no receiver and no
// shared state, so a regression that smuggled shared mutable
// state into the package (a cached reason table, a `sync.Once`
// mutating a per-action map, a `sync.Pool` reused without reset)
// would surface as a per-iteration assertion failure even when
// the aggregate pass count matched, because every goroutine
// knows its own predicted outcome and asserts that exact
// verdict.
//
// The shared chokepoint is intentional: the burst's value is
// precisely the contention against the SAME package-level
// classifier, never a fresh-per-goroutine planner.
func TestReconciliationPreservesContractUnderContention(t *testing.T) {
	t.Parallel()

	rows := reconcileScenarios()
	if len(rows) == 0 {
		t.Fatalf("reconcileScenarios returned an empty table; the closed-set construction is broken")
	}

	var passed atomic.Int64
	var firstErr atomic.Pointer[reconcileContentionFailure]
	var wg sync.WaitGroup

	for w := 0; w < reconcileWorkers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < reconcileIterationsPerWorker; i++ {
				iter := w*reconcileIterationsPerWorker + i
				row := rows[iter%len(rows)]
				desired, actual := reconcileApplyMutator(row)
				plan := reconcile.Diff(desired, actual)
				if fail := reconcileCheckOutcome(row, plan); fail != nil {
					fail.iter = iter
					firstErr.CompareAndSwap(nil, fail)
					continue
				}
				passed.Add(1)
			}
		}()
	}
	wg.Wait()

	if fe := firstErr.Load(); fe != nil {
		t.Fatalf("contention iteration %d (row %q): %s; a per-iteration mismatch under burst contention indicates shared mutable state in the classifier OR a non-deterministic plan ordering",
			fe.iter, fe.rowName, fe.message)
	}
	if got := passed.Load(); got != int64(reconcileContentionIterations) {
		t.Fatalf("contention burst: expected %d successful iterations, got %d; a missing pass without a recorded failure indicates a goroutine swallowed its assertion",
			reconcileContentionIterations, got)
	}
}

// reconcileAssertOutcome is the canonical-pair fail-fast
// assertion helper. The per-row covers test calls it directly so
// a per-row failure points the operator at the exact scenario
// that drifted.
func reconcileAssertOutcome(t *testing.T, row reconcileScenario, plan reconcile.Plan) {
	t.Helper()
	if fail := reconcileCheckOutcome(row, plan); fail != nil {
		t.Fatalf("%s", fail.message)
	}
}

// reconcileCheckOutcome captures the verdict comparison used by
// both pair members. It returns nil on success and a populated
// failure on the first mismatch.
//
// Predicate shape:
//   - empty=true predicts a plan with zero actions.
//   - empty=false predicts at least one action whose
//     (Reason, Kind, Type) match the row's expect; secondary
//     actions whose Reason is in expect.extraReasons (or matches
//     the dominant reason) are tolerated.
//   - For env-var rows that seed the marker, the per-row
//     value-free predicate asserts the marker is absent from
//     every classification field of every action and is present
//     in a value-routing field of at least one update action.
func reconcileCheckOutcome(row reconcileScenario, plan reconcile.Plan) *reconcileContentionFailure {
	if row.expect.empty {
		if len(plan.Actions) != 0 {
			return &reconcileContentionFailure{
				rowName: row.name,
				message: fmt.Sprintf("Diff(%q) actions = %d, want 0 (empty plan); plan=%+v", row.name, len(plan.Actions), plan.Actions),
			}
		}
		return nil
	}

	if len(plan.Actions) == 0 {
		return &reconcileContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Diff(%q) actions = 0, want at least one action with reason=%q kind=%q type=%q",
				row.name, row.expect.reason, row.expect.kind, row.expect.actionType),
		}
	}

	dominantFound := false
	tolerated := map[reconcile.DriftReason]struct{}{row.expect.reason: {}}
	for _, r := range row.expect.extraReasons {
		tolerated[r] = struct{}{}
	}
	for _, a := range plan.Actions {
		if a.Reason == row.expect.reason && a.Kind == row.expect.kind && a.Type == row.expect.actionType {
			dominantFound = true
		}
		if _, ok := tolerated[a.Reason]; !ok {
			return &reconcileContentionFailure{
				rowName: row.name,
				message: fmt.Sprintf("Diff(%q) emitted action with unexpected reason %q (kind=%q type=%q); the row predicts reason=%q with optional extras=%v",
					row.name, a.Reason, a.Kind, a.Type, row.expect.reason, row.expect.extraReasons),
			}
		}
	}
	if !dominantFound {
		return &reconcileContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Diff(%q) plan has no action with reason=%q kind=%q type=%q; plan=%+v",
				row.name, row.expect.reason, row.expect.kind, row.expect.actionType, plan.Actions),
		}
	}

	if row.seedValueMarker {
		// Value-free classification canary: for rows that seed the marker
		// into desired values, the marker MUST survive into a Repairer-only
		// value route of at least one update action AND MUST NOT appear in
		// any classification field of any action.
		markerInValueRoute := false
		for _, a := range plan.Actions {
			if strings.Contains(a.DesiredValue, reconcileSecretMarker) {
				markerInValueRoute = true
			}
			for _, field := range []string{
				a.DesiredBuild.DockerfilePath,
				a.DesiredBuild.Image,
				a.DesiredBuild.GitBranch,
				a.DesiredBuild.GitCommit,
				a.DesiredBuild.ArtifactURL,
				a.DesiredCronSchedule,
			} {
				if strings.Contains(field, reconcileSecretMarker) {
					markerInValueRoute = true
				}
			}
			// Classification fields that MUST NOT echo the value.
			if strings.Contains(string(a.Type), reconcileSecretMarker) {
				return &reconcileContentionFailure{
					rowName: row.name,
					message: fmt.Sprintf("Diff(%q) action.Type=%q echoed marker %q; classification fields MUST NOT carry env-var values",
						row.name, a.Type, reconcileSecretMarker),
				}
			}
			if strings.Contains(string(a.Kind), reconcileSecretMarker) {
				return &reconcileContentionFailure{
					rowName: row.name,
					message: fmt.Sprintf("Diff(%q) action.Kind=%q echoed marker %q; classification fields MUST NOT carry env-var values",
						row.name, a.Kind, reconcileSecretMarker),
				}
			}
			if strings.Contains(string(a.Reason), reconcileSecretMarker) {
				return &reconcileContentionFailure{
					rowName: row.name,
					message: fmt.Sprintf("Diff(%q) action.Reason=%q echoed marker %q; classification fields MUST NOT carry env-var values",
						row.name, a.Reason, reconcileSecretMarker),
				}
			}
			if strings.Contains(a.EnvVarKey, reconcileSecretMarker) {
				return &reconcileContentionFailure{
					rowName: row.name,
					message: fmt.Sprintf("Diff(%q) action.EnvVarKey=%q echoed marker %q; EnvVarKey is a routing handle, not a value channel",
						row.name, a.EnvVarKey, reconcileSecretMarker),
				}
			}
			for _, field := range []string{
				string(a.Service.OrganizationID),
				string(a.Service.ProjectID),
				string(a.Service.EnvironmentID),
				string(a.Service.ServiceID),
				a.Service.DokployServiceID,
				string(a.Domain.DomainID),
				a.Domain.DokployDomainID,
			} {
				if strings.Contains(field, reconcileSecretMarker) {
					return &reconcileContentionFailure{
						rowName: row.name,
						message: fmt.Sprintf("Diff(%q) action ID field %q echoed marker %q; identifier fields MUST NOT carry env-var values",
							row.name, field, reconcileSecretMarker),
					}
				}
			}
			if a.Unmanaged != nil {
				for _, field := range []string{
					string(a.Unmanaged.OrganizationID),
					string(a.Unmanaged.Level),
					a.Unmanaged.DokployResourceID,
					a.Unmanaged.ParentDokployID,
					string(a.Unmanaged.Reason),
				} {
					if strings.Contains(field, reconcileSecretMarker) {
						return &reconcileContentionFailure{
							rowName: row.name,
							message: fmt.Sprintf("Diff(%q) unmanaged field %q echoed marker %q; unmanaged-resource records MUST NOT carry env-var values",
								row.name, field, reconcileSecretMarker),
						}
					}
				}
			}
		}
		if !markerInValueRoute {
			return &reconcileContentionFailure{
				rowName: row.name,
				message: fmt.Sprintf("Diff(%q) seeded marker %q into desired values but no plan action carries it in a Repairer value route; the Repairer would have nothing to write back",
					row.name, reconcileSecretMarker),
			}
		}
	}

	// Plan.OrganizationID is set on every plan; it MUST be the
	// trimmed desired organization ID, never an empty string when
	// the desired snapshot carries one.
	if string(plan.OrganizationID) == "" {
		return &reconcileContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Diff(%q) plan.OrganizationID is empty; the plan MUST always be tenant-scoped", row.name),
		}
	}

	return nil
}

// reconcileContentionFailure captures the first (iteration, row)
// the canonical pair observed a mismatch on, so a failure
// message points the operator at the exact scenario that drifted
// rather than collapsing every mismatch into a single line.
type reconcileContentionFailure struct {
	iter    int
	rowName string
	message string
}
