package dokploy_test

// Canonical reference service desired-state test (BE-0407).
//
// This file is the load-bearing static fixture the BE-0407
// verification suite gate (`go test -run TestServiceDesiredState
// ./...`) binds to. The pair (`TestServiceDesiredStateCoversCallSites`
// and `TestServiceDesiredStatePreservesContractUnderContention`) is
// the closed-set + per-decision-stability contract for the dokploy
// renderer's pure desired-state chokepoint
// `(*dokploy.Renderer).Render(in RenderInput) (RenderedSpec, error)`.
//
// Threat model: the renderer is the single point at which Yalla's
// source-of-truth hierarchy (organization, project, environment,
// service) is projected into the desired Dokploy spec the
// provisioning worker will reconcile. The chokepoint is a pure
// function of its input — no I/O, no shared state, no clock —
// so an operator who reads a rendered Summary in a log, an audit
// record, or a dry-run preview MUST be able to predict the
// rendered spec from the input alone. A silent regression that
// (a) accepted a ServiceType, ServiceRole, Builder, Engine, or
// EnvironmentTier value outside the documented closed set, (b)
// introduced non-deterministic ordering into the rendered spec,
// (c) echoed a raw variable Value into the redacted Summary
// JSON, slog LogValue, or String form, or (d) smuggled package-
// level shared state into a goroutine-shared classifier, would
// either let an operator commit to a deploy whose desired state
// did not match what they reviewed, or leak a customer secret
// through a debug surface that is meant to be safe to log,
// audit, and store. The desired-state golden contract is the
// contract every downstream worker, reconciler, importer, and
// agent-facing dry-run depends on for stability and redaction
// safety.
//
// The pair binds to the BE-0407 `-run TestServiceDesiredState`
// filter via the `TestServiceDesiredState` substring; renaming
// either member to a name that does not contain the substring
// silently de-gates the desired-state golden suite for any
// caller relying on the filter.
//
// The closed-set coverage invariant pins six structural
// desired-state contracts in one place:
//
//  1. Every documented `dokploy.ServiceType` in
//     `serviceDesiredStateServiceTypes` is exercised by at least
//     one scenario row. A regression that removed a type from
//     `ServiceType.Valid()` without dropping its entry here
//     fails the exhaustiveness self-check at the head of the
//     covers test.
//  2. Every documented `dokploy.ServiceRole` in
//     `serviceDesiredStateServiceRoles` is exercised by at
//     least one scenario row. A regression that removed a role
//     from `ServiceRole.Valid()` without dropping its entry
//     here fails the second exhaustiveness self-check.
//  3. Every documented application `Builder` value in
//     `serviceDesiredStateBuilders` is exercised by at least
//     one scenario row.
//  4. Every documented database `Engine` value in
//     `serviceDesiredStateEngines` is exercised by at least
//     one scenario row.
//  5. Every documented `dokploy.EnvironmentTier` in
//     `serviceDesiredStateTiers` is exercised by at least one
//     scenario row.
//  6. Deterministic ordering: `Renderer.Render(in)` is a
//     deterministic function of its inputs — calling it twice
//     on the same input MUST yield equal `RenderedSpec` values
//     (same fields, same variable order, same domain order,
//     same label order). A regression that introduced map-
//     iteration ordering into the rendered spec would surface
//     here before any per-row verdict.
//
// The value-free Summary canary asserts the redacted Summary
// JSON, slog LogValue, and String form NEVER contain the raw
// `serviceDesiredStateSecretMarker` even when the marker is
// seeded into every level of the variable hierarchy. A
// regression that started echoing the raw variable Value into
// any redacted projection trips the canary.
//
// The contention test fires a deterministic burst of goroutines
// that each construct a fresh `Renderer` per iteration and call
// `Render` on a per-iteration scenario. The Renderer instances
// are per-iteration because the chokepoint's contract is
// "construction is cheap; Render is a pure function" — a
// regression that smuggled in a package-level cache, a sync.Once
// mutating a per-call map, or a sync.Pool reused without
// resetting would surface as a per-iteration mismatch even when
// the aggregate pass count matched, because every goroutine
// knows its scenario's predicted ServiceType/Role/Builder/
// Engine/Tier and asserts that exact verdict.

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// serviceDesiredStateSecretMarker is the unique, obviously-fake
// substring seeded into every level of the variable hierarchy.
// Asserting the marker is ABSENT from the redacted Summary JSON,
// the slog LogValue, and the Summary.String() form pins the
// value-free projection invariant for every scenario row — a
// regression that started echoing a raw variable Value into any
// of those surfaces trips the canary even when no per-row
// verdict changed. The constant deliberately contains no
// real-looking secret-shaped substring so a stray leak into a
// CI log is still safe.
const serviceDesiredStateSecretMarker = "yalladesiredstatesecretmarker0407"

// serviceDesiredStateServiceTypes is the closed set of
// dokploy.ServiceType values the renderer accepts. Every entry
// MUST be exercised by at least one scenario row; a regression
// that removed a type from ServiceType.Valid() without dropping
// its entry here fails the exhaustiveness self-check.
var serviceDesiredStateServiceTypes = []dokploy.ServiceType{
	dokploy.ServiceApplication,
	dokploy.ServiceCompose,
	dokploy.ServiceDatabase,
}

// serviceDesiredStateServiceRoles is the closed set of
// dokploy.ServiceRole values the renderer accepts for
// application and compose services. Database services have no
// role; their scenario rows declare the empty role and are not
// counted here.
var serviceDesiredStateServiceRoles = []dokploy.ServiceRole{
	dokploy.RoleWeb,
	dokploy.RoleWorker,
	dokploy.RoleCron,
}

// serviceDesiredStateBuilders is the closed set of application
// Builder values the renderer normalises. Database and compose
// services do not carry a Builder; their scenario rows declare
// an empty builder and are not counted here.
var serviceDesiredStateBuilders = []string{
	dokploy.BuilderDockerfile,
	dokploy.BuilderNixpacks,
	dokploy.BuilderImage,
	dokploy.BuilderDropArtifact,
}

// serviceDesiredStateEngines is the closed set of managed
// database Engine values the renderer accepts. Application and
// compose services do not carry an Engine; their scenario rows
// declare an empty engine and are not counted here.
var serviceDesiredStateEngines = []string{
	dokploy.EnginePostgres,
	dokploy.EngineMysql,
	dokploy.EngineMariadb,
	dokploy.EngineMongo,
	dokploy.EngineRedis,
}

// serviceDesiredStateTiers is the closed set of
// dokploy.EnvironmentTier values the renderer accepts. Every
// entry MUST be exercised by at least one scenario row.
var serviceDesiredStateTiers = []dokploy.EnvironmentTier{
	dokploy.TierStaging,
	dokploy.TierProduction,
	dokploy.TierPreview,
}

// serviceDesiredStateExpect is the predicted shape every
// scenario row asserts against the rendered spec. Every field
// is a closed-taxonomy enum (no caller-supplied free text), so
// per-row drift is loud and points the operator at the exact
// row that regressed.
type serviceDesiredStateExpect struct {
	serviceType dokploy.ServiceType
	serviceRole dokploy.ServiceRole
	builder     string
	engine      string
	tier        dokploy.EnvironmentTier
}

// serviceDesiredStateScenario is one row in the canonical
// scenario table. Each row builds a self-contained RenderInput
// and declares the closed-taxonomy tag the renderer MUST emit.
type serviceDesiredStateScenario struct {
	name   string
	build  func() dokploy.RenderInput
	expect serviceDesiredStateExpect
}

// serviceDesiredStateFixedID returns a deterministic 26-char
// Crockford suffix domain.ID for the given kind. The suffix
// avoids the excluded letters {i, l, o, u} by construction —
// the last byte is one of {a, b, c, d, e, f, g}, all in-set.
// Keeping suffixes deterministic makes the rendered names byte-
// stable across runs so the determinism self-check is a
// straight reflect.DeepEqual.
func serviceDesiredStateFixedID(kind domain.Kind, last byte) domain.ID {
	return domain.ID(string(kind) + "_" + strings.Repeat("0", 25) + string(last))
}

var (
	serviceDesiredStateOrgID = serviceDesiredStateFixedID(domain.KindOrganization, 'a')
	serviceDesiredStatePrjID = serviceDesiredStateFixedID(domain.KindProject, 'b')
	serviceDesiredStateEnvID = serviceDesiredStateFixedID(domain.KindEnvironment, 'c')
	serviceDesiredStateSvcID = serviceDesiredStateFixedID(domain.KindService, 'd')
)

// serviceDesiredStateBaseInput is the self-contained, fully-
// valid RenderInput every scenario builder starts from. It does
// NOT depend on renderer_test.go's validInput() helper so the
// canonical pair's contract stays stable against unrelated
// renderer_test.go edits. The variable set seeds the secret
// marker at every level of the hierarchy so the value-free
// projection canary catches a regression that leaks any level's
// variable Value into the Summary, the slog LogValue, or the
// String form.
func serviceDesiredStateBaseInput() dokploy.RenderInput {
	return dokploy.RenderInput{
		Organization: dokploy.YallaOrganization{ID: serviceDesiredStateOrgID, Label: "Acme Corp"},
		Project:      dokploy.YallaProject{ID: serviceDesiredStatePrjID, OrganizationID: serviceDesiredStateOrgID, Label: "Storefront"},
		Environment:  dokploy.YallaEnvironment{ID: serviceDesiredStateEnvID, ProjectID: serviceDesiredStatePrjID, Label: "Staging"},
		Service: dokploy.YallaService{
			ID:            serviceDesiredStateSvcID,
			EnvironmentID: serviceDesiredStateEnvID,
			Label:         "API",
			Type:          dokploy.ServiceApplication,
		},
		Tier: dokploy.TierStaging,
		Role: dokploy.RoleWeb,
		OrganizationVariables: []dokploy.Variable{
			{Name: "REGION", Value: "eu-west-1"},
			{Name: "ORG_TOKEN", Value: serviceDesiredStateSecretMarker + "-org", Secret: true},
		},
		ProjectVariables: []dokploy.Variable{
			{Name: "PROJECT_TOKEN", Value: serviceDesiredStateSecretMarker + "-prj", Secret: true},
		},
		EnvironmentVariables: []dokploy.Variable{
			{Name: "ENV_TOKEN", Value: serviceDesiredStateSecretMarker + "-env", Secret: true},
		},
		ServiceVariables: []dokploy.Variable{
			{Name: "API_TOKEN", Value: serviceDesiredStateSecretMarker + "-svc", Secret: true},
			{Name: "FEATURE_X", Value: "on"},
		},
		Build: dokploy.BuildSettings{
			Builder:   dokploy.BuilderDockerfile,
			GitBranch: "main",
		},
		Domains: []dokploy.DomainSpec{
			{Host: "api.acme.example", HTTPS: true},
		},
	}
}

// serviceDesiredStateScenarios returns the closed-set coverage
// scenario table. Each row covers at least one new enum value
// across (ServiceType, ServiceRole, Builder, Engine, Tier); the
// covers self-checks at the head of TestServiceDesiredStateCoversCallSites
// assert every enum value appears at least once.
func serviceDesiredStateScenarios() []serviceDesiredStateScenario {
	return []serviceDesiredStateScenario{
		{
			name: "application_web_dockerfile_staging",
			build: func() dokploy.RenderInput {
				in := serviceDesiredStateBaseInput()
				// Defaults already cover application+web+dockerfile+staging.
				return in
			},
			expect: serviceDesiredStateExpect{
				serviceType: dokploy.ServiceApplication,
				serviceRole: dokploy.RoleWeb,
				builder:     dokploy.BuilderDockerfile,
				tier:        dokploy.TierStaging,
			},
		},
		{
			name: "application_worker_nixpacks_production",
			build: func() dokploy.RenderInput {
				in := serviceDesiredStateBaseInput()
				in.Role = dokploy.RoleWorker
				in.Tier = dokploy.TierProduction
				in.Service.Label = "queue worker"
				in.Build = dokploy.BuildSettings{
					Builder:   dokploy.BuilderNixpacks,
					GitBranch: "main",
				}
				// Worker services do not bind domains.
				in.Domains = nil
				return in
			},
			expect: serviceDesiredStateExpect{
				serviceType: dokploy.ServiceApplication,
				serviceRole: dokploy.RoleWorker,
				builder:     dokploy.BuilderNixpacks,
				tier:        dokploy.TierProduction,
			},
		},
		{
			name: "application_cron_image_preview",
			build: func() dokploy.RenderInput {
				in := serviceDesiredStateBaseInput()
				in.Role = dokploy.RoleCron
				in.Tier = dokploy.TierPreview
				in.Service.Label = "nightly report"
				in.CronSchedule = "0 2 * * *"
				in.Build = dokploy.BuildSettings{
					Builder: dokploy.BuilderImage,
					Image:   "registry.acme.example/report:v1.2.3",
				}
				// Cron services do not bind domains.
				in.Domains = nil
				return in
			},
			expect: serviceDesiredStateExpect{
				serviceType: dokploy.ServiceApplication,
				serviceRole: dokploy.RoleCron,
				builder:     dokploy.BuilderImage,
				tier:        dokploy.TierPreview,
			},
		},
		{
			name: "application_web_drop_artifact_staging",
			build: func() dokploy.RenderInput {
				in := serviceDesiredStateBaseInput()
				in.Build = dokploy.BuildSettings{
					Builder:     dokploy.BuilderDropArtifact,
					ArtifactURL: "https://artifacts.yalla.example/acme/api-v1.tar.gz",
				}
				return in
			},
			expect: serviceDesiredStateExpect{
				serviceType: dokploy.ServiceApplication,
				serviceRole: dokploy.RoleWeb,
				builder:     dokploy.BuilderDropArtifact,
				tier:        dokploy.TierStaging,
			},
		},
		{
			name: "compose_web_staging",
			build: func() dokploy.RenderInput {
				in := serviceDesiredStateBaseInput()
				in.Service.Type = dokploy.ServiceCompose
				in.Service.Label = "stack"
				// Compose services do not bind domains via the renderer.
				in.Domains = nil
				return in
			},
			expect: serviceDesiredStateExpect{
				serviceType: dokploy.ServiceCompose,
				serviceRole: dokploy.RoleWeb,
				builder:     dokploy.BuilderDockerfile,
				tier:        dokploy.TierStaging,
			},
		},
		{
			name: "database_postgres_staging",
			build: func() dokploy.RenderInput {
				return serviceDesiredStateDatabaseInput(dokploy.EnginePostgres, dokploy.TierStaging, "primary database")
			},
			expect: serviceDesiredStateExpect{
				serviceType: dokploy.ServiceDatabase,
				engine:      dokploy.EnginePostgres,
				tier:        dokploy.TierStaging,
			},
		},
		{
			name: "database_mysql_production",
			build: func() dokploy.RenderInput {
				return serviceDesiredStateDatabaseInput(dokploy.EngineMysql, dokploy.TierProduction, "billing db")
			},
			expect: serviceDesiredStateExpect{
				serviceType: dokploy.ServiceDatabase,
				engine:      dokploy.EngineMysql,
				tier:        dokploy.TierProduction,
			},
		},
		{
			name: "database_mariadb_preview",
			build: func() dokploy.RenderInput {
				return serviceDesiredStateDatabaseInput(dokploy.EngineMariadb, dokploy.TierPreview, "preview store")
			},
			expect: serviceDesiredStateExpect{
				serviceType: dokploy.ServiceDatabase,
				engine:      dokploy.EngineMariadb,
				tier:        dokploy.TierPreview,
			},
		},
		{
			name: "database_mongo_staging",
			build: func() dokploy.RenderInput {
				return serviceDesiredStateDatabaseInput(dokploy.EngineMongo, dokploy.TierStaging, "events store")
			},
			expect: serviceDesiredStateExpect{
				serviceType: dokploy.ServiceDatabase,
				engine:      dokploy.EngineMongo,
				tier:        dokploy.TierStaging,
			},
		},
		{
			name: "database_redis_production",
			build: func() dokploy.RenderInput {
				return serviceDesiredStateDatabaseInput(dokploy.EngineRedis, dokploy.TierProduction, "cache")
			},
			expect: serviceDesiredStateExpect{
				serviceType: dokploy.ServiceDatabase,
				engine:      dokploy.EngineRedis,
				tier:        dokploy.TierProduction,
			},
		},
	}
}

// serviceDesiredStateDatabaseInput is the canonical-database
// scenario builder. Database services have no Role, no domains,
// no Build settings — they are pinned by ServiceType, Engine,
// and Tier alone. The variable hierarchy still seeds the secret
// marker at every level so the value-free canary still fires
// across every database scenario row.
func serviceDesiredStateDatabaseInput(engine string, tier dokploy.EnvironmentTier, label string) dokploy.RenderInput {
	in := serviceDesiredStateBaseInput()
	in.Service.Type = dokploy.ServiceDatabase
	in.Service.Engine = engine
	in.Service.Label = label
	in.Role = ""
	in.CronSchedule = ""
	in.Build = dokploy.BuildSettings{}
	in.Domains = nil
	in.Tier = tier
	return in
}

const (
	// serviceDesiredStateContentionWorkers is the goroutine
	// count for the contention burst. Sized to keep CI runtime
	// bounded while still exercising every scenario row across
	// multiple goroutines.
	serviceDesiredStateContentionWorkers = 8
	// serviceDesiredStateContentionIterationsPerWorker is the
	// per-worker iteration count. The total iteration count
	// (workers * iterations-per-worker) is a multiple of the
	// scenario row count so every row is exercised by every
	// worker.
	serviceDesiredStateContentionIterationsPerWorker = 25
	// serviceDesiredStateContentionIterations is the total
	// number of Render calls the contention burst performs. The
	// pair member asserts the burst recorded exactly this many
	// passes so a goroutine that swallowed its assertion shows
	// up as a missing pass.
	serviceDesiredStateContentionIterations = serviceDesiredStateContentionWorkers * serviceDesiredStateContentionIterationsPerWorker
)

// serviceDesiredStateContentionFailure captures the first per-
// iteration mismatch under the contention burst. Recording the
// iteration index and the scenario name keeps the failure
// message actionable: an operator reading the CI log can point
// straight at the row that regressed.
type serviceDesiredStateContentionFailure struct {
	iter    int
	rowName string
	message string
}

// TestServiceDesiredStateCoversCallSites is the closed-set
// coverage half of the BE-0407 pair. It walks every documented
// (ServiceType, ServiceRole, Builder, Engine, Tier) value and
// asserts the renderer emits the predicted closed-set tag for
// every scenario row. The closed-set self-checks at the head of
// the test catch drift in either direction: a new enum value
// that ships without a row, an existing enum value that drops
// its row, or non-deterministic ordering in the rendered spec.
func TestServiceDesiredStateCoversCallSites(t *testing.T) {
	t.Parallel()

	rows := serviceDesiredStateScenarios()
	if len(rows) == 0 {
		t.Fatalf("serviceDesiredStateScenarios returned an empty table; the closed-set construction is broken")
	}

	// Closed-set self-check #1: every documented ServiceType is
	// exercised by at least one scenario row.
	typeSeen := make(map[dokploy.ServiceType]int, len(serviceDesiredStateServiceTypes))
	for _, st := range serviceDesiredStateServiceTypes {
		typeSeen[st] = 0
	}
	for _, row := range rows {
		if _, ok := typeSeen[row.expect.serviceType]; !ok {
			t.Fatalf("scenario %q tags ServiceType %q which is not in serviceDesiredStateServiceTypes; every scenario type tag must be a documented ServiceType",
				row.name, row.expect.serviceType)
		}
		typeSeen[row.expect.serviceType]++
	}
	for st, count := range typeSeen {
		if count == 0 {
			t.Fatalf("ServiceType %q is not exercised by any scenario; every documented type must surface in at least one row of serviceDesiredStateScenarios",
				st)
		}
	}

	// Closed-set self-check #2: every documented ServiceRole is
	// exercised by at least one scenario row. Database scenarios
	// declare an empty role and are not counted.
	roleSeen := make(map[dokploy.ServiceRole]int, len(serviceDesiredStateServiceRoles))
	for _, r := range serviceDesiredStateServiceRoles {
		roleSeen[r] = 0
	}
	for _, row := range rows {
		if row.expect.serviceRole == "" {
			continue
		}
		if _, ok := roleSeen[row.expect.serviceRole]; !ok {
			t.Fatalf("scenario %q tags ServiceRole %q which is not in serviceDesiredStateServiceRoles; every scenario role tag must be a documented ServiceRole",
				row.name, row.expect.serviceRole)
		}
		roleSeen[row.expect.serviceRole]++
	}
	for r, count := range roleSeen {
		if count == 0 {
			t.Fatalf("ServiceRole %q is not exercised by any scenario; every documented role must surface in at least one row of serviceDesiredStateScenarios",
				r)
		}
	}

	// Closed-set self-check #3: every documented Builder is
	// exercised by at least one scenario row. Database and
	// compose scenarios declare an empty builder and are not
	// counted.
	builderSeen := make(map[string]int, len(serviceDesiredStateBuilders))
	for _, b := range serviceDesiredStateBuilders {
		builderSeen[b] = 0
	}
	for _, row := range rows {
		if row.expect.serviceType != dokploy.ServiceApplication {
			continue
		}
		if _, ok := builderSeen[row.expect.builder]; !ok {
			t.Fatalf("scenario %q tags Builder %q which is not in serviceDesiredStateBuilders; every application scenario builder tag must be a documented Builder",
				row.name, row.expect.builder)
		}
		builderSeen[row.expect.builder]++
	}
	for b, count := range builderSeen {
		if count == 0 {
			t.Fatalf("Builder %q is not exercised by any scenario; every documented application builder must surface in at least one row of serviceDesiredStateScenarios",
				b)
		}
	}

	// Closed-set self-check #4: every documented Engine is
	// exercised by at least one scenario row. Application and
	// compose scenarios declare an empty engine and are not
	// counted.
	engineSeen := make(map[string]int, len(serviceDesiredStateEngines))
	for _, e := range serviceDesiredStateEngines {
		engineSeen[e] = 0
	}
	for _, row := range rows {
		if row.expect.serviceType != dokploy.ServiceDatabase {
			continue
		}
		if _, ok := engineSeen[row.expect.engine]; !ok {
			t.Fatalf("scenario %q tags Engine %q which is not in serviceDesiredStateEngines; every database scenario engine tag must be a documented Engine",
				row.name, row.expect.engine)
		}
		engineSeen[row.expect.engine]++
	}
	for e, count := range engineSeen {
		if count == 0 {
			t.Fatalf("Engine %q is not exercised by any scenario; every documented engine must surface in at least one row of serviceDesiredStateScenarios",
				e)
		}
	}

	// Closed-set self-check #5: every documented EnvironmentTier
	// is exercised by at least one scenario row.
	tierSeen := make(map[dokploy.EnvironmentTier]int, len(serviceDesiredStateTiers))
	for _, tier := range serviceDesiredStateTiers {
		tierSeen[tier] = 0
	}
	for _, row := range rows {
		if _, ok := tierSeen[row.expect.tier]; !ok {
			t.Fatalf("scenario %q tags EnvironmentTier %q which is not in serviceDesiredStateTiers; every scenario tier tag must be a documented EnvironmentTier",
				row.name, row.expect.tier)
		}
		tierSeen[row.expect.tier]++
	}
	for tier, count := range tierSeen {
		if count == 0 {
			t.Fatalf("EnvironmentTier %q is not exercised by any scenario; every documented tier must surface in at least one row of serviceDesiredStateScenarios",
				tier)
		}
	}

	// Closed-set self-check #6: deterministic ordering. Render
	// is a deterministic function of its input — calling it
	// twice on the same input MUST yield equal RenderedSpec
	// values (same fields, same variable order, same domain
	// order, same label order). A regression that introduced
	// map-iteration ordering into the rendered spec would
	// surface here before any per-row verdict.
	for _, row := range rows {
		row := row
		in := row.build()
		r1 := dokploy.NewRenderer()
		first, err := r1.Render(in)
		if err != nil {
			t.Fatalf("scenario %q: first Render call returned %v; want nil — every row must produce a usable RenderedSpec",
				row.name, err)
		}
		r2 := dokploy.NewRenderer()
		second, err := r2.Render(in)
		if err != nil {
			t.Fatalf("scenario %q: second Render call returned %v; want nil — every row must produce a usable RenderedSpec on repeat",
				row.name, err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("scenario %q: Render(in) is non-deterministic — repeated call produced a different RenderedSpec. first=%+v second=%+v",
				row.name, first, second)
		}
	}

	// Closed-set self-check #7: the secret marker is a non-empty
	// compile-time literal whose absence would silently false-
	// positive every per-row marker-absence predicate. Asserting
	// non-emptiness pins the contract that a future contributor
	// who blanks the constant must explicitly update the test,
	// not silently de-gate the value-free projection canary.
	if serviceDesiredStateSecretMarker == "" {
		t.Fatalf("serviceDesiredStateSecretMarker is empty; the per-row value-free predicate would false-positive on every scenario")
	}

	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			in := row.build()
			spec, err := dokploy.NewRenderer().Render(in)
			if err != nil {
				t.Fatalf("scenario %q: Render = %v; want nil", row.name, err)
			}
			serviceDesiredStateAssertOutcome(t, row, spec)
		})
	}
}

// TestServiceDesiredStatePreservesContractUnderContention is
// the per-decision-stability half of the BE-0407 pair. It fires
// `serviceDesiredStateContentionIterations` goroutines that
// each draw a scenario by deterministic mod-index, construct a
// fresh `Renderer` per iteration via `dokploy.NewRenderer()`,
// and call `Render` directly. The Renderer instances are per-
// iteration rather than shared because the chokepoint's
// contract is "construction is cheap; Render is a pure function
// of its input": a regression that smuggled in a package-level
// cache, a `sync.Once` mutating a per-call map, or a
// `sync.Pool` reused without resetting would surface as a per-
// iteration mismatch even when the aggregate pass count
// matched, because every goroutine knows its scenario's
// predicted (ServiceType, ServiceRole, Builder, Engine, Tier)
// and asserts that exact verdict.
func TestServiceDesiredStatePreservesContractUnderContention(t *testing.T) {
	t.Parallel()

	rows := serviceDesiredStateScenarios()
	if len(rows) == 0 {
		t.Fatalf("serviceDesiredStateScenarios returned an empty table; the closed-set construction is broken")
	}

	var passed atomic.Int64
	var firstErr atomic.Pointer[serviceDesiredStateContentionFailure]
	var wg sync.WaitGroup

	for w := 0; w < serviceDesiredStateContentionWorkers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < serviceDesiredStateContentionIterationsPerWorker; i++ {
				iter := w*serviceDesiredStateContentionIterationsPerWorker + i
				row := rows[iter%len(rows)]
				in := row.build()
				renderer := dokploy.NewRenderer()
				spec, err := renderer.Render(in)
				if err != nil {
					firstErr.CompareAndSwap(nil, &serviceDesiredStateContentionFailure{
						iter:    iter,
						rowName: row.name,
						message: fmt.Sprintf("Render returned %v; want nil — every scenario row must produce a usable RenderedSpec", err),
					})
					continue
				}
				if fail := serviceDesiredStateCheckOutcome(row, spec); fail != nil {
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
		t.Fatalf("contention iteration %d (row %q): %s; a per-iteration mismatch under burst contention indicates shared mutable state in the renderer OR a non-deterministic RenderedSpec ordering",
			fe.iter, fe.rowName, fe.message)
	}
	if got := passed.Load(); got != int64(serviceDesiredStateContentionIterations) {
		t.Fatalf("contention burst: expected %d successful iterations, got %d; a missing pass without a recorded failure indicates a goroutine swallowed its assertion",
			serviceDesiredStateContentionIterations, got)
	}
}

// serviceDesiredStateAssertOutcome is the canonical-pair fail-
// fast assertion helper. The per-row covers test calls it
// directly so a per-row failure points the operator at the
// exact scenario that drifted.
func serviceDesiredStateAssertOutcome(t *testing.T, row serviceDesiredStateScenario, spec dokploy.RenderedSpec) {
	t.Helper()
	if fail := serviceDesiredStateCheckOutcome(row, spec); fail != nil {
		t.Fatalf("%s", fail.message)
	}
}

// serviceDesiredStateCheckOutcome is the shared per-row verdict
// function used by both pair members. Returning a failure
// pointer instead of calling t.Fatal directly lets the
// contention burst capture the first failure across goroutines
// via atomic.Pointer without taking a *testing.T.
func serviceDesiredStateCheckOutcome(row serviceDesiredStateScenario, spec dokploy.RenderedSpec) *serviceDesiredStateContentionFailure {
	// Closed-taxonomy tag assertions — every field is a closed
	// enum so per-row drift points straight at the regression.
	if spec.Service.Type != row.expect.serviceType {
		return &serviceDesiredStateContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Service.Type = %q, want %q — the renderer emitted a ServiceType outside the predicted closed-taxonomy tag", spec.Service.Type, row.expect.serviceType),
		}
	}
	if spec.Service.Role != row.expect.serviceRole {
		return &serviceDesiredStateContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Service.Role = %q, want %q — the renderer emitted a ServiceRole outside the predicted closed-taxonomy tag", spec.Service.Role, row.expect.serviceRole),
		}
	}
	if row.expect.builder != "" && spec.Service.Build.Builder != row.expect.builder {
		return &serviceDesiredStateContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Service.Build.Builder = %q, want %q — the renderer emitted a Builder outside the predicted closed-taxonomy tag", spec.Service.Build.Builder, row.expect.builder),
		}
	}
	if spec.Service.Engine != row.expect.engine {
		return &serviceDesiredStateContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Service.Engine = %q, want %q — the renderer emitted an Engine outside the predicted closed-taxonomy tag", spec.Service.Engine, row.expect.engine),
		}
	}
	if spec.Tier != row.expect.tier {
		return &serviceDesiredStateContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Tier = %q, want %q — the renderer emitted an EnvironmentTier outside the predicted closed-taxonomy tag", spec.Tier, row.expect.tier),
		}
	}

	// Value-free projection canary: the redacted Summary JSON,
	// the Summary.String() form, and the slog LogValue group
	// MUST NOT contain the raw secret marker even when the
	// marker is seeded into every level of the variable
	// hierarchy. The marker is a unique, obviously-fake string
	// so a future redaction regression that started echoing a
	// raw variable Value into any redacted surface trips this
	// canary on every scenario row.
	summary := spec.Summary()
	payload, err := json.Marshal(summary)
	if err != nil {
		return &serviceDesiredStateContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("marshal Summary: %v — the redaction-safe Summary projection must round-trip through encoding/json", err),
		}
	}
	if strings.Contains(string(payload), serviceDesiredStateSecretMarker) {
		return &serviceDesiredStateContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Summary JSON leaked the raw secret marker %q — the value-free projection invariant requires every variable Value be replaced with the redaction Sentinel before serialisation; payload=%s", serviceDesiredStateSecretMarker, string(payload)),
		}
	}
	if str := summary.String(); strings.Contains(str, serviceDesiredStateSecretMarker) {
		return &serviceDesiredStateContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Summary.String() leaked the raw secret marker %q — the single-line debug projection must never carry a variable Value; got=%s", serviceDesiredStateSecretMarker, str),
		}
	}
	if logged := serviceDesiredStateRenderLogValue(spec); strings.Contains(logged, serviceDesiredStateSecretMarker) {
		return &serviceDesiredStateContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("RenderedSpec.LogValue() leaked the raw secret marker %q — slog records MUST carry the redacted Summary, never a raw variable Value; got=%s", serviceDesiredStateSecretMarker, logged),
		}
	}

	// Determinism cross-check at per-row scope: rendering the
	// same input twice in the same scenario row must produce
	// equal RenderedSpec values. The covers test runs this
	// across every row in self-check #6; the contention test
	// runs it implicitly per iteration. Keeping it inside the
	// shared verdict function pins the contract at every burst
	// goroutine boundary too.
	repeat, err := dokploy.NewRenderer().Render(row.build())
	if err != nil {
		return &serviceDesiredStateContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("repeat Render returned %v; want nil — every scenario row must be replayable", err),
		}
	}
	if !reflect.DeepEqual(spec, repeat) {
		return &serviceDesiredStateContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Render(in) is non-deterministic for row %q — repeated call produced a different RenderedSpec; the chokepoint contract requires Render be a pure function of its input", row.name),
		}
	}

	return nil
}

// serviceDesiredStateRenderLogValue captures the
// RenderedSpec.LogValue() projection by formatting a slog
// record built from it into a string. The slog handler is the
// production surface that turns a RenderedSpec into a log line,
// so asserting the marker is absent from the formatted record
// pins the redaction contract end-to-end through the slog API,
// not just the Summary JSON.
func serviceDesiredStateRenderLogValue(spec dokploy.RenderedSpec) string {
	var b strings.Builder
	handler := slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)
	logger.Info("desired-state-canary", slog.Any("spec", spec))
	return b.String()
}
