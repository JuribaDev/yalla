package dokploy_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// BE-0309: Provision postgres services.
//
// This file pins the per-service-type renderer contract for "postgres"
// services. Unlike the application-* and compose pins, the postgres
// subtype boundary at the renderer layer is the Engine value on a
// ServiceDatabase service — not the ServiceType and not the Build.Builder.
// A future BE-0311 (mysql) / BE-0313 (mariadb) / BE-0315 (mongo) /
// BE-0317 (redis) story will clone this file and pin its own engine; the
// closed validEngine() whitelist in renderer.go is the production-code
// seam each sibling story extends by one constant.
//
// Subtype identity at the renderer layer:
//
//	Service.Type == ServiceDatabase
//	Service.Engine == EnginePostgres ("postgres")
//	Role         dropped (effectiveRole = "" for database services)
//	Domains      dropped (effectiveRole != RoleWeb)
//	CronSchedule dropped (effectiveRole != RoleCron)
//
// While the durable provisioning worker that creates or updates the
// matching Dokploy postgres resource and stores dokploy_refs atomically
// lands in a later worker story, this file is the structural barrier that
// pins the declarative-content half of the BE-0309 acceptance contract:
//
//   - The renderer validates every required field with stable, indexed
//     apierr.FieldViolations whose Reason text never echoes the submitted
//     value (a violation message is always safe for client envelopes,
//     logs, and audit metadata).
//   - The renderer preserves Service.Engine == EnginePostgres verbatim
//     across renders and surfaces it as the yalla.engine label so the
//     subtype is visible to downstream audit/observability consumers
//     without re-reading the spec body.
//   - The renderer drops Role, Domains, and CronSchedule for a database
//     service — even if the caller submits all three — so a postgres
//     service can never accidentally render as a web/worker/cron shape.
//   - Database services do NOT participate in the production-web 2-replica
//     bump (defaultResources only bumps for application/compose with
//     RoleWeb on TierProduction); every tier × replicas combination for
//     postgres defaults to one replica.
//   - The renderer carries verbatim variable values for the worker but
//     redacts every value (secret-flagged or not) in the Summary, slog
//     LogValue, and Summary.String() debug surface — so the secrets
//     redaction acceptance criterion is structurally enforced.
//
// Pattern: this is the renderer-level counterpart to the engine-pin
// pattern used for admin-action policy matrices (BE-0285 / BE-0288 /
// BE-0291 / BE-0294 / BE-0297 / BE-0300) and the structural sibling of
// renderer_application_git_test.go (BE-0301),
// renderer_application_image_test.go (BE-0303),
// renderer_application_drop_artifact_test.go (BE-0305), and
// renderer_compose_test.go (BE-0307) — a state-independent file that
// pins the contract the worker-side story must continue to satisfy.

// databasePostgresInput returns a fully-valid postgres RenderInput. It
// reuses validInput() (from renderer_test.go) for the hierarchy and
// variable fixtures so the canonical-id and per-level secret sets stay in
// lockstep with every other renderer pin. The Role / Domains /
// CronSchedule fields are explicitly populated to a non-zero web shape so
// the "database drops role/domains/cron" subtype-boundary assertions
// prove the renderer's drop semantics rather than passively absorbing
// zero values.
func databasePostgresInput() dokploy.RenderInput {
	in := validInput()
	in.Service.Type = dokploy.ServiceDatabase
	in.Service.Engine = dokploy.EnginePostgres
	in.Role = dokploy.RoleWeb
	in.CronSchedule = "0 2 * * *"
	in.Domains = []dokploy.DomainSpec{
		{Host: "db.acme.example", HTTPS: true},
	}
	return in
}

// TestRenderDatabasePostgresSuccess pins the canonical postgres happy
// path: Type=database, Engine=postgres, the engine is preserved verbatim
// on the rendered service and surfaced as the yalla.engine label, and
// the role / domains / cron schedule submitted in the input are all
// dropped because a database is not a web/worker/cron service.
func TestRenderDatabasePostgresSuccess(t *testing.T) {
	t.Parallel()

	spec := mustRender(t, databasePostgresInput())

	if spec.Service.Type != dokploy.ServiceDatabase {
		t.Errorf("service type = %q, want database", spec.Service.Type)
	}
	if spec.Service.Engine != dokploy.EnginePostgres {
		t.Errorf("engine = %q, want %q", spec.Service.Engine, dokploy.EnginePostgres)
	}
	if spec.Service.Role != "" {
		t.Errorf("postgres rendered Role = %q, want dropped (database services have no role)", spec.Service.Role)
	}
	if got := len(spec.Service.Domains); got != 0 {
		t.Errorf("postgres rendered Domains = %d, want 0 (database services have no domains)", got)
	}
	if spec.Service.CronSchedule != "" {
		t.Errorf("postgres rendered CronSchedule = %q, want dropped (database services have no cron)", spec.Service.CronSchedule)
	}

	// The yalla.engine label is the audit/observability surface that
	// distinguishes a postgres database from a future mysql/mongo/redis
	// database without re-reading the spec body. yalla.service-type
	// stays "database" — the engine is the discriminator.
	var typeLabel, engineLabel, roleLabel string
	for _, l := range spec.Service.Labels {
		switch l.Key {
		case "yalla.service-type":
			typeLabel = l.Value
		case "yalla.engine":
			engineLabel = l.Value
		case "yalla.role":
			roleLabel = l.Value
		}
	}
	if typeLabel != string(dokploy.ServiceDatabase) {
		t.Errorf("yalla.service-type label = %q, want %q", typeLabel, dokploy.ServiceDatabase)
	}
	if engineLabel != dokploy.EnginePostgres {
		t.Errorf("yalla.engine label = %q, want %q", engineLabel, dokploy.EnginePostgres)
	}
	if roleLabel != "" {
		t.Errorf("yalla.role label = %q, want unset for database services", roleLabel)
	}
}

// TestRenderDatabasePostgresSubtypeBoundaryFromApplication is the
// per-service-type subtype-boundary pin: a RenderInput whose
// Service.Type is ServiceDatabase + Engine == EnginePostgres must render
// with Service.Type == ServiceDatabase and Service.Engine ==
// EnginePostgres — never silently coerced to ServiceApplication and
// never silently re-typed to any other engine — even when the submitted
// Variables, Build, and hierarchy are otherwise identical to an
// application-git input. The reverse holds too: an application input
// must NOT render as a database and must NOT carry an engine. This is
// the structural barrier against any future refactor that conflates
// "application" with "database" inside the type switch in Render() or
// that silently rewrites the engine in renderLabels().
func TestRenderDatabasePostgresSubtypeBoundaryFromApplication(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		in         func() dokploy.RenderInput
		wantType   dokploy.ServiceType
		wantEngine string
	}{
		{
			name:       "postgres stays postgres",
			in:         databasePostgresInput,
			wantType:   dokploy.ServiceDatabase,
			wantEngine: dokploy.EnginePostgres,
		},
		{
			name:       "application stays application",
			in:         applicationGitDockerfileInput,
			wantType:   dokploy.ServiceApplication,
			wantEngine: "",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			spec := mustRender(t, c.in())
			if spec.Service.Type != c.wantType {
				t.Errorf("service type = %q, want %q", spec.Service.Type, c.wantType)
			}
			if spec.Service.Engine != c.wantEngine {
				t.Errorf("service engine = %q, want %q", spec.Service.Engine, c.wantEngine)
			}

			// Labels must reflect the rendered type and engine
			// verbatim. The yalla.engine label is present only for
			// database services, mirroring how yalla.role is present
			// only for application/compose services.
			var typeLabel, engineLabel string
			var engineLabelPresent bool
			for _, l := range spec.Service.Labels {
				switch l.Key {
				case "yalla.service-type":
					typeLabel = l.Value
				case "yalla.engine":
					engineLabel = l.Value
					engineLabelPresent = true
				}
			}
			if typeLabel != string(c.wantType) {
				t.Errorf("yalla.service-type label = %q, want %q", typeLabel, c.wantType)
			}
			if c.wantEngine == "" {
				if engineLabelPresent {
					t.Errorf("yalla.engine label = %q present, want absent for non-database service", engineLabel)
				}
			} else {
				if engineLabel != c.wantEngine {
					t.Errorf("yalla.engine label = %q, want %q", engineLabel, c.wantEngine)
				}
			}
		})
	}
}

// TestRenderDatabasePostgresDropsRoleDomainsAndCron is the explicit
// subtype-boundary pin against the application/compose sub-shapes: a
// postgres input that submits Role=RoleWeb, a non-empty Domains slice,
// AND a CronSchedule must render with NONE of them present on the
// rendered service. This proves the renderer's drop semantics
// individually for each of the three application/compose-only fields
// and prevents a future refactor of the type switch in Render() from
// silently leaking any of them through for a database service.
func TestRenderDatabasePostgresDropsRoleDomainsAndCron(t *testing.T) {
	t.Parallel()

	in := databasePostgresInput()
	// Re-affirm every application/compose-only field is populated in the
	// input so the rendered drops below are observably load-bearing.
	if in.Role == "" || len(in.Domains) == 0 || in.CronSchedule == "" {
		t.Fatalf("test setup: expected non-empty role/domains/cron in input, got %+v", in)
	}

	spec := mustRender(t, in)

	if spec.Service.Role != "" {
		t.Errorf("Role = %q, want dropped", spec.Service.Role)
	}
	if got := len(spec.Service.Domains); got != 0 {
		t.Errorf("Domains = %d items, want dropped", got)
	}
	if spec.Service.CronSchedule != "" {
		t.Errorf("CronSchedule = %q, want dropped", spec.Service.CronSchedule)
	}

	// Drops must also be reflected in the redaction-safe debug surfaces:
	// Summary JSON / slog record / Summary.String() must not leak the
	// dropped values (a future logging path that re-introduced any of
	// the dropped fields would break this assertion).
	summary := spec.Summary()
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("rendered", "spec", spec, "summary", summary)

	for label, s := range map[string]string{
		"summary json":   string(summaryJSON),
		"slog record":    logBuf.String(),
		"summary string": summary.String(),
	} {
		if strings.Contains(s, "db.acme.example") {
			t.Errorf("%s leaked the dropped domain host: %s", label, s)
		}
		if strings.Contains(s, "0 2 * * *") {
			t.Errorf("%s leaked the dropped cron schedule: %s", label, s)
		}
	}
}

// TestRenderDatabasePostgresValidationFailures pins that every required
// field the renderer rejects for a postgres input becomes a typed
// apierr.InvalidInput with a stable, indexed Field path, and that no
// submitted value is ever echoed into the rendered error surface. The
// table covers the failure modes most relevant to postgres: hierarchy
// identity, parent linkage, environment tier, service type, the
// database-specific missing-engine and unsupported-engine cases (the
// engine-value check is the seam the BE-0311..0317 stories extend by
// adding their constant to validEngine), variable name rejection (no
// value echo), and negative resource limits — using a postgres base.
func TestRenderDatabasePostgresValidationFailures(t *testing.T) {
	t.Parallel()

	leakyValues := []string{
		"not-a-yalla-id",
		"1bad",
		"sk-live-supersecret",
		"function",
		"prod-tier",
		"sqlite",
	}

	cases := []struct {
		name      string
		mutate    func(*dokploy.RenderInput)
		wantField string
	}{
		{"bad organization id", func(in *dokploy.RenderInput) {
			in.Organization.ID = "not-a-yalla-id"
		}, "organization.id"},
		{"mismatched project parent", func(in *dokploy.RenderInput) {
			in.Project.OrganizationID = fixedOtherOrg
		}, "project.organization_id"},
		{"bad environment tier", func(in *dokploy.RenderInput) {
			in.Tier = "prod-tier"
		}, "tier"},
		{"bad service type", func(in *dokploy.RenderInput) {
			in.Service.Type = "function"
		}, "service.type"},
		{"missing engine", func(in *dokploy.RenderInput) {
			in.Service.Engine = ""
		}, "service.engine"},
		{"unsupported engine", func(in *dokploy.RenderInput) {
			// "sqlite" is not a Yalla-managed engine. The value is
			// trimmed to non-empty and then rejected by validEngine.
			// Once BE-0311..0317 add their engines, the rejection
			// set narrows but never includes "sqlite", so this case
			// remains stable across the whole BE-0309..0317 family.
			in.Service.Engine = "sqlite"
		}, "service.engine"},
		{"bad variable name", func(in *dokploy.RenderInput) {
			in.ServiceVariables = []dokploy.Variable{
				{Name: "1bad", Value: "sk-live-supersecret", Secret: true},
			}
		}, "service.variables[0].name"},
		{"negative cpu millis", func(in *dokploy.RenderInput) {
			in.Resources = dokploy.ResourceLimits{CPUMillis: -1}
		}, "resources.cpu_millis"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			in := databasePostgresInput()
			c.mutate(&in)
			spec, err := dokploy.NewRenderer().Render(in)
			if err == nil {
				t.Fatalf("expected error, got spec %+v", spec)
			}

			var ye *yerr.Error
			if !yerrAs(err, &ye) || ye.Code != yerr.CodeInvalidInput {
				t.Fatalf("error = %v, want E_INVALID_INPUT", err)
			}

			violations, ok := apierr.ViolationsOf(err)
			if !ok {
				t.Fatalf("error carries no structured violations: %v", err)
			}
			var found bool
			for _, viol := range violations {
				if viol.Field == c.wantField {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("violations %+v do not include field %q", violations, c.wantField)
			}

			// No submitted value is ever echoed into the rendered
			// error. The engine value "sqlite" in particular must
			// not leak into the violation message — the stable
			// Reason "must be a supported database engine" never
			// names the rejected engine.
			rendered := err.Error()
			for _, leak := range leakyValues {
				if strings.Contains(rendered, leak) {
					t.Errorf("error echoed submitted value %q: %v", leak, err)
				}
			}
		})
	}
}

// TestRenderDatabasePostgresTierResourceDefaults pins the tier resource
// defaults for postgres specifically: database services drop Role (so
// effectiveRole is empty for every tier × replicas combination), which
// means a postgres service never participates in the production-web
// 2-replica bump even when the caller submits Role=RoleWeb. Every tier
// defaults to one replica with the tier-default CPU/memory.
func TestRenderDatabasePostgresTierResourceDefaults(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tier         dokploy.EnvironmentTier
		wantCPU      int
		wantMemory   int
		wantReplicas int
	}{
		{dokploy.TierProduction, 1000, 1024, 1},
		{dokploy.TierStaging, 500, 512, 1},
		{dokploy.TierPreview, 250, 256, 1},
	}
	for _, c := range cases {
		c := c
		t.Run(string(c.tier), func(t *testing.T) {
			t.Parallel()
			in := databasePostgresInput()
			in.Tier = c.tier
			spec := mustRender(t, in)
			got := spec.Service.Resources
			if got.CPUMillis != c.wantCPU || got.MemoryMiB != c.wantMemory || got.Replicas != c.wantReplicas {
				t.Errorf("tier=%s: resources = %+v, want %d/%d/%d",
					c.tier, got, c.wantCPU, c.wantMemory, c.wantReplicas)
			}
		})
	}
}

// TestRenderDatabasePostgresRedactsAllVariableValues pins the
// secrets-redaction contract for postgres: the RenderedSpec carries
// verbatim variable values (the worker needs them so the managed
// database can pick up engine configuration like POSTGRES_PASSWORD)
// but the Summary, its JSON, its slog LogValue, and its String never
// expose any variable value — neither the Secret-flagged one nor the
// plain one. Every value site shows the redaction sentinel.
func TestRenderDatabasePostgresRedactsAllVariableValues(t *testing.T) {
	t.Parallel()

	const secret = "sk-live-supersecret"
	const plain = "off"

	in := databasePostgresInput()
	spec := mustRender(t, in)

	// The verbatim secret must still reach the worker through the
	// RenderedSpec.
	var hasSecret bool
	for _, rv := range spec.Service.Variables {
		if rv.Name == "API_TOKEN" && rv.Value == secret && rv.Secret {
			hasSecret = true
		}
	}
	if !hasSecret {
		t.Fatal("rendered spec lost the verbatim secret value the worker needs")
	}

	// But every debug surface must redact every variable value.
	summary := spec.Summary()
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info(
		"rendered", "spec", spec, "summary", summary,
	)

	for label, s := range map[string]string{
		"summary json":   string(summaryJSON),
		"slog record":    logBuf.String(),
		"summary string": summary.String(),
	} {
		if strings.Contains(s, secret) {
			t.Errorf("%s leaked the secret variable value: %s", label, s)
		}
		if strings.Contains(s, plain) {
			t.Errorf("%s leaked the non-secret variable value: %s", label, s)
		}
	}
	for _, vs := range summary.Service.Variables {
		if vs.Value != output.Sentinel {
			t.Errorf("variable %q summary value = %q, want sentinel",
				vs.Name, vs.Value)
		}
	}
}

// TestRenderDatabasePostgresDeterministic pins that a postgres input
// renders to a byte-stable RenderedSpec across renderer invocations.
// Determinism is the renderer contract that lets the worker compare a
// freshly rendered spec to a previously-stored one to decide whether a
// Dokploy database update is needed at all.
func TestRenderDatabasePostgresDeterministic(t *testing.T) {
	t.Parallel()

	in := databasePostgresInput()
	first, err := dokploy.NewRenderer().Render(in)
	if err != nil {
		t.Fatalf("Render (first): %v", err)
	}
	second, err := dokploy.NewRenderer().Render(in)
	if err != nil {
		t.Fatalf("Render (second): %v", err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Errorf("render is not deterministic:\nfirst:  %s\nsecond: %s", a, b)
	}
}
