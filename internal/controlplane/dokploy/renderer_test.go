package dokploy_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
	"github.com/JuribaDev/yalla/internal/testutil"
)

// fixedID builds a canonical, deterministic resource ID: the kind prefix joined
// to a 25-zero suffix plus one distinguishing Crockford character. Using a
// helper keeps the suffix length correct (ParseID requires exactly 26
// characters) so rendered names and golden files stay byte-stable.
func fixedID(kind domain.Kind, last byte) domain.ID {
	return domain.ID(string(kind) + "_" + strings.Repeat("0", 25) + string(last))
}

// Fixed, deterministic IDs so rendered names and golden files are byte-stable.
var (
	fixedOrgID    = fixedID(domain.KindOrganization, 'a')
	fixedProjID   = fixedID(domain.KindProject, 'b')
	fixedEnvID    = fixedID(domain.KindEnvironment, 'c')
	fixedSvcID    = fixedID(domain.KindService, 'd')
	fixedOtherOrg = fixedID(domain.KindOrganization, 'z')
)

const dbServiceLabel = "primary database"

// validInput returns a fully-valid RenderInput for a staging web application
// with variables defined at every level of the hierarchy.
func validInput() dokploy.RenderInput {
	return dokploy.RenderInput{
		Organization: dokploy.YallaOrganization{ID: fixedOrgID, Label: "Acme Corp"},
		Project:      dokploy.YallaProject{ID: fixedProjID, OrganizationID: fixedOrgID, Label: "Storefront"},
		Environment:  dokploy.YallaEnvironment{ID: fixedEnvID, ProjectID: fixedProjID, Label: "Staging"},
		Service:      dokploy.YallaService{ID: fixedSvcID, EnvironmentID: fixedEnvID, Label: "API", Type: dokploy.ServiceApplication},
		Tier:         dokploy.TierStaging,
		Role:         dokploy.RoleWeb,
		OrganizationVariables: []dokploy.Variable{
			{Name: "REGION", Value: "eu-west-1"},
			{Name: "LOG_LEVEL", Value: "warn"},
		},
		ProjectVariables: []dokploy.Variable{
			{Name: "FEATURE_X", Value: "off"},
		},
		EnvironmentVariables: []dokploy.Variable{
			{Name: "LOG_LEVEL", Value: "debug"},
		},
		ServiceVariables: []dokploy.Variable{
			{Name: "API_TOKEN", Value: "sk-live-supersecret", Secret: true},
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

func mustRender(t *testing.T, in dokploy.RenderInput) dokploy.RenderedSpec {
	t.Helper()
	spec, err := dokploy.NewRenderer().Render(in)
	if err != nil {
		t.Fatalf("Render: unexpected error: %v", err)
	}
	return spec
}

func TestRenderSuccess(t *testing.T) {
	t.Parallel()
	spec := mustRender(t, validInput())

	dash := func(id domain.ID) string { return strings.ReplaceAll(string(id), "_", "-") }
	if want := "acme-corp-" + dash(fixedOrgID); spec.OrganizationName != want {
		t.Errorf("organization name = %q, want %q", spec.OrganizationName, want)
	}
	if want := "storefront-" + dash(fixedProjID); spec.ProjectName != want {
		t.Errorf("project name = %q, want %q", spec.ProjectName, want)
	}
	if want := "staging-" + dash(fixedEnvID); spec.EnvironmentName != want {
		t.Errorf("environment name = %q, want %q", spec.EnvironmentName, want)
	}
	if want := "api-" + dash(fixedSvcID); spec.Service.Name != want {
		t.Errorf("service name = %q, want %q", spec.Service.Name, want)
	}
	if spec.Tier != dokploy.TierStaging || spec.Service.Role != dokploy.RoleWeb {
		t.Errorf("tier/role = %q/%q", spec.Tier, spec.Service.Role)
	}
	// Staging defaults: 500m / 512Mi / 1 replica.
	if got := spec.Service.Resources; got.CPUMillis != 500 || got.MemoryMiB != 512 || got.Replicas != 1 {
		t.Errorf("resources = %+v, want 500/512/1", got)
	}
	if spec.Service.Build.DockerfilePath != "Dockerfile" {
		t.Errorf("dockerfile path = %q, want defaulted Dockerfile", spec.Service.Build.DockerfilePath)
	}
	if len(spec.Service.Domains) != 1 || spec.Service.Domains[0].Path != "/" {
		t.Errorf("domains = %+v, want one domain with defaulted path", spec.Service.Domains)
	}
	// Labels are deterministic and sorted by key.
	wantLabels := map[string]string{
		"yalla.organization": string(fixedOrgID),
		"yalla.project":      string(fixedProjID),
		"yalla.environment":  string(fixedEnvID),
		"yalla.service":      string(fixedSvcID),
		"yalla.tier":         "staging",
		"yalla.service-type": "application",
		"yalla.role":         "web",
		"yalla.managed-by":   "yalla-control-plane",
	}
	if len(spec.Service.Labels) != len(wantLabels) {
		t.Fatalf("labels = %+v", spec.Service.Labels)
	}
	for i, l := range spec.Service.Labels {
		if i > 0 && spec.Service.Labels[i-1].Key >= l.Key {
			t.Errorf("labels not sorted by key: %+v", spec.Service.Labels)
		}
		if wantLabels[l.Key] != l.Value {
			t.Errorf("label %q = %q, want %q", l.Key, l.Value, wantLabels[l.Key])
		}
	}
}

func TestRenderVariablePrecedence(t *testing.T) {
	t.Parallel()
	spec := mustRender(t, validInput())

	got := make(map[string]dokploy.RenderedVariable, len(spec.Service.Variables))
	for i, rv := range spec.Service.Variables {
		if i > 0 && spec.Service.Variables[i-1].Name >= rv.Name {
			t.Errorf("variables not sorted by name: %+v", spec.Service.Variables)
		}
		got[rv.Name] = rv
	}

	cases := []struct {
		name       string
		wantValue  string
		wantSource dokploy.VariableSource
		wantSecret bool
	}{
		{"REGION", "eu-west-1", dokploy.SourceOrganization, false},
		{"LOG_LEVEL", "debug", dokploy.SourceEnvironment, false}, // environment overrides organization
		{"FEATURE_X", "on", dokploy.SourceService, false},        // service overrides project
		{"API_TOKEN", "sk-live-supersecret", dokploy.SourceService, true},
	}
	for _, c := range cases {
		rv, ok := got[c.name]
		if !ok {
			t.Errorf("variable %q missing from effective set", c.name)
			continue
		}
		if rv.Value != c.wantValue || rv.Source != c.wantSource || rv.Secret != c.wantSecret {
			t.Errorf("variable %q = %+v, want value=%q source=%q secret=%v",
				c.name, rv, c.wantValue, c.wantSource, c.wantSecret)
		}
	}
	if len(got) != len(cases) {
		t.Errorf("effective set has %d variables, want %d", len(got), len(cases))
	}
}

func TestRenderDeterministic(t *testing.T) {
	t.Parallel()
	in := validInput()
	first, err := dokploy.NewRenderer().Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	second, err := dokploy.NewRenderer().Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Errorf("render is not deterministic:\nfirst:  %s\nsecond: %s", a, b)
	}
}

func TestRenderResourceDefaults(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tier         dokploy.EnvironmentTier
		role         dokploy.ServiceRole
		typ          dokploy.ServiceType
		wantCPU      int
		wantMemory   int
		wantReplicas int
	}{
		{dokploy.TierProduction, dokploy.RoleWeb, dokploy.ServiceApplication, 1000, 1024, 2},
		{dokploy.TierProduction, dokploy.RoleWorker, dokploy.ServiceApplication, 1000, 1024, 1},
		{dokploy.TierStaging, dokploy.RoleWeb, dokploy.ServiceApplication, 500, 512, 1},
		{dokploy.TierPreview, dokploy.RoleWeb, dokploy.ServiceApplication, 250, 256, 1},
	}
	for _, c := range cases {
		in := validInput()
		in.Tier = c.tier
		in.Role = c.role
		in.Service.Type = c.typ
		if c.role != dokploy.RoleWeb {
			in.Domains = nil
		}
		spec := mustRender(t, in)
		if got := spec.Service.Resources; got.CPUMillis != c.wantCPU || got.MemoryMiB != c.wantMemory || got.Replicas != c.wantReplicas {
			t.Errorf("tier=%s role=%s: resources = %+v, want %d/%d/%d",
				c.tier, c.role, got, c.wantCPU, c.wantMemory, c.wantReplicas)
		}
	}

	// Explicit limits override the tier defaults; only zero fields inherit.
	in := validInput()
	in.Tier = dokploy.TierProduction
	in.Resources = dokploy.ResourceLimits{CPUMillis: 250, Replicas: 5}
	spec := mustRender(t, in)
	if got := spec.Service.Resources; got.CPUMillis != 250 || got.Replicas != 5 || got.MemoryMiB != 1024 {
		t.Errorf("partial override: resources = %+v, want 250/1024/5", got)
	}
}

func TestRenderDropsInapplicableFields(t *testing.T) {
	t.Parallel()

	// A database service drops its role; its engine is kept.
	dbIn := validInput()
	dbIn.Service.Type = dokploy.ServiceDatabase
	dbIn.Service.Engine = "postgres"
	dbIn.Role = dokploy.RoleWeb
	dbIn.Domains = nil
	dbSpec := mustRender(t, dbIn)
	if dbSpec.Service.Role != "" {
		t.Errorf("database service role = %q, want dropped", dbSpec.Service.Role)
	}
	if dbSpec.Service.Engine != "postgres" {
		t.Errorf("database service engine = %q, want postgres", dbSpec.Service.Engine)
	}

	// A worker service drops domains.
	workerIn := validInput()
	workerIn.Role = dokploy.RoleWorker
	workerSpec := mustRender(t, workerIn)
	if len(workerSpec.Service.Domains) != 0 {
		t.Errorf("worker domains = %+v, want dropped", workerSpec.Service.Domains)
	}

	// A non-cron service drops its cron schedule.
	in := validInput()
	in.CronSchedule = "* * * * *"
	spec := mustRender(t, in)
	if spec.Service.CronSchedule != "" {
		t.Errorf("web service cron schedule = %q, want dropped", spec.Service.CronSchedule)
	}
}

func TestRenderValidationFailures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		mutate    func(*dokploy.RenderInput)
		wantField string
	}{
		{"bad org id", func(in *dokploy.RenderInput) { in.Organization.ID = "not-an-id" }, "organization.id"},
		{"mismatched parent", func(in *dokploy.RenderInput) { in.Project.OrganizationID = fixedOtherOrg }, "project.organization_id"},
		{"bad tier", func(in *dokploy.RenderInput) { in.Tier = "prod" }, "tier"},
		{"bad role", func(in *dokploy.RenderInput) { in.Role = "frontend" }, "role"},
		{"bad service type", func(in *dokploy.RenderInput) { in.Service.Type = "function" }, "service.type"},
		{"database missing engine", func(in *dokploy.RenderInput) {
			in.Service.Type = dokploy.ServiceDatabase
			in.Service.Engine = ""
		}, "service.engine"},
		{"cron missing schedule", func(in *dokploy.RenderInput) {
			in.Role = dokploy.RoleCron
			in.CronSchedule = ""
			in.Domains = nil
		}, "cron_schedule"},
		{"bad variable name", func(in *dokploy.RenderInput) {
			in.ServiceVariables = []dokploy.Variable{{Name: "1-bad", Value: "leaky-secret-value"}}
		}, "service.variables[0].name"},
		{"duplicate variable name", func(in *dokploy.RenderInput) {
			in.ServiceVariables = []dokploy.Variable{{Name: "FOO", Value: "a"}, {Name: "FOO", Value: "b"}}
		}, "service.variables[1].name"},
		{"negative cpu", func(in *dokploy.RenderInput) {
			in.Resources = dokploy.ResourceLimits{CPUMillis: -1}
		}, "resources.cpu_millis"},
		{"bad builder", func(in *dokploy.RenderInput) {
			in.Build = dokploy.BuildSettings{Builder: "bazel"}
		}, "build.builder"},
		{"image builder missing image", func(in *dokploy.RenderInput) {
			in.Build = dokploy.BuildSettings{Builder: dokploy.BuilderImage}
		}, "build.image"},
		{"bad domain host", func(in *dokploy.RenderInput) {
			in.Domains = []dokploy.DomainSpec{{Host: "leakyhost not valid"}}
		}, "domains[0].host"},
		{"bad domain path", func(in *dokploy.RenderInput) {
			in.Domains = []dokploy.DomainSpec{{Host: "ok.acme.example", Path: "relative"}}
		}, "domains[0].path"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := validInput()
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
			found := false
			for _, viol := range violations {
				if viol.Field == c.wantField {
					found = true
				}
			}
			if !found {
				t.Errorf("violations %+v do not include field %q", violations, c.wantField)
			}
			// No submitted value is ever echoed into the error surface.
			for _, leak := range []string{"not-an-id", "1-bad", "leaky-secret-value", "bazel", "leakyhost not valid", "relative", "frontend", "function"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("error echoed submitted value %q: %v", leak, err)
				}
			}
		})
	}
}

func TestRenderRedactsVariableValuesInDebugOutput(t *testing.T) {
	t.Parallel()
	const secret = "sk-live-supersecret"
	const plain = "debug"
	spec := mustRender(t, validInput())

	// The spec itself carries verbatim values — the worker needs them.
	var specHasSecret bool
	for _, rv := range spec.Service.Variables {
		if rv.Name == "API_TOKEN" && rv.Value == secret {
			specHasSecret = true
		}
	}
	if !specHasSecret {
		t.Fatal("rendered spec must carry the verbatim secret value for the worker")
	}

	// The Summary, its JSON, its slog record, and its String never do — and
	// every variable value is redacted, not only the Secret-flagged ones.
	summary := spec.Summary()
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("rendered", "spec", spec, "summary", summary)

	surfaces := map[string]string{
		"summary json":   string(summaryJSON),
		"slog record":    logBuf.String(),
		"summary string": summary.String(),
	}
	for label, s := range surfaces {
		if strings.Contains(s, secret) {
			t.Errorf("%s leaked the secret variable value: %s", label, s)
		}
		if strings.Contains(s, plain) {
			t.Errorf("%s leaked a non-secret variable value: %s", label, s)
		}
	}
	if !strings.Contains(string(summaryJSON), output.Sentinel) {
		t.Errorf("summary json does not show the redaction sentinel: %s", summaryJSON)
	}
	for _, vs := range summary.Service.Variables {
		if vs.Value != output.Sentinel {
			t.Errorf("variable %q summary value = %q, want sentinel", vs.Name, vs.Value)
		}
	}
}

// TestRenderGolden pins the redacted Summary of representative render scenarios
// to byte-stable golden files. Run `go test -update-golden ./...` to refresh.
func TestRenderGolden(t *testing.T) {
	t.Parallel()
	for name, in := range goldenScenarios() {
		t.Run(name, func(t *testing.T) {
			spec := mustRender(t, in)
			payload, err := json.Marshal(spec.Summary())
			if err != nil {
				t.Fatalf("marshal summary: %v", err)
			}
			// The golden artifact is the redacted Summary: it must never
			// contain a raw variable value.
			if strings.Contains(string(payload), "supersecret") || strings.Contains(string(payload), "raw-value") {
				t.Fatalf("golden payload leaked a variable value: %s", payload)
			}
			testutil.GoldenJSON(t, "renderer/"+name, string(payload))
		})
	}
}

// goldenScenarios returns the representative render inputs covered by golden
// tests: each ServiceType, each ServiceRole, and each EnvironmentTier.
func goldenScenarios() map[string]dokploy.RenderInput {
	base := func() dokploy.RenderInput {
		in := validInput()
		// Use a stable, obviously-fake secret so the golden never embeds a
		// real-looking value even if redaction regresses.
		in.ServiceVariables = []dokploy.Variable{
			{Name: "API_TOKEN", Value: "raw-value-supersecret", Secret: true},
			{Name: "FEATURE_X", Value: "raw-value-on"},
		}
		return in
	}

	application := base()

	database := base()
	database.Service.Type = dokploy.ServiceDatabase
	database.Service.Engine = "postgres"
	database.Service.Label = dbServiceLabel
	database.Role = ""
	database.Domains = nil

	compose := base()
	compose.Service.Type = dokploy.ServiceCompose
	compose.Service.Label = "stack"

	worker := base()
	worker.Role = dokploy.RoleWorker
	worker.Service.Label = "queue worker"
	worker.Domains = nil

	cron := base()
	cron.Role = dokploy.RoleCron
	cron.Service.Label = "nightly report"
	cron.CronSchedule = "0 2 * * *"
	cron.Domains = nil

	staging := base()
	staging.Tier = dokploy.TierStaging

	production := base()
	production.Tier = dokploy.TierProduction
	production.Environment.Label = "Production"
	production.Build = dokploy.BuildSettings{Builder: dokploy.BuilderImage, Image: "registry.example/api:v1.2.3"}

	preview := base()
	preview.Tier = dokploy.TierPreview
	preview.Environment.Label = "Preview"
	preview.Build = dokploy.BuildSettings{Builder: dokploy.BuilderNixpacks, GitBranch: "pr-42", GitCommit: "abc123"}
	preview.Domains = []dokploy.DomainSpec{{Host: "pr-42.preview.acme.example", HTTPS: true, Path: "/app"}}

	return map[string]dokploy.RenderInput{
		"application": application,
		"database":    database,
		"compose":     compose,
		"worker":      worker,
		"cron":        cron,
		"staging":     staging,
		"production":  production,
		"preview":     preview,
	}
}

// yerrAs is a tiny errors.As shim kept local so the test file's imports stay
// focused on the package under test.
func yerrAs(err error, target **yerr.Error) bool {
	for err != nil {
		if e, ok := err.(*yerr.Error); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
