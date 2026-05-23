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

// BE-0307: Provision compose services.
//
// This file pins the per-service-type renderer contract for "compose"
// services. Unlike the application-git / application-image / application-
// drop-artifact pins, the compose subtype boundary at the renderer layer
// is the ServiceType itself, not the Builder — a compose service may be
// built from a Dockerfile or with Nixpacks just like an application-git
// service, but the renderer must preserve Service.Type == ServiceCompose
// so the downstream worker provisions a Dokploy compose stack rather than
// a single-container application.
//
// Subtype identity at the renderer layer:
//
//	Service.Type   == ServiceCompose
//	Build.Builder  ∈ {BuilderDockerfile, BuilderNixpacks}
//	Role           ∈ {RoleWeb, RoleWorker, RoleCron}
//
// While the durable provisioning worker that creates or updates the
// matching Dokploy compose resource and stores dokploy_refs atomically
// lands in a later worker story, this file is the structural barrier that
// pins the declarative-content half of the BE-0307 acceptance contract:
//
//   - The renderer validates every required field with stable, indexed
//     apierr.FieldViolations whose Reason text never echoes the submitted
//     value (a violation message is always safe for client envelopes,
//     logs, and audit metadata).
//   - The renderer preserves Service.Type == ServiceCompose even when the
//     caller's submitted Build is a git-builder shape that an
//     "application" subtype would accept; the type is the subtype
//     boundary against BE-0301 / BE-0303 / BE-0305 (application-*).
//   - The renderer honours the load-bearing production-web 2-replica
//     default for compose just as it does for application — this is the
//     contract pinned in defaultResources(): ServiceCompose participates
//     in the (TierProduction × RoleWeb) replica bump.
//   - The renderer carries verbatim variable values for the worker but
//     redacts every value (secret-flagged or not) in the Summary, slog
//     LogValue, and Summary.String() debug surface — so the secrets
//     redaction acceptance criterion is structurally enforced for both
//     dockerfile and nixpacks variants across every supported role.
//
// Pattern: this is the renderer-level counterpart to the engine-pin
// pattern used for admin-action policy matrices (BE-0285 / BE-0288 /
// BE-0291 / BE-0294 / BE-0297 / BE-0300) and the structural sibling of
// renderer_application_git_test.go (BE-0301),
// renderer_application_image_test.go (BE-0303), and
// renderer_application_drop_artifact_test.go (BE-0305) — a
// state-independent file that pins the contract the worker-side story
// must continue to satisfy.

// composeDockerfileInput returns a fully-valid compose RenderInput using
// the Dockerfile builder. It reuses validInput() (from renderer_test.go)
// for the hierarchy and variable fixtures so the canonical-id and
// per-level secret sets stay in lockstep with every other renderer pin.
func composeDockerfileInput() dokploy.RenderInput {
	in := validInput()
	in.Service.Type = dokploy.ServiceCompose
	in.Service.Engine = ""
	in.Role = dokploy.RoleWeb
	in.Build = dokploy.BuildSettings{
		Builder:        dokploy.BuilderDockerfile,
		DockerfilePath: "compose/Dockerfile",
		GitBranch:      "main",
		GitCommit:      "deadbeefcafebabe",
	}
	return in
}

// composeNixpacksInput returns a fully-valid compose RenderInput using the
// Nixpacks builder.
func composeNixpacksInput() dokploy.RenderInput {
	in := validInput()
	in.Service.Type = dokploy.ServiceCompose
	in.Service.Engine = ""
	in.Role = dokploy.RoleWeb
	in.Build = dokploy.BuildSettings{
		Builder:   dokploy.BuilderNixpacks,
		GitBranch: "main",
		GitCommit: "deadbeefcafebabe",
	}
	return in
}

// TestRenderComposeDockerfileSuccess pins the canonical
// dockerfile-builder compose happy path: type=compose,
// builder=dockerfile, the requested DockerfilePath survives normalisation,
// GitBranch and GitCommit are preserved verbatim, Image stays empty, and
// the Engine field stays empty (compose is not a database).
func TestRenderComposeDockerfileSuccess(t *testing.T) {
	t.Parallel()

	spec := mustRender(t, composeDockerfileInput())

	if spec.Service.Type != dokploy.ServiceCompose {
		t.Errorf("service type = %q, want compose", spec.Service.Type)
	}
	if spec.Service.Engine != "" {
		t.Errorf("compose rendered Engine = %q, want empty (engine is database-only)", spec.Service.Engine)
	}
	if spec.Service.Build.Builder != dokploy.BuilderDockerfile {
		t.Errorf("builder = %q, want dockerfile", spec.Service.Build.Builder)
	}
	if got := spec.Service.Build.DockerfilePath; got != "compose/Dockerfile" {
		t.Errorf("dockerfile path = %q, want %q", got, "compose/Dockerfile")
	}
	if got := spec.Service.Build.GitBranch; got != "main" {
		t.Errorf("git branch = %q, want main", got)
	}
	if got := spec.Service.Build.GitCommit; got != "deadbeefcafebabe" {
		t.Errorf("git commit = %q, want deadbeefcafebabe", got)
	}
	if got := spec.Service.Build.Image; got != "" {
		t.Errorf("compose rendered Image = %q, want empty for git builder", got)
	}
	if got := spec.Service.Build.ArtifactURL; got != "" {
		t.Errorf("compose rendered ArtifactURL = %q, want empty for git builder", got)
	}
	if spec.Service.Role != dokploy.RoleWeb {
		t.Errorf("role = %q, want web", spec.Service.Role)
	}
}

// TestRenderComposeNixpacksSuccess pins the canonical nixpacks-builder
// compose happy path: type=compose, builder=nixpacks, no DockerfilePath,
// no Image, no ArtifactURL, and the git refs preserved verbatim.
func TestRenderComposeNixpacksSuccess(t *testing.T) {
	t.Parallel()

	spec := mustRender(t, composeNixpacksInput())

	if spec.Service.Type != dokploy.ServiceCompose {
		t.Errorf("service type = %q, want compose", spec.Service.Type)
	}
	if spec.Service.Engine != "" {
		t.Errorf("compose rendered Engine = %q, want empty (engine is database-only)", spec.Service.Engine)
	}
	if spec.Service.Build.Builder != dokploy.BuilderNixpacks {
		t.Errorf("builder = %q, want nixpacks", spec.Service.Build.Builder)
	}
	if got := spec.Service.Build.DockerfilePath; got != "" {
		t.Errorf("nixpacks builder rendered DockerfilePath = %q, want empty", got)
	}
	if got := spec.Service.Build.Image; got != "" {
		t.Errorf("compose rendered Image = %q, want empty (git builder)", got)
	}
	if got := spec.Service.Build.ArtifactURL; got != "" {
		t.Errorf("compose rendered ArtifactURL = %q, want empty (git builder)", got)
	}
	if got := spec.Service.Build.GitBranch; got != "main" {
		t.Errorf("git branch = %q, want main", got)
	}
	if got := spec.Service.Build.GitCommit; got != "deadbeefcafebabe" {
		t.Errorf("git commit = %q, want deadbeefcafebabe", got)
	}
}

// TestRenderComposeSubtypeBoundaryFromApplication is the per-service-type
// subtype-boundary pin: a RenderInput whose Service.Type is ServiceCompose
// must render with Service.Type == ServiceCompose — never silently
// downgraded to ServiceApplication — even when the submitted Build,
// Domains, and Variables are otherwise identical to an application-git
// input. The reverse holds too: an application input must NOT render as
// compose. This is the structural barrier against any future refactor
// that conflates "application" and "compose" inside normaliseBuild() or
// the type switch in Render(). The label set must also surface the type
// faithfully so dashboards and audit trails distinguish a compose stack
// from a single-container application.
func TestRenderComposeSubtypeBoundaryFromApplication(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   func() dokploy.RenderInput
		want dokploy.ServiceType
	}{
		{
			name: "compose stays compose",
			in:   composeDockerfileInput,
			want: dokploy.ServiceCompose,
		},
		{
			name: "application stays application",
			in:   applicationGitDockerfileInput,
			want: dokploy.ServiceApplication,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			spec := mustRender(t, c.in())
			if spec.Service.Type != c.want {
				t.Errorf("service type = %q, want %q", spec.Service.Type, c.want)
			}
			// The labels must surface the rendered type so a future
			// audit/observability consumer can distinguish a compose
			// service from a single-container application without
			// re-reading the spec body.
			var typeLabel string
			for _, l := range spec.Service.Labels {
				if l.Key == "yalla.service-type" {
					typeLabel = l.Value
				}
			}
			if typeLabel != string(c.want) {
				t.Errorf("yalla.service-type label = %q, want %q", typeLabel, c.want)
			}
		})
	}
}

// TestRenderComposeRoleMatrix pins that compose supports every documented
// service role — web, worker, and cron — at both dockerfile and nixpacks
// builders. The shape of each rendered spec matches the role's documented
// invariants:
//
//   - web    : domains rendered, no cron schedule.
//   - worker : domains dropped, no cron schedule.
//   - cron   : domains dropped, cron schedule preserved.
//
// Across every (builder × role) combination the rendered Service.Type
// stays ServiceCompose and the Image / ArtifactURL fields stay empty
// (subtype boundary against BE-0303 / BE-0305).
func TestRenderComposeRoleMatrix(t *testing.T) {
	t.Parallel()

	type want struct {
		domains      int
		cronSchedule string
	}
	cases := []struct {
		name string
		role dokploy.ServiceRole
		cron string
		want want
	}{
		{"web", dokploy.RoleWeb, "", want{domains: 1, cronSchedule: ""}},
		{"worker", dokploy.RoleWorker, "", want{domains: 0, cronSchedule: ""}},
		{"cron", dokploy.RoleCron, "0 2 * * *", want{domains: 0, cronSchedule: "0 2 * * *"}},
	}

	for _, makeIn := range []func() dokploy.RenderInput{
		composeDockerfileInput,
		composeNixpacksInput,
	} {
		makeIn := makeIn
		for _, c := range cases {
			c := c
			builderInput := makeIn()
			builderName := builderInput.Build.Builder
			t.Run(builderName+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				in := makeIn()
				in.Role = c.role
				in.CronSchedule = c.cron
				if c.role != dokploy.RoleWeb {
					in.Domains = nil
				}
				spec := mustRender(t, in)
				if spec.Service.Type != dokploy.ServiceCompose {
					t.Errorf("service type = %q, want compose", spec.Service.Type)
				}
				if spec.Service.Role != c.role {
					t.Errorf("role = %q, want %q", spec.Service.Role, c.role)
				}
				if got := len(spec.Service.Domains); got != c.want.domains {
					t.Errorf("domains count = %d, want %d", got, c.want.domains)
				}
				if spec.Service.CronSchedule != c.want.cronSchedule {
					t.Errorf("cron schedule = %q, want %q",
						spec.Service.CronSchedule, c.want.cronSchedule)
				}
				if spec.Service.Build.Image != "" {
					t.Errorf("compose rendered Image = %q, want empty", spec.Service.Build.Image)
				}
				if spec.Service.Build.ArtifactURL != "" {
					t.Errorf("compose rendered ArtifactURL = %q, want empty", spec.Service.Build.ArtifactURL)
				}
				if spec.Service.Engine != "" {
					t.Errorf("compose rendered Engine = %q, want empty", spec.Service.Engine)
				}
			})
		}
	}
}

// TestRenderComposeValidationFailures pins that every required field the
// renderer rejects for a compose input becomes a typed apierr.InvalidInput
// with a stable, indexed Field path, and that no submitted value is ever
// echoed into the rendered error surface. The table covers the failure
// modes most relevant to compose: hierarchy identity, parent linkage,
// environment tier, service type, service role, cron schedule absence on
// a cron role, variable name rejection (no value echo), negative resource
// limits, image-builder-missing-image (compose may use any of the four
// supported builders, so the image-builder failure path is part of the
// compose contract), drop-artifact-builder-missing-artifact-url, and bad
// builder strings — using a Dockerfile-builder compose base.
func TestRenderComposeValidationFailures(t *testing.T) {
	t.Parallel()

	leakyValues := []string{
		"not-a-yalla-id",
		"1bad",
		"sk-live-supersecret",
		"frontend",
		"function",
		"prod-tier",
		"bazel",
		"every-minute-please",
		"leaky-image.example.com/secret-app:v9.9.9",
		"https://artifacts.yalla.example/uploads/api-v1.2.3.tar.gz",
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
		{"bad role", func(in *dokploy.RenderInput) {
			in.Role = "frontend"
		}, "role"},
		{"bad service type", func(in *dokploy.RenderInput) {
			in.Service.Type = "function"
		}, "service.type"},
		{"cron role missing schedule", func(in *dokploy.RenderInput) {
			in.Role = dokploy.RoleCron
			in.CronSchedule = ""
			in.Domains = nil
		}, "cron_schedule"},
		{"cron role bad schedule", func(in *dokploy.RenderInput) {
			in.Role = dokploy.RoleCron
			in.CronSchedule = "every-minute-please"
			in.Domains = nil
		}, "cron_schedule"},
		{"bad variable name", func(in *dokploy.RenderInput) {
			in.ServiceVariables = []dokploy.Variable{
				{Name: "1bad", Value: "sk-live-supersecret", Secret: true},
			}
		}, "service.variables[0].name"},
		{"negative cpu millis", func(in *dokploy.RenderInput) {
			in.Resources = dokploy.ResourceLimits{CPUMillis: -1}
		}, "resources.cpu_millis"},
		{"image builder missing image", func(in *dokploy.RenderInput) {
			in.Build = dokploy.BuildSettings{Builder: dokploy.BuilderImage}
		}, "build.image"},
		{"drop-artifact builder missing artifact url", func(in *dokploy.RenderInput) {
			in.Build = dokploy.BuildSettings{Builder: dokploy.BuilderDropArtifact}
		}, "build.artifact_url"},
		{"bad builder", func(in *dokploy.RenderInput) {
			in.Build = dokploy.BuildSettings{Builder: "bazel", GitBranch: "main"}
		}, "build.builder"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			in := composeDockerfileInput()
			c.mutate(&in)
			spec, err := dokploy.NewRenderer().Render(in)
			if err == nil {
				t.Fatalf("expected error, got spec %+v", spec)
			}

			var ye *yerr.Error
			if !yerrAs(err, &ye) || ye.Code != yerr.CodeValidation {
				t.Fatalf("error = %v, want E_VALIDATION", err)
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

			// No submitted value is ever echoed into the rendered error.
			rendered := err.Error()
			for _, leak := range leakyValues {
				if strings.Contains(rendered, leak) {
					t.Errorf("error echoed submitted value %q: %v", leak, err)
				}
			}
		})
	}
}

// TestRenderComposeTierResourceDefaults pins the tier × role resource
// defaults for compose specifically: only a production web compose
// service gets the load-bearing 2-replica default; every other tier × role
// combination defaults to a single replica regardless of the
// dockerfile-vs-nixpacks builder choice. Compose participates in the
// production-web replica bump exactly as application does — this is the
// load-bearing resource-allocation contract a future autoscaler story has
// to honour.
func TestRenderComposeTierResourceDefaults(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tier         dokploy.EnvironmentTier
		role         dokploy.ServiceRole
		wantCPU      int
		wantMemory   int
		wantReplicas int
	}{
		{dokploy.TierProduction, dokploy.RoleWeb, 1000, 1024, 2},
		{dokploy.TierProduction, dokploy.RoleWorker, 1000, 1024, 1},
		{dokploy.TierStaging, dokploy.RoleWeb, 500, 512, 1},
		{dokploy.TierStaging, dokploy.RoleWorker, 500, 512, 1},
		{dokploy.TierPreview, dokploy.RoleWeb, 250, 256, 1},
		{dokploy.TierPreview, dokploy.RoleWorker, 250, 256, 1},
	}
	for _, makeIn := range []func() dokploy.RenderInput{
		composeDockerfileInput,
		composeNixpacksInput,
	} {
		makeIn := makeIn
		for _, c := range cases {
			c := c
			builderInput := makeIn()
			builderName := builderInput.Build.Builder
			t.Run(builderName+"/"+string(c.tier)+"/"+string(c.role), func(t *testing.T) {
				t.Parallel()
				in := makeIn()
				in.Tier = c.tier
				in.Role = c.role
				if c.role != dokploy.RoleWeb {
					in.Domains = nil
				}
				spec := mustRender(t, in)
				got := spec.Service.Resources
				if got.CPUMillis != c.wantCPU || got.MemoryMiB != c.wantMemory || got.Replicas != c.wantReplicas {
					t.Errorf("tier=%s role=%s builder=%s: resources = %+v, want %d/%d/%d",
						c.tier, c.role, builderName, got, c.wantCPU, c.wantMemory, c.wantReplicas)
				}
			})
		}
	}
}

// TestRenderComposeRedactsAllVariableValuesAcrossRoles pins the
// secrets-redaction contract for compose across every role and both
// supported builders: the RenderedSpec carries verbatim variable values
// (the worker needs them) but the Summary, its JSON, its slog LogValue,
// and its String never expose any variable value — neither the
// Secret-flagged one nor the plain one. Every value site shows the
// redaction sentinel.
func TestRenderComposeRedactsAllVariableValuesAcrossRoles(t *testing.T) {
	t.Parallel()

	const secret = "sk-live-supersecret"
	const plain = "off"

	roles := []struct {
		role dokploy.ServiceRole
		cron string
	}{
		{dokploy.RoleWeb, ""},
		{dokploy.RoleWorker, ""},
		{dokploy.RoleCron, "0 2 * * *"},
	}

	for _, makeIn := range []func() dokploy.RenderInput{
		composeDockerfileInput,
		composeNixpacksInput,
	} {
		makeIn := makeIn
		for _, r := range roles {
			r := r
			builderInput := makeIn()
			builderName := builderInput.Build.Builder
			t.Run(builderName+"/"+string(r.role), func(t *testing.T) {
				t.Parallel()
				in := makeIn()
				in.Role = r.role
				in.CronSchedule = r.cron
				if r.role != dokploy.RoleWeb {
					in.Domains = nil
				}

				spec := mustRender(t, in)

				// The verbatim secret must still reach the worker through
				// the RenderedSpec.
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
			})
		}
	}
}

// TestRenderComposeDeterministic pins that a compose input renders to a
// byte-stable RenderedSpec across renderer invocations for both supported
// builders. Determinism is the renderer contract that lets the worker
// compare a freshly rendered spec to a previously-stored one to decide
// whether a Dokploy compose-stack update is needed at all.
func TestRenderComposeDeterministic(t *testing.T) {
	t.Parallel()
	for _, makeIn := range []func() dokploy.RenderInput{
		composeDockerfileInput,
		composeNixpacksInput,
	} {
		makeIn := makeIn
		in := makeIn()
		builderName := in.Build.Builder
		t.Run(builderName, func(t *testing.T) {
			t.Parallel()
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
		})
	}
}
