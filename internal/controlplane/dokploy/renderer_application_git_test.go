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

// BE-0301: Provision application-git services.
//
// This file pins the per-subtype renderer contract for "application-git"
// — Yalla's name for an application service whose image is built from a
// git source. The subtype identity at the renderer layer is:
//
//	Service.Type   == ServiceApplication
//	Build.Builder  ∈ {BuilderDockerfile, BuilderNixpacks}
//	Role           ∈ {RoleWeb, RoleWorker, RoleCron}
//
// While the durable provisioning worker that creates or updates the
// matching Dokploy resource and stores dokploy_refs atomically lands in a
// later worker story, this file is the structural barrier that pins the
// declarative-content half of the BE-0301 acceptance contract:
//
//   - The renderer validates every required field with stable, indexed
//     apierr.FieldViolations whose Reason text never echoes the submitted
//     value (a violation message is always safe for client envelopes,
//     logs, and audit metadata).
//   - The renderer drops Image for git-sourced builders so an application-
//     git spec can never carry an Image reference — that is the subtype
//     boundary against BE-0303 (application-image).
//   - The renderer carries verbatim variable values for the worker but
//     redacts every value (secret-flagged or not) in the Summary, slog
//     LogValue, and Summary.String() debug surface — so the secrets
//     redaction acceptance criterion is structurally enforced for both
//     dockerfile and nixpacks variants across every supported role.
//
// Pattern: this is the renderer-level counterpart to the engine-pin
// pattern used for admin-action policy matrices (BE-0285 / BE-0288 /
// BE-0291 / BE-0294 / BE-0297 / BE-0300) — a state-independent file that
// pins the contract the worker-side story must continue to satisfy.

// applicationGitDockerfileInput returns a fully-valid application-git
// RenderInput using the Dockerfile builder. It reuses validInput() (from
// renderer_test.go) for the hierarchy and variable fixtures so the
// canonical-id and per-level secret sets stay in lockstep with the other
// renderer pins.
func applicationGitDockerfileInput() dokploy.RenderInput {
	in := validInput()
	in.Service.Type = dokploy.ServiceApplication
	in.Service.Engine = ""
	in.Role = dokploy.RoleWeb
	in.Build = dokploy.BuildSettings{
		Builder:        dokploy.BuilderDockerfile,
		DockerfilePath: "build/Dockerfile",
		GitBranch:      "main",
		GitCommit:      "deadbeefcafebabe",
	}
	return in
}

// applicationGitNixpacksInput returns a fully-valid application-git
// RenderInput using the Nixpacks builder.
func applicationGitNixpacksInput() dokploy.RenderInput {
	in := validInput()
	in.Service.Type = dokploy.ServiceApplication
	in.Service.Engine = ""
	in.Role = dokploy.RoleWeb
	in.Build = dokploy.BuildSettings{
		Builder:   dokploy.BuilderNixpacks,
		GitBranch: "main",
		GitCommit: "deadbeefcafebabe",
	}
	return in
}

// TestRenderApplicationGitDockerfileSuccess pins the canonical
// dockerfile-builder application-git happy path: type=application,
// builder=dockerfile, the requested DockerfilePath survives normalisation,
// GitBranch and GitCommit are preserved verbatim, and Image stays empty.
func TestRenderApplicationGitDockerfileSuccess(t *testing.T) {
	t.Parallel()

	spec := mustRender(t, applicationGitDockerfileInput())

	if spec.Service.Type != dokploy.ServiceApplication {
		t.Errorf("service type = %q, want application", spec.Service.Type)
	}
	if spec.Service.Build.Builder != dokploy.BuilderDockerfile {
		t.Errorf("builder = %q, want dockerfile", spec.Service.Build.Builder)
	}
	if got := spec.Service.Build.DockerfilePath; got != "build/Dockerfile" {
		t.Errorf("dockerfile path = %q, want %q", got, "build/Dockerfile")
	}
	if got := spec.Service.Build.GitBranch; got != "main" {
		t.Errorf("git branch = %q, want main", got)
	}
	if got := spec.Service.Build.GitCommit; got != "deadbeefcafebabe" {
		t.Errorf("git commit = %q, want deadbeefcafebabe", got)
	}
	if got := spec.Service.Build.Image; got != "" {
		t.Errorf("application-git rendered Image = %q, want empty (subtype boundary)", got)
	}
}

// TestRenderApplicationGitNixpacksSuccess pins the canonical
// nixpacks-builder application-git happy path: type=application,
// builder=nixpacks, no DockerfilePath, no Image, and the git refs are
// preserved verbatim.
func TestRenderApplicationGitNixpacksSuccess(t *testing.T) {
	t.Parallel()

	spec := mustRender(t, applicationGitNixpacksInput())

	if spec.Service.Type != dokploy.ServiceApplication {
		t.Errorf("service type = %q, want application", spec.Service.Type)
	}
	if spec.Service.Build.Builder != dokploy.BuilderNixpacks {
		t.Errorf("builder = %q, want nixpacks", spec.Service.Build.Builder)
	}
	if got := spec.Service.Build.DockerfilePath; got != "" {
		t.Errorf("nixpacks builder rendered DockerfilePath = %q, want empty", got)
	}
	if got := spec.Service.Build.Image; got != "" {
		t.Errorf("application-git rendered Image = %q, want empty (subtype boundary)", got)
	}
	if got := spec.Service.Build.GitBranch; got != "main" {
		t.Errorf("git branch = %q, want main", got)
	}
	if got := spec.Service.Build.GitCommit; got != "deadbeefcafebabe" {
		t.Errorf("git commit = %q, want deadbeefcafebabe", got)
	}
}

// TestRenderApplicationGitDropsImageField is the subtype-boundary pin: an
// application-git input that smuggles in an Image reference renders with
// the Image field cleared and the submitted Image string never echoed in
// any error or log surface. This is the structural barrier against BE-0303
// (application-image): an "application-git" spec MUST NOT carry an Image,
// no matter what the caller submitted.
func TestRenderApplicationGitDropsImageField(t *testing.T) {
	t.Parallel()

	const leakyImage = "leaky-image.example.com/secret-app:v9.9.9"

	for _, builder := range []string{dokploy.BuilderDockerfile, dokploy.BuilderNixpacks} {
		t.Run(builder, func(t *testing.T) {
			t.Parallel()
			in := applicationGitDockerfileInput()
			in.Build = dokploy.BuildSettings{
				Builder:        builder,
				DockerfilePath: "Dockerfile",
				GitBranch:      "main",
				GitCommit:      "deadbeefcafebabe",
				Image:          leakyImage,
			}

			spec := mustRender(t, in)

			if spec.Service.Build.Builder != builder {
				t.Errorf("builder = %q, want %q", spec.Service.Build.Builder, builder)
			}
			if spec.Service.Build.Image != "" {
				t.Errorf("application-git rendered Image = %q, want empty for builder %q",
					spec.Service.Build.Image, builder)
			}

			// The submitted Image must not leak into the Summary surfaces.
			summary := spec.Summary()
			payload, err := json.Marshal(summary)
			if err != nil {
				t.Fatalf("marshal summary: %v", err)
			}
			var logBuf bytes.Buffer
			slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("rendered", "spec", spec)
			for label, s := range map[string]string{
				"summary json":   string(payload),
				"slog record":    logBuf.String(),
				"summary string": summary.String(),
			} {
				if strings.Contains(s, leakyImage) {
					t.Errorf("%s leaked the dropped Image: %s", label, s)
				}
			}
		})
	}
}

// TestRenderApplicationGitRoleMatrix pins that application-git supports
// every documented service role — web, worker, and cron — at both
// dockerfile and nixpacks builders. The shape of each rendered spec
// matches the role's documented invariants:
//
//   - web    : domains rendered, no cron schedule.
//   - worker : domains dropped, no cron schedule.
//   - cron   : domains dropped, cron schedule preserved.
func TestRenderApplicationGitRoleMatrix(t *testing.T) {
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

	for _, builderCase := range []func() dokploy.RenderInput{
		applicationGitDockerfileInput,
		applicationGitNixpacksInput,
	} {
		for _, c := range cases {
			c := c
			builderInput := builderCase()
			builderName := builderInput.Build.Builder
			t.Run(builderName+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				in := builderCase()
				in.Role = c.role
				in.CronSchedule = c.cron
				if c.role != dokploy.RoleWeb {
					in.Domains = nil
				}
				spec := mustRender(t, in)
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
					t.Errorf("rendered Image = %q, want empty for application-git",
						spec.Service.Build.Image)
				}
			})
		}
	}
}

// TestRenderApplicationGitValidationFailures pins that every required field
// the renderer rejects for an application-git input becomes a typed
// apierr.InvalidInput with a stable, indexed Field path, and that no
// submitted value is ever echoed into the rendered error surface. The
// table covers the failure modes most relevant to application-git:
// hierarchy identity, parent linkage, environment tier, service type,
// service role, cron schedule absence on a cron role, variable name
// rejection (no value echo), negative resource limits, and bad builder
// strings — using a Dockerfile-builder application-git base.
func TestRenderApplicationGitValidationFailures(t *testing.T) {
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
		{"bad builder", func(in *dokploy.RenderInput) {
			in.Build = dokploy.BuildSettings{Builder: "bazel", GitBranch: "main"}
		}, "build.builder"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			in := applicationGitDockerfileInput()
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

// TestRenderApplicationGitTierResourceDefaults pins the
// tier × role resource defaults for application-git specifically: only a
// production web app-git gets the load-bearing 2-replica default; every
// other tier × role combination defaults to a single replica regardless of
// the dockerfile-vs-nixpacks builder choice. This is the load-bearing
// resource-allocation contract a future autoscaler story has to honour.
func TestRenderApplicationGitTierResourceDefaults(t *testing.T) {
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
		applicationGitDockerfileInput,
		applicationGitNixpacksInput,
	} {
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

// TestRenderApplicationGitRedactsAllVariableValuesAcrossRoles pins the
// secrets-redaction contract for application-git across every role and
// both supported builders: the RenderedSpec carries verbatim variable
// values (the worker needs them) but the Summary, its JSON, its slog
// LogValue, and its String never expose any variable value — neither the
// Secret-flagged one nor the plain one. Every value site shows the
// redaction sentinel.
func TestRenderApplicationGitRedactsAllVariableValuesAcrossRoles(t *testing.T) {
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
		applicationGitDockerfileInput,
		applicationGitNixpacksInput,
	} {
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

// TestRenderApplicationGitDeterministic pins that an application-git input
// renders to a byte-stable RenderedSpec across renderer invocations for
// both supported builders. Determinism is the renderer contract that lets
// the worker compare a freshly rendered spec to a previously-stored one to
// decide whether a Dokploy update is needed at all.
func TestRenderApplicationGitDeterministic(t *testing.T) {
	t.Parallel()
	for _, makeIn := range []func() dokploy.RenderInput{
		applicationGitDockerfileInput,
		applicationGitNixpacksInput,
	} {
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
