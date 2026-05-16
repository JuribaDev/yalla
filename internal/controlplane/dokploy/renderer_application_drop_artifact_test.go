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

// BE-0305: Provision application-drop-artifact services.
//
// This file pins the per-subtype renderer contract for
// "application-drop-artifact" — Yalla's name for an application service
// whose container image is built from a customer-uploaded pre-built
// artifact (a tarball, zip, or similar bundle), rather than from a git
// source (BE-0301) or a pre-existing registry image (BE-0303). The
// subtype identity at the renderer layer is:
//
//	Service.Type   == ServiceApplication
//	Build.Builder  == BuilderDropArtifact
//	Role           ∈ {RoleWeb, RoleWorker, RoleCron}
//
// While the durable provisioning worker that creates or updates the
// matching Dokploy resource and stores dokploy_refs atomically lands in a
// later worker story, this file is the structural barrier that pins the
// declarative-content half of the BE-0305 acceptance contract:
//
//   - The renderer validates every required field — including the
//     drop-artifact-specific `build.artifact_url` field — with stable,
//     indexed apierr.FieldViolations whose Reason text never echoes the
//     submitted value (a violation message is always safe for client
//     envelopes, logs, and audit metadata).
//   - The renderer drops every git-source-only build field
//     (dockerfile_path, git_branch, git_commit) AND the BuilderImage-only
//     `image` field for builder=drop-artifact, so an
//     application-drop-artifact spec can never carry git-source metadata
//     or a registry image reference — that is the dual subtype boundary
//     against BE-0301 (application-git) and BE-0303 (application-image).
//   - The renderer carries the verbatim ArtifactURL for the worker and
//     the verbatim variable values for the worker, but redacts every
//     variable value (secret-flagged or not) in the Summary, its slog
//     LogValue, and Summary.String() so a debug surface never leaks
//     them.
//
// Pattern: this is the renderer-level counterpart to the engine-pin
// pattern used for admin-action policy matrices (BE-0285 / BE-0288 /
// BE-0291 / BE-0294 / BE-0297 / BE-0300) and the structural sibling of
// renderer_application_git_test.go (BE-0301) and
// renderer_application_image_test.go (BE-0303) — a state-independent
// file that pins the contract the worker-side story must continue to
// satisfy.

// applicationDropArtifactInput returns a fully-valid
// application-drop-artifact RenderInput using the DropArtifact builder.
// It reuses validInput() (from renderer_test.go) for the hierarchy and
// variable fixtures so the canonical-id and per-level secret sets stay
// in lockstep with the other renderer pins.
func applicationDropArtifactInput() dokploy.RenderInput {
	in := validInput()
	in.Service.Type = dokploy.ServiceApplication
	in.Service.Engine = ""
	in.Role = dokploy.RoleWeb
	in.Build = dokploy.BuildSettings{
		Builder:     dokploy.BuilderDropArtifact,
		ArtifactURL: "https://artifacts.yalla.example/uploads/api-v1.2.3.tar.gz",
	}
	return in
}

// TestRenderApplicationDropArtifactSuccess pins the canonical
// application-drop-artifact happy path: type=application,
// builder=drop-artifact, the requested ArtifactURL is preserved verbatim,
// and every git-source-only and image-only build field stays empty.
func TestRenderApplicationDropArtifactSuccess(t *testing.T) {
	t.Parallel()

	spec := mustRender(t, applicationDropArtifactInput())

	if spec.Service.Type != dokploy.ServiceApplication {
		t.Errorf("service type = %q, want application", spec.Service.Type)
	}
	if spec.Service.Build.Builder != dokploy.BuilderDropArtifact {
		t.Errorf("builder = %q, want drop-artifact", spec.Service.Build.Builder)
	}
	const wantArtifact = "https://artifacts.yalla.example/uploads/api-v1.2.3.tar.gz"
	if got := spec.Service.Build.ArtifactURL; got != wantArtifact {
		t.Errorf("artifact url = %q, want %q", got, wantArtifact)
	}
	if got := spec.Service.Build.Image; got != "" {
		t.Errorf("application-drop-artifact rendered Image = %q, want empty (subtype boundary)", got)
	}
	if got := spec.Service.Build.DockerfilePath; got != "" {
		t.Errorf("application-drop-artifact rendered DockerfilePath = %q, want empty (subtype boundary)", got)
	}
	if got := spec.Service.Build.GitBranch; got != "" {
		t.Errorf("application-drop-artifact rendered GitBranch = %q, want empty (subtype boundary)", got)
	}
	if got := spec.Service.Build.GitCommit; got != "" {
		t.Errorf("application-drop-artifact rendered GitCommit = %q, want empty (subtype boundary)", got)
	}
}

// TestRenderApplicationDropArtifactDropsGitAndImageFields is the dual
// subtype-boundary pin: an application-drop-artifact input that smuggles
// in BOTH git-source-only build fields (dockerfile_path, git_branch,
// git_commit) AND the BuilderImage-only image field renders with every
// one of those fields cleared and none of the submitted values echoed in
// any error or log surface. This is the structural barrier against both
// BE-0301 (application-git) and BE-0303 (application-image): an
// "application-drop-artifact" spec MUST NOT carry git build metadata OR
// a registry image reference, no matter what the caller submitted.
func TestRenderApplicationDropArtifactDropsGitAndImageFields(t *testing.T) {
	t.Parallel()

	const (
		leakyDockerfile = "leaky/path/Dockerfile.secret"
		leakyBranch     = "leaky-branch-with-secret-name"
		leakyCommit     = "leakycommitc0ffee1337beefcafe"
		leakyImage      = "leaky-image.example.com/secret-app:v9.9.9"
	)
	leakyValues := []string{leakyDockerfile, leakyBranch, leakyCommit, leakyImage}

	in := applicationDropArtifactInput()
	in.Build = dokploy.BuildSettings{
		Builder:        dokploy.BuilderDropArtifact,
		ArtifactURL:    "https://artifacts.yalla.example/uploads/api-v1.2.3.tar.gz",
		Image:          leakyImage,
		DockerfilePath: leakyDockerfile,
		GitBranch:      leakyBranch,
		GitCommit:      leakyCommit,
	}

	spec := mustRender(t, in)

	if spec.Service.Build.Builder != dokploy.BuilderDropArtifact {
		t.Errorf("builder = %q, want drop-artifact", spec.Service.Build.Builder)
	}
	if spec.Service.Build.Image != "" {
		t.Errorf("application-drop-artifact rendered Image = %q, want empty",
			spec.Service.Build.Image)
	}
	if spec.Service.Build.DockerfilePath != "" {
		t.Errorf("application-drop-artifact rendered DockerfilePath = %q, want empty",
			spec.Service.Build.DockerfilePath)
	}
	if spec.Service.Build.GitBranch != "" {
		t.Errorf("application-drop-artifact rendered GitBranch = %q, want empty",
			spec.Service.Build.GitBranch)
	}
	if spec.Service.Build.GitCommit != "" {
		t.Errorf("application-drop-artifact rendered GitCommit = %q, want empty",
			spec.Service.Build.GitCommit)
	}

	// None of the submitted foreign-builder values may leak into the
	// Summary surfaces.
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
		for _, leak := range leakyValues {
			if strings.Contains(s, leak) {
				t.Errorf("%s leaked the dropped foreign-builder field value %q: %s", label, leak, s)
			}
		}
	}
}

// TestRenderApplicationDropArtifactRoleMatrix pins that
// application-drop-artifact supports every documented service role —
// web, worker, and cron. The shape of each rendered spec matches the
// role's documented invariants:
//
//   - web    : domains rendered, no cron schedule.
//   - worker : domains dropped, no cron schedule.
//   - cron   : domains dropped, cron schedule preserved.
//
// Across every role the ArtifactURL is preserved verbatim and every
// git-source-only and image-only build field stays empty.
func TestRenderApplicationDropArtifactRoleMatrix(t *testing.T) {
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

	for _, c := range cases {
		c := c
		t.Run(string(c.role), func(t *testing.T) {
			t.Parallel()
			in := applicationDropArtifactInput()
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
			if spec.Service.Build.Builder != dokploy.BuilderDropArtifact {
				t.Errorf("builder = %q, want drop-artifact", spec.Service.Build.Builder)
			}
			const wantArtifact = "https://artifacts.yalla.example/uploads/api-v1.2.3.tar.gz"
			if spec.Service.Build.ArtifactURL != wantArtifact {
				t.Errorf("artifact url = %q, want preserved",
					spec.Service.Build.ArtifactURL)
			}
			if spec.Service.Build.Image != "" {
				t.Errorf("application-drop-artifact rendered Image = %q, want empty",
					spec.Service.Build.Image)
			}
			if spec.Service.Build.DockerfilePath != "" {
				t.Errorf("application-drop-artifact rendered DockerfilePath = %q, want empty",
					spec.Service.Build.DockerfilePath)
			}
			if spec.Service.Build.GitBranch != "" {
				t.Errorf("application-drop-artifact rendered GitBranch = %q, want empty",
					spec.Service.Build.GitBranch)
			}
			if spec.Service.Build.GitCommit != "" {
				t.Errorf("application-drop-artifact rendered GitCommit = %q, want empty",
					spec.Service.Build.GitCommit)
			}
		})
	}
}

// TestRenderApplicationDropArtifactValidationFailures pins that every
// required field the renderer rejects for an application-drop-artifact
// input becomes a typed apierr.InvalidInput with a stable, indexed Field
// path, and that no submitted value is ever echoed into the rendered
// error surface. The table covers the failure modes most relevant to
// application-drop-artifact: hierarchy identity, parent linkage,
// environment tier, service type, service role, cron schedule absence on
// a cron role, variable name rejection (no value echo), negative
// resource limits, the drop-artifact-specific missing-artifact case, and
// bad builder strings.
func TestRenderApplicationDropArtifactValidationFailures(t *testing.T) {
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
		{"drop-artifact builder missing artifact url", func(in *dokploy.RenderInput) {
			in.Build = dokploy.BuildSettings{Builder: dokploy.BuilderDropArtifact}
		}, "build.artifact_url"},
		{"bad builder", func(in *dokploy.RenderInput) {
			in.Build = dokploy.BuildSettings{Builder: "bazel"}
		}, "build.builder"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			in := applicationDropArtifactInput()
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

// TestRenderApplicationDropArtifactTierResourceDefaults pins the
// tier × role resource defaults for application-drop-artifact
// specifically: only a production web drop-artifact gets the load-bearing
// 2-replica default; every other tier × role combination defaults to a
// single replica. This matches BE-0301 / BE-0303's invariant and is the
// load-bearing resource-allocation contract a future autoscaler story
// has to honour.
func TestRenderApplicationDropArtifactTierResourceDefaults(t *testing.T) {
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
	for _, c := range cases {
		c := c
		t.Run(string(c.tier)+"/"+string(c.role), func(t *testing.T) {
			t.Parallel()
			in := applicationDropArtifactInput()
			in.Tier = c.tier
			in.Role = c.role
			if c.role != dokploy.RoleWeb {
				in.Domains = nil
			}
			spec := mustRender(t, in)
			got := spec.Service.Resources
			if got.CPUMillis != c.wantCPU || got.MemoryMiB != c.wantMemory || got.Replicas != c.wantReplicas {
				t.Errorf("tier=%s role=%s: resources = %+v, want %d/%d/%d",
					c.tier, c.role, got, c.wantCPU, c.wantMemory, c.wantReplicas)
			}
		})
	}
}

// TestRenderApplicationDropArtifactRedactsAllVariableValuesAcrossRoles
// pins the secrets-redaction contract for application-drop-artifact
// across every role: the RenderedSpec carries the verbatim ArtifactURL
// and the verbatim variable values (the worker needs them) but the
// Summary, its JSON, its slog LogValue, and its String never expose any
// variable value — neither the Secret-flagged one nor the plain one.
// Every value site shows the redaction sentinel.
func TestRenderApplicationDropArtifactRedactsAllVariableValuesAcrossRoles(t *testing.T) {
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

	for _, r := range roles {
		r := r
		t.Run(string(r.role), func(t *testing.T) {
			t.Parallel()
			in := applicationDropArtifactInput()
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

			// And the verbatim ArtifactURL must still reach the worker so
			// the real provisioning call can pin a Dokploy application to
			// that exact uploaded artifact.
			const wantArtifact = "https://artifacts.yalla.example/uploads/api-v1.2.3.tar.gz"
			if got := spec.Service.Build.ArtifactURL; got != wantArtifact {
				t.Errorf("rendered spec lost the verbatim ArtifactURL: got %q", got)
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

// TestRenderApplicationDropArtifactDeterministic pins that an
// application-drop-artifact input renders to a byte-stable RenderedSpec
// across renderer invocations. Determinism is the renderer contract that
// lets the worker compare a freshly rendered spec to a previously-stored
// one to decide whether a Dokploy update is needed at all.
func TestRenderApplicationDropArtifactDeterministic(t *testing.T) {
	t.Parallel()
	in := applicationDropArtifactInput()
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
