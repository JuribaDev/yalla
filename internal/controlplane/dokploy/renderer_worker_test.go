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

// BE-0319: Provision worker services.
//
// This file pins the per-role renderer contract for "worker" services —
// Yalla's name for a continuously-running service with no inbound HTTP
// traffic. Unlike the BE-0301/BE-0303/BE-0305 application-* pins (whose
// subtype identity is Build.Builder) and unlike BE-0307 compose / BE-0309..
// BE-0317 database engines (whose subtype identity is Service.Type or the
// database Engine), the worker subtype boundary at the renderer layer is
// the Role itself. A worker service may be either an application or a
// compose stack and may build with any of the four supported builders;
// what makes it a worker is Role == RoleWorker.
//
// Subtype identity at the renderer layer:
//
//	Role           == RoleWorker
//	Service.Type   ∈ {ServiceApplication, ServiceCompose}
//	Build.Builder  ∈ {BuilderDockerfile, BuilderNixpacks, BuilderImage,
//	                  BuilderDropArtifact}
//
// While the durable provisioning worker that creates or updates the
// matching Dokploy resource and stores dokploy_refs atomically lands in a
// later worker story, this file is the structural barrier that pins the
// declarative-content half of the BE-0319 acceptance contract:
//
//   - The renderer validates every required field with stable, indexed
//     apierr.FieldViolations whose Reason text never echoes the submitted
//     value (a violation message is always safe for client envelopes,
//     logs, and audit metadata).
//   - The renderer drops every web-only and cron-only field for a worker
//     service: Domains are dropped (a worker has no inbound HTTP) and
//     CronSchedule is dropped (a worker runs continuously, not on a
//     schedule). The submitted values never echo into any rendered error,
//     Summary JSON, slog record, or Summary.String() surface — that is
//     the structural barrier against BE-0301..BE-0307 (web shape) and
//     BE-0321 (cron shape).
//   - The renderer surfaces the worker role as a yalla.role label so
//     dashboards and audit trails can distinguish a worker from a web or
//     cron service without re-reading the spec body.
//   - The renderer never grants a worker the load-bearing production-web
//     2-replica default; every (tier × worker) combination renders with
//     exactly one replica. This is the load-bearing resource-allocation
//     contract a future autoscaler story has to honour.
//   - The renderer carries verbatim variable values for the worker
//     (the provisioner needs them) but redacts every value in the
//     Summary, slog LogValue, and Summary.String() debug surface — so the
//     secrets redaction acceptance criterion is structurally enforced for
//     both application and compose variants of a worker service.
//
// Pattern: this is the renderer-level counterpart to the engine-pin
// pattern used for admin-action policy matrices (BE-0285 / BE-0288 /
// BE-0291 / BE-0294 / BE-0297 / BE-0300) and the structural sibling of
// renderer_application_git_test.go (BE-0301),
// renderer_application_image_test.go (BE-0303),
// renderer_application_drop_artifact_test.go (BE-0305),
// renderer_compose_test.go (BE-0307), and the database-engine family
// (BE-0309..BE-0317) — a state-independent file that pins the contract
// the worker-side story must continue to satisfy. The single-role
// collapse mirrors BE-0303 (single-builder collapse): no production code
// change is needed because the renderer already drops domains and cron
// schedule for non-web/non-cron roles; this file is the structural
// barrier against any future refactor that would relax that drop.

// workerApplicationInput returns a fully-valid worker RenderInput on a
// ServiceApplication, using the Dockerfile builder. It reuses
// validInput() (from renderer_test.go) for the hierarchy and variable
// fixtures so the canonical-id and per-level secret sets stay in lockstep
// with every other renderer pin. Domains are cleared because a worker has
// no inbound HTTP; the caller may re-add them to exercise the drop pin.
func workerApplicationInput() dokploy.RenderInput {
	in := validInput()
	in.Service.Type = dokploy.ServiceApplication
	in.Service.Engine = ""
	in.Role = dokploy.RoleWorker
	in.Domains = nil
	in.CronSchedule = ""
	in.Build = dokploy.BuildSettings{
		Builder:        dokploy.BuilderDockerfile,
		DockerfilePath: "build/Dockerfile",
		GitBranch:      "main",
		GitCommit:      "deadbeefcafebabe",
	}
	return in
}

// workerComposeInput returns a fully-valid worker RenderInput on a
// ServiceCompose, using the Dockerfile builder. It mirrors
// workerApplicationInput on the compose side of the worker subtype.
func workerComposeInput() dokploy.RenderInput {
	in := validInput()
	in.Service.Type = dokploy.ServiceCompose
	in.Service.Engine = ""
	in.Role = dokploy.RoleWorker
	in.Domains = nil
	in.CronSchedule = ""
	in.Build = dokploy.BuildSettings{
		Builder:        dokploy.BuilderDockerfile,
		DockerfilePath: "compose/Dockerfile",
		GitBranch:      "main",
		GitCommit:      "deadbeefcafebabe",
	}
	return in
}

// TestRenderWorkerApplicationSuccess pins the canonical worker-on-
// application happy path: role=worker, type=application, the rendered
// spec carries no domains and no cron schedule, and the yalla.role label
// is surfaced as "worker".
func TestRenderWorkerApplicationSuccess(t *testing.T) {
	t.Parallel()

	spec := mustRender(t, workerApplicationInput())

	if spec.Service.Type != dokploy.ServiceApplication {
		t.Errorf("service type = %q, want application", spec.Service.Type)
	}
	if spec.Service.Role != dokploy.RoleWorker {
		t.Errorf("role = %q, want worker", spec.Service.Role)
	}
	if got := len(spec.Service.Domains); got != 0 {
		t.Errorf("worker rendered Domains count = %d, want 0", got)
	}
	if got := spec.Service.CronSchedule; got != "" {
		t.Errorf("worker rendered CronSchedule = %q, want empty", got)
	}
	if got := spec.Service.Engine; got != "" {
		t.Errorf("worker rendered Engine = %q, want empty (engine is database-only)", got)
	}
	var roleLabel string
	for _, l := range spec.Service.Labels {
		if l.Key == "yalla.role" {
			roleLabel = l.Value
		}
	}
	if roleLabel != string(dokploy.RoleWorker) {
		t.Errorf("yalla.role label = %q, want %q", roleLabel, dokploy.RoleWorker)
	}
}

// TestRenderWorkerComposeSuccess pins the canonical worker-on-compose
// happy path: role=worker, type=compose, the rendered spec carries no
// domains and no cron schedule, and the yalla.role label is surfaced as
// "worker".
func TestRenderWorkerComposeSuccess(t *testing.T) {
	t.Parallel()

	spec := mustRender(t, workerComposeInput())

	if spec.Service.Type != dokploy.ServiceCompose {
		t.Errorf("service type = %q, want compose", spec.Service.Type)
	}
	if spec.Service.Role != dokploy.RoleWorker {
		t.Errorf("role = %q, want worker", spec.Service.Role)
	}
	if got := len(spec.Service.Domains); got != 0 {
		t.Errorf("worker rendered Domains count = %d, want 0", got)
	}
	if got := spec.Service.CronSchedule; got != "" {
		t.Errorf("worker rendered CronSchedule = %q, want empty", got)
	}
	if got := spec.Service.Engine; got != "" {
		t.Errorf("worker rendered Engine = %q, want empty (engine is database-only)", got)
	}
	var roleLabel string
	for _, l := range spec.Service.Labels {
		if l.Key == "yalla.role" {
			roleLabel = l.Value
		}
	}
	if roleLabel != string(dokploy.RoleWorker) {
		t.Errorf("yalla.role label = %q, want %q", roleLabel, dokploy.RoleWorker)
	}
}

// TestRenderWorkerDropsWebAndCronFields is the subtype-boundary pin: a
// worker input that smuggles in web-only Domains and a cron-only
// CronSchedule renders with both cleared and the submitted values never
// echoed into any rendered error, Summary JSON, slog record, or
// Summary.String() surface. This is the structural barrier against
// BE-0301..BE-0307 (web shape: Domains preserved) and BE-0321 (cron
// shape: CronSchedule preserved). It runs across both worker variants
// (application and compose) to prove the drop is role-driven, not
// type-driven.
func TestRenderWorkerDropsWebAndCronFields(t *testing.T) {
	t.Parallel()

	const (
		leakyHost = "worker-leak.example"
		leakyCron = "13 13 * * 5"
	)
	leakyValues := []string{leakyHost, leakyCron}

	for _, makeIn := range []func() dokploy.RenderInput{
		workerApplicationInput,
		workerComposeInput,
	} {
		makeIn := makeIn
		in := makeIn()
		t.Run(string(in.Service.Type), func(t *testing.T) {
			t.Parallel()
			in := makeIn()
			in.Domains = []dokploy.DomainSpec{
				{Host: leakyHost, HTTPS: true, Path: "/"},
			}
			in.CronSchedule = leakyCron

			spec := mustRender(t, in)

			if spec.Service.Role != dokploy.RoleWorker {
				t.Errorf("role = %q, want worker", spec.Service.Role)
			}
			if got := len(spec.Service.Domains); got != 0 {
				t.Errorf("worker rendered Domains count = %d, want 0", got)
			}
			if got := spec.Service.CronSchedule; got != "" {
				t.Errorf("worker rendered CronSchedule = %q, want empty", got)
			}

			// None of the submitted web-only or cron-only values may
			// leak into any debug surface.
			summary := spec.Summary()
			payload, err := json.Marshal(summary)
			if err != nil {
				t.Fatalf("marshal summary: %v", err)
			}
			var logBuf bytes.Buffer
			slog.New(slog.NewJSONHandler(&logBuf, nil)).Info(
				"rendered", "spec", spec, "summary", summary,
			)
			for label, s := range map[string]string{
				"summary json":   string(payload),
				"slog record":    logBuf.String(),
				"summary string": summary.String(),
			} {
				for _, leak := range leakyValues {
					if strings.Contains(s, leak) {
						t.Errorf("%s leaked the dropped value %q: %s", label, leak, s)
					}
				}
			}
		})
	}
}

// TestRenderWorkerSubtypeBoundaryFromWebAndCron pins that a worker input
// renders as a worker, a web input renders as a web (with domains
// preserved), and a cron input renders as a cron (with cron schedule
// preserved). The yalla.role label faithfully surfaces the role across
// every case, so a future audit/observability consumer can distinguish a
// worker from its sibling roles without re-reading the spec body. This is
// the structural barrier against any future refactor that would conflate
// the three roles inside the type switch in Render().
func TestRenderWorkerSubtypeBoundaryFromWebAndCron(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		in          func() dokploy.RenderInput
		wantRole    dokploy.ServiceRole
		wantDomains int
		wantCron    string
	}{
		{
			name:        "worker stays worker (application)",
			in:          workerApplicationInput,
			wantRole:    dokploy.RoleWorker,
			wantDomains: 0,
			wantCron:    "",
		},
		{
			name:        "worker stays worker (compose)",
			in:          workerComposeInput,
			wantRole:    dokploy.RoleWorker,
			wantDomains: 0,
			wantCron:    "",
		},
		{
			name:        "web stays web (application)",
			in:          applicationGitDockerfileInput,
			wantRole:    dokploy.RoleWeb,
			wantDomains: 1,
			wantCron:    "",
		},
		{
			name:        "web stays web (compose)",
			in:          composeDockerfileInput,
			wantRole:    dokploy.RoleWeb,
			wantDomains: 1,
			wantCron:    "",
		},
		{
			name: "cron stays cron (application)",
			in: func() dokploy.RenderInput {
				in := applicationGitDockerfileInput()
				in.Role = dokploy.RoleCron
				in.CronSchedule = "0 2 * * *"
				in.Domains = nil
				return in
			},
			wantRole:    dokploy.RoleCron,
			wantDomains: 0,
			wantCron:    "0 2 * * *",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			spec := mustRender(t, c.in())
			if spec.Service.Role != c.wantRole {
				t.Errorf("role = %q, want %q", spec.Service.Role, c.wantRole)
			}
			if got := len(spec.Service.Domains); got != c.wantDomains {
				t.Errorf("domains count = %d, want %d", got, c.wantDomains)
			}
			if spec.Service.CronSchedule != c.wantCron {
				t.Errorf("cron schedule = %q, want %q",
					spec.Service.CronSchedule, c.wantCron)
			}
			var roleLabel string
			for _, l := range spec.Service.Labels {
				if l.Key == "yalla.role" {
					roleLabel = l.Value
				}
			}
			if roleLabel != string(c.wantRole) {
				t.Errorf("yalla.role label = %q, want %q", roleLabel, c.wantRole)
			}
		})
	}
}

// TestRenderWorkerBuilderMatrix pins that a worker service supports every
// documented builder — dockerfile, nixpacks, image, drop-artifact — across
// both application and compose variants. For every (service-type ×
// builder) combination the rendered spec is still a worker (no domains,
// no cron schedule) and the builder-specific build settings are preserved
// or normalised exactly as they are for web services.
func TestRenderWorkerBuilderMatrix(t *testing.T) {
	t.Parallel()

	const (
		dockerfilePath = "deploy/Dockerfile"
		image          = "registry.acme.example/worker:v1.2.3"
		artifactURL    = "https://artifacts.yalla.example/uploads/worker-v1.2.3.tar.gz"
	)

	type buildCase struct {
		name  string
		build dokploy.BuildSettings
		check func(t *testing.T, b dokploy.BuildSettings)
	}
	builders := []buildCase{
		{
			name: "dockerfile",
			build: dokploy.BuildSettings{
				Builder:        dokploy.BuilderDockerfile,
				DockerfilePath: dockerfilePath,
				GitBranch:      "main",
				GitCommit:      "deadbeefcafebabe",
			},
			check: func(t *testing.T, b dokploy.BuildSettings) {
				t.Helper()
				if b.Builder != dokploy.BuilderDockerfile {
					t.Errorf("builder = %q, want dockerfile", b.Builder)
				}
				if b.DockerfilePath != dockerfilePath {
					t.Errorf("dockerfile path = %q, want %q", b.DockerfilePath, dockerfilePath)
				}
				if b.Image != "" {
					t.Errorf("dockerfile builder rendered Image = %q, want empty", b.Image)
				}
				if b.ArtifactURL != "" {
					t.Errorf("dockerfile builder rendered ArtifactURL = %q, want empty", b.ArtifactURL)
				}
			},
		},
		{
			name: "nixpacks",
			build: dokploy.BuildSettings{
				Builder:   dokploy.BuilderNixpacks,
				GitBranch: "main",
				GitCommit: "deadbeefcafebabe",
			},
			check: func(t *testing.T, b dokploy.BuildSettings) {
				t.Helper()
				if b.Builder != dokploy.BuilderNixpacks {
					t.Errorf("builder = %q, want nixpacks", b.Builder)
				}
				if b.DockerfilePath != "" {
					t.Errorf("nixpacks builder rendered DockerfilePath = %q, want empty", b.DockerfilePath)
				}
				if b.Image != "" {
					t.Errorf("nixpacks builder rendered Image = %q, want empty", b.Image)
				}
				if b.ArtifactURL != "" {
					t.Errorf("nixpacks builder rendered ArtifactURL = %q, want empty", b.ArtifactURL)
				}
			},
		},
		{
			name: "image",
			build: dokploy.BuildSettings{
				Builder: dokploy.BuilderImage,
				Image:   image,
			},
			check: func(t *testing.T, b dokploy.BuildSettings) {
				t.Helper()
				if b.Builder != dokploy.BuilderImage {
					t.Errorf("builder = %q, want image", b.Builder)
				}
				if b.Image != image {
					t.Errorf("image = %q, want %q", b.Image, image)
				}
				if b.DockerfilePath != "" {
					t.Errorf("image builder rendered DockerfilePath = %q, want empty", b.DockerfilePath)
				}
				if b.GitBranch != "" {
					t.Errorf("image builder rendered GitBranch = %q, want empty", b.GitBranch)
				}
				if b.GitCommit != "" {
					t.Errorf("image builder rendered GitCommit = %q, want empty", b.GitCommit)
				}
				if b.ArtifactURL != "" {
					t.Errorf("image builder rendered ArtifactURL = %q, want empty", b.ArtifactURL)
				}
			},
		},
		{
			name: "drop-artifact",
			build: dokploy.BuildSettings{
				Builder:     dokploy.BuilderDropArtifact,
				ArtifactURL: artifactURL,
			},
			check: func(t *testing.T, b dokploy.BuildSettings) {
				t.Helper()
				if b.Builder != dokploy.BuilderDropArtifact {
					t.Errorf("builder = %q, want drop-artifact", b.Builder)
				}
				if b.ArtifactURL != artifactURL {
					t.Errorf("artifact url = %q, want %q", b.ArtifactURL, artifactURL)
				}
				if b.DockerfilePath != "" {
					t.Errorf("drop-artifact builder rendered DockerfilePath = %q, want empty", b.DockerfilePath)
				}
				if b.Image != "" {
					t.Errorf("drop-artifact builder rendered Image = %q, want empty", b.Image)
				}
				if b.GitBranch != "" {
					t.Errorf("drop-artifact builder rendered GitBranch = %q, want empty", b.GitBranch)
				}
				if b.GitCommit != "" {
					t.Errorf("drop-artifact builder rendered GitCommit = %q, want empty", b.GitCommit)
				}
			},
		},
	}

	for _, makeIn := range []func() dokploy.RenderInput{
		workerApplicationInput,
		workerComposeInput,
	} {
		makeIn := makeIn
		baseIn := makeIn()
		serviceType := string(baseIn.Service.Type)
		for _, b := range builders {
			b := b
			t.Run(serviceType+"/"+b.name, func(t *testing.T) {
				t.Parallel()
				in := makeIn()
				in.Build = b.build
				spec := mustRender(t, in)

				if spec.Service.Role != dokploy.RoleWorker {
					t.Errorf("role = %q, want worker", spec.Service.Role)
				}
				if got := len(spec.Service.Domains); got != 0 {
					t.Errorf("worker rendered Domains count = %d, want 0", got)
				}
				if spec.Service.CronSchedule != "" {
					t.Errorf("worker rendered CronSchedule = %q, want empty",
						spec.Service.CronSchedule)
				}
				b.check(t, spec.Service.Build)
			})
		}
	}
}

// TestRenderWorkerValidationFailures pins that every required field the
// renderer rejects for a worker input becomes a typed apierr.InvalidInput
// with a stable, indexed Field path, and that no submitted value is ever
// echoed into the rendered error surface. The table covers the failure
// modes most relevant to a worker: hierarchy identity, parent linkage,
// environment tier, service type, service role, variable name rejection
// (no value echo), negative resource limits, image-builder-missing-image
// (a worker may use any of the four supported builders, so the
// image-builder failure path is part of the worker contract),
// drop-artifact-builder-missing-artifact-url, and bad builder strings —
// using a Dockerfile-builder worker-application base.
func TestRenderWorkerValidationFailures(t *testing.T) {
	t.Parallel()

	leakyValues := []string{
		"not-a-yalla-id",
		"1bad",
		"sk-live-supersecret",
		"frontend",
		"function",
		"prod-tier",
		"bazel",
		"leaky-image.example.com/secret-worker:v9.9.9",
		"https://artifacts.yalla.example/uploads/worker-secret-v1.2.3.tar.gz",
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
			in := workerApplicationInput()
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

// TestRenderWorkerTierResourceDefaults pins the tier × worker resource
// defaults across both worker variants (application and compose). A
// worker never gets the load-bearing production-web 2-replica default;
// every (tier × worker) combination defaults to a single replica
// regardless of whether the worker is an application or a compose stack.
// This is the inverse of the BE-0301/BE-0307 production-web replica bump
// and is the load-bearing resource-allocation contract a future
// autoscaler story has to honour.
func TestRenderWorkerTierResourceDefaults(t *testing.T) {
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
	for _, makeIn := range []func() dokploy.RenderInput{
		workerApplicationInput,
		workerComposeInput,
	} {
		makeIn := makeIn
		baseIn := makeIn()
		serviceType := string(baseIn.Service.Type)
		for _, c := range cases {
			c := c
			t.Run(serviceType+"/"+string(c.tier), func(t *testing.T) {
				t.Parallel()
				in := makeIn()
				in.Tier = c.tier
				spec := mustRender(t, in)
				got := spec.Service.Resources
				if got.CPUMillis != c.wantCPU || got.MemoryMiB != c.wantMemory || got.Replicas != c.wantReplicas {
					t.Errorf("tier=%s type=%s: resources = %+v, want %d/%d/%d",
						c.tier, serviceType, got, c.wantCPU, c.wantMemory, c.wantReplicas)
				}
			})
		}
	}
}

// TestRenderWorkerRedactsAllVariableValues pins the secrets-redaction
// contract for worker services across both worker variants: the
// RenderedSpec carries verbatim variable values (the provisioner needs
// them) but the Summary, its JSON, its slog LogValue, and its String
// never expose any variable value — neither the Secret-flagged one nor
// the plain one. Every value site shows the redaction sentinel.
func TestRenderWorkerRedactsAllVariableValues(t *testing.T) {
	t.Parallel()

	const secret = "sk-live-supersecret"
	const plain = "off"

	for _, makeIn := range []func() dokploy.RenderInput{
		workerApplicationInput,
		workerComposeInput,
	} {
		makeIn := makeIn
		baseIn := makeIn()
		serviceType := string(baseIn.Service.Type)
		t.Run(serviceType, func(t *testing.T) {
			t.Parallel()
			in := makeIn()

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
		})
	}
}

// TestRenderWorkerDeterministic pins that a worker input renders to a
// byte-stable RenderedSpec across renderer invocations for both
// application and compose worker variants. Determinism is the renderer
// contract that lets the provisioner compare a freshly rendered spec to
// a previously-stored one to decide whether a Dokploy update is needed at
// all.
func TestRenderWorkerDeterministic(t *testing.T) {
	t.Parallel()
	for _, makeIn := range []func() dokploy.RenderInput{
		workerApplicationInput,
		workerComposeInput,
	} {
		makeIn := makeIn
		in := makeIn()
		serviceType := string(in.Service.Type)
		t.Run(serviceType, func(t *testing.T) {
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
