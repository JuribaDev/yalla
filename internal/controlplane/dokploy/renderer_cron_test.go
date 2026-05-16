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

// BE-0321: Provision cron services.
//
// This file pins the per-role renderer contract for "cron" services —
// Yalla's name for a service that runs on a schedule instead of either
// taking inbound HTTP traffic (web) or running continuously (worker).
// Like BE-0319 (worker), the cron subtype boundary at the renderer layer
// is the Role itself; unlike BE-0319, the cron role REQUIRES a
// CronSchedule and preserves it through the rendered spec. A cron
// service may be either an application or a compose stack and may build
// with any of the four supported builders; what makes it a cron is
// Role == RoleCron + a valid CronSchedule.
//
// Subtype identity at the renderer layer:
//
//	Role           == RoleCron
//	CronSchedule   != "" and parses as a 5- or 6-field cron expression
//	Service.Type   ∈ {ServiceApplication, ServiceCompose}
//	Build.Builder  ∈ {BuilderDockerfile, BuilderNixpacks, BuilderImage,
//	                  BuilderDropArtifact}
//
// While the durable provisioning worker that creates or updates the
// matching Dokploy resource and stores dokploy_refs atomically lands in
// a later worker story, this file is the structural barrier that pins
// the declarative-content half of the BE-0321 acceptance contract:
//
//   - The renderer validates every required field with stable, indexed
//     apierr.FieldViolations whose Reason text never echoes the
//     submitted value (a violation message is always safe for client
//     envelopes, logs, and audit metadata). CronSchedule itself is
//     validated structurally (5 or 6 fields); the reason text is
//     value-free.
//   - The renderer drops every web-only field for a cron service:
//     Domains are dropped (a cron service has no inbound HTTP). The
//     submitted domain values never echo into any rendered error,
//     Summary JSON, slog record, or Summary.String() surface — that is
//     the structural barrier against BE-0301..BE-0307 (web shape: Domains
//     preserved).
//   - The renderer PRESERVES the cron schedule on the rendered spec and
//     on the redaction-safe Summary surface (the schedule is not a
//     secret — dashboards and runbooks need to surface it). That is the
//     structural barrier against BE-0319 (worker shape: CronSchedule
//     dropped).
//   - The renderer surfaces the cron role as a yalla.role label so
//     dashboards and audit trails can distinguish a cron from a web or
//     worker service without re-reading the spec body.
//   - The renderer never grants a cron the load-bearing production-web
//     2-replica default; every (tier × cron) combination renders with
//     exactly one replica. This is the load-bearing resource-allocation
//     contract a future autoscaler story has to honour and matches the
//     BE-0319 worker contract.
//   - The renderer carries verbatim variable values for the cron service
//     (the provisioner needs them) but redacts every value in the
//     Summary, slog LogValue, and Summary.String() debug surface — so
//     the secrets redaction acceptance criterion is structurally enforced
//     for both application and compose variants of a cron service.
//
// Pattern: this is the FIFTH role-axis variant in the renderer-subtype
// family after the Builder axis (BE-0301/0303/0305), the ServiceType
// axis (BE-0307), the Engine axis (BE-0309..0317), and the worker
// role-axis pin (BE-0319). The clone shape vs BE-0319 is a 3-token swap
// (Worker→Cron in identifiers, RoleWorker→RoleCron, role label value)
// plus one structural addition: a cron-schedule-validation leg in
// ValidationFailures, since the cron role IS subject to cron_schedule
// validation while the worker role is not — the inverse omission to the
// one renderer_worker_test.go documents.

// validCronExpr is the canonical 5-field cron expression the cron
// helpers and assertions use as the verbatim schedule fixture. It is
// short, byte-stable, and contains no value that a customer could leak
// through it.
const validCronExpr = "0 2 * * *"

// cronApplicationInput returns a fully-valid cron RenderInput on a
// ServiceApplication, using the Dockerfile builder. It reuses
// validInput() (from renderer_test.go) for the hierarchy and variable
// fixtures so the canonical-id and per-level secret sets stay in
// lockstep with every other renderer pin. Domains are cleared because a
// cron service has no inbound HTTP; the caller may re-add them to
// exercise the drop pin. CronSchedule is set to the canonical fixture.
func cronApplicationInput() dokploy.RenderInput {
	in := validInput()
	in.Service.Type = dokploy.ServiceApplication
	in.Service.Engine = ""
	in.Role = dokploy.RoleCron
	in.Domains = nil
	in.CronSchedule = validCronExpr
	in.Build = dokploy.BuildSettings{
		Builder:        dokploy.BuilderDockerfile,
		DockerfilePath: "build/Dockerfile",
		GitBranch:      "main",
		GitCommit:      "deadbeefcafebabe",
	}
	return in
}

// cronComposeInput returns a fully-valid cron RenderInput on a
// ServiceCompose, using the Dockerfile builder. It mirrors
// cronApplicationInput on the compose side of the cron subtype.
func cronComposeInput() dokploy.RenderInput {
	in := validInput()
	in.Service.Type = dokploy.ServiceCompose
	in.Service.Engine = ""
	in.Role = dokploy.RoleCron
	in.Domains = nil
	in.CronSchedule = validCronExpr
	in.Build = dokploy.BuildSettings{
		Builder:        dokploy.BuilderDockerfile,
		DockerfilePath: "compose/Dockerfile",
		GitBranch:      "main",
		GitCommit:      "deadbeefcafebabe",
	}
	return in
}

// TestRenderCronApplicationSuccess pins the canonical cron-on-
// application happy path: role=cron, type=application, the rendered
// spec carries no domains, the cron schedule is preserved verbatim, and
// the yalla.role label is surfaced as "cron".
func TestRenderCronApplicationSuccess(t *testing.T) {
	t.Parallel()

	spec := mustRender(t, cronApplicationInput())

	if spec.Service.Type != dokploy.ServiceApplication {
		t.Errorf("service type = %q, want application", spec.Service.Type)
	}
	if spec.Service.Role != dokploy.RoleCron {
		t.Errorf("role = %q, want cron", spec.Service.Role)
	}
	if got := len(spec.Service.Domains); got != 0 {
		t.Errorf("cron rendered Domains count = %d, want 0", got)
	}
	if got := spec.Service.CronSchedule; got != validCronExpr {
		t.Errorf("cron rendered CronSchedule = %q, want %q", got, validCronExpr)
	}
	if got := spec.Service.Engine; got != "" {
		t.Errorf("cron rendered Engine = %q, want empty (engine is database-only)", got)
	}
	var roleLabel string
	for _, l := range spec.Service.Labels {
		if l.Key == "yalla.role" {
			roleLabel = l.Value
		}
	}
	if roleLabel != string(dokploy.RoleCron) {
		t.Errorf("yalla.role label = %q, want %q", roleLabel, dokploy.RoleCron)
	}
}

// TestRenderCronComposeSuccess pins the canonical cron-on-compose happy
// path: role=cron, type=compose, the rendered spec carries no domains,
// the cron schedule is preserved verbatim, and the yalla.role label is
// surfaced as "cron".
func TestRenderCronComposeSuccess(t *testing.T) {
	t.Parallel()

	spec := mustRender(t, cronComposeInput())

	if spec.Service.Type != dokploy.ServiceCompose {
		t.Errorf("service type = %q, want compose", spec.Service.Type)
	}
	if spec.Service.Role != dokploy.RoleCron {
		t.Errorf("role = %q, want cron", spec.Service.Role)
	}
	if got := len(spec.Service.Domains); got != 0 {
		t.Errorf("cron rendered Domains count = %d, want 0", got)
	}
	if got := spec.Service.CronSchedule; got != validCronExpr {
		t.Errorf("cron rendered CronSchedule = %q, want %q", got, validCronExpr)
	}
	if got := spec.Service.Engine; got != "" {
		t.Errorf("cron rendered Engine = %q, want empty (engine is database-only)", got)
	}
	var roleLabel string
	for _, l := range spec.Service.Labels {
		if l.Key == "yalla.role" {
			roleLabel = l.Value
		}
	}
	if roleLabel != string(dokploy.RoleCron) {
		t.Errorf("yalla.role label = %q, want %q", roleLabel, dokploy.RoleCron)
	}
}

// TestRenderCronDropsWebFields is the subtype-boundary pin: a cron
// input that smuggles in web-only Domains renders with the Domains
// cleared, while the submitted host never echoes into any rendered
// error, Summary JSON, slog record, or Summary.String() surface. The
// cron schedule remains preserved (cron is the OWNER of cron_schedule;
// dropping it here would conflate the cron and worker roles). This is
// the structural barrier against BE-0301..BE-0307 (web shape: Domains
// preserved). It runs across both cron variants (application and
// compose) to prove the drop is role-driven, not type-driven.
func TestRenderCronDropsWebFields(t *testing.T) {
	t.Parallel()

	const leakyHost = "cron-leak.example"
	leakyValues := []string{leakyHost}

	for _, makeIn := range []func() dokploy.RenderInput{
		cronApplicationInput,
		cronComposeInput,
	} {
		makeIn := makeIn
		in := makeIn()
		t.Run(string(in.Service.Type), func(t *testing.T) {
			t.Parallel()
			in := makeIn()
			in.Domains = []dokploy.DomainSpec{
				{Host: leakyHost, HTTPS: true, Path: "/"},
			}

			spec := mustRender(t, in)

			if spec.Service.Role != dokploy.RoleCron {
				t.Errorf("role = %q, want cron", spec.Service.Role)
			}
			if got := len(spec.Service.Domains); got != 0 {
				t.Errorf("cron rendered Domains count = %d, want 0", got)
			}
			if got := spec.Service.CronSchedule; got != validCronExpr {
				t.Errorf("cron rendered CronSchedule = %q, want %q", got, validCronExpr)
			}

			// The submitted web-only value may never leak into any
			// debug surface.
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

// TestRenderCronPreservesCronScheduleInSummary pins the structural
// barrier against BE-0319 (worker): cron services preserve their
// CronSchedule on the rendered spec AND on the redaction-safe Summary
// struct AND in the Summary JSON encoding. The schedule is not a secret
// — operators and audit consumers need to see it — and the marshaled
// summary is the canonical audit-trail surface for the rendered spec.
// The compact slog LogValue and Summary.String() debug surfaces remain
// intentionally minimal and are deliberately not asserted here so that
// shrinking those views in the future does not break the cron contract;
// the full Summary JSON is the load-bearing observability surface.
// This test runs across both cron variants (application and compose) so
// the preservation is role-driven, not type-driven.
func TestRenderCronPreservesCronScheduleInSummary(t *testing.T) {
	t.Parallel()

	for _, makeIn := range []func() dokploy.RenderInput{
		cronApplicationInput,
		cronComposeInput,
	} {
		makeIn := makeIn
		baseIn := makeIn()
		serviceType := string(baseIn.Service.Type)
		t.Run(serviceType, func(t *testing.T) {
			t.Parallel()
			spec := mustRender(t, makeIn())

			if got := spec.Service.CronSchedule; got != validCronExpr {
				t.Errorf("rendered CronSchedule = %q, want %q", got, validCronExpr)
			}

			summary := spec.Summary()
			if got := summary.Service.CronSchedule; got != validCronExpr {
				t.Errorf("summary CronSchedule = %q, want %q", got, validCronExpr)
			}

			payload, err := json.Marshal(summary)
			if err != nil {
				t.Fatalf("marshal summary: %v", err)
			}
			if !strings.Contains(string(payload), validCronExpr) {
				t.Errorf("summary json does not contain preserved cron schedule %q: %s",
					validCronExpr, string(payload))
			}
		})
	}
}

// TestRenderCronSubtypeBoundaryFromWebAndWorker pins that a cron input
// renders as a cron (with cron schedule preserved and domains dropped),
// a worker input renders as a worker (with both cron schedule and
// domains dropped), and a web input renders as a web (with domains
// preserved and cron schedule dropped). The yalla.role label faithfully
// surfaces the role across every case, so a future audit/observability
// consumer can distinguish a cron from its sibling roles without
// re-reading the spec body. This is the structural barrier against any
// future refactor that would conflate the three roles inside the type
// switch in Render().
func TestRenderCronSubtypeBoundaryFromWebAndWorker(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		in          func() dokploy.RenderInput
		wantRole    dokploy.ServiceRole
		wantDomains int
		wantCron    string
	}{
		{
			name:        "cron stays cron (application)",
			in:          cronApplicationInput,
			wantRole:    dokploy.RoleCron,
			wantDomains: 0,
			wantCron:    validCronExpr,
		},
		{
			name:        "cron stays cron (compose)",
			in:          cronComposeInput,
			wantRole:    dokploy.RoleCron,
			wantDomains: 0,
			wantCron:    validCronExpr,
		},
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

// TestRenderCronBuilderMatrix pins that a cron service supports every
// documented builder — dockerfile, nixpacks, image, drop-artifact —
// across both application and compose variants. For every (service-type
// × builder) combination the rendered spec is still a cron (no domains,
// cron schedule preserved) and the builder-specific build settings are
// preserved or normalised exactly as they are for web and worker
// services.
func TestRenderCronBuilderMatrix(t *testing.T) {
	t.Parallel()

	const (
		dockerfilePath = "deploy/Dockerfile"
		image          = "registry.acme.example/cron:v1.2.3"
		artifactURL    = "https://artifacts.yalla.example/uploads/cron-v1.2.3.tar.gz"
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
		cronApplicationInput,
		cronComposeInput,
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

				if spec.Service.Role != dokploy.RoleCron {
					t.Errorf("role = %q, want cron", spec.Service.Role)
				}
				if got := len(spec.Service.Domains); got != 0 {
					t.Errorf("cron rendered Domains count = %d, want 0", got)
				}
				if spec.Service.CronSchedule != validCronExpr {
					t.Errorf("cron rendered CronSchedule = %q, want %q",
						spec.Service.CronSchedule, validCronExpr)
				}
				b.check(t, spec.Service.Build)
			})
		}
	}
}

// TestRenderCronValidationFailures pins that every required field the
// renderer rejects for a cron input becomes a typed apierr.InvalidInput
// with a stable, indexed Field path, and that no submitted value is
// ever echoed into the rendered error surface. The table covers the
// failure modes most relevant to a cron: hierarchy identity, parent
// linkage, environment tier, service type, service role, variable name
// rejection (no value echo), negative resource limits,
// image-builder-missing-image (a cron may use any of the four supported
// builders, so the image-builder failure path is part of the cron
// contract), drop-artifact-builder-missing-artifact-url, bad builder
// strings, AND the cron-specific leg — missing cron schedule and
// malformed cron schedule — using a Dockerfile-builder
// cron-application base. This is the structural addition vs the
// BE-0319 worker matrix, where the cron_schedule validation does not
// apply because RoleWorker drops the schedule.
func TestRenderCronValidationFailures(t *testing.T) {
	t.Parallel()

	leakyValues := []string{
		"not-a-yalla-id",
		"1bad",
		"sk-live-supersecret",
		"frontend",
		"function",
		"prod-tier",
		"bazel",
		"leaky-image.example.com/secret-cron:v9.9.9",
		"https://artifacts.yalla.example/uploads/cron-secret-v1.2.3.tar.gz",
		"not-a-cron-expression",
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
		{"missing cron schedule", func(in *dokploy.RenderInput) {
			in.CronSchedule = ""
		}, "cron_schedule"},
		{"malformed cron schedule", func(in *dokploy.RenderInput) {
			in.CronSchedule = "not-a-cron-expression"
		}, "cron_schedule"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			in := cronApplicationInput()
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

// TestRenderCronTierResourceDefaults pins the tier × cron resource
// defaults across both cron variants (application and compose). A cron
// never gets the load-bearing production-web 2-replica default; every
// (tier × cron) combination defaults to a single replica regardless of
// whether the cron is an application or a compose stack. This is the
// inverse of the BE-0301/BE-0307 production-web replica bump and is
// the load-bearing resource-allocation contract a future autoscaler
// story has to honour.
func TestRenderCronTierResourceDefaults(t *testing.T) {
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
		cronApplicationInput,
		cronComposeInput,
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

// TestRenderCronRedactsAllVariableValues pins the secrets-redaction
// contract for cron services across both cron variants: the
// RenderedSpec carries verbatim variable values (the provisioner needs
// them) but the Summary, its JSON, its slog LogValue, and its String
// never expose any variable value — neither the Secret-flagged one nor
// the plain one. Every value site shows the redaction sentinel. The
// cron schedule itself is non-secret and remains visible across every
// surface (covered by TestRenderCronPreservesCronScheduleInSummary).
func TestRenderCronRedactsAllVariableValues(t *testing.T) {
	t.Parallel()

	const secret = "sk-live-supersecret"
	const plain = "off"

	for _, makeIn := range []func() dokploy.RenderInput{
		cronApplicationInput,
		cronComposeInput,
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

// TestRenderCronDeterministic pins that a cron input renders to a
// byte-stable RenderedSpec across renderer invocations for both
// application and compose cron variants. Determinism is the renderer
// contract that lets the provisioner compare a freshly rendered spec to
// a previously-stored one to decide whether a Dokploy update is needed
// at all.
func TestRenderCronDeterministic(t *testing.T) {
	t.Parallel()
	for _, makeIn := range []func() dokploy.RenderInput{
		cronApplicationInput,
		cronComposeInput,
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
