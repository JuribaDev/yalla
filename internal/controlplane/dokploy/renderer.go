package dokploy

import (
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/output"
)

// The desired-state renderer turns Yalla's source-of-truth hierarchy
// (organization -> project -> environment -> service) into a complete,
// declarative Dokploy provisioning spec: deterministic resource names and
// labels, the effective environment-variable set after precedence merging,
// resource limits, build settings, and domains.
//
// The renderer is the declarative-content layer; the Mapper (mapping.go) is the
// ID-resolution layer. The renderer never resolves a parent's Dokploy ID and
// never performs I/O — it is pure and deterministic, so the same RenderInput
// always renders the same RenderedSpec. The worker combines the two: it walks
// the Mapper top-down to resolve Dokploy IDs and feeds this spec's content into
// each Ensure call.
//
// Every value the renderer rejects becomes a typed apierr.InvalidInput with a
// stable, indexed field path that never echoes the submitted value, so a
// validation error is always safe for client envelopes, logs, and audit
// metadata. Rendered environment-variable values are carried verbatim on the
// RenderedSpec (the worker needs them to provision) but are redacted in every
// debug Summary, in slog output, and in the spec's own LogValue.

// EnvironmentTier classifies an environment. The tier seeds deterministic
// resource defaults (CPU, memory, replica counts) and is recorded on the
// rendered spec and its labels. The set of tiers is a stable contract.
type EnvironmentTier string

const (
	// TierStaging is a pre-production environment.
	TierStaging EnvironmentTier = "staging"
	// TierProduction is a production environment.
	TierProduction EnvironmentTier = "production"
	// TierPreview is an ephemeral per-change preview environment.
	TierPreview EnvironmentTier = "preview"
)

// Valid reports whether t is one of the recognised environment tiers.
func (t EnvironmentTier) Valid() bool {
	switch t {
	case TierStaging, TierProduction, TierPreview:
		return true
	default:
		return false
	}
}

// ServiceRole classifies a service's runtime shape independently of its
// ServiceType. It applies to application and compose services; it is ignored
// for database services, which have no web/worker/cron semantics.
type ServiceRole string

const (
	// RoleWeb is a service reachable over HTTP; only a web service may bind
	// domains.
	RoleWeb ServiceRole = "web"
	// RoleWorker is a continuously-running service with no inbound traffic.
	RoleWorker ServiceRole = "worker"
	// RoleCron is a service that runs on a schedule; a cron service must carry
	// a CronSchedule.
	RoleCron ServiceRole = "cron"
)

// Valid reports whether r is one of the recognised service roles.
func (r ServiceRole) Valid() bool {
	switch r {
	case RoleWeb, RoleWorker, RoleCron:
		return true
	default:
		return false
	}
}

// Builder identifiers select how Dokploy builds a service image.
const (
	// BuilderDockerfile builds the image from a Dockerfile in the repository.
	BuilderDockerfile = "dockerfile"
	// BuilderNixpacks builds the image with Nixpacks (no Dockerfile).
	BuilderNixpacks = "nixpacks"
	// BuilderImage deploys a pre-built image reference without a build step.
	BuilderImage = "image"
	// BuilderDropArtifact deploys a pre-built artifact (tarball, zip, or
	// similar bundle) that the customer uploaded to Yalla. There is no git
	// source and no registry image — the worker hands the recorded artifact
	// reference to Dokploy verbatim.
	BuilderDropArtifact = "drop-artifact"
)

// VariableSource identifies which level of the hierarchy contributed a
// variable's effective value after precedence merging.
type VariableSource string

const (
	// SourceOrganization is the lowest-precedence level.
	SourceOrganization VariableSource = "organization"
	// SourceProject overrides organization-level variables.
	SourceProject VariableSource = "project"
	// SourceEnvironment overrides project-level variables.
	SourceEnvironment VariableSource = "environment"
	// SourceService is the highest-precedence level.
	SourceService VariableSource = "service"
)

// Variable is one environment variable contributed at a single level of the
// hierarchy. Secret marks the value as sensitive: it changes nothing about
// rendering precedence, but it is preserved on the rendered spec so the worker
// can store the value as a Dokploy secret rather than plain config.
type Variable struct {
	// Name is the environment variable name. It is trimmed and must match a
	// POSIX-shell environment variable name ([A-Za-z_][A-Za-z0-9_]*).
	Name string
	// Value is the variable's value. It is carried verbatim (not trimmed) and
	// is redacted in every debug Summary and log record.
	Value string
	// Secret marks the value as sensitive.
	Secret bool
}

// ResourceLimits bounds a service's compute. A zero field means "inherit the
// deterministic tier default"; the renderer fills every zero field so the
// rendered spec always carries fully-resolved, non-zero limits. Negative
// fields are rejected.
type ResourceLimits struct {
	// CPUMillis is the CPU limit in millicores (1000 = one core).
	CPUMillis int `json:"cpu_millis"`
	// MemoryMiB is the memory limit in mebibytes.
	MemoryMiB int `json:"memory_mib"`
	// Replicas is the desired replica count.
	Replicas int `json:"replicas"`
}

// BuildSettings describes how Dokploy builds (or skips building) the service
// image. The renderer normalises it: fields that do not apply to the chosen
// Builder are dropped, so the rendered spec is unambiguous.
type BuildSettings struct {
	// Builder selects the build strategy: BuilderDockerfile, BuilderNixpacks,
	// BuilderImage, or BuilderDropArtifact. It defaults to BuilderDockerfile
	// when blank.
	Builder string `json:"builder"`
	// DockerfilePath is the Dockerfile path relative to the repository root;
	// it applies only to BuilderDockerfile and defaults to "Dockerfile".
	DockerfilePath string `json:"dockerfile_path,omitempty"`
	// Image is a pre-built image reference; it is required for and applies
	// only to BuilderImage.
	Image string `json:"image,omitempty"`
	// GitBranch is the branch to build; it applies to BuilderDockerfile and
	// BuilderNixpacks.
	GitBranch string `json:"git_branch,omitempty"`
	// GitCommit pins the build to a specific commit; it applies to
	// BuilderDockerfile and BuilderNixpacks.
	GitCommit string `json:"git_commit,omitempty"`
	// ArtifactURL is a pre-built artifact reference (typically a Yalla
	// storage URL pointing at a tarball or zip the customer uploaded); it
	// is required for and applies only to BuilderDropArtifact.
	ArtifactURL string `json:"artifact_url,omitempty"`
}

// DomainSpec is a requested hostname for a web service.
type DomainSpec struct {
	// Host is the fully-qualified hostname; it is lower-cased and validated.
	Host string
	// HTTPS reports whether the domain should terminate TLS.
	HTTPS bool
	// Path is the routed path prefix; it defaults to "/" and must be absolute.
	Path string
}

// RenderInput is the complete set of source-of-truth records the renderer
// turns into one RenderedSpec. It carries the four hierarchy projections (for
// IDs, labels, parent linkage, and deterministic naming), the environment tier
// and service role, the per-level variable sets, and the service's resource
// limits, build settings, and requested domains.
type RenderInput struct {
	// Organization, Project, Environment, and Service are the source-of-truth
	// hierarchy. Their IDs and parent linkages are validated; their Labels
	// seed deterministic Dokploy names.
	Organization YallaOrganization
	Project      YallaProject
	Environment  YallaEnvironment
	Service      YallaService

	// Tier classifies the environment; it is always required.
	Tier EnvironmentTier
	// Role classifies the service; it is required for application and compose
	// services and ignored for database services.
	Role ServiceRole
	// CronSchedule is the schedule for a cron service; it is required when the
	// effective role is RoleCron and dropped otherwise.
	CronSchedule string

	// OrganizationVariables, ProjectVariables, EnvironmentVariables, and
	// ServiceVariables are merged in ascending precedence: a service variable
	// overrides an environment variable of the same name, which overrides a
	// project variable, which overrides an organization variable.
	OrganizationVariables []Variable
	ProjectVariables      []Variable
	EnvironmentVariables  []Variable
	ServiceVariables      []Variable

	// Resources is the service's resource limits; zero fields inherit the
	// deterministic tier default.
	Resources ResourceLimits
	// Build describes how the service image is built.
	Build BuildSettings
	// Domains are the requested hostnames; they are rendered only for a web
	// service and dropped otherwise.
	Domains []DomainSpec
}

// RenderedVariable is one entry in a service's effective variable set, after
// precedence merging. Source records which level contributed the value.
type RenderedVariable struct {
	Name   string         `json:"name"`
	Value  string         `json:"value"`
	Secret bool           `json:"secret"`
	Source VariableSource `json:"source"`
}

// RenderedDomain is a fully-resolved domain on a rendered web service.
type RenderedDomain struct {
	Host  string `json:"host"`
	HTTPS bool   `json:"https"`
	Path  string `json:"path"`
}

// Label is a deterministic key/value tag the renderer attaches to the Dokploy
// service for observability and defence-in-depth tenant attribution.
type Label struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// RenderedService is the declarative spec for one Dokploy service.
type RenderedService struct {
	// Name is the deterministic, Docker-safe Dokploy name.
	Name string `json:"name"`
	// Type is the Dokploy service type.
	Type ServiceType `json:"type"`
	// Engine is the database engine; set only for database services.
	Engine string `json:"engine,omitempty"`
	// Role is the effective service role; empty for database services.
	Role ServiceRole `json:"role,omitempty"`
	// CronSchedule is set only for a cron service.
	CronSchedule string `json:"cron_schedule,omitempty"`
	// Variables is the effective merged variable set, sorted by Name. Values
	// are verbatim — redact via the spec's Summary before logging.
	Variables []RenderedVariable `json:"variables"`
	// Resources is the fully-resolved resource limits (no zero fields).
	Resources ResourceLimits `json:"resources"`
	// Build is the normalised build settings.
	Build BuildSettings `json:"build"`
	// Domains is the rendered domain set, sorted by Host then Path; empty for
	// non-web services.
	Domains []RenderedDomain `json:"domains"`
	// Labels is the deterministic label set, sorted by Key.
	Labels []Label `json:"labels"`
}

// RenderedSpec is the complete, declarative Dokploy provisioning spec for one
// Yalla service and its hierarchy. It is deterministic and carries no resolved
// Dokploy parent IDs; the worker walks the Mapper to resolve those.
//
// RenderedSpec.Service.Variables carries verbatim values, including secrets, so
// never log or audit a RenderedSpec directly — call Summary first. As a
// backstop, RenderedSpec.LogValue redacts: a RenderedSpec logged via slog
// always emits its redacted Summary.
type RenderedSpec struct {
	OrganizationName string          `json:"organization_name"`
	ProjectName      string          `json:"project_name"`
	EnvironmentName  string          `json:"environment_name"`
	Tier             EnvironmentTier `json:"tier"`
	Service          RenderedService `json:"service"`
}

// Renderer renders RenderInput values into RenderedSpec values. It is pure,
// stateless, and safe for concurrent use. Construct one with NewRenderer.
type Renderer struct{}

// NewRenderer returns a Renderer.
func NewRenderer() *Renderer { return &Renderer{} }

// envVarName matches a POSIX-shell environment variable name.
var envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// hostnameLabel matches one DNS label.
var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// maxHostnameLen bounds a fully-qualified hostname.
const maxHostnameLen = 253

// Render turns a RenderInput into a RenderedSpec. It validates the whole
// hierarchy, merges variables with the documented precedence, fills resource
// limits from tier defaults, normalises build settings, and resolves domains
// and labels. Every rejected value is collected into a single
// apierr.InvalidInput with stable, indexed field paths that never echo the
// submitted value.
func (*Renderer) Render(in RenderInput) (RenderedSpec, error) {
	var v []apierr.FieldViolation

	// Hierarchy identity and parent linkage.
	validYallaID(&v, "organization.id", in.Organization.ID, domain.KindOrganization)
	validYallaID(&v, "project.id", in.Project.ID, domain.KindProject)
	validYallaID(&v, "project.organization_id", in.Project.OrganizationID, domain.KindOrganization)
	validYallaID(&v, "environment.id", in.Environment.ID, domain.KindEnvironment)
	validYallaID(&v, "environment.project_id", in.Environment.ProjectID, domain.KindProject)
	validYallaID(&v, "service.id", in.Service.ID, domain.KindService)
	validYallaID(&v, "service.environment_id", in.Service.EnvironmentID, domain.KindEnvironment)
	requireMatchingParent(&v, "project.organization_id", in.Project.OrganizationID, in.Organization.ID)
	requireMatchingParent(&v, "environment.project_id", in.Environment.ProjectID, in.Project.ID)
	requireMatchingParent(&v, "service.environment_id", in.Service.EnvironmentID, in.Environment.ID)

	// Environment tier.
	if !in.Tier.Valid() {
		v = append(v, apierr.FieldViolation{
			Field:  "tier",
			Reason: "must be staging, production, or preview",
		})
	}

	// Service type and engine.
	if !in.Service.Type.Valid() {
		v = append(v, apierr.FieldViolation{
			Field:  "service.type",
			Reason: "must be application, compose, or database",
		})
	}
	engine := strings.TrimSpace(in.Service.Engine)
	if in.Service.Type == ServiceDatabase && engine == "" {
		v = append(v, apierr.FieldViolation{
			Field:  "service.engine",
			Reason: "required for database services",
		})
	}

	// Service role. It applies to application and compose services and is
	// ignored (dropped) for database services, mirroring how the engine is
	// dropped for non-database services.
	effectiveRole := in.Role
	if in.Service.Type == ServiceDatabase {
		effectiveRole = ""
	} else if in.Service.Type.Valid() && !in.Role.Valid() {
		v = append(v, apierr.FieldViolation{
			Field:  "role",
			Reason: "must be web, worker, or cron",
		})
	}

	// Cron schedule. Required for a cron service, dropped otherwise.
	cronSchedule := strings.TrimSpace(in.CronSchedule)
	if effectiveRole == RoleCron {
		if !validCronSchedule(cronSchedule) {
			v = append(v, apierr.FieldViolation{
				Field:  "cron_schedule",
				Reason: "must be a 5- or 6-field cron expression",
			})
		}
	} else {
		cronSchedule = ""
	}

	// Variables: validate each level, then merge with ascending precedence.
	variables := mergeVariables(&v, in)

	// Resource limits.
	resources := resolveResources(&v, in.Resources, in.Tier, in.Service.Type, effectiveRole)

	// Build settings.
	build := normaliseBuild(&v, in.Build)

	// Domains: rendered only for a web service, dropped otherwise.
	var domains []RenderedDomain
	if effectiveRole == RoleWeb {
		domains = resolveDomains(&v, in.Domains)
	}

	if len(v) > 0 {
		return RenderedSpec{}, apierr.InvalidInput(v...)
	}

	orgName, err := domain.DokployName(in.Organization.Label, in.Organization.ID)
	if err != nil {
		return RenderedSpec{}, apierr.Internal(err)
	}
	projName, err := domain.DokployName(in.Project.Label, in.Project.ID)
	if err != nil {
		return RenderedSpec{}, apierr.Internal(err)
	}
	envName, err := domain.DokployName(in.Environment.Label, in.Environment.ID)
	if err != nil {
		return RenderedSpec{}, apierr.Internal(err)
	}
	svcName, err := domain.DokployName(in.Service.Label, in.Service.ID)
	if err != nil {
		return RenderedSpec{}, apierr.Internal(err)
	}

	svc := RenderedService{
		Name:         svcName,
		Type:         in.Service.Type,
		Role:         effectiveRole,
		CronSchedule: cronSchedule,
		Variables:    variables,
		Resources:    resources,
		Build:        build,
		Domains:      domains,
		Labels:       renderLabels(in, effectiveRole),
	}
	if in.Service.Type == ServiceDatabase {
		svc.Engine = engine
	}

	return RenderedSpec{
		OrganizationName: orgName,
		ProjectName:      projName,
		EnvironmentName:  envName,
		Tier:             in.Tier,
		Service:          svc,
	}, nil
}

// requireMatchingParent appends a violation when child — a child record's
// recorded parent ID — does not equal want, the parent record's own ID. The
// check runs only when both IDs are individually well formed, so a malformed
// ID is reported once (by validYallaID) rather than twice. Neither ID is
// echoed.
func requireMatchingParent(violations *[]apierr.FieldViolation, field string, child, want domain.ID) {
	if !child.Valid() || !want.Valid() {
		return
	}
	if child != want {
		*violations = append(*violations, apierr.FieldViolation{
			Field:  field,
			Reason: "must reference the parent resource in the hierarchy",
		})
	}
}

// mergeVariables validates every level's variables and merges them with
// ascending precedence (organization < project < environment < service). A
// blank or malformed name, or a duplicate name within one level, is collected
// as a violation with an indexed field path that never echoes the value. The
// returned slice is sorted by Name for determinism.
func mergeVariables(violations *[]apierr.FieldViolation, in RenderInput) []RenderedVariable {
	type sourced struct {
		src  VariableSource
		vars []Variable
	}
	levels := []sourced{
		{SourceOrganization, in.OrganizationVariables},
		{SourceProject, in.ProjectVariables},
		{SourceEnvironment, in.EnvironmentVariables},
		{SourceService, in.ServiceVariables},
	}

	merged := make(map[string]RenderedVariable)
	for _, lvl := range levels {
		seen := make(map[string]struct{}, len(lvl.vars))
		for i, raw := range lvl.vars {
			name := strings.TrimSpace(raw.Name)
			path := fmt.Sprintf("%s.variables[%d].name", lvl.src, i)
			if !envVarName.MatchString(name) {
				*violations = append(*violations, apierr.FieldViolation{
					Field:  path,
					Reason: "must be a valid environment variable name",
				})
				continue
			}
			if _, dup := seen[name]; dup {
				*violations = append(*violations, apierr.FieldViolation{
					Field:  path,
					Reason: "duplicate variable name within this level",
				})
				continue
			}
			seen[name] = struct{}{}
			merged[name] = RenderedVariable{
				Name:   name,
				Value:  raw.Value,
				Secret: raw.Secret,
				Source: lvl.src,
			}
		}
	}

	out := make([]RenderedVariable, 0, len(merged))
	for _, rv := range merged {
		out = append(out, rv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// resolveResources rejects negative fields and fills every zero field from the
// deterministic tier/role default, so the returned limits are fully resolved.
func resolveResources(violations *[]apierr.FieldViolation, in ResourceLimits, tier EnvironmentTier, typ ServiceType, role ServiceRole) ResourceLimits {
	if in.CPUMillis < 0 {
		*violations = append(*violations, apierr.FieldViolation{Field: "resources.cpu_millis", Reason: "must not be negative"})
	}
	if in.MemoryMiB < 0 {
		*violations = append(*violations, apierr.FieldViolation{Field: "resources.memory_mib", Reason: "must not be negative"})
	}
	if in.Replicas < 0 {
		*violations = append(*violations, apierr.FieldViolation{Field: "resources.replicas", Reason: "must not be negative"})
	}

	def := defaultResources(tier, typ, role)
	out := in
	if out.CPUMillis == 0 {
		out.CPUMillis = def.CPUMillis
	}
	if out.MemoryMiB == 0 {
		out.MemoryMiB = def.MemoryMiB
	}
	if out.Replicas == 0 {
		out.Replicas = def.Replicas
	}
	return out
}

// defaultResources returns the deterministic resource defaults for a tier. A
// production web (application or compose) service defaults to two replicas;
// every other shape defaults to one.
func defaultResources(tier EnvironmentTier, typ ServiceType, role ServiceRole) ResourceLimits {
	cpu, mem := 500, 512
	switch tier {
	case TierProduction:
		cpu, mem = 1000, 1024
	case TierStaging:
		cpu, mem = 500, 512
	case TierPreview:
		cpu, mem = 250, 256
	}
	replicas := 1
	if tier == TierProduction && role == RoleWeb && (typ == ServiceApplication || typ == ServiceCompose) {
		replicas = 2
	}
	return ResourceLimits{CPUMillis: cpu, MemoryMiB: mem, Replicas: replicas}
}

// normaliseBuild validates and normalises build settings, dropping every field
// that does not apply to the chosen builder so the rendered spec is
// unambiguous. A blank builder defaults to BuilderDockerfile.
func normaliseBuild(violations *[]apierr.FieldViolation, in BuildSettings) BuildSettings {
	builder := strings.ToLower(strings.TrimSpace(in.Builder))
	if builder == "" {
		builder = BuilderDockerfile
	}
	branch := strings.TrimSpace(in.GitBranch)
	commit := strings.TrimSpace(in.GitCommit)
	dockerfile := strings.TrimSpace(in.DockerfilePath)
	image := strings.TrimSpace(in.Image)

	switch builder {
	case BuilderDockerfile:
		if dockerfile == "" {
			dockerfile = "Dockerfile"
		}
		return BuildSettings{
			Builder:        BuilderDockerfile,
			DockerfilePath: dockerfile,
			GitBranch:      branch,
			GitCommit:      commit,
		}
	case BuilderNixpacks:
		return BuildSettings{
			Builder:   BuilderNixpacks,
			GitBranch: branch,
			GitCommit: commit,
		}
	case BuilderImage:
		if image == "" {
			*violations = append(*violations, apierr.FieldViolation{
				Field:  "build.image",
				Reason: "required when builder is image",
			})
		}
		return BuildSettings{
			Builder: BuilderImage,
			Image:   image,
		}
	case BuilderDropArtifact:
		artifact := strings.TrimSpace(in.ArtifactURL)
		if artifact == "" {
			*violations = append(*violations, apierr.FieldViolation{
				Field:  "build.artifact_url",
				Reason: "required when builder is drop-artifact",
			})
		}
		return BuildSettings{
			Builder:     BuilderDropArtifact,
			ArtifactURL: artifact,
		}
	default:
		*violations = append(*violations, apierr.FieldViolation{
			Field:  "build.builder",
			Reason: "must be dockerfile, nixpacks, image, or drop-artifact",
		})
		return BuildSettings{}
	}
}

// resolveDomains validates and normalises a web service's requested domains:
// hosts are lower-cased and must be fully-qualified, paths default to "/" and
// must be absolute. The returned slice is sorted by Host then Path. Hosts and
// paths are never echoed in violations — paths are indexed instead.
func resolveDomains(violations *[]apierr.FieldViolation, in []DomainSpec) []RenderedDomain {
	out := make([]RenderedDomain, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for i, d := range in {
		host := strings.ToLower(strings.TrimSpace(d.Host))
		hostField := fmt.Sprintf("domains[%d].host", i)
		switch {
		case host == "":
			*violations = append(*violations, apierr.FieldViolation{Field: hostField, Reason: "required"})
			continue
		case len(host) > maxHostnameLen:
			*violations = append(*violations, apierr.FieldViolation{Field: hostField, Reason: "must be at most 253 characters"})
			continue
		case !strings.Contains(host, ".") || !hostnameRe.MatchString(host):
			*violations = append(*violations, apierr.FieldViolation{Field: hostField, Reason: "must be a fully-qualified hostname"})
			continue
		}

		path := strings.TrimSpace(d.Path)
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, "/") {
			*violations = append(*violations, apierr.FieldViolation{
				Field:  fmt.Sprintf("domains[%d].path", i),
				Reason: "must be an absolute path",
			})
			continue
		}

		key := host + "\x00" + path
		if _, dup := seen[key]; dup {
			*violations = append(*violations, apierr.FieldViolation{
				Field:  hostField,
				Reason: "duplicate host and path",
			})
			continue
		}
		seen[key] = struct{}{}
		out = append(out, RenderedDomain{Host: host, HTTPS: d.HTTPS, Path: path})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// renderLabels builds the deterministic label set attached to the Dokploy
// service. The Yalla IDs are not secrets — they are self-describing kind-tagged
// tokens — so embedding them as labels is safe and aids tenant attribution.
func renderLabels(in RenderInput, role ServiceRole) []Label {
	labels := []Label{
		{Key: "yalla.organization", Value: in.Organization.ID.String()},
		{Key: "yalla.project", Value: in.Project.ID.String()},
		{Key: "yalla.environment", Value: in.Environment.ID.String()},
		{Key: "yalla.service", Value: in.Service.ID.String()},
		{Key: "yalla.tier", Value: string(in.Tier)},
		{Key: "yalla.service-type", Value: string(in.Service.Type)},
		{Key: "yalla.managed-by", Value: "yalla-control-plane"},
	}
	if role != "" {
		labels = append(labels, Label{Key: "yalla.role", Value: string(role)})
	}
	sort.Slice(labels, func(i, j int) bool { return labels[i].Key < labels[j].Key })
	return labels
}

// validCronSchedule reports whether s looks like a 5- or 6-field cron
// expression. It is a deliberately light structural check — the worker (or
// Dokploy) performs full schedule parsing.
func validCronSchedule(s string) bool {
	fields := strings.Fields(s)
	return len(fields) == 5 || len(fields) == 6
}

// VariableSummary is the redaction-safe view of one effective variable: its
// Value is always the redaction Sentinel, never the real value.
type VariableSummary struct {
	Name   string         `json:"name"`
	Value  string         `json:"value"`
	Secret bool           `json:"secret"`
	Source VariableSource `json:"source"`
}

// ServiceSummary is the redaction-safe view of a rendered service.
type ServiceSummary struct {
	Name         string            `json:"name"`
	Type         ServiceType       `json:"type"`
	Engine       string            `json:"engine,omitempty"`
	Role         ServiceRole       `json:"role,omitempty"`
	CronSchedule string            `json:"cron_schedule,omitempty"`
	Resources    ResourceLimits    `json:"resources"`
	Build        BuildSettings     `json:"build"`
	Domains      []RenderedDomain  `json:"domains"`
	Labels       []Label           `json:"labels"`
	Variables    []VariableSummary `json:"variables"`
}

// Summary is the redaction-safe projection of a RenderedSpec. It is the view
// that belongs in logs, error context, and audit metadata: it carries every
// deterministic name, label, resource limit, build setting, and domain, and it
// lists every effective variable by name and source — but never carries a
// variable value. Build settings (git refs, image, Dockerfile path) are not
// secrets and are shown in full.
type Summary struct {
	Organization string          `json:"organization"`
	Project      string          `json:"project"`
	Environment  string          `json:"environment"`
	Tier         EnvironmentTier `json:"tier"`
	Service      ServiceSummary  `json:"service"`
}

// Summary returns the redaction-safe projection of the rendered spec. Every
// variable value is replaced with the redaction Sentinel, so a Summary is
// always safe to log, wrap into an error, or store as audit metadata.
func (s RenderedSpec) Summary() Summary {
	vars := make([]VariableSummary, len(s.Service.Variables))
	for i, rv := range s.Service.Variables {
		vars[i] = VariableSummary{
			Name:   rv.Name,
			Value:  output.Sentinel,
			Secret: rv.Secret,
			Source: rv.Source,
		}
	}
	return Summary{
		Organization: s.OrganizationName,
		Project:      s.ProjectName,
		Environment:  s.EnvironmentName,
		Tier:         s.Tier,
		Service: ServiceSummary{
			Name:         s.Service.Name,
			Type:         s.Service.Type,
			Engine:       s.Service.Engine,
			Role:         s.Service.Role,
			CronSchedule: s.Service.CronSchedule,
			Resources:    s.Service.Resources,
			Build:        s.Service.Build,
			Domains:      append([]RenderedDomain(nil), s.Service.Domains...),
			Labels:       append([]Label(nil), s.Service.Labels...),
			Variables:    vars,
		},
	}
}

// LogValue redacts a RenderedSpec for slog: logging a spec emits its Summary,
// so a raw spec — which carries verbatim secret variable values — can never
// leak through a structured log record.
func (s RenderedSpec) LogValue() slog.Value { return s.Summary().LogValue() }

// LogValue renders a compact, redaction-safe group for slog. It deliberately
// does not enumerate variables — only their count — so a log record stays
// bounded and free of any per-variable detail.
func (s Summary) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("organization", s.Organization),
		slog.String("project", s.Project),
		slog.String("environment", s.Environment),
		slog.String("tier", string(s.Tier)),
		slog.String("service", s.Service.Name),
		slog.String("service_type", string(s.Service.Type)),
		slog.String("service_role", string(s.Service.Role)),
		slog.String("builder", s.Service.Build.Builder),
		slog.Int("cpu_millis", s.Service.Resources.CPUMillis),
		slog.Int("memory_mib", s.Service.Resources.MemoryMiB),
		slog.Int("replicas", s.Service.Resources.Replicas),
		slog.Int("variable_count", len(s.Service.Variables)),
		slog.Int("domain_count", len(s.Service.Domains)),
	)
}

// String renders a single-line, redaction-safe description of the summary.
func (s Summary) String() string {
	return fmt.Sprintf(
		"dokploy spec org=%s project=%s env=%s tier=%s service=%s type=%s role=%s replicas=%d vars=%d domains=%d",
		s.Organization, s.Project, s.Environment, s.Tier,
		s.Service.Name, s.Service.Type, s.Service.Role,
		s.Service.Resources.Replicas, len(s.Service.Variables), len(s.Service.Domains),
	)
}
