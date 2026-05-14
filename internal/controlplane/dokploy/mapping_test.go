package dokploy

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// invalidInputViolations asserts err is a typed E_INVALID_INPUT error and
// returns its field violations for inspection.
func invalidInputViolations(t *testing.T, err error) []apierr.FieldViolation {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) {
		t.Fatalf("error is not a *yerr.Error: %v", err)
	}
	if ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("error code = %q, want %q", ye.Code, yerr.CodeInvalidInput)
	}
	v, _ := apierr.ViolationsOf(err)
	if len(v) == 0 {
		t.Fatalf("expected at least one field violation, got none: %v", err)
	}
	return v
}

// hasViolation reports whether violations contains an entry for field.
func hasViolation(violations []apierr.FieldViolation, field string) bool {
	for _, v := range violations {
		if v.Field == field {
			return true
		}
	}
	return false
}

func TestMapperOrganizationDedicated(t *testing.T) {
	t.Parallel()
	m := NewMapper()
	if m.SharesOrganization() {
		t.Fatal("default Mapper must not share an organization")
	}
	orgID := domain.MustNewID(domain.KindOrganization)

	target, err := m.Organization(YallaOrganization{ID: orgID, Label: "Acme Corp"})
	if err != nil {
		t.Fatalf("Organization: unexpected error: %v", err)
	}
	if target.Shared {
		t.Fatal("dedicated mode must not report Shared")
	}
	if target.EnsureInput == nil {
		t.Fatal("dedicated mode must produce an EnsureInput")
	}
	if target.DokployID != "" {
		t.Fatalf("DokployID = %q, want empty for an unprovisioned org", target.DokployID)
	}
	if target.EnsureInput.ExistingID != "" {
		t.Fatalf("ExistingID = %q, want empty for an unprovisioned org", target.EnsureInput.ExistingID)
	}
	if err := domain.ValidateDokployName(target.EnsureInput.Name); err != nil {
		t.Fatalf("EnsureInput.Name %q is not Docker-safe: %v", target.EnsureInput.Name, err)
	}
	if !strings.Contains(target.EnsureInput.Name, "acme-corp") {
		t.Fatalf("EnsureInput.Name %q does not embed the label slug", target.EnsureInput.Name)
	}
}

func TestMapperOrganizationExistingIDIsIdempotent(t *testing.T) {
	t.Parallel()
	m := NewMapper()
	orgID := domain.MustNewID(domain.KindOrganization)

	target, err := m.Organization(YallaOrganization{
		ID:        orgID,
		Label:     "Acme",
		DokployID: "org_42",
	})
	if err != nil {
		t.Fatalf("Organization: unexpected error: %v", err)
	}
	if target.DokployID != "org_42" {
		t.Fatalf("DokployID = %q, want org_42", target.DokployID)
	}
	if target.EnsureInput.ExistingID != "org_42" {
		t.Fatalf("ExistingID = %q, want org_42 — a recorded id must make the intent verify, not create", target.EnsureInput.ExistingID)
	}
}

func TestMapperOrganizationShared(t *testing.T) {
	t.Parallel()
	m := NewMapper(WithSharedOrganization("  org_shared  "))
	if !m.SharesOrganization() {
		t.Fatal("Mapper built WithSharedOrganization must report SharesOrganization")
	}
	orgID := domain.MustNewID(domain.KindOrganization)

	target, err := m.Organization(YallaOrganization{ID: orgID, Label: "Acme"})
	if err != nil {
		t.Fatalf("Organization: unexpected error: %v", err)
	}
	if !target.Shared {
		t.Fatal("shared mode must report Shared")
	}
	if target.DokployID != "org_shared" {
		t.Fatalf("DokployID = %q, want trimmed org_shared", target.DokployID)
	}
	if target.EnsureInput != nil {
		t.Fatal("shared mode must not produce an EnsureInput — there is no per-tenant org to ensure")
	}
}

func TestMapperProject(t *testing.T) {
	t.Parallel()
	m := NewMapper()
	projID := domain.MustNewID(domain.KindProject)
	orgID := domain.MustNewID(domain.KindOrganization)

	in, err := m.Project("org_1", YallaProject{
		ID:             projID,
		OrganizationID: orgID,
		Label:          "Billing API",
		DokployID:      "proj_7",
	})
	if err != nil {
		t.Fatalf("Project: unexpected error: %v", err)
	}
	if in.OrganizationID != "org_1" {
		t.Fatalf("OrganizationID = %q, want the parent Dokploy org id org_1", in.OrganizationID)
	}
	if in.ExistingID != "proj_7" {
		t.Fatalf("ExistingID = %q, want proj_7", in.ExistingID)
	}
	if err := domain.ValidateDokployName(in.Name); err != nil {
		t.Fatalf("Name %q is not Docker-safe: %v", in.Name, err)
	}
	if !strings.Contains(in.Name, "billing-api") {
		t.Fatalf("Name %q does not embed the label slug", in.Name)
	}
}

func TestMapperEnvironment(t *testing.T) {
	t.Parallel()
	m := NewMapper()
	envID := domain.MustNewID(domain.KindEnvironment)
	projID := domain.MustNewID(domain.KindProject)

	in, err := m.Environment("proj_1", YallaEnvironment{
		ID:        envID,
		ProjectID: projID,
		Label:     "Production",
	})
	if err != nil {
		t.Fatalf("Environment: unexpected error: %v", err)
	}
	if in.ProjectID != "proj_1" {
		t.Fatalf("ProjectID = %q, want the parent Dokploy project id proj_1", in.ProjectID)
	}
	if in.ExistingID != "" {
		t.Fatalf("ExistingID = %q, want empty for an unprovisioned environment", in.ExistingID)
	}
	if err := domain.ValidateDokployName(in.Name); err != nil {
		t.Fatalf("Name %q is not Docker-safe: %v", in.Name, err)
	}
}

func TestMapperServiceByType(t *testing.T) {
	t.Parallel()
	m := NewMapper()
	svcID := domain.MustNewID(domain.KindService)
	envID := domain.MustNewID(domain.KindEnvironment)

	tests := []struct {
		name       string
		typ        ServiceType
		engine     string
		wantEngine string
	}{
		{"application", ServiceApplication, "", ""},
		{"compose", ServiceCompose, "", ""},
		{"database carries its engine", ServiceDatabase, "postgres", "postgres"},
		{"engine dropped for non-database", ServiceApplication, "postgres", ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in, err := m.Service("env_1", YallaService{
				ID:            svcID,
				EnvironmentID: envID,
				Label:         "Web",
				Type:          tc.typ,
				Engine:        tc.engine,
			})
			if err != nil {
				t.Fatalf("Service: unexpected error: %v", err)
			}
			if in.EnvironmentID != "env_1" {
				t.Fatalf("EnvironmentID = %q, want env_1", in.EnvironmentID)
			}
			if in.Type != tc.typ {
				t.Fatalf("Type = %q, want %q", in.Type, tc.typ)
			}
			if in.Engine != tc.wantEngine {
				t.Fatalf("Engine = %q, want %q", in.Engine, tc.wantEngine)
			}
			if err := domain.ValidateDokployName(in.Name); err != nil {
				t.Fatalf("Name %q is not Docker-safe: %v", in.Name, err)
			}
		})
	}
}

func TestMapperValidationFailures(t *testing.T) {
	t.Parallel()
	m := NewMapper()
	orgID := domain.MustNewID(domain.KindOrganization)
	projID := domain.MustNewID(domain.KindProject)
	envID := domain.MustNewID(domain.KindEnvironment)
	svcID := domain.MustNewID(domain.KindService)

	t.Run("organization with a malformed id", func(t *testing.T) {
		t.Parallel()
		_, err := m.Organization(YallaOrganization{ID: "not-an-id"})
		v := invalidInputViolations(t, err)
		if !hasViolation(v, "organization.id") {
			t.Fatalf("violations %v missing organization.id", v)
		}
	})

	t.Run("organization id of the wrong kind", func(t *testing.T) {
		t.Parallel()
		_, err := m.Organization(YallaOrganization{ID: projID})
		v := invalidInputViolations(t, err)
		if !hasViolation(v, "organization.id") {
			t.Fatalf("violations %v missing organization.id", v)
		}
	})

	t.Run("project with a blank parent dokploy id", func(t *testing.T) {
		t.Parallel()
		_, err := m.Project("  ", YallaProject{ID: projID, OrganizationID: orgID})
		v := invalidInputViolations(t, err)
		if !hasViolation(v, "dokploy_organization_id") {
			t.Fatalf("violations %v missing dokploy_organization_id", v)
		}
	})

	t.Run("project with a wrong-kind organization linkage", func(t *testing.T) {
		t.Parallel()
		_, err := m.Project("org_1", YallaProject{ID: projID, OrganizationID: envID})
		v := invalidInputViolations(t, err)
		if !hasViolation(v, "project.organization_id") {
			t.Fatalf("violations %v missing project.organization_id", v)
		}
	})

	t.Run("environment with a wrong-kind project linkage", func(t *testing.T) {
		t.Parallel()
		_, err := m.Environment("proj_1", YallaEnvironment{ID: envID, ProjectID: orgID})
		v := invalidInputViolations(t, err)
		if !hasViolation(v, "environment.project_id") {
			t.Fatalf("violations %v missing environment.project_id", v)
		}
	})

	t.Run("service with an unrecognised type", func(t *testing.T) {
		t.Parallel()
		_, err := m.Service("env_1", YallaService{ID: svcID, EnvironmentID: envID, Type: "lambda"})
		v := invalidInputViolations(t, err)
		if !hasViolation(v, "service.type") {
			t.Fatalf("violations %v missing service.type", v)
		}
	})

	t.Run("database service missing its engine", func(t *testing.T) {
		t.Parallel()
		_, err := m.Service("env_1", YallaService{ID: svcID, EnvironmentID: envID, Type: ServiceDatabase})
		v := invalidInputViolations(t, err)
		if !hasViolation(v, "service.engine") {
			t.Fatalf("violations %v missing service.engine", v)
		}
	})

	t.Run("violations are collected, not short-circuited", func(t *testing.T) {
		t.Parallel()
		_, err := m.Service("", YallaService{ID: "bad", EnvironmentID: "bad", Type: "bad"})
		v := invalidInputViolations(t, err)
		for _, field := range []string{"dokploy_environment_id", "service.id", "service.environment_id", "service.type"} {
			if !hasViolation(v, field) {
				t.Fatalf("violations %v missing %s", v, field)
			}
		}
	})
}

// TestMapperValidationDoesNotEchoInput proves a rejected mapping never places
// the submitted id, label, or type value into the error — field violations
// carry a path and a reason only, so the error is safe for logs and audit
// metadata.
func TestMapperValidationDoesNotEchoInput(t *testing.T) {
	t.Parallel()
	m := NewMapper()
	const secretish = "super-secret-leaked-value"

	_, err := m.Service("", YallaService{
		ID:            domain.ID(secretish),
		EnvironmentID: domain.ID(secretish),
		Label:         secretish,
		Type:          ServiceType(secretish),
		Engine:        secretish,
	})
	if err == nil {
		t.Fatal("expected a validation error")
	}
	if strings.Contains(err.Error(), secretish) {
		t.Fatalf("error message echoes the submitted value: %v", err)
	}
	var ye *yerr.Error
	if stderrors.As(err, &ye) && strings.Contains(ye.Hint, secretish) {
		t.Fatalf("error hint echoes the submitted value: %v", ye.Hint)
	}
	violations, _ := apierr.ViolationsOf(err)
	for _, v := range violations {
		if strings.Contains(v.String(), secretish) {
			t.Fatalf("field violation echoes the submitted value: %v", v)
		}
	}
}

// TestMapperIsDeterministic proves the same Yalla input always yields the same
// Dokploy intent — a precondition for idempotent provisioning.
func TestMapperIsDeterministic(t *testing.T) {
	t.Parallel()
	m := NewMapper()
	svc := YallaService{
		ID:            domain.MustNewID(domain.KindService),
		EnvironmentID: domain.MustNewID(domain.KindEnvironment),
		Label:         "Café Service",
		Type:          ServiceDatabase,
		Engine:        "postgres",
	}
	first, err := m.Service("env_1", svc)
	if err != nil {
		t.Fatalf("Service: unexpected error: %v", err)
	}
	second, err := m.Service("env_1", svc)
	if err != nil {
		t.Fatalf("Service: unexpected error: %v", err)
	}
	if first != second {
		t.Fatalf("mapping is not deterministic: %+v != %+v", first, second)
	}
}

// TestMapperFullHierarchy walks a complete organization -> project ->
// environment -> service chain the way the worker will: each level's mapped
// intent feeds the (simulated) recorded Dokploy ID into the next.
func TestMapperFullHierarchy(t *testing.T) {
	t.Parallel()
	m := NewMapper()

	orgTarget, err := m.Organization(YallaOrganization{
		ID:    domain.MustNewID(domain.KindOrganization),
		Label: "Acme",
	})
	if err != nil {
		t.Fatalf("Organization: %v", err)
	}
	// Worker ensures the org and records the returned Dokploy id.
	dokployOrgID := "org_provisioned"

	projIn, err := m.Project(dokployOrgID, YallaProject{
		ID:             domain.MustNewID(domain.KindProject),
		OrganizationID: domain.MustNewID(domain.KindOrganization),
		Label:          "Shop",
	})
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if projIn.OrganizationID != dokployOrgID {
		t.Fatalf("project parent = %q, want %q", projIn.OrganizationID, dokployOrgID)
	}
	dokployProjID := "proj_provisioned"

	envIn, err := m.Environment(dokployProjID, YallaEnvironment{
		ID:        domain.MustNewID(domain.KindEnvironment),
		ProjectID: domain.MustNewID(domain.KindProject),
		Label:     "Staging",
	})
	if err != nil {
		t.Fatalf("Environment: %v", err)
	}
	if envIn.ProjectID != dokployProjID {
		t.Fatalf("environment parent = %q, want %q", envIn.ProjectID, dokployProjID)
	}
	dokployEnvID := "env_provisioned"

	svcIn, err := m.Service(dokployEnvID, YallaService{
		ID:            domain.MustNewID(domain.KindService),
		EnvironmentID: domain.MustNewID(domain.KindEnvironment),
		Label:         "Web",
		Type:          ServiceApplication,
	})
	if err != nil {
		t.Fatalf("Service: %v", err)
	}
	if svcIn.EnvironmentID != dokployEnvID {
		t.Fatalf("service parent = %q, want %q", svcIn.EnvironmentID, dokployEnvID)
	}
	_ = orgTarget
}
