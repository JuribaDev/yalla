package store

import (
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// White-box unit tests for the pure decision logic behind ServiceAccountService
// — input validation and constructor guards. They need no database, so they
// run on every `go test ./...` regardless of whether Postgres is available.

func validServiceAccountInput() CreateServiceAccountInput {
	return CreateServiceAccountInput{
		OrganizationID:   domain.MustNewID(domain.KindOrganization).String(),
		ServiceAccountID: domain.MustNewID(domain.KindServiceAccount).String(),
		Slug:             "ci-deployer",
		DisplayName:      "CI Deployer",
	}
}

func TestValidateCreateServiceAccountInputAccepted(t *testing.T) {
	t.Parallel()

	in := validServiceAccountInput()
	got, err := validateCreateServiceAccountInput(in)
	if err != nil {
		t.Fatalf("validateCreateServiceAccountInput(valid) error = %v", err)
	}
	if got.ID != in.ServiceAccountID || got.OrganizationID != in.OrganizationID {
		t.Errorf("ids = %q/%q, want %q/%q", got.ID, got.OrganizationID, in.ServiceAccountID, in.OrganizationID)
	}
	if got.Slug != "ci-deployer" || got.DisplayName != "CI Deployer" {
		t.Errorf("got %+v, want slug/name ci-deployer/CI Deployer", got)
	}
}

func TestValidateCreateServiceAccountInputTrimsWhitespace(t *testing.T) {
	t.Parallel()

	in := validServiceAccountInput()
	in.OrganizationID = "  " + in.OrganizationID + "  "
	in.DisplayName = "  CI Deployer  "
	got, err := validateCreateServiceAccountInput(in)
	if err != nil {
		t.Fatalf("validateCreateServiceAccountInput(padded) error = %v", err)
	}
	if strings.TrimSpace(got.OrganizationID) != got.OrganizationID {
		t.Errorf("organization_id not trimmed: %q", got.OrganizationID)
	}
	if got.DisplayName != "CI Deployer" {
		t.Errorf("display_name not trimmed: %q", got.DisplayName)
	}
}

func TestValidateCreateServiceAccountInputRejectsEachField(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		mutate    func(*CreateServiceAccountInput)
		wantField string
	}{
		{"bad organization id", func(in *CreateServiceAccountInput) { in.OrganizationID = "not-an-id" }, "organization_id"},
		{"organization id of wrong kind", func(in *CreateServiceAccountInput) {
			in.OrganizationID = domain.MustNewID(domain.KindServiceAccount).String()
		}, "organization_id"},
		{"bad service account id", func(in *CreateServiceAccountInput) { in.ServiceAccountID = "nope" }, "service_account_id"},
		{"service account id of wrong kind", func(in *CreateServiceAccountInput) {
			in.ServiceAccountID = domain.MustNewID(domain.KindOrganization).String()
		}, "service_account_id"},
		{"empty slug", func(in *CreateServiceAccountInput) { in.Slug = "" }, "slug"},
		{"non-canonical slug", func(in *CreateServiceAccountInput) { in.Slug = "Not A Slug!" }, "slug"},
		{"empty display name", func(in *CreateServiceAccountInput) { in.DisplayName = "   " }, "display_name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := validServiceAccountInput()
			tc.mutate(&in)
			_, err := validateCreateServiceAccountInput(in)
			if err == nil {
				t.Fatalf("validateCreateServiceAccountInput(%s) error = nil, want InvalidInput", tc.name)
			}
			if ye := yerr.From(err); ye.Code != yerr.CodeInvalidInput {
				t.Fatalf("error code = %s, want %s", ye.Code, yerr.CodeInvalidInput)
			}
			violations, ok := apierr.ViolationsOf(err)
			if !ok {
				t.Fatalf("apierr.ViolationsOf returned ok=false for %v", err)
			}
			found := false
			for _, v := range violations {
				if v.Field == tc.wantField {
					found = true
				}
			}
			if !found {
				t.Errorf("violations %+v do not name field %q", violations, tc.wantField)
			}
		})
	}
}

func TestValidateCreateServiceAccountInputReportsAllViolations(t *testing.T) {
	t.Parallel()

	_, err := validateCreateServiceAccountInput(CreateServiceAccountInput{})
	if err == nil {
		t.Fatal("validateCreateServiceAccountInput(zero) error = nil, want InvalidInput")
	}
	violations, ok := apierr.ViolationsOf(err)
	if !ok {
		t.Fatalf("apierr.ViolationsOf returned ok=false for %v", err)
	}
	if len(violations) != 4 {
		t.Errorf("got %d violations, want 4 (one per field): %+v", len(violations), violations)
	}
}

func TestNewServiceAccountServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()

	s := &Store{}
	repo := NewServiceAccountRepository()
	authz := nopAuthorizer{}
	quota := nopQuotaReserver{}

	cases := []struct {
		name string
		call func() (*ServiceAccountService, error)
	}{
		{"nil store", func() (*ServiceAccountService, error) { return NewServiceAccountService(nil, repo, authz, quota) }},
		{"nil repo", func() (*ServiceAccountService, error) { return NewServiceAccountService(s, nil, authz, quota) }},
		{"nil authorizer", func() (*ServiceAccountService, error) { return NewServiceAccountService(s, repo, nil, quota) }},
		{"nil quota", func() (*ServiceAccountService, error) { return NewServiceAccountService(s, repo, authz, nil) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tc.call(); err == nil {
				t.Errorf("NewServiceAccountService(%s) error = nil, want an error", tc.name)
			}
		})
	}

	if _, err := NewServiceAccountService(s, repo, authz, quota); err != nil {
		t.Errorf("NewServiceAccountService(all set) error = %v, want nil", err)
	}
}
