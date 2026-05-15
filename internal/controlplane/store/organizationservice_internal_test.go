package store

import (
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// White-box unit tests for the pure decision logic behind OrganizationService
// — input validation and constructor guards. They need no database, so they
// run on every `go test ./...` regardless of whether Postgres is available.

func TestBuildOrganizationToCreateAccepted(t *testing.T) {
	t.Parallel()

	got, err := buildOrganizationToCreate(CreateOrganizationInput{
		Slug:        "acme",
		DisplayName: "  Acme, Inc.  ",
	})
	if err != nil {
		t.Fatalf("buildOrganizationToCreate(valid) error = %v", err)
	}
	if got.Slug != "acme" {
		t.Errorf("slug = %q, want acme", got.Slug)
	}
	if got.DisplayName != "Acme, Inc." {
		t.Errorf("display_name = %q, want the trimmed %q", got.DisplayName, "Acme, Inc.")
	}
	id, perr := domain.ParseID(got.ID)
	if perr != nil || id.Kind() != domain.KindOrganization {
		t.Errorf("id = %q, want a freshly minted organization id", got.ID)
	}
}

func TestBuildOrganizationToCreateMintsUniqueIDs(t *testing.T) {
	t.Parallel()

	in := CreateOrganizationInput{Slug: "acme", DisplayName: "Acme"}
	first, err := buildOrganizationToCreate(in)
	if err != nil {
		t.Fatalf("buildOrganizationToCreate first error = %v", err)
	}
	second, err := buildOrganizationToCreate(in)
	if err != nil {
		t.Fatalf("buildOrganizationToCreate second error = %v", err)
	}
	if first.ID == second.ID {
		t.Errorf("two creates minted the same id %q, want non-guessable unique ids", first.ID)
	}
}

func TestBuildOrganizationToCreateRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		in        CreateOrganizationInput
		wantField string
	}{
		{"invalid slug", CreateOrganizationInput{Slug: "Not A Slug", DisplayName: "Acme"}, "slug"},
		{"blank slug", CreateOrganizationInput{Slug: "", DisplayName: "Acme"}, "slug"},
		{"blank display name", CreateOrganizationInput{Slug: "acme", DisplayName: "   "}, "display_name"},
		{"control char in display name", CreateOrganizationInput{Slug: "acme", DisplayName: "Acme\x00Inc"}, "display_name"},
		{"display name too long", CreateOrganizationInput{Slug: "acme", DisplayName: strings.Repeat("x", organizationDisplayNameMaxLen+1)}, "display_name"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := buildOrganizationToCreate(tc.in)
			if ye := yerr.From(err); ye.Code != yerr.CodeInvalidInput {
				t.Fatalf("error code = %v, want %s", err, yerr.CodeInvalidInput)
			}
			violations, ok := apierr.ViolationsOf(err)
			if !ok || len(violations) == 0 {
				t.Fatalf("error carries no field violations: %v", err)
			}
			found := false
			for _, v := range violations {
				if v.Field == tc.wantField {
					found = true
				}
				// The reason is a fixed classification, never the submitted
				// value: an invalid input must not be echoed back.
				if strings.Contains(v.Reason, tc.in.DisplayName) && tc.in.DisplayName != "" {
					t.Errorf("violation reason %q echoes the submitted value", v.Reason)
				}
			}
			if !found {
				t.Errorf("violations = %+v, want one for field %q", violations, tc.wantField)
			}
		})
	}
}

func TestNewOrganizationServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()

	repo := NewOrganizationRepository()
	audit := NewAuditRepository()
	store := &Store{}

	cases := []struct {
		name  string
		store *Store
		repo  *OrganizationRepository
		audit AuditAppender
	}{
		{"nil store", nil, repo, audit},
		{"nil repository", store, nil, audit},
		{"nil audit appender", store, repo, nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewOrganizationService(tc.store, tc.repo, tc.audit); err == nil {
				t.Errorf("NewOrganizationService(%s) error = nil, want a construction error", tc.name)
			}
		})
	}
}
