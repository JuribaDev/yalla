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
			if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
				t.Fatalf("error code = %v, want %s", err, yerr.CodeValidation)
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

func TestBuildOrganizationUpdateAccepted(t *testing.T) {
	t.Parallel()

	slug := "acme-worldwide"
	displayName := "  Acme Worldwide  "
	change, err := buildOrganizationUpdate(UpdateOrganizationInput{
		Slug:        &slug,
		DisplayName: &displayName,
	})
	if err != nil {
		t.Fatalf("buildOrganizationUpdate(valid) error = %v", err)
	}
	if change.slug == nil || *change.slug != "acme-worldwide" {
		t.Errorf("slug = %v, want a pointer to acme-worldwide", change.slug)
	}
	if change.displayName == nil || *change.displayName != "Acme Worldwide" {
		t.Errorf("display_name = %v, want a pointer to the trimmed %q", change.displayName, "Acme Worldwide")
	}
	if got := strings.Join(change.fields, ","); got != "slug,display_name" {
		t.Errorf("fields = %q, want %q", got, "slug,display_name")
	}
}

func TestBuildOrganizationUpdatePartialLeavesOmittedFieldsNil(t *testing.T) {
	t.Parallel()

	displayName := "Acme"
	change, err := buildOrganizationUpdate(UpdateOrganizationInput{DisplayName: &displayName})
	if err != nil {
		t.Fatalf("buildOrganizationUpdate(partial) error = %v", err)
	}
	if change.slug != nil {
		t.Errorf("slug = %v, want nil — the caller omitted it", change.slug)
	}
	if change.displayName == nil || *change.displayName != "Acme" {
		t.Errorf("display_name = %v, want a pointer to Acme", change.displayName)
	}
	if got := strings.Join(change.fields, ","); got != "display_name" {
		t.Errorf("fields = %q, want %q", got, "display_name")
	}
}

func TestBuildOrganizationUpdateRejectsEmptyPatch(t *testing.T) {
	t.Parallel()

	_, err := buildOrganizationUpdate(UpdateOrganizationInput{})
	if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
		t.Fatalf("error code = %v, want %s — a patch that names no field is a client error", err, yerr.CodeValidation)
	}
	if violations, ok := apierr.ViolationsOf(err); !ok || len(violations) == 0 {
		t.Fatalf("error carries no field violations: %v", err)
	}
}

func TestBuildOrganizationUpdateRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	longName := strings.Repeat("x", organizationDisplayNameMaxLen+1)
	cases := []struct {
		name      string
		in        UpdateOrganizationInput
		wantField string
	}{
		{"invalid slug", UpdateOrganizationInput{Slug: ptrOf("Not A Slug")}, "slug"},
		{"blank slug", UpdateOrganizationInput{Slug: ptrOf("")}, "slug"},
		{"blank display name", UpdateOrganizationInput{DisplayName: ptrOf("   ")}, "display_name"},
		{"control char in display name", UpdateOrganizationInput{DisplayName: ptrOf("Acme\x00Inc")}, "display_name"},
		{"display name too long", UpdateOrganizationInput{DisplayName: ptrOf(longName)}, "display_name"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := buildOrganizationUpdate(tc.in)
			if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
				t.Fatalf("error code = %v, want %s", err, yerr.CodeValidation)
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
				if tc.in.DisplayName != nil && *tc.in.DisplayName != "" && strings.Contains(v.Reason, *tc.in.DisplayName) {
					t.Errorf("violation reason %q echoes the submitted value", v.Reason)
				}
			}
			if !found {
				t.Errorf("violations = %+v, want one for field %q", violations, tc.wantField)
			}
		})
	}
}

// ptrOf returns a pointer to v. The buildOrganizationUpdate cases use it to set
// the optional pointer fields of an UpdateOrganizationInput inline.
func ptrOf[T any](v T) *T { return &v }

func TestNewOrganizationServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()

	repo := NewOrganizationRepository()
	jobs := nopJobEnqueuer{}
	audit := NewAuditRepository()
	store := &Store{}

	cases := []struct {
		name  string
		store *Store
		repo  *OrganizationRepository
		jobs  JobEnqueuer
		audit AuditAppender
	}{
		{"nil store", nil, repo, jobs, audit},
		{"nil repository", store, nil, jobs, audit},
		{"nil job enqueuer", store, repo, nil, audit},
		{"nil audit appender", store, repo, jobs, nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewOrganizationService(tc.store, tc.repo, tc.jobs, tc.audit); err == nil {
				t.Errorf("NewOrganizationService(%s) error = nil, want a construction error", tc.name)
			}
		})
	}
}
