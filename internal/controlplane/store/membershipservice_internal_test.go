package store

import (
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// White-box unit tests for the pure decision logic behind MembershipService —
// input validation and constructor guards. They need no database, so they
// run on every `go test ./...` regardless of whether Postgres is available.

func TestValidateMembershipAddAccepted(t *testing.T) {
	t.Parallel()

	userID := string(domain.MustNewID(domain.KindUser))
	for _, role := range []string{"owner", "admin", "member"} {
		role := role
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			orgID, gotUserID, gotRole, err := validateMembershipAdd(AddMembershipInput{
				OrganizationID: "  org_acme  ",
				UserID:         "  " + userID + "  ",
				Role:           "  " + role + "  ",
			})
			if err != nil {
				t.Fatalf("validateMembershipAdd(valid) error = %v", err)
			}
			if orgID != "org_acme" {
				t.Errorf("organization_id = %q, want the trimmed %q", orgID, "org_acme")
			}
			if gotUserID != userID {
				t.Errorf("user_id = %q, want %q", gotUserID, userID)
			}
			if gotRole != role {
				t.Errorf("role = %q, want %q", gotRole, role)
			}
		})
	}
}

func TestValidateMembershipAddRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	validUser := string(domain.MustNewID(domain.KindUser))
	orgID := string(domain.MustNewID(domain.KindOrganization))

	cases := []struct {
		name      string
		in        AddMembershipInput
		wantField string
	}{
		{"blank organization", AddMembershipInput{OrganizationID: "  ", UserID: validUser, Role: "admin"}, "organization_id"},
		{"blank user", AddMembershipInput{OrganizationID: orgID, UserID: "  ", Role: "admin"}, "user_id"},
		{"malformed user id", AddMembershipInput{OrganizationID: orgID, UserID: "not-an-id", Role: "admin"}, "user_id"},
		{"wrong kind user id", AddMembershipInput{OrganizationID: orgID, UserID: orgID, Role: "admin"}, "user_id"},
		{"blank role", AddMembershipInput{OrganizationID: orgID, UserID: validUser, Role: "  "}, "role"},
		{"unknown role", AddMembershipInput{OrganizationID: orgID, UserID: validUser, Role: "developer"}, "role"},
		{"viewer is not a db role", AddMembershipInput{OrganizationID: orgID, UserID: validUser, Role: "viewer"}, "role"},
		{"support is not a db role", AddMembershipInput{OrganizationID: orgID, UserID: validUser, Role: "support"}, "role"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, _, _, err := validateMembershipAdd(tc.in)
			ye := yerr.From(err)
			if ye.Code != yerr.CodeValidation {
				t.Fatalf("error code = %v, want %s; got %v", ye.Code, yerr.CodeValidation, err)
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
				if tc.in.UserID != "" && strings.Contains(v.Reason, tc.in.UserID) {
					t.Errorf("violation %+v echoes the submitted user_id %q", v, tc.in.UserID)
				}
				if tc.in.Role != "" && strings.Contains(v.Reason, tc.in.Role) {
					t.Errorf("violation %+v echoes the submitted role %q", v, tc.in.Role)
				}
			}
			if !found {
				t.Errorf("violations = %+v, want a violation for field %q", violations, tc.wantField)
			}
		})
	}
}

// TestValidateMembershipUpdateAccepted proves the role-only PATCH validator
// accepts every role the CHECK constraint allows, trims surrounding
// whitespace from every field, and returns the normalised values.
func TestValidateMembershipUpdateAccepted(t *testing.T) {
	t.Parallel()

	userID := string(domain.MustNewID(domain.KindUser))
	for _, role := range []string{"owner", "admin", "member"} {
		role := role
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			orgID, gotUserID, gotRole, err := validateMembershipUpdate(UpdateMembershipInput{
				OrganizationID: "  org_acme  ",
				UserID:         "  " + userID + "  ",
				Role:           "  " + role + "  ",
			})
			if err != nil {
				t.Fatalf("validateMembershipUpdate(valid) error = %v", err)
			}
			if orgID != "org_acme" {
				t.Errorf("organization_id = %q, want the trimmed %q", orgID, "org_acme")
			}
			if gotUserID != userID {
				t.Errorf("user_id = %q, want %q", gotUserID, userID)
			}
			if gotRole != role {
				t.Errorf("role = %q, want %q", gotRole, role)
			}
		})
	}
}

// TestValidateMembershipUpdateRejectsInvalidInput proves every shape the
// validator rejects renders a typed apierr.InvalidInput naming the offending
// field, never echoes the submitted value, and exposes the violations through
// the apierr.ViolationsOf helper agents read.
func TestValidateMembershipUpdateRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	validUser := string(domain.MustNewID(domain.KindUser))
	orgID := string(domain.MustNewID(domain.KindOrganization))

	cases := []struct {
		name      string
		in        UpdateMembershipInput
		wantField string
	}{
		{"blank organization", UpdateMembershipInput{OrganizationID: "  ", UserID: validUser, Role: "admin"}, "organization_id"},
		{"blank member", UpdateMembershipInput{OrganizationID: orgID, UserID: "  ", Role: "admin"}, "member_id"},
		{"malformed member id", UpdateMembershipInput{OrganizationID: orgID, UserID: "not-an-id", Role: "admin"}, "member_id"},
		{"wrong kind member id", UpdateMembershipInput{OrganizationID: orgID, UserID: orgID, Role: "admin"}, "member_id"},
		{"blank role", UpdateMembershipInput{OrganizationID: orgID, UserID: validUser, Role: "  "}, "role"},
		{"unknown role", UpdateMembershipInput{OrganizationID: orgID, UserID: validUser, Role: "emperor"}, "role"},
		{"viewer is not a db role", UpdateMembershipInput{OrganizationID: orgID, UserID: validUser, Role: "viewer"}, "role"},
		{"support is not a db role", UpdateMembershipInput{OrganizationID: orgID, UserID: validUser, Role: "support"}, "role"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, _, _, err := validateMembershipUpdate(tc.in)
			ye := yerr.From(err)
			if ye.Code != yerr.CodeValidation {
				t.Fatalf("error code = %v, want %s; got %v", ye.Code, yerr.CodeValidation, err)
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
				if tc.in.UserID != "" && strings.Contains(v.Reason, tc.in.UserID) {
					t.Errorf("violation %+v echoes the submitted user_id %q", v, tc.in.UserID)
				}
				if tc.in.Role != "" && strings.Contains(v.Reason, tc.in.Role) {
					t.Errorf("violation %+v echoes the submitted role %q", v, tc.in.Role)
				}
			}
			if !found {
				t.Errorf("violations = %+v, want a violation for field %q", violations, tc.wantField)
			}
		})
	}
}

// TestNewMembershipServiceRejectsNilDependencies proves a misconfigured
// service fails at construction rather than on its first request — the same
// defensive contract NewOrganizationService enforces.
func TestNewMembershipServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()

	orgs := NewOrganizationRepository()
	memberships := NewMembershipRepository()
	quota := nopQuotaReserver{}
	audit := NewAuditRepository()

	cases := []struct {
		name        string
		store       *Store
		orgs        *OrganizationRepository
		memberships *MembershipRepository
		quota       QuotaReserver
		audit       AuditAppender
	}{
		{"nil store", nil, orgs, memberships, quota, audit},
		{"nil orgs", &Store{}, nil, memberships, quota, audit},
		{"nil memberships", &Store{}, orgs, nil, quota, audit},
		{"nil quota", &Store{}, orgs, memberships, nil, audit},
		{"nil audit", &Store{}, orgs, memberships, quota, nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewMembershipService(tc.store, tc.orgs, tc.memberships, tc.quota, tc.audit); err == nil {
				t.Fatal("NewMembershipService returned nil error, want a typed construction error")
			}
		})
	}
}

// TestValidateMembershipRemoveAccepted proves the DELETE validator trims
// surrounding whitespace from the identifiers and returns the normalised
// values. Remove has no role field — the row goes away, not the role.
func TestValidateMembershipRemoveAccepted(t *testing.T) {
	t.Parallel()

	userID := string(domain.MustNewID(domain.KindUser))
	orgID, gotUserID, err := validateMembershipRemove(RemoveMembershipInput{
		OrganizationID: "  org_acme  ",
		UserID:         "  " + userID + "  ",
	})
	if err != nil {
		t.Fatalf("validateMembershipRemove(valid) error = %v", err)
	}
	if orgID != "org_acme" {
		t.Errorf("organization_id = %q, want the trimmed %q", orgID, "org_acme")
	}
	if gotUserID != userID {
		t.Errorf("user_id = %q, want %q", gotUserID, userID)
	}
}

// TestValidateMembershipRemoveRejectsInvalidInput proves every shape the
// DELETE validator rejects renders a typed apierr.InvalidInput naming the
// offending field, never echoes the submitted value, and exposes the
// violations through the apierr.ViolationsOf helper agents read.
func TestValidateMembershipRemoveRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	validUser := string(domain.MustNewID(domain.KindUser))
	orgID := string(domain.MustNewID(domain.KindOrganization))

	cases := []struct {
		name      string
		in        RemoveMembershipInput
		wantField string
	}{
		{"blank organization", RemoveMembershipInput{OrganizationID: "  ", UserID: validUser}, "organization_id"},
		{"blank member", RemoveMembershipInput{OrganizationID: orgID, UserID: "  "}, "member_id"},
		{"malformed member id", RemoveMembershipInput{OrganizationID: orgID, UserID: "not-an-id"}, "member_id"},
		{"wrong kind member id", RemoveMembershipInput{OrganizationID: orgID, UserID: orgID}, "member_id"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := validateMembershipRemove(tc.in)
			ye := yerr.From(err)
			if ye.Code != yerr.CodeValidation {
				t.Fatalf("error code = %v, want %s; got %v", ye.Code, yerr.CodeValidation, err)
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
				if tc.in.UserID != "" && strings.Contains(v.Reason, tc.in.UserID) {
					t.Errorf("violation %+v echoes the submitted user_id %q", v, tc.in.UserID)
				}
			}
			if !found {
				t.Errorf("violations = %+v, want a violation for field %q", violations, tc.wantField)
			}
		})
	}
}
