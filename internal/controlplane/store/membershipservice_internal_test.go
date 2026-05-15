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
			if ye.Code != yerr.CodeInvalidInput {
				t.Fatalf("error code = %v, want %s; got %v", ye.Code, yerr.CodeInvalidInput, err)
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

// TestNewMembershipServiceRejectsNilDependencies proves a misconfigured
// service fails at construction rather than on its first request — the same
// defensive contract NewOrganizationService enforces.
func TestNewMembershipServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()

	orgs := NewOrganizationRepository()
	memberships := NewMembershipRepository()
	audit := NewAuditRepository()

	cases := []struct {
		name        string
		store       *Store
		orgs        *OrganizationRepository
		memberships *MembershipRepository
		audit       AuditAppender
	}{
		{"nil store", nil, orgs, memberships, audit},
		{"nil orgs", &Store{}, nil, memberships, audit},
		{"nil memberships", &Store{}, orgs, nil, audit},
		{"nil audit", &Store{}, orgs, memberships, nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewMembershipService(tc.store, tc.orgs, tc.memberships, tc.audit); err == nil {
				t.Fatal("NewMembershipService returned nil error, want a typed construction error")
			}
		})
	}
}
