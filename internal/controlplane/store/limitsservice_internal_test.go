package store

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// White-box unit tests for the pure decision logic behind LimitsService —
// the buildLimitsUpdate input-validation function. They need no database, so
// they run on every `go test ./...` regardless of whether Postgres is
// available.

func TestBuildLimitsUpdateAccepted(t *testing.T) {
	t.Parallel()

	got, err := buildLimitsUpdate([]LimitUpdate{
		{Resource: QuotaResourceProjects, LimitValue: 10},
		{Resource: QuotaResourceServices, LimitValue: 25, EnforcementMode: EnforcementModeSoft},
		// A blank enforcement mode defaults to hard, mirroring the schema.
		{Resource: QuotaResourceDomains, LimitValue: 0},
	})
	if err != nil {
		t.Fatalf("buildLimitsUpdate(valid) error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3; got = %+v", len(got), got)
	}
	if got[0].Resource != QuotaResourceProjects || got[0].LimitValue != 10 || got[0].EnforcementMode != EnforcementModeHard {
		t.Errorf("items[0] = %+v, want projects/10/hard (default mode)", got[0])
	}
	if got[1].EnforcementMode != EnforcementModeSoft {
		t.Errorf("items[1] = %+v, want services/25/soft", got[1])
	}
	if got[2].LimitValue != 0 || got[2].EnforcementMode != EnforcementModeHard {
		t.Errorf("items[2] = %+v, want domains/0/hard (zero is meaningful)", got[2])
	}
}

func TestBuildLimitsUpdateRejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := buildLimitsUpdate(nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
		t.Fatalf("error = %v, want %s", err, yerr.CodeValidation)
	}
	violations, _ := apierr.ViolationsOf(err)
	if len(violations) != 1 || violations[0].Field != "limits" {
		t.Errorf("violations = %+v, want a single limits field violation", violations)
	}
}

func TestBuildLimitsUpdateRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		in        []LimitUpdate
		wantField string
	}{
		{
			name:      "unknown resource",
			in:        []LimitUpdate{{Resource: QuotaResource("not_a_resource"), LimitValue: 10}},
			wantField: "limits[0].resource",
		},
		{
			name:      "blank resource",
			in:        []LimitUpdate{{Resource: "", LimitValue: 10}},
			wantField: "limits[0].resource",
		},
		{
			name:      "negative limit",
			in:        []LimitUpdate{{Resource: QuotaResourceProjects, LimitValue: -1}},
			wantField: "limits[0].limit_value",
		},
		{
			name:      "bad enforcement mode",
			in:        []LimitUpdate{{Resource: QuotaResourceProjects, LimitValue: 10, EnforcementMode: EnforcementMode("urgent")}},
			wantField: "limits[0].enforcement_mode",
		},
		{
			name: "duplicate resource",
			in: []LimitUpdate{
				{Resource: QuotaResourceProjects, LimitValue: 10},
				{Resource: QuotaResourceProjects, LimitValue: 20},
			},
			wantField: "limits[1].resource",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := buildLimitsUpdate(tc.in)
			if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
				t.Fatalf("error code = %v, want %s", err, yerr.CodeValidation)
			}
			violations, ok := apierr.ViolationsOf(err)
			if !ok || len(violations) == 0 {
				t.Fatalf("error carries no field violations: %v", err)
			}
			var found bool
			for _, v := range violations {
				if v.Field == tc.wantField {
					found = true
				}
				// Field violations must never echo the submitted value, even
				// for a value-bearing rejection like a negative limit or an
				// unknown enforcement mode.
				if tc.name == "negative limit" && v.Reason != "" {
					if v.Reason == "-1" || v.Reason == "limit_value -1" {
						t.Errorf("violation %+v echoes the rejected value", v)
					}
				}
				if tc.name == "bad enforcement mode" && v.Reason != "" {
					if v.Reason == "urgent" {
						t.Errorf("violation %+v echoes the rejected value", v)
					}
				}
			}
			if !found {
				t.Errorf("violations = %+v, want one targeting field %q", violations, tc.wantField)
			}
		})
	}
}

func TestNewLimitsServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()

	if _, err := NewLimitsService(nil, NewOrganizationRepository(), NewQuotaRepository(), NewAuditRepository(), nil); err == nil {
		t.Error("NewLimitsService(nil store, ...) returned no error")
	}
	if _, err := NewLimitsService(&Store{}, nil, NewQuotaRepository(), NewAuditRepository(), nil); err == nil {
		t.Error("NewLimitsService(nil orgs, ...) returned no error")
	}
	if _, err := NewLimitsService(&Store{}, NewOrganizationRepository(), nil, NewAuditRepository(), nil); err == nil {
		t.Error("NewLimitsService(nil quotas, ...) returned no error")
	}
	if _, err := NewLimitsService(&Store{}, NewOrganizationRepository(), NewQuotaRepository(), nil, nil); err == nil {
		t.Error("NewLimitsService(nil audit, ...) returned no error")
	}
}
