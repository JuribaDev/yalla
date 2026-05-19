package store

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestBuildPlanToCreateValidation(t *testing.T) {
	t.Parallel()

	_, err := buildPlanToCreate(CreatePlanInput{
		Slug:          "Bad Slug!",
		Name:          "",
		Status:        PlanStatusArchived,
		BillingPeriod: "weekly",
		DisplayOrder:  -1,
		Version:       -1,
	})
	if err == nil {
		t.Fatal("buildPlanToCreate(invalid) error = nil, want validation")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
		t.Fatalf("error code = %s, want %s", ye.Code, yerr.CodeValidation)
	}
	violations, ok := apierr.ViolationsOf(err)
	if !ok {
		t.Fatalf("ViolationsOf(%v) ok=false", err)
	}
	want := map[string]bool{
		"slug":           false,
		"name":           false,
		"status":         false,
		"billing_period": false,
		"display_order":  false,
		"version":        false,
	}
	for _, v := range violations {
		if _, exists := want[v.Field]; exists {
			want[v.Field] = true
		}
	}
	for field, found := range want {
		if !found {
			t.Errorf("validation did not report field %q: %+v", field, violations)
		}
	}
}

func TestBuildPlanEntitlementToUpsertValidation(t *testing.T) {
	t.Parallel()

	neg := int64(-1)
	_, err := buildPlanEntitlementToUpsert(UpsertPlanEntitlementInput{
		PlanID:          "",
		EntitlementKey:  "bad key",
		LimitValue:      &neg,
		EnforcementMode: "sometimes",
	})
	if err == nil {
		t.Fatal("buildPlanEntitlementToUpsert(invalid) error = nil, want validation")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
		t.Fatalf("error code = %s, want %s", ye.Code, yerr.CodeValidation)
	}
	violations, ok := apierr.ViolationsOf(err)
	if !ok {
		t.Fatalf("ViolationsOf(%v) ok=false", err)
	}
	want := map[string]bool{
		"plan_id":          false,
		"entitlement_key":  false,
		"limit_value":      false,
		"enforcement_mode": false,
	}
	for _, v := range violations {
		if _, exists := want[v.Field]; exists {
			want[v.Field] = true
		}
	}
	for field, found := range want {
		if !found {
			t.Errorf("validation did not report field %q: %+v", field, violations)
		}
	}
}
