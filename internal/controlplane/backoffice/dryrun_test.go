package backoffice

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

type fakeImpactReader struct {
	usage map[string]map[string]float64
	err   error
	got   []string
}

func (f *fakeImpactReader) UsageByOrganization(_ context.Context, organizationIDs []string, _ time.Time) (map[string]map[string]float64, error) {
	f.got = append([]string(nil), organizationIDs...)
	if f.err != nil {
		return nil, f.err
	}
	return f.usage, nil
}

func TestValidatorAcceptsValidCandidateAndSimulatesImpact(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	limit := int64(5)
	impact := &fakeImpactReader{usage: map[string]map[string]float64{
		orgID: {"services": 3},
	}}
	validator := NewValidator(
		WithNow(func() time.Time { return time.Date(2026, 5, 19, 8, 0, 0, 0, time.UTC) }),
		WithImpactReader(impact),
	)

	result, err := validator.Validate(context.Background(), DryRunInput{
		Domain:                  store.AdminConfigDomainPricing,
		Payload:                 []byte(validPayload(limit)),
		SimulateOrganizationIDs: []string{orgID},
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !result.Valid || len(result.BlockingErrors) != 0 {
		t.Fatalf("Valid/blocking = %v/%+v, want valid dry-run", result.Valid, result.BlockingErrors)
	}
	if result.Domain != "pricing" || !result.ValidatedAt.Equal(time.Date(2026, 5, 19, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("metadata = domain %q at %s", result.Domain, result.ValidatedAt)
	}
	if len(result.SimulatedOrganizations) != 1 || result.SimulatedOrganizations[0].OrganizationID != orgID || result.SimulatedOrganizations[0].Status != "unchanged" {
		t.Fatalf("simulated organizations = %+v", result.SimulatedOrganizations)
	}
	if len(impact.got) != 1 || impact.got[0] != orgID {
		t.Fatalf("impact reader got %v, want %s", impact.got, orgID)
	}
}

func TestValidatorReturnsBlockingIssuesForInvalidReferencesAndUnsafeDeletes(t *testing.T) {
	t.Parallel()

	validator := NewValidator()
	result, err := validator.Validate(context.Background(), DryRunInput{
		Domain: store.AdminConfigDomainPricing,
		Payload: []byte(`{
			"plans":[{
				"slug":"starter",
				"billing_period":"monthly",
				"entitlements":[
					{"key":"missing_dimension","limit_value":1,"enforcement_mode":"hard"},
					{"key":"services","limit_value":2,"enforcement_mode":"hard"}
				]
			}],
			"deletes":[{"kind":"entitlement_key","key":"services"}]
		}`),
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Valid {
		t.Fatal("Valid = true, want blocking dry-run")
	}
	assertIssueCode(t, result.BlockingErrors, "entitlement_key_unknown")
	assertIssueCode(t, result.BlockingErrors, "unsafe_delete")
}

func TestValidatorRejectsSecretValuesWithoutLeakingThem(t *testing.T) {
	t.Parallel()

	secret := "yka_super_secret_token"
	validator := NewValidator()
	result, err := validator.Validate(context.Background(), DryRunInput{
		Domain: store.AdminConfigDomainBilling,
		Payload: []byte(`{
			"metering_sources":[{"key":"traefik","type":"prometheus","enabled":true,"credential_ref":"` + secret + `"}],
			"billing_providers":[{"key":"stripe_main","type":"stripe","enabled":true,"credential_ref":"Bearer ` + secret + `"}]
		}`),
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Valid {
		t.Fatal("Valid = true, want secret-value blocking errors")
	}
	body := strings.Builder{}
	for _, issue := range result.BlockingErrors {
		body.WriteString(issue.Message)
		body.WriteByte('\n')
	}
	if strings.Contains(body.String(), secret) || strings.Contains(body.String(), "Bearer "+secret) {
		t.Fatalf("secret leaked in issue messages: %q", body.String())
	}
	if !strings.Contains(body.String(), "stored secret reference") {
		t.Fatalf("messages = %q, want stable remediation text", body.String())
	}
}

func TestValidatorRejectsMalformedRequestAsTypedValidation(t *testing.T) {
	t.Parallel()

	validator := NewValidator()
	_, err := validator.Validate(context.Background(), DryRunInput{
		Domain:                  store.AdminConfigDomainPricing,
		Payload:                 []byte(`{}`),
		SimulateOrganizationIDs: []string{"not-an-org"},
	})
	if err == nil {
		t.Fatal("Validate() error = nil, want typed validation error")
	}
	if code := yerr.From(err).Code; code != yerr.CodeValidation {
		t.Fatalf("code = %s, want %s; err %v", code, yerr.CodeValidation, err)
	}
	violations, ok := apierr.ViolationsOf(err)
	if !ok {
		t.Fatalf("ViolationsOf ok = false for %v", err)
	}
	if len(violations) != 1 || violations[0].Field != "simulate_organization_ids[0]" {
		t.Fatalf("violations = %+v", violations)
	}
}

func TestValidatorPropagatesImpactNotFound(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	validator := NewValidator(WithImpactReader(&fakeImpactReader{err: apierr.NotFound("organization", orgID)}))
	_, err := validator.Validate(context.Background(), DryRunInput{
		Domain:                  store.AdminConfigDomainPricing,
		Payload:                 []byte(validPayload(1)),
		SimulateOrganizationIDs: []string{orgID},
	})
	if err == nil {
		t.Fatal("Validate() error = nil, want not found")
	}
	if code := yerr.From(err).Code; code != yerr.CodeNotFound {
		t.Fatalf("code = %s, want %s", code, yerr.CodeNotFound)
	}
}

func TestValidatorImpactCanBlockUnsafeLimitReductions(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	validator := NewValidator(WithImpactReader(&fakeImpactReader{usage: map[string]map[string]float64{
		orgID: {"services": 8},
	}}))
	result, err := validator.Validate(context.Background(), DryRunInput{
		Domain:                  store.AdminConfigDomainPricing,
		Payload:                 []byte(validPayload(5)),
		SimulateOrganizationIDs: []string{orgID},
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Valid {
		t.Fatal("Valid = true, want impact blocking error")
	}
	if len(result.SimulatedOrganizations) != 1 || result.SimulatedOrganizations[0].Status != "would_exceed_limit" {
		t.Fatalf("impact = %+v", result.SimulatedOrganizations)
	}
	assertIssueCode(t, result.BlockingErrors, "impact_limit_exceeded")
}

func TestValidatorPropagatesImpactDependencyFailure(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	validator := NewValidator(WithImpactReader(&fakeImpactReader{err: apierr.StoreUnavailable(errors.New("db down"))}))
	_, err := validator.Validate(context.Background(), DryRunInput{
		Domain:                  store.AdminConfigDomainPricing,
		Payload:                 []byte(validPayload(5)),
		SimulateOrganizationIDs: []string{orgID},
	})
	if err == nil {
		t.Fatal("Validate() error = nil, want dependency failure")
	}
	if code := yerr.From(err).Code; code != yerr.CodeDBUnavailable {
		t.Fatalf("code = %s, want %s", code, yerr.CodeDBUnavailable)
	}
}

func validPayload(limit int64) string {
	return `{
		"plans":[{
			"slug":"starter",
			"billing_period":"monthly",
			"entitlements":[{"key":"services","limit_value":` + fmtInt(limit) + `,"enforcement_mode":"hard","unit":"service"}]
		}],
		"metric_definitions":[{"key":"custom_metric","unit":"request","source":"traefik","enforcement":"metered","billing_grade":true}],
		"metering_sources":[{"key":"traefik","type":"prometheus","enabled":true,"credential_ref":"secret_ref_traefik"}],
		"billing_providers":[{"key":"manual_main","type":"manual","enabled":false,"currency":"USD","compatible_sources":["traefik"]}]
	}`
}

func fmtInt(n int64) string {
	return strconv.FormatInt(n, 10)
}

func assertIssueCode(t *testing.T, issues []Issue, code string) {
	t.Helper()
	for _, issue := range issues {
		if strings.Contains(issue.Message, output.Sentinel) {
			t.Fatalf("issue message unexpectedly contains redaction sentinel: %+v", issue)
		}
		if issue.Code == code {
			return
		}
	}
	t.Fatalf("issue code %q not found in %+v", code, issues)
}
