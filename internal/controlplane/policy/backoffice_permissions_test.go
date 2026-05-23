package policy

import (
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

func TestBackofficePermissionActionsAreSplit(t *testing.T) {
	t.Parallel()

	e := NewEngine()
	cases := []struct {
		name       string
		action     Action
		capability Capability
	}{
		{"pricing", ActionPricingManage, CapPricingManage},
		{"metering", ActionMeteringManage, CapMeteringManage},
		{"billing", ActionBillingManage, CapBillingManage},
		{"feature flags", ActionFeatureFlagsManage, CapFeatureFlagsManage},
		{"support", ActionSupportManage, CapSupport},
		{"config publish", ActionConfigPublish, CapConfigPublish},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := e.ActionCapability(tc.action)
			if !ok {
				t.Fatalf("action %q is not catalogued", tc.action)
			}
			if got != tc.capability {
				t.Fatalf("action %q capability = %q, want %q", tc.action, got, tc.capability)
			}
		})
	}
}

func TestBackofficePermissionRoleMatrix(t *testing.T) {
	t.Parallel()

	e := NewEngine()
	resource := Resource{Kind: domain.KindOrganization, Scope: Scope{OrganizationID: orgA}}
	cases := []struct {
		name   string
		role   Role
		action Action
		allow  bool
		reason Reason
	}{
		{"pricing admin manages pricing", RolePricingAdmin, ActionPricingManage, true, ReasonAllowedByRole},
		{"pricing admin cannot publish config", RolePricingAdmin, ActionConfigPublish, false, ReasonDeniedNoCapability},
		{"metering admin manages metering", RoleMeteringAdmin, ActionMeteringManage, true, ReasonAllowedByRole},
		{"metering admin cannot manage pricing", RoleMeteringAdmin, ActionPricingManage, false, ReasonDeniedNoCapability},
		{"billing admin manages billing", RoleBillingAdmin, ActionBillingManage, true, ReasonAllowedByRole},
		{"feature flag admin manages feature flags", RoleFeatureFlagAdmin, ActionFeatureFlagsManage, true, ReasonAllowedByRole},
		{"config publisher publishes production-impacting config", RoleConfigPublisher, ActionConfigPublish, true, ReasonAllowedByRole},
		{"backoffice admin manages pricing", RoleBackofficeAdmin, ActionPricingManage, true, ReasonAllowedByRole},
		{"backoffice admin publishes config", RoleBackofficeAdmin, ActionConfigPublish, true, ReasonAllowedByRole},
		{"support manages support operations", RoleSupport, ActionSupportManage, true, ReasonAllowedByRole},
		{"support cannot manage pricing", RoleSupport, ActionPricingManage, false, ReasonDeniedNoCapability},
		{"owner cannot manage pricing", RoleOwner, ActionPricingManage, false, ReasonDeniedNoCapability},
		{"organization admin cannot manage metering", RoleAdmin, ActionMeteringManage, false, ReasonDeniedNoCapability},
		{"viewer cannot publish config", RoleViewer, ActionConfigPublish, false, ReasonDeniedNoCapability},
		{"ci cannot manage billing", RoleCI, ActionBillingManage, false, ReasonDeniedNoCapability},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := e.Decide(principalIn(orgA, tc.role), tc.action, resource)
			assertDecision(t, got, tc.allow, tc.reason)
		})
	}
}

func TestBackofficeScopedServiceAccountRequiresOrgScopedGrant(t *testing.T) {
	t.Parallel()

	e := NewEngine()
	resource := Resource{Kind: domain.KindOrganization, Scope: Scope{OrganizationID: orgA}}
	projectGrant := Grant{
		Role:  RolePricingAdmin,
		Scope: Scope{OrganizationID: orgA, ProjectID: "proj_backoffice_permissions"},
	}
	orgGrant := Grant{
		Role:  RolePricingAdmin,
		Scope: Scope{OrganizationID: orgA},
	}

	projectScoped := Principal{
		ID:             "sa_backoffice_permissions_project",
		Kind:           domain.KindServiceAccount,
		OrganizationID: orgA,
		Grants:         []Grant{projectGrant},
	}
	assertDecision(t, e.Decide(projectScoped, ActionPricingManage, resource), false, ReasonDeniedOutOfScope)

	orgScoped := Principal{
		ID:             "sa_backoffice_permissions_org",
		Kind:           domain.KindServiceAccount,
		OrganizationID: orgA,
		Grants:         []Grant{orgGrant},
	}
	assertDecision(t, e.Decide(orgScoped, ActionPricingManage, resource), true, ReasonAllowedByGrant)
}
