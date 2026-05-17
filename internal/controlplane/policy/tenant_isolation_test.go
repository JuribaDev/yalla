package policy

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Canonical tenant-isolation regression pair (BE-0398). Both members of
// this pair exercise the policy engine — the load-bearing chokepoint every
// authenticated endpoint flows through — and prove the engine's tenant
// boundary is intact under both closed-set coverage AND concurrent
// contention. The PRD's `go test -run TestTenantIsolation ./...` filter
// binds to the `TestTenantIsolation` prefix; the static defence for the
// surrounding surfaces (CI step, verify.sh prefix, CONTRIBUTING entry,
// SECURITY row + section, PRD command, canonical file existence) lives in
// internal/release/verification_suite_tenant_isolation_static_test.go.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Per-row repository tenant-isolation (cross-tenant ID lookups against
//     the store layer) is proven by the live-Postgres
//     organization_tenant_isolation_test.go + sibling child-table
//     isolation tests under internal/controlplane/store.
//   - The HTTP-layer "another tenant's id is a 404, not a 403" wire
//     contract is proven by the per-endpoint policy matrix and contract
//     tests in internal/controlplane/httpapi.
//   - The action-catalog well-formedness contract is proven by
//     TestCatalogAndRolesAreWellFormed in policy_test.go.

const (
	// tenantIsolationWorkers and tenantIsolationIterationsPerWorker bound
	// the contention burst the per-decision stability member fires. The
	// product is also the closed-set sample size against the coverage
	// table — every goroutine asserts its own tuple's verdict matches the
	// closed-set scenario's predicted verdict, so a cross-write under the
	// race would fail the per-iteration assertion even when the aggregate
	// verdict counts matched.
	tenantIsolationWorkers             = 12
	tenantIsolationIterationsPerWorker = 32
)

// tenantIsolationScenario is one closed-set coverage tuple plus the verdict
// the engine MUST return for it. Every coverage and contention assertion is
// derived from this same record so the two members cannot drift out of
// sync.
type tenantIsolationScenario struct {
	name       string
	principal  Principal
	action     Action
	resource   Resource
	wantAllow  bool
	wantReason Reason
}

// scenarioPrincipal builds a sentinel principal for a tenant + role + flags.
// The IDs are deliberately constant so a regression that leaked a principal
// id into an error message would be visible in the redaction sub-assertion.
func scenarioPrincipal(org string, role Role, disabled bool, grants ...Grant) Principal {
	return Principal{
		ID:             "usr_00000000000000000000000001",
		Kind:           domain.KindUser,
		OrganizationID: org,
		Role:           role,
		Grants:         grants,
		Disabled:       disabled,
	}
}

// scenarioResource builds a project-scoped resource in the named org. The
// Kind is irrelevant to the engine's tenant-isolation ordering — only the
// Scope.OrganizationID matters — but using a deeper-than-org-level resource
// makes a regression that confused scope levels with tenant boundaries
// visible.
func scenarioResource(org string) Resource {
	return Resource{Kind: domain.KindProject, Scope: Scope{OrganizationID: org}}
}

// expectedCrossTenantVerdict returns the verdict the engine's documented
// cross-tenant ordering yields for (role, action) on a resource in a
// foreign tenant. It is the SAME function that backs the closed-set
// scenario table AND the contention burst's per-iteration prediction, so
// the two cannot drift.
func expectedCrossTenantVerdict(e *Engine, role Role, action Action) (bool, Reason) {
	required, ok := e.ActionCapability(action)
	if !ok {
		return false, ReasonDeniedUnknownAction
	}
	if required == CapSelf {
		// CapSelf is organization-independent and short-circuits before
		// the cross-tenant check in engine.Decide.
		return true, ReasonAllowedSelf
	}
	if builtinRoleCaps[role].has(CapSupport) && (required == CapRead || required == CapSupport) {
		return true, ReasonAllowedBySupport
	}
	return false, ReasonDeniedCrossTenant
}

// buildTenantIsolationScenarios enumerates the closed-set tenant-isolation
// coverage table. Every built-in role × every catalogued action is
// expanded against a cross-tenant resource, plus a fixed set of
// short-circuit and grant scenarios that MUST precede or bypass the
// cross-tenant clause.
func buildTenantIsolationScenarios(t *testing.T) []tenantIsolationScenario {
	t.Helper()
	e := NewEngine()
	scenarios := make([]tenantIsolationScenario, 0, 256)

	// (1) Role × action coverage against a cross-tenant resource.
	for _, role := range BuiltinRoles() {
		for _, action := range Actions() {
			allow, reason := expectedCrossTenantVerdict(e, role, action)
			scenarios = append(scenarios, tenantIsolationScenario{
				name:       fmt.Sprintf("role=%s/action=%s/cross-tenant", role, action),
				principal:  scenarioPrincipal(orgA, role, false),
				action:     action,
				resource:   scenarioResource(orgB),
				wantAllow:  allow,
				wantReason: reason,
			})
		}
	}

	// (2) Short-circuit ordering. Every short-circuit MUST precede the
	// cross-tenant check so a missing/disabled principal or an
	// uncatalogued action is denied with its OWN reason, never masked as
	// ReasonDeniedCrossTenant.
	scenarios = append(scenarios,
		tenantIsolationScenario{
			name:       "short-circuit/no-principal/cross-tenant",
			principal:  Principal{},
			action:     ActionProjectRead,
			resource:   scenarioResource(orgB),
			wantAllow:  false,
			wantReason: ReasonDeniedNoPrincipal,
		},
		tenantIsolationScenario{
			name:       "short-circuit/disabled-principal/cross-tenant",
			principal:  scenarioPrincipal(orgA, RoleOwner, true),
			action:     ActionProjectRead,
			resource:   scenarioResource(orgB),
			wantAllow:  false,
			wantReason: ReasonDeniedPrincipalDisabled,
		},
		tenantIsolationScenario{
			name:       "short-circuit/unknown-action/cross-tenant",
			principal:  scenarioPrincipal(orgA, RoleOwner, false),
			action:     Action("nonsense.not.in.catalog"),
			resource:   scenarioResource(orgB),
			wantAllow:  false,
			wantReason: ReasonDeniedUnknownAction,
		},
	)

	// (3) Grants never bridge tenants. A Grant whose Scope.OrganizationID
	// is the cross tenant is silently ignored by the engine; the verdict
	// MUST be the same as if the grant were absent. A regression that
	// dropped the grant-tenant comparison would surface here.
	crossOrgGrant := Grant{
		Role:  RoleDeveloper,
		Scope: Scope{OrganizationID: orgB, ProjectID: "proj_000000000000000000000ppp"},
	}
	scenarios = append(scenarios,
		tenantIsolationScenario{
			name:       "grant/cross-tenant-grant-ignored/same-tenant-resource",
			principal:  scenarioPrincipal(orgA, RoleViewer, false, crossOrgGrant),
			action:     ActionServiceCreate,
			resource:   Resource{Kind: domain.KindService, Scope: Scope{OrganizationID: orgA, ProjectID: "proj_000000000000000000000ppp"}},
			wantAllow:  false,
			wantReason: ReasonDeniedNoCapability,
		},
		tenantIsolationScenario{
			name:       "grant/cross-tenant-grant-ignored/cross-tenant-resource",
			principal:  scenarioPrincipal(orgA, RoleViewer, false, crossOrgGrant),
			action:     ActionServiceCreate,
			resource:   Resource{Kind: domain.KindService, Scope: Scope{OrganizationID: orgB, ProjectID: "proj_000000000000000000000ppp"}},
			wantAllow:  false,
			wantReason: ReasonDeniedCrossTenant,
		},
	)

	return scenarios
}

// TestTenantIsolationCoversCallSites is the closed-set tenant-isolation
// coverage member of the canonical pair. It walks the scenario table built
// by buildTenantIsolationScenarios and asserts the engine's verdict
// matches the predicted verdict for every (role, action, cross-tenant)
// tuple, every short-circuit ordering case, and every grant-never-bridges
// case. A regression in the cross-tenant ordering, the short-circuit
// ordering, or the grant-tenant comparison trips the gate on the offending
// scenario name.
func TestTenantIsolationCoversCallSites(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	scenarios := buildTenantIsolationScenarios(t)
	if len(scenarios) == 0 {
		t.Fatal("scenario table is empty; the coverage member would vacuously pass")
	}

	for _, scen := range scenarios {
		scen := scen
		t.Run(scen.name, func(t *testing.T) {
			t.Parallel()
			got := e.Decide(scen.principal, scen.action, scen.resource)
			if got.Allow != scen.wantAllow || got.Reason != scen.wantReason {
				t.Fatalf("Decide(%s) = {allow:%v reason:%s}, want {allow:%v reason:%s}",
					scen.name, got.Allow, got.Reason, scen.wantAllow, scen.wantReason)
			}

			// Authorize is the imperative form: when Decide allows, it
			// MUST return nil; when Decide denies, it MUST return a
			// typed apierr whose rendered message names the action and
			// the reason but NEVER any tenant or principal id (the
			// engine's redaction contract).
			err := e.Authorize(scen.principal, scen.action, scen.resource)
			if scen.wantAllow {
				if err != nil {
					t.Fatalf("Authorize(%s) returned %v on allow", scen.name, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Authorize(%s) returned nil on deny", scen.name)
			}
			msg := err.Error()
			for _, secret := range []string{orgA, orgB, scen.principal.ID} {
				if secret == "" {
					continue
				}
				if strings.Contains(msg, secret) {
					t.Fatalf("Authorize(%s) error %q leaked identifier %q — the engine MUST NOT echo principal or tenant ids in the wire error",
						scen.name, msg, secret)
				}
			}
			// The action MUST be in the rendered error so an operator
			// reading a CI log can correlate the denial with a specific
			// call site without re-running the suite. A regression that
			// dropped the action from the rendered message would trip
			// here.
			if !strings.Contains(msg, string(scen.action)) {
				t.Fatalf("Authorize(%s) error %q missing action %q", scen.name, msg, scen.action)
			}
			// The Forbidden path also carries the stable reason code;
			// the Unauthenticated path (ReasonDeniedNoPrincipal) maps
			// to a fixed "authentication is required" message that does
			// NOT echo the reason, so the reason-in-message check only
			// applies to the Forbidden branch.
			if scen.wantReason != ReasonDeniedNoPrincipal && !strings.Contains(msg, string(scen.wantReason)) {
				t.Fatalf("Authorize(%s) error %q missing reason %q", scen.name, msg, scen.wantReason)
			}
		})
	}
}

// TestTenantIsolationPreservesScopeUnderContention is the per-decision
// stability member of the canonical pair. It fires
// `tenantIsolationWorkers * tenantIsolationIterationsPerWorker` goroutines
// against a single shared policy.Engine, each goroutine drawing a tuple
// from the same coverage table and asserting the verdict it observed
// matches its OWN tuple's predicted verdict. A cross-write under the race
// that swapped two goroutines' principals or resources would fail the
// per-iteration assertion even when the aggregate verdict counts matched.
func TestTenantIsolationPreservesScopeUnderContention(t *testing.T) {
	t.Parallel()
	e := NewEngine()
	scenarios := buildTenantIsolationScenarios(t)
	if len(scenarios) == 0 {
		t.Fatal("scenario table is empty; the contention burst would vacuously pass")
	}

	type observation struct {
		worker     int
		iteration  int
		scenario   string
		gotAllow   bool
		gotReason  Reason
		wantAllow  bool
		wantReason Reason
	}

	var (
		mu       sync.Mutex
		failures []observation
	)

	var wg sync.WaitGroup
	wg.Add(tenantIsolationWorkers)
	for w := 0; w < tenantIsolationWorkers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < tenantIsolationIterationsPerWorker; i++ {
				// Deterministic per-worker + per-iteration index so
				// every parallel run paginates the identical decision
				// set. A cross-write that swapped two goroutines'
				// tuples would map to a different scenario than the
				// one this iteration predicted.
				idx := (w*tenantIsolationIterationsPerWorker + i) % len(scenarios)
				scen := scenarios[idx]

				got := e.Decide(scen.principal, scen.action, scen.resource)
				if got.Allow == scen.wantAllow && got.Reason == scen.wantReason {
					continue
				}

				mu.Lock()
				failures = append(failures, observation{
					worker:     w,
					iteration:  i,
					scenario:   scen.name,
					gotAllow:   got.Allow,
					gotReason:  got.Reason,
					wantAllow:  scen.wantAllow,
					wantReason: scen.wantReason,
				})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(failures) == 0 {
		return
	}

	// Surface every divergent decision with worker + iteration + scenario
	// so an operator can correlate the regression with the in-flight
	// tuple without re-running the suite. The aggregate count alone would
	// hide a single cross-write among thousands of successful decisions.
	for _, f := range failures {
		t.Errorf("worker=%d iteration=%d scenario=%s: got {allow:%v reason:%s}, want {allow:%v reason:%s}",
			f.worker, f.iteration, f.scenario, f.gotAllow, f.gotReason, f.wantAllow, f.wantReason)
	}
}

// TestTenantIsolationGrantNeverBridgesTenants is a focused regression test
// on top of the coverage member. It builds a principal with NO
// organization role but a single scoped grant whose Scope.OrganizationID
// is the cross tenant, then asserts the engine ignores the grant entirely:
// the verdict against a SAME-tenant resource is the no-capability denial
// (the grant did not widen authority because its tenant did not match),
// and the verdict against the CROSS-tenant resource is the cross-tenant
// denial (the grant did not bridge the tenant boundary). A regression
// that dropped the `g.Scope.OrganizationID != principal.OrganizationID`
// guard in engine.Decide would surface as the wrong reason on either leg.
func TestTenantIsolationGrantNeverBridgesTenants(t *testing.T) {
	t.Parallel()
	e := NewEngine()

	crossOrgGrant := Grant{
		Role:  RoleOwner,
		Scope: Scope{OrganizationID: orgB},
	}
	noRolePrincipal := Principal{
		ID:             "usr_00000000000000000000000099",
		Kind:           domain.KindUser,
		OrganizationID: orgA,
		Grants:         []Grant{crossOrgGrant},
	}

	// Same-tenant resource: the grant is ignored because its tenant does
	// not match the principal's; the principal has no organization role
	// and no in-tenant grant, so the verdict is ReasonDeniedNoCapability.
	got := e.Decide(noRolePrincipal, ActionProjectCreate, scenarioResource(orgA))
	if got.Allow || got.Reason != ReasonDeniedNoCapability {
		t.Fatalf("same-tenant resource w/ cross-tenant grant: got {allow:%v reason:%s}, want {allow:false reason:%s}",
			got.Allow, got.Reason, ReasonDeniedNoCapability)
	}

	// Cross-tenant resource: even with the (ignored) cross-tenant grant,
	// the engine denies with ReasonDeniedCrossTenant. The grant did not
	// bridge the tenant boundary.
	got = e.Decide(noRolePrincipal, ActionProjectCreate, scenarioResource(orgB))
	if got.Allow || got.Reason != ReasonDeniedCrossTenant {
		t.Fatalf("cross-tenant resource w/ cross-tenant grant: got {allow:%v reason:%s}, want {allow:false reason:%s}",
			got.Allow, got.Reason, ReasonDeniedCrossTenant)
	}
}
