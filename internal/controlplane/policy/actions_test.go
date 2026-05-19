package policy

import (
	"sort"
	"testing"
)

// TestActionCatalogMatchesEnumeration proves the three action sources stay in
// lockstep: allActions (the enumeration), defaultActionCatalog (the
// capability mapping), and the constant values. A drift between them — an
// action enumerated without a capability, or mapped without being enumerated —
// fails CI here.
func TestActionCatalogMatchesEnumeration(t *testing.T) {
	t.Parallel()

	seen := make(map[Action]struct{}, len(allActions))
	for _, a := range allActions {
		if a == "" {
			t.Error("allActions contains an empty action")
		}
		if _, dup := seen[a]; dup {
			t.Errorf("allActions lists %q more than once", a)
		}
		seen[a] = struct{}{}
		if !Catalogued(a) {
			t.Errorf("action %q is enumerated but has no capability mapping", a)
		}
	}

	for a := range defaultActionCatalog {
		if _, ok := seen[a]; !ok {
			t.Errorf("action %q is mapped to a capability but not enumerated in allActions", a)
		}
	}

	if len(allActions) != len(defaultActionCatalog) {
		t.Errorf("allActions has %d entries, defaultActionCatalog has %d; they must match",
			len(allActions), len(defaultActionCatalog))
	}
}

// TestActionsReturnsSortedStableCopy proves Actions() is a sorted snapshot that
// callers cannot use to mutate package state.
func TestActionsReturnsSortedStableCopy(t *testing.T) {
	t.Parallel()

	got := Actions()
	if len(got) != len(allActions) {
		t.Fatalf("Actions() returned %d actions, want %d", len(got), len(allActions))
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i] < got[j] }) {
		t.Errorf("Actions() is not sorted: %v", got)
	}
	// Mutating the returned slice must not affect a subsequent call.
	got[0] = "mutated"
	if again := Actions(); again[0] == "mutated" {
		t.Error("Actions() returned a slice aliasing package state")
	}
}

// TestCatalogued covers the known/unknown/empty cases of the membership check
// the authorization middleware relies on.
func TestCatalogued(t *testing.T) {
	t.Parallel()

	if !Catalogued(ActionProjectCreate) {
		t.Errorf("Catalogued(%q) = false, want true", ActionProjectCreate)
	}
	if Catalogued(Action("project.teleport")) {
		t.Error("Catalogued returned true for an unknown action")
	}
	if Catalogued(Action("")) {
		t.Error("Catalogued returned true for the empty action")
	}
}

// TestActionConceptsCovered pins the BE-0019 acceptance criterion: the catalog
// covers every named action concept the story enumerates. Each concept is
// asserted through its constant so a rename is a compile error and a removal
// fails the catalog check.
func TestActionConceptsCovered(t *testing.T) {
	t.Parallel()

	concepts := map[string]Action{
		"read":           ActionProjectRead,
		"create":         ActionProjectCreate,
		"update":         ActionProjectUpdate,
		"delete":         ActionProjectDelete,
		"deploy":         ActionDeploymentCreate,
		"restart":        ActionServiceRestart,
		"rollback":       ActionDeploymentRollback,
		"logs.read":      ActionLogsRead,
		"metrics.read":   ActionMetricsRead,
		"env.read":       ActionEnvRead,
		"env.write":      ActionEnvWrite,
		"limits.read":    ActionLimitsRead,
		"limits.write":   ActionLimitsWrite,
		"members.manage": ActionMembersManage,
		"keys.manage":    ActionKeysManage,
		"support.manage": ActionSupportManage,
	}
	for concept, action := range concepts {
		if !Catalogued(action) {
			t.Errorf("action concept %q (%q) is not catalogued", concept, action)
		}
	}
}

// TestActionStringValuesAreStable spot-checks that constant string values match
// the documented wire contract. These strings are public API and must never
// change; the dotted form is what appears in audit records and grants.
func TestActionStringValuesAreStable(t *testing.T) {
	t.Parallel()

	want := map[Action]string{
		ActionAuthMe:                 "auth.me",
		ActionOrganizationCreate:     "organization.create",
		ActionProjectGrantsRead:      "project.grants.read",
		ActionEnvironmentGrantsWrite: "environment.grants.write",
		ActionEnvRead:                "env.read",
		ActionSupportManage:          "support.manage",
		ActionPricingManage:          "pricing.manage",
		ActionMeteringManage:         "metering.manage",
		ActionBillingManage:          "billing.manage",
		ActionFeatureFlagsManage:     "feature_flags.manage",
		ActionConfigPublish:          "config.publish",
	}
	for action, str := range want {
		if string(action) != str {
			t.Errorf("action constant = %q, want %q", string(action), str)
		}
	}
}
