package dokploy

import "testing"

func TestIdempotencyRulesIncludeCompositeCreates(t *testing.T) {
	rules := IdempotencyRules()
	seen := map[string]bool{}
	for _, rule := range rules {
		seen[rule.CreateOperation] = rule.LookupOperation != "" && rule.NameField != "" && rule.IDField != ""
	}
	for _, op := range []string{"project-create", "environment-create", "compose-create"} {
		if !seen[op] {
			t.Fatalf("missing idempotency rule for %s", op)
		}
	}
}
