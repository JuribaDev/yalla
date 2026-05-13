package dokploy

// IdempotencyRule describes how a create operation can be resolved by exact
// name before mutation. The raw API command consumes an equivalent table in
// the cli package because it owns the public flag, while composite commands
// use this package-level description for planning and documentation.
type IdempotencyRule struct {
	CreateOperation string   `json:"create_operation"`
	LookupOperation string   `json:"lookup_operation"`
	IDField         string   `json:"id_field"`
	NameField       string   `json:"name_field"`
	ScopeFields     []string `json:"scope_fields,omitempty"`
}

// IdempotencyRules returns the supported exact-name create lookup rules.
func IdempotencyRules() []IdempotencyRule {
	return []IdempotencyRule{
		{CreateOperation: "project-create", LookupOperation: "project-all", IDField: "id", NameField: "name"},
		{CreateOperation: "environment-create", LookupOperation: "environment-search", IDField: "id", NameField: "name", ScopeFields: []string{"projectId"}},
		{CreateOperation: "compose-create", LookupOperation: "compose-search", IDField: "id", NameField: "name", ScopeFields: []string{"environmentId", "projectId"}},
	}
}
