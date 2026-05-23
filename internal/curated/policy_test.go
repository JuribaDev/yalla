package curated

import (
	"strings"
	"testing"
)

// validCommand returns a baseline curated command literal that passes
// Validate. Tests mutate one field at a time to assert each policy
// rule fires independently.
func validCommand() Command {
	return Command{
		Path:         "yalla app deploy",
		Domain:       DomainApp,
		Verb:         "deploy",
		Summary:      "Deploy an application service",
		OperationIDs: []string{"createServiceDeployment"},
		HumanExample: "yalla app deploy --service-id svc_123",
		JSONExample:  "yalla --json app deploy --id app_123",
	}
}

func TestDomains_Stable(t *testing.T) {
	got := Domains()
	want := []Domain{
		DomainApp, DomainCompose, DomainDatabase, DomainProject,
		DomainProvider, DomainServer, DomainSettings,
	}
	if len(got) != len(want) {
		t.Fatalf("Domains() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Domains()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestIsDomain(t *testing.T) {
	for _, d := range Domains() {
		if !IsDomain(string(d)) {
			t.Errorf("IsDomain(%q) = false, want true", d)
		}
	}
	if IsDomain("nope") {
		t.Errorf("IsDomain(\"nope\") = true, want false")
	}
}

func TestCommand_Validate_HappyPath(t *testing.T) {
	if err := validCommand().Validate(); err != nil {
		t.Fatalf("baseline command should validate; got %v", err)
	}
}

func TestCommand_Validate_RejectsBadInputs(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Command)
		wantSub string
	}{
		{"empty path", func(c *Command) { c.Path = "" }, "Path is required"},
		{"too few segments", func(c *Command) { c.Path = "yalla app" }, "at least three segments"},
		{"missing yalla prefix", func(c *Command) { c.Path = "app deploy now" }, `must start with "yalla"`},
		{"unknown domain", func(c *Command) {
			c.Path = "yalla widgets deploy"
			c.Domain = Domain("widgets")
		}, "unknown domain"},
		{"path domain mismatch", func(c *Command) { c.Domain = DomainServer }, "does not match Domain field"},
		{"non kebab segment", func(c *Command) {
			c.Path = "yalla app Deploy"
			c.Verb = "Deploy"
		}, "kebab-case"},
		{"verb mismatch", func(c *Command) { c.Verb = "redeploy" }, "does not match trailing path segment"},
		{"banned alias ls", func(c *Command) {
			c.Path = "yalla app ls"
			c.Verb = "ls"
		}, "banned short alias"},
		{"empty verb", func(c *Command) { c.Verb = "" }, "Verb is required"},
		{"no operationIds", func(c *Command) { c.OperationIDs = nil }, "OperationIDs"},
		{"empty operationId entry", func(c *Command) { c.OperationIDs = []string{""} }, "empty OperationID"},
		{"duplicate operationId", func(c *Command) {
			c.OperationIDs = []string{"createServiceDeployment", "createServiceDeployment"}
		}, "twice"},
		{"missing summary", func(c *Command) { c.Summary = "" }, "Summary"},
		{"summary trailing period", func(c *Command) { c.Summary = "Deploys an app." }, "must not end with a period"},
		{"missing human example", func(c *Command) { c.HumanExample = "" }, "HumanExample"},
		{"human example wrong prefix", func(c *Command) { c.HumanExample = "deploy app" }, "must start with"},
		{"human example contains json", func(c *Command) { c.HumanExample = "yalla --json app deploy" }, "must not contain --json"},
		{"missing json example", func(c *Command) { c.JSONExample = "" }, "JSONExample"},
		{"json example missing flag", func(c *Command) { c.JSONExample = "yalla app deploy" }, "must contain --json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validCommand()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected validation error for %q", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestBannedVerbAliases_AllPointToPreferred(t *testing.T) {
	prefSet := make(map[string]struct{}, len(PreferredVerbs))
	for _, v := range PreferredVerbs {
		prefSet[v] = struct{}{}
	}
	for alias, replacement := range BannedVerbAliases {
		if _, ok := prefSet[replacement]; !ok {
			t.Errorf("banned alias %q maps to %q which is not in PreferredVerbs", alias, replacement)
		}
	}
}

func TestSortCommands(t *testing.T) {
	cmds := []Command{
		{Path: "yalla project list"},
		{Path: "yalla app deploy"},
		{Path: "yalla compose start"},
	}
	SortCommands(cmds)
	want := []string{"yalla app deploy", "yalla compose start", "yalla project list"}
	for i, c := range cmds {
		if c.Path != want[i] {
			t.Errorf("[%d] = %q, want %q", i, c.Path, want[i])
		}
	}
}
