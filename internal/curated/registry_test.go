package curated

import (
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
)

// fakeLookup is the in-test implementation of OperationLookup. It keeps
// the registry tests independent of the embedded OpenAPI spec — the
// spec-aware regression lives in TestDefaultRegistry_VerifiesAgainstSpec.
type fakeLookup struct{ ids map[string]struct{} }

func newFakeLookup(ids ...string) *fakeLookup {
	out := &fakeLookup{ids: make(map[string]struct{}, len(ids))}
	for _, id := range ids {
		out.ids[id] = struct{}{}
	}
	return out
}

func (f *fakeLookup) Has(id string) bool {
	_, ok := f.ids[id]
	return ok
}

func TestNewRegistry_Empty(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() empty: %v", err)
	}
	if r.Len() != 0 {
		t.Errorf("Len = %d, want 0", r.Len())
	}
	if got := r.Commands(); len(got) != 0 {
		t.Errorf("Commands = %v, want []", got)
	}
}

func TestNewRegistry_Sorts(t *testing.T) {
	a := validCommand()
	b := validCommand()
	b.Path = "yalla project list"
	b.Domain = DomainProject
	b.Verb = "list"
	b.OperationIDs = []string{"project-all"}
	b.HumanExample = "yalla project list"
	b.JSONExample = "yalla --json project list"

	r, err := NewRegistry(b, a)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	got := r.Commands()
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Path != "yalla app deploy" {
		t.Errorf("[0] = %q, want yalla app deploy", got[0].Path)
	}
	if got[1].Path != "yalla project list" {
		t.Errorf("[1] = %q, want yalla project list", got[1].Path)
	}
}

func TestNewRegistry_RejectsDuplicates(t *testing.T) {
	a := validCommand()
	b := validCommand()
	_, err := NewRegistry(a, b)
	if err == nil {
		t.Fatalf("expected duplicate path error")
	}
	if !strings.Contains(err.Error(), "duplicate command path") {
		t.Errorf("error %q does not mention duplication", err.Error())
	}
}

func TestNewRegistry_PropagatesValidateError(t *testing.T) {
	bad := validCommand()
	bad.Verb = "ls"
	bad.Path = "yalla app ls"
	_, err := NewRegistry(bad)
	if err == nil {
		t.Fatalf("expected validate error")
	}
	if !strings.Contains(err.Error(), "banned short alias") {
		t.Errorf("error %q missing banned alias hint", err.Error())
	}
}

func TestRegistry_Commands_DefensiveCopy(t *testing.T) {
	r, err := NewRegistry(validCommand())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	cmds := r.Commands()
	cmds[0].Path = "mutated"
	if r.Commands()[0].Path == "mutated" {
		t.Errorf("Commands() returned a non-defensive copy")
	}
}

func TestRegistry_ByDomain(t *testing.T) {
	a := validCommand()
	b := validCommand()
	b.Path = "yalla project list"
	b.Domain = DomainProject
	b.Verb = "list"
	b.OperationIDs = []string{"project-all"}
	b.HumanExample = "yalla project list"
	b.JSONExample = "yalla --json project list"

	r, err := NewRegistry(a, b)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	apps := r.ByDomain(DomainApp)
	if len(apps) != 1 || apps[0].Verb != "deploy" {
		t.Errorf("ByDomain(app) = %v", apps)
	}
	if got := r.ByDomain(DomainSettings); len(got) != 0 {
		t.Errorf("ByDomain(settings) = %v, want []", got)
	}
}

func TestRegistry_VerifyAgainstSpec_OK(t *testing.T) {
	r, err := NewRegistry(validCommand())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := r.VerifyAgainstSpec(newFakeLookup("application-deploy")); err != nil {
		t.Errorf("VerifyAgainstSpec: %v", err)
	}
}

func TestRegistry_VerifyAgainstSpec_FlagsUnknown(t *testing.T) {
	r, err := NewRegistry(validCommand())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	err = r.VerifyAgainstSpec(newFakeLookup())
	if err == nil {
		t.Fatalf("expected unknown operationId error")
	}
	if !strings.Contains(err.Error(), "application-deploy") {
		t.Errorf("error %q missing operation id", err.Error())
	}
}

func TestRegistry_VerifyAgainstSpec_NilLookup(t *testing.T) {
	r, err := NewRegistry(validCommand())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := r.VerifyAgainstSpec(nil); err == nil {
		t.Errorf("nil lookup must error")
	}
}

func TestRegistry_NilSafe(t *testing.T) {
	var r *Registry
	if r.Len() != 0 {
		t.Errorf("nil Registry Len = %d, want 0", r.Len())
	}
	if got := r.Commands(); got != nil {
		t.Errorf("nil Registry Commands = %v, want nil", got)
	}
	if got := r.ByDomain(DomainApp); got != nil {
		t.Errorf("nil Registry ByDomain = %v, want nil", got)
	}
	if err := r.VerifyAgainstSpec(newFakeLookup()); err != nil {
		t.Errorf("nil Registry VerifyAgainstSpec = %v, want nil", err)
	}
}

// apiLookup adapts *api.Registry to OperationLookup for the
// production-spec regression below.
type apiLookup struct{ r *api.Registry }

func (a apiLookup) Has(id string) bool {
	_, ok := a.r.Get(id)
	return ok
}

// TestDefaultRegistry_VerifiesAgainstSpec is the safety net that keeps
// the static curated registry in sync with the embedded OpenAPI spec.
// If a future curated entry references an operationId that the spec
// dropped or renamed, this test fails before the binary is built.
func TestDefaultRegistry_VerifiesAgainstSpec(t *testing.T) {
	if err := Default().VerifyAgainstSpec(apiLookup{r: api.Default()}); err != nil {
		t.Fatalf("default curated registry out of sync with embedded spec: %v", err)
	}
}

func TestDefaultRegistry_IncludesDatabaseCommands(t *testing.T) {
	cmds := Default().Commands()
	byPath := make(map[string]Command, len(cmds))
	for _, cmd := range cmds {
		byPath[cmd.Path] = cmd
	}
	for _, path := range []string{
		"yalla database backup create",
		"yalla database backup delete",
		"yalla database backup get",
		"yalla database backup list-files",
		"yalla database backup run",
		"yalla database backup update",
		"yalla database create",
		"yalla database deploy",
		"yalla database update",
	} {
		cmd, ok := byPath[path]
		if !ok {
			t.Fatalf("missing curated command %q", path)
		}
		if cmd.Domain != DomainDatabase {
			t.Errorf("%s domain = %q, want %q", path, cmd.Domain, DomainDatabase)
		}
		if len(cmd.OperationIDs) == 0 {
			t.Errorf("%s has no operation IDs", path)
		}
		if !strings.Contains(cmd.JSONExample, "--json") {
			t.Errorf("%s JSONExample must contain --json: %q", path, cmd.JSONExample)
		}
	}
	update := byPath["yalla database update"]
	for _, want := range []string{"postgres-one", "postgres-update", "redis-one", "redis-update"} {
		if !containsString(update.OperationIDs, want) {
			t.Errorf("database update operation IDs missing %q: %v", want, update.OperationIDs)
		}
	}
	backupRun := byPath["yalla database backup run"]
	for _, want := range []string{"backup-manualBackupPostgres", "backup-manualBackupMySql", "backup-manualBackupMariadb", "backup-manualBackupMongo"} {
		if !containsString(backupRun.OperationIDs, want) {
			t.Errorf("database backup run operation IDs missing %q: %v", want, backupRun.OperationIDs)
		}
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
