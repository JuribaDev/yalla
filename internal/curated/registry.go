package curated

import (
	"fmt"
	"sync"
)

// OperationLookup is the minimal shape [Registry.VerifyAgainstSpec]
// needs to confirm every curated mapping resolves to a real OpenAPI
// operation. The full *api.Registry satisfies it; tests can pass a
// hand-rolled fake without dragging the OpenAPI machinery in.
type OperationLookup interface {
	// Has reports whether the supplied operationId resolves in the
	// underlying OpenAPI spec.
	Has(operationID string) bool
}

// Registry aggregates curated [Command] descriptors. Construct one
// with [NewRegistry]; the package-level default is reachable via
// [Default]. The zero Registry is empty but usable.
type Registry struct {
	commands []Command
}

// NewRegistry builds a registry from the supplied commands. Each
// command is validated against the policy and the slice is checked
// for duplicate paths. Sorting is stable and by Path. Returning an
// error rather than panicking keeps the constructor usable from
// tests, but production callers (e.g. [Default]) treat any error as
// programmer-fatal.
func NewRegistry(cmds ...Command) (*Registry, error) {
	out := make([]Command, 0, len(cmds))
	seen := make(map[string]struct{}, len(cmds))
	for _, c := range cmds {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if _, dup := seen[c.Path]; dup {
			return nil, fmt.Errorf("curated: duplicate command path %q", c.Path)
		}
		seen[c.Path] = struct{}{}
		out = append(out, c)
	}
	SortCommands(out)
	return &Registry{commands: out}, nil
}

// Commands returns the curated commands in deterministic Path order.
// The returned slice is a defensive copy; mutations on the caller
// side do not bleed back into the registry.
func (r *Registry) Commands() []Command {
	if r == nil {
		return nil
	}
	out := make([]Command, len(r.commands))
	copy(out, r.commands)
	return out
}

// Len reports the number of curated commands in the registry. A nil
// receiver is treated as empty so callers can write
// `curated.Default().Len()` without a guard.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.commands)
}

// ByDomain returns all curated commands attached to the supplied
// domain in Path order. Unknown domains return an empty slice.
func (r *Registry) ByDomain(d Domain) []Command {
	if r == nil {
		return nil
	}
	out := make([]Command, 0)
	for _, c := range r.commands {
		if c.Domain == d {
			out = append(out, c)
		}
	}
	return out
}

// VerifyAgainstSpec walks every curated command and asserts every
// declared OperationID resolves in lookup. The first missing ID is
// returned with the curated command's Path so a stale registry fails
// loudly rather than at command-invocation time.
func (r *Registry) VerifyAgainstSpec(lookup OperationLookup) error {
	if r == nil {
		return nil
	}
	if lookup == nil {
		return fmt.Errorf("curated: VerifyAgainstSpec requires a non-nil OperationLookup")
	}
	for _, c := range r.commands {
		for _, id := range c.OperationIDs {
			if !lookup.Has(id) {
				return fmt.Errorf("curated: command %q references unknown operationId %q", c.Path, id)
			}
		}
	}
	return nil
}

var (
	defaultOnce sync.Once
	defaultReg  *Registry
)

// Default returns the package-level curated registry. The default is
// intentionally empty for the policy-foundation story (US-0012); each
// curated-command story (US-001x and onward) appends its descriptor
// to defaultCommands and the manifest picks it up automatically.
//
// Callers MUST treat the returned registry as read-only.
func Default() *Registry {
	defaultOnce.Do(func() {
		reg, err := NewRegistry(defaultCommands...)
		if err != nil {
			// A bad default is a programmer error caught by tests in
			// this package; surfacing it here keeps the cli/manifest
			// layer free of error handling for the static set.
			panic(fmt.Errorf("curated: default registry invalid: %w", err))
		}
		defaultReg = reg
	})
	return defaultReg
}

// defaultCommands is the package-private static list of curated
// commands wired into the binary. US-0012 establishes the registry
// shape; future curated-command stories append their descriptors
// here. Keep entries grouped by Domain and alphabetised by Path.
var defaultCommands = []Command{
	{
		Path:    "yalla compose deploy",
		Domain:  DomainCompose,
		Verb:    "deploy",
		Summary: "Deploy a Compose stack with project, environment, domains, and wait orchestration",
		OperationIDs: []string{
			"project-create", "environment-create", "compose-create", "compose-update", "domain-create", "compose-deploy", "compose-one",
		},
		HumanExample: "yalla deploy compose --project app --env staging --compose-file docker-compose.yml",
		JSONExample:  "yalla --json deploy compose --project app --env staging --compose-file docker-compose.yml",
	},
	{
		Path:    "yalla compose rescue",
		Domain:  DomainCompose,
		Verb:    "rescue",
		Summary: "Clean orphaned Docker resources for a Compose appName",
		OperationIDs: []string{
			"docker-compose-down", "docker-getContainersByAppNameMatch",
		},
		HumanExample: "yalla rescue orphans --app-name app",
		JSONExample:  "yalla --json rescue orphans --app-name app",
	},
	{
		Path:    "yalla compose wait",
		Domain:  DomainCompose,
		Verb:    "wait",
		Summary: "Wait for Compose status, URL status, or orphan counts",
		OperationIDs: []string{
			"compose-one", "docker-getContainersByAppNameMatch",
		},
		HumanExample: "yalla wait compose --id compose_123 --status done",
		JSONExample:  "yalla --json wait compose --id compose_123 --status done",
	},
	{
		Path:    "yalla database backup create",
		Domain:  DomainDatabase,
		Verb:    "create",
		Summary: "Create a scheduled database backup",
		OperationIDs: []string{
			"backup-create",
			"postgres-one",
			"mysql-one",
			"mariadb-one",
			"mongo-one",
			"user-getBackups",
		},
		HumanExample: "yalla database backup create postgres --id postgres_123 --destination-id dst_123 --database app --prefix backups/app/ --schedule \"0 2 * * *\" --keep-latest 7",
		JSONExample:  "yalla --json database backup create postgres --id postgres_123 --destination-id dst_123 --database app --prefix backups/app/ --schedule \"0 2 * * *\" --keep-latest 7",
	},
	{
		Path:    "yalla project delete",
		Domain:  DomainProject,
		Verb:    "delete",
		Summary: "Safely teardown a project and assert no orphan containers remain",
		OperationIDs: []string{
			"project-one", "project-all", "environment-byProjectId", "compose-search", "compose-stop", "compose-delete", "environment-remove", "project-remove", "docker-compose-down", "docker-getContainersByAppNameMatch",
		},
		HumanExample: "yalla teardown project --project app",
		JSONExample:  "yalla --json teardown project --project app",
	},
	{
		Path:    "yalla database backup delete",
		Domain:  DomainDatabase,
		Verb:    "delete",
		Summary: "Delete a database backup schedule",
		OperationIDs: []string{
			"backup-remove",
		},
		HumanExample: "yalla database backup delete --backup-id backup_123",
		JSONExample:  "yalla --json database backup delete --backup-id backup_123",
	},
	{
		Path:    "yalla database backup get",
		Domain:  DomainDatabase,
		Verb:    "get",
		Summary: "Get a database backup schedule",
		OperationIDs: []string{
			"backup-one",
		},
		HumanExample: "yalla database backup get --backup-id backup_123",
		JSONExample:  "yalla --json database backup get --backup-id backup_123",
	},
	{
		Path:    "yalla database backup list-files",
		Domain:  DomainDatabase,
		Verb:    "list-files",
		Summary: "List backup files for a destination and prefix",
		OperationIDs: []string{
			"backup-listBackupFiles",
		},
		HumanExample: "yalla database backup list-files --destination-id dst_123 --prefix backups/app/",
		JSONExample:  "yalla --json database backup list-files --destination-id dst_123 --prefix backups/app/",
	},
	{
		Path:    "yalla database backup run",
		Domain:  DomainDatabase,
		Verb:    "run",
		Summary: "Run a database backup now",
		OperationIDs: []string{
			"backup-manualBackupMariadb",
			"backup-manualBackupMongo",
			"backup-manualBackupMySql",
			"backup-manualBackupPostgres",
		},
		HumanExample: "yalla database backup run postgres --backup-id backup_123",
		JSONExample:  "yalla --json database backup run postgres --backup-id backup_123",
	},
	{
		Path:    "yalla database backup update",
		Domain:  DomainDatabase,
		Verb:    "update",
		Summary: "Update a scheduled database backup",
		OperationIDs: []string{
			"backup-one",
			"backup-update",
		},
		HumanExample: "yalla database backup update postgres --backup-id backup_123 --schedule \"0 4 * * *\" --keep-latest 14",
		JSONExample:  "yalla --json database backup update postgres --backup-id backup_123 --schedule \"0 4 * * *\" --keep-latest 14",
	},
	{
		Path:    "yalla database create",
		Domain:  DomainDatabase,
		Verb:    "create",
		Summary: "Create a Dokploy database",
		OperationIDs: []string{
			"mariadb-create", "mariadb-search",
			"mongo-create", "mongo-search",
			"mysql-create", "mysql-search",
			"postgres-create", "postgres-search",
			"redis-create", "redis-search",
		},
		HumanExample: "yalla database create postgres --environment-id env_123 --name app-postgres --database-name app --database-user app --database-password \"$DATABASE_PASSWORD\"",
		JSONExample:  "yalla --json database create postgres --environment-id env_123 --name app-postgres --database-name app --database-user app --database-password \"$DATABASE_PASSWORD\"",
	},
	{
		Path:    "yalla database deploy",
		Domain:  DomainDatabase,
		Verb:    "deploy",
		Summary: "Deploy a Dokploy database",
		OperationIDs: []string{
			"mariadb-deploy",
			"mongo-deploy",
			"mysql-deploy",
			"postgres-deploy",
			"redis-deploy",
		},
		HumanExample: "yalla database deploy postgres --id postgres_123",
		JSONExample:  "yalla --json database deploy postgres --id postgres_123",
	},
	{
		Path:    "yalla database update",
		Domain:  DomainDatabase,
		Verb:    "update",
		Summary: "Update and scale a Dokploy database",
		OperationIDs: []string{
			"mariadb-one", "mariadb-update",
			"mongo-one", "mongo-update",
			"mysql-one", "mysql-update",
			"postgres-one", "postgres-update",
			"redis-one", "redis-update",
		},
		HumanExample: "yalla database update postgres --id postgres_123 --memory-limit 1G --cpu-limit 1 --replicas 1",
		JSONExample:  "yalla --json database update postgres --id postgres_123 --memory-limit 1G --cpu-limit 1 --replicas 1",
	},
}
