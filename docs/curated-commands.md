# Curated command policy

This document is the human-facing companion to the `internal/curated`
package. It defines how raw Dokploy OpenAPI operations turn into
stable, agent-friendly yalla commands without sacrificing full API
coverage.

The policy is locked in by [US-0012] and enforced by
`internal/curated/policy.go::Command.Validate`, the manifest payload
emitted by `yalla manifest --json`, and the registry test in
`internal/curated/registry_test.go::TestDefaultRegistry_VerifiesAgainstSpec`.

[US-0012]: ../ralph/prd.json

## Two surfaces, both first-class

yalla exposes the Dokploy API through two parallel surfaces:

1. **Raw API.** Every operation in the embedded OpenAPI document is
   reachable via `yalla api call <operationId>` and inspectable via
   `yalla schema get <operationId>`. The full operation list is
   discoverable through `yalla api operations` and through the
   `operations.ids` array in `yalla manifest --json`. Raw access is
   complete by construction; it never lags behind a Dokploy release.
2. **Curated commands.** A growing, opinionated set of named verbs
   under stable groups (`yalla app deploy`, `yalla project list`, …)
   that compose the most common workflows. Each curated command maps
   to one or more raw operationIds and is documented in the manifest
   payload's `curated_commands` array.

Curated commands never replace raw access. Both surfaces are first
class: raw is the safety net for new Dokploy features and uncommon
workflows; curated is the ergonomic path for the things most agents
and humans do every day.

## Domains

Curated commands live under one of seven closed domain groups. The
list is locked: adding a new domain is a public-API change that must
update `curated.Domains()`, the manifest test
`TestManifest_JSONListsCuratedDomains`, and this document together.

| Domain     | Scope                                                                |
|------------|----------------------------------------------------------------------|
| `project`  | Dokploy projects (the top-level grouping for apps/composes/databases) |
| `app`      | Single-image applications, deploys, lifecycle (`application-*` ops)  |
| `compose`  | Compose stacks (`compose-*` ops)                                     |
| `database` | Managed databases across postgres/mysql/mariadb/mongo/redis          |
| `server`   | Dokploy server / cluster management                                  |
| `settings` | Tenant-level configuration: certificates, notifications, prefs       |
| `provider` | External integrations: git providers, container registries, AI      |

A curated command path always takes the form:

```
yalla <domain> <verb> [more ...]
```

`<more>` is allowed for sub-grouped commands (e.g.
`yalla provider git list`) but must keep the `yalla <domain>` prefix
intact.

## Naming rules

The policy is intentionally narrow. The full list lives in
`internal/curated/policy.go`; the highlights:

- **Lowercase kebab-case for every segment.** Identifiers match
  `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`. No CamelCase, no snake_case.
- **No clever short aliases.** `BannedVerbAliases` rejects `ls`,
  `rm`, `del`, `new`, `show`, `info`, `edit`, `mod`, `push`, `up`,
  `down`, and `tail`. Each is mapped to the canonical replacement so
  the validator can hint the right verb.
- **Prefer full English verbs.** The recommended verb vocabulary is:
  `create`, `delete`, `deploy`, `get`, `list`, `logs`, `redeploy`,
  `register`, `rollback`, `set`, `start`, `stop`, `update`. A
  curated command MAY introduce a new verb if it is genuinely needed,
  but the change must update both `PreferredVerbs` and this
  document.
- **One Summary, one HumanExample, one JSONExample per command.**
  Validation requires every curated command to ship a Cobra
  `Short`-style summary and two example invocations: a human one
  (no `--json`) and an agent one (with `--json`). The same examples
  appear in `--help` output and in the manifest payload so
  discovery never depends on out-of-band documentation.
- **OperationIDs are mandatory.** A curated command must list at
  least one OpenAPI operationId, every entry must resolve in the
  embedded spec, and the same operationId may appear in more than
  one curated command (e.g. `app deploy` and `app redeploy` may both
  drive `application-deploy`).

## Recommended verb sets per domain

These tables record the verbs already approved for each domain. They
are not exhaustive; new verbs land alongside the curated-command
story that introduces them.

### project
`list`, `get`, `create`, `update`, `delete`

### app
`list`, `get`, `create`, `update`, `delete`, `deploy`, `redeploy`,
`rollback`, `start`, `stop`, `logs`

### compose
`list`, `get`, `create`, `update`, `delete`, `deploy`, `redeploy`,
`start`, `stop`, `logs`

### database
`list`, `list-files`, `get`, `create`, `update`, `delete`, `deploy`,
`run`, `start`, `stop`, `logs`

Initial friendly database commands:

```sh
yalla database create postgres --environment-id env_123 --name app-postgres --database-name app --database-user app --database-password "$DATABASE_PASSWORD"
yalla database create redis --environment-id env_123 --name app-redis --database-password "$REDIS_PASSWORD" --deploy
yalla database create mongo --environment-id env_123 --name app-mongo --database-user app --database-password "$MONGO_PASSWORD" --replica-sets
yalla database deploy postgres --id postgres_123
yalla database update postgres --id postgres_123 --memory-reservation 512M --memory-limit 1G --cpu-reservation 0.25 --cpu-limit 1 --replicas 1
yalla database backup create postgres --id postgres_123 --destination-id dst_123 --database app --prefix backups/app/ --schedule "0 2 * * *" --keep-latest 7
yalla database backup run postgres --backup-id backup_123
yalla database backup update postgres --backup-id backup_123 --schedule "0 4 * * *" --keep-latest 14
yalla database backup list-files --destination-id dst_123 --prefix backups/app/
yalla database backup delete --backup-id backup_123
```

Agent-mode examples use the same flags with `--json`, for example:

```sh
yalla --json database update postgres --id postgres_123 --memory-limit 1G --cpu-limit 1
yalla --json database backup create postgres --id postgres_123 --destination-id dst_123 --database app --prefix backups/app/ --schedule "0 2 * * *" --keep-latest 7
```

### server
`list`, `get`, `register`, `update`, `delete`

### settings
`get`, `update`

### provider
`list`, `get`, `register`, `update`, `delete`

## Manifest contract

`yalla manifest --json` emits the full curated catalogue under two
fields:

- `curated_domains` — the canonical domain list (`["app",
  "compose", "database", "project", "provider", "server",
  "settings"]`).
- `curated_commands` — an always-present array (possibly empty)
  whose elements have the shape:

```json
{
  "path": "yalla app deploy",
  "domain": "app",
  "verb": "deploy",
  "summary": "Deploy a Dokploy application",
  "operation_ids": ["application-deploy"],
  "human_example": "yalla app deploy --id app_123",
  "json_example":  "yalla --json app deploy --id app_123"
}
```

Agents can join `operation_ids` to the manifest's `operations.ids`
list to confirm raw API coverage, and to `curated_commands[].path`
to discover the named verbs that wrap a given operation.

## How to add a curated command

1. Append a `Command` literal to `defaultCommands` in
   `internal/curated/registry.go`. Keep entries grouped by `Domain`
   and alphabetised by `Path`.
2. Make sure `OperationIDs` is non-empty and every entry resolves in
   `api.Default()`. The manifest test
   `TestManifest_DefaultCuratedRegistryMatchesAPISpec` and the
   curated test `TestDefaultRegistry_VerifiesAgainstSpec` catch
   stale entries before the binary is built.
3. Provide both `HumanExample` and `JSONExample`. The Cobra command's
   `Example` text should mirror them so `--help`, the manifest, and
   the docs stay in sync.
4. Wire the actual Cobra command under `internal/cli/`. Curated
   command files SHOULD live next to the existing top-level command
   files (`<domain>_cmd.go`, `<domain>_<verb>_cmd.go`).
5. Update this document with any new verb conventions you introduce.
