# Curated command policy

This document is the human-facing companion to the `internal/curated`
package. In backend-only CLI mode, curated commands must describe Yalla
backend product routes only. The previous Dokploy-operation catalogue is
not published by `yalla manifest`.

The policy is locked in by [US-0012] and enforced by
`internal/curated/policy.go::Command.Validate`, the manifest payload
emitted by `yalla manifest --json`, and the registry test in
`internal/curated/registry_test.go::TestDefaultRegistry_VerifiesAgainstSpec`.

[US-0012]: ../ralph/prd.json

## Discovery Surfaces

yalla exposes the Yalla backend API through two discovery surfaces:

1. **Backend OpenAPI discovery.** The backend serves `/openapi.json`.
   `yalla api operations` lists operationIds and `yalla schema get
   <operationId>` inspects request/response schemas. `yalla api call
   <operationId>` is unsupported for normal users; mutations use product
   commands instead.
2. **Curated commands.** A future set of opinionated named verbs under
   stable groups. Each curated command must map to one or more Yalla
   backend operationIds and must never bypass the backend.

The current backend-only release intentionally ships an empty default
curated catalogue until backend-native curated entries are added.

## Domains

Curated commands live under one of seven closed domain groups. The list
is locked: adding a new domain is a public-API change that must update
`curated.Domains()`, the manifest test `TestManifest_JSONListsCuratedDomains`,
and this document together.

| Domain | Scope |
| --- | --- |
| `project` | Yalla projects |
| `app` | Application services, deploys, lifecycle |
| `compose` | Compose-backed services |
| `database` | Managed databases across supported engines |
| `server` | Server / cluster management |
| `settings` | Tenant-level configuration |
| `provider` | External integrations |

A curated command path always takes the form:

```sh
yalla <domain> <verb> [more ...]
```

## Naming Rules

- **Lowercase kebab-case for every segment.** Identifiers match
  `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`.
- **No clever short aliases.** `BannedVerbAliases` rejects `ls`, `rm`,
  `del`, `new`, `show`, `info`, `edit`, `mod`, `push`, `up`, `down`,
  and `tail`.
- **Prefer full English verbs.** The recommended verb vocabulary is
  documented in `internal/curated/policy.go`.
- **One Summary, one HumanExample, one JSONExample per command.**
  Validation requires both human and JSON examples.
- **OperationIDs are mandatory.** A curated command must list at least
  one Yalla backend OpenAPI operationId.

## Current Backend-Only Commands

The active Cobra commands are documented by `yalla --json manifest`.
Representative backend-mediated workflows:

```sh
yalla deploy compose --service-id svc_123 --source manual
yalla wait deployment --deployment-id dep_123 --status succeeded
yalla wait job --job-id job_123 --status succeeded
yalla teardown project --project-id proj_123
yalla database create --environment-id env_123 --service-id svc_db --name app-postgres --engine postgres
yalla database deploy --service-id svc_db
yalla database backup create --service-id svc_db --backup-id sbkp_123 --schedule "0 2 * * *" --retention-count 7
yalla database backup run --service-id svc_db --backup-id sbkp_123
yalla database backup restore --service-id svc_db --backup-id sbkp_123
yalla database backup delete --service-id svc_db --backup-id sbkp_123
```

Rescue diagnostics remain disabled until backend admin routes exist.

## Manifest Contract

`yalla manifest --json` emits:

- `curated_domains` — the canonical domain list.
- `curated_commands` — an always-present array. In the current
  backend-only release this array is empty by default.

Future entries must use backend operationIds, for example:

```json
{
  "path": "yalla app deploy",
  "domain": "app",
  "verb": "deploy",
  "summary": "Deploy an application service",
  "operation_ids": ["createServiceDeployment"],
  "human_example": "yalla app deploy --service-id svc_123",
  "json_example": "yalla --json app deploy --service-id svc_123"
}
```

## How To Add A Curated Command

1. Append a `Command` literal to `defaultCommands` in
   `internal/curated/registry.go`.
2. Make sure `OperationIDs` is non-empty and every entry resolves in the
   Yalla backend OpenAPI contract used by that command.
3. Provide both `HumanExample` and `JSONExample`.
4. Wire the actual Cobra command under `internal/cli/`.
5. Update this document and the matching tests.
