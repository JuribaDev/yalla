# curated — agent notes

This package is the policy layer for yalla's curated commands. Read
`docs/curated-commands.md` for the human-facing version of the same
rules.

## What this package owns

- The closed list of curated [`Domain`s][doc-domain] (`project`,
  `app`, `compose`, `database`, `server`, `settings`, `provider`).
- The verb style guide (`PreferredVerbs`) and the deny-list of clever
  short aliases (`BannedVerbAliases`).
- The [`Command`][doc-command] descriptor that maps a curated
  invocation to one or more OpenAPI operationIds and to its required
  human + JSON help examples.
- The [`Registry`][doc-registry] that aggregates curated commands and
  validates them against a live OpenAPI registry.

[doc-domain]: ./policy.go
[doc-command]: ./policy.go
[doc-registry]: ./registry.go

## What this package does NOT do

- Register Cobra commands. Curated-command stories wire the actual
  command tree under `internal/cli/`. This package is the contract;
  `internal/cli/` is the implementation.
- Replace raw API coverage. `yalla api call <opId>` and
  `yalla schema get <opId>` remain available for every operation in
  the OpenAPI spec, even when a curated command exists. The two
  surfaces are independent by design.

## When you add a curated command

1. Append a `Command` literal to `defaultCommands` in `registry.go`,
   keeping the slice grouped by `Domain` and alphabetised by `Path`.
2. Make sure `OperationIDs` is non-empty and every entry resolves in
   `api.Default()`. The `TestDefaultRegistry_VerifiesAgainstSpec`
   regression catches stale entries.
3. Provide both `HumanExample` and `JSONExample`. The policy enforces
   that one starts with `yalla ` (no `--json`) and the other contains
   `--json`. The Cobra command's `Example` text should mirror them so
   the manifest, docs, and `--help` stay in sync.
4. Keep the verb out of `BannedVerbAliases`. If a new verb is
   genuinely needed, add it to `PreferredVerbs` and the docs in the
   same change.
5. Update `docs/curated-commands.md` with the new entry and any new
   verb conventions you introduce.

## Why the registry is empty today

US-0012 is the foundation story: it locks the policy shape, the
manifest payload, and the test contract before any curated commands
land. Each subsequent curated-command story adds one row to
`defaultCommands` and inherits the validation, manifest, and docs
plumbing for free.
