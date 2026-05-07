# Ralph Agent Instructions

You are an autonomous coding agent working on a Go CLI project (Yalla - a production-grade, AI-agent-first CLI for Dokploy).

## Project Context

- **Product**: `yalla`, a native cross-platform CLI for controlling Dokploy through its public API surface.
- **Language**: Go. Users must not need Go installed; releases ship compiled binaries.
- **CLI framework**: Cobra + pflag. Use `github.com/spf13/cobra` for the command tree.
- **Architecture**: Keep commands thin. Put logic in `internal/` packages: `cli/`, `api/`, `config/`, `output/`, `errors/`, `version/`, and `testutil/`.
- **API coverage**: Every Dokploy OpenAPI operation in `ralph/prd.json` must be covered. Raw API coverage is required even when curated commands exist.
- **Agent contract**: `--json`, `--schema`, `--no-input`, stable exit codes, machine-readable errors, deterministic stdout/stderr behavior.
- **Output rule**: Data goes to stdout. Logs, warnings, prompts, progress, and errors go to stderr.
- **Networking**: Use `net/http` with typed wrappers, explicit timeouts, `context.Context`, cancellation support, and secret redaction.
- **Config precedence**: CLI flags > environment variables > config file > defaults.
- **Distribution**: GoReleaser, GitHub Releases, Homebrew, npm/npx wrapper, Scoop, WinGet, install script, and `go install` as contributor fallback only.
- **Versioning**: Use SemVer from git tags. Treat command names, flags, JSON schemas, error codes, exit codes, and config shape as public API.

Read `prompt.md`, `ralph/prd.json`, and `ralph/progress.txt` before working. If an `AGENTS.md` exists in the repo or edited directories, follow it too.

## Your Task

1. Read the PRD at `ralph/prd.json` (in the same directory as this file).
2. Read the progress log at `ralph/progress.txt` (check Codebase Patterns section first).
3. Check for relevant `AGENTS.md` files in the repo and edited directories.
4. Check you're on the correct branch from PRD `branchName`. If not, check it out or create from main.
5. Pick the **highest priority** user story where `passes: false`.
6. Implement that single user story.
7. Run quality checks (see below).
8. If checks pass, update the PRD to set `passes: true` for the completed story.
9. Append your progress to `ralph/progress.txt`.
10. Commit ALL relevant changes with message: `feat(<scope>): [Story ID] - [Story Title]`.

## Quality Checks (Required Before Every Commit)

Run these from the repository root:

```bash
# 1. Formatting
gofmt -w .

# 2. Imports, if goimports is installed
goimports -w .

# 3. Module cleanup
go mod tidy

# 4. Unit and integration tests
go test ./...

# 5. Race detector
go test -race ./...

# 6. Static checks
go vet ./...
```

If configured or installed, also run:

```bash
# Linting
golangci-lint run ./...

# Additional static analysis
staticcheck ./...

# Vulnerability scan
govulncheck ./...

# Release configuration
goreleaser check

# Release dry run
goreleaser release --snapshot --clean
```

- ALL commits must pass formatting, `go test ./...`, `go test -race ./...`, and `go vet ./...`.
- Do NOT commit broken code.
- Keep changes focused on one story.
- Follow existing code patterns in the codebase.
- If a tool is not installed, document that clearly in `ralph/progress.txt`.
- Never skip verification silently.

## Agent & CLI UX

When implementing any command, make it first-class for AI agents and still usable by humans.

Required behavior:

1. Support `--json` for deterministic machine-readable output.
2. Support `--no-input` so agents never hang on prompts.
3. Keep stdout data-only and stderr diagnostics-only.
4. Return stable exit codes.
5. Return stable error codes in JSON errors.
6. Redact tokens, cookies, API keys, and secrets from all output.
7. Provide useful `Short`, `Long`, and `Example` text for Cobra commands.
8. Add schema or manifest metadata when the command changes the public command surface.

Do not build a TUI as the primary interface. Interactive UI can be optional later, but the core CLI must stay scriptable.

## Feature Implementation Checklist

When implementing a new feature, command, or API operation:

1. **Contract first**: identify the PRD story, expected command shape, JSON output, error codes, and exit codes.
2. **Command layer**: add or update Cobra commands under `internal/cli/`. Keep command files thin.
3. **Config layer**: load config once and pass typed config down. Respect CLI > env > config file > defaults.
4. **API layer**: add typed request/response handling in `internal/api/` using `net/http`, context, timeouts, and redaction.
5. **Output layer**: render all `--json` output through `internal/output/`. Do not hand-roll JSON in commands.
6. **Error layer**: return typed errors from `internal/errors/` so exit codes and JSON errors stay stable.
7. **Schemas/manifest**: update schema and manifest support for new commands or API operations.
8. **Tests**: add unit tests, command tests with in-memory stdout/stderr, JSON golden tests where useful, and `httptest.Server` contract tests.
9. **Docs/completions**: update generated command docs or completion support if the command surface changes.
10. **Verification**: run the full quality checks before marking the story as passing.

## API Coverage Rules

Yalla must cover every Dokploy OpenAPI operation listed in `ralph/prd.json`.

Required raw API interface:

```bash
yalla api operations --json
yalla api call <operationId> --input request.json --json
yalla schema list --json
yalla schema get <operationId> --json
yalla manifest --json
```

For each API operation story:

1. Add or verify the operation registry entry.
2. Ensure `yalla api call <operationId> --input request.json --json` works.
3. Ensure `yalla schema get <operationId> --json` works.
4. Add tests for success and at least one representative failure.
5. Verify the operation appears in `yalla manifest --json`.

Curated commands are encouraged for common workflows, but they must not replace raw API coverage.

## Commit Convention

Use conventional commits scoped to the affected module:

```text
feat(cli): [US-0001] - Bootstrap Cobra root command
feat(api): [API-0016] - Cover application-deploy
fix(output): [US-0002] - Redact tokens in JSON errors
test(api): [API-0040] - Add backup-create contract tests
```

## Progress Report Format

APPEND to `ralph/progress.txt` (never replace, always append):

```text
## [Date/Time] - [Story ID]
- What was implemented
- Files changed
- Verification run
- Results
- Remaining risks or follow-ups
- **Learnings for future iterations:**
  - Patterns discovered
  - Gotchas encountered
  - Useful context
---
```

Include enough context so future iterations can understand what was done. Memory persists via git history and `ralph/progress.txt`.

The learnings section is critical. It helps future iterations avoid repeating mistakes and understand the codebase better.

## Consolidate Patterns

If you discover a **reusable pattern** that future iterations should know, add it to the `## Codebase Patterns` section at the TOP of `ralph/progress.txt` (create it if it doesn't exist). This section should consolidate the most important learnings:

```text
## Codebase Patterns
- Cobra commands use `RunE` and return typed Yalla errors.
- `--json` output is rendered only through `internal/output`.
- Command tests construct root commands with in-memory stdin, stdout, and stderr.
- API tests use `httptest.Server` fixtures and never require a live Dokploy server.
- Config precedence is CLI flags > environment variables > config file > defaults.
- Raw API operation coverage must stay in sync with `ralph/prd.json`.
```

Only add patterns that are **general and reusable**, not story-specific details.

## Update AGENTS.md Files

Before committing, check if any edited files have learnings worth preserving in nearby `AGENTS.md` files:

1. **Identify directories with edited files** - Look at which directories you modified.
2. **Check for existing AGENTS.md** - Look for `AGENTS.md` in those directories or parent directories.
3. **Add valuable learnings** - If you discovered something future developers/agents should know:
    - CLI command patterns or conventions specific to that module
    - API client patterns or request/response mapping rules
    - Gotchas or non-obvious requirements
    - Dependencies between files, schemas, manifests, and tests
    - Testing approaches for that area

**Examples of good AGENTS.md additions:**
- "When adding a command, also update manifest metadata and command tests."
- "All JSON envelopes must go through internal/output."
- "API operation tests should use httptest fixtures, not live Dokploy calls."
- "The npm wrapper must preserve args, stdout, stderr, and exit code exactly."

**Do NOT add:**
- Story-specific implementation details
- Temporary debugging notes
- Information already in `ralph/progress.txt`

Only update `AGENTS.md` if you have **genuinely reusable knowledge** that would help future work in that directory.

## Stop Condition

After completing a user story, check if ALL stories have `passes: true`.

If ALL stories are complete and passing, reply with:
<promise>COMPLETE</promise>

If there are still stories with `passes: false`, end your response normally (another iteration will pick up the next story).


## Important

- Work on ONE story per iteration.
- Commit frequently.
- Keep CI green: `gofmt`, `go test ./...`, `go test -race ./...`, and `go vet ./...` must pass.
- Read the Codebase Patterns section in `ralph/progress.txt` before starting.
- Every Dokploy API operation in the PRD must remain covered.
- Do not make MVP shortcuts. Build production-grade code.
- Do not print secrets in logs, errors, dry-run output, test output, or JSON.
- Never put progress text in stdout when `--json` is used.
- Never let `--no-input` hang on a prompt.
- Do not edit generated release artifacts unless the repo explicitly tracks them.
- Prefer simple, testable Go code over clever abstractions.
- Use native Go binaries for distribution; users should not need Go installed.
