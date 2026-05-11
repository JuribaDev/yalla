# skills/

Agent skills shipped alongside the yalla CLI. A skill is a self-contained
folder of operational guidance an AI agent loads when the user wants to
drive yalla through natural language — fresh deploys, drops, redeploys,
promotions, rollbacks, day-2 ops. The runtime is the agent (Claude Code,
Codex, etc.); the skill is the playbook the agent reads before it picks
which yalla calls to run.

## Layout

```
skills/
├── claude/                     # Skills authored for Claude (Anthropic).
│   └── yalla-dokploy-deploy/   # The flagship deploy-and-manage skill.
│       ├── SKILL.md            # Trigger metadata + the operator playbook.
│       ├── references/         # Topic-scoped recipes the agent reads lazily.
│       │   ├── drop-deploy.md  # …e.g. the multipart upload workflow.
│       │   ├── lifecycle.md
│       │   └── …
│       ├── scripts/            # Helpers the skill may execute (no network).
│       ├── fixtures/           # Stable inputs the evals reference (if any).
│       └── evals/evals.json    # The test set used to validate the skill.
└── codex/                      # Skills authored for OpenAI Codex.
    └── (slot, see codex/README.md)
```

The Claude and Codex variants exist side by side because the two agents
have different defaults (skill discovery, tool selection, output
shape). A shared SKILL.md often works, but keeping the trees separate
makes it cheap to diverge when one runtime needs to.

## Installing a skill locally

Skills are loaded by the agent runtime, not by yalla itself. For
Claude Code, copy or symlink the folder into your user-scoped skills
directory:

```sh
# Symlink — easiest if you want repo edits to apply instantly.
ln -snf "$(pwd)/skills/claude/yalla-dokploy-deploy" \
  ~/.claude/skills/yalla-dokploy-deploy

# Or copy if you prefer a snapshot:
cp -r skills/claude/yalla-dokploy-deploy ~/.claude/skills/
```

For Codex (or any other runtime), follow that runtime's skill-loading
convention. The folder contract — `SKILL.md` at the root, optional
`references/`, `scripts/`, `fixtures/`, `evals/` — is the same.

## Source of truth

The repo is the source of truth. Edit `skills/claude/<skill>/…` in this
tree, commit, and the installed copy in `~/.claude/skills/` either picks
up the change automatically (if symlinked) or after a re-copy. Editing
the installed copy in place is fine for fast iteration but please mirror
back into the repo before the change is forgotten.

## Adding a new skill variant

When a new agent runtime needs its own playbook, add a sibling directory
(`skills/<runtime>/<skill-name>/`) rather than fork the existing skill
in place. The README in each runtime folder calls out what diverges
from the canonical Claude version, so future contributors can decide
quickly whether to keep the variants in sync or let them drift.
