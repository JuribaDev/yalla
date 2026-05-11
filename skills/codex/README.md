# skills/codex/

Slot for OpenAI Codex-flavored skills that pair with the yalla CLI.

This directory is intentionally empty in the `ralph/claude-yalla` branch
— the corresponding Codex playbook lives on the parallel Codex branch
(`ralph/yalla-cli`) and should be mirrored here when that branch is
ready to publish its skill alongside the Claude one.

The folder contract is identical to `skills/claude/<skill>/`:

```
skills/codex/<skill-name>/
├── SKILL.md            # Trigger metadata + operator playbook.
├── references/*.md     # Topic-scoped recipes.
├── scripts/            # Helpers the skill executes.
├── fixtures/           # Stable inputs the evals reference.
└── evals/evals.json    # Test set.
```

When you import a Codex skill into this tree, add a one-paragraph
"How this diverges from the Claude variant" note at the top of its
README so future contributors can tell at a glance which differences
are intentional (default tool budgets, output framing, fast-mode
behavior) and which are drift to reconcile.
