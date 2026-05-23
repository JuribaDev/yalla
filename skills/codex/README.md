# skills/codex/

OpenAI Codex-flavored skills that pair with the yalla CLI.

This tree currently ships the Codex variant of `yalla-deploy`. It mirrors the
Claude skill's deploy references, but includes Codex-facing metadata and notes
for how Codex loads and presents skills.

The folder contract is identical to `skills/claude/<skill>/`:

```
skills/codex/<skill-name>/
├── SKILL.md            # Trigger metadata + operator playbook.
├── agents/openai.yaml  # Codex UI metadata.
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
