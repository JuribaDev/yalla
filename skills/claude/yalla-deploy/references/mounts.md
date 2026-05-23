# Persistent storage

Capture storage requirements in the plan: mount path, size, service ID, backup
expectation, and whether data must survive redeploys.

If no first-class Yalla command exists for this workflow in `yalla --json
manifest`, do not invent a private API operation. State the missing Yalla
command, stop before mutation, and ask the user whether they want a follow-up
implementation task.

Never fake persistence with an environment variable or a local repo file.
