# Preview deployments

Preview deployment requests must define source branch or change identifier,
environment naming, service naming, TTL, and cleanup expectations.

If no first-class Yalla command exists for this workflow in `yalla --json
manifest`, do not invent a private API operation. State the missing Yalla
command, stop before mutation, and ask the user whether they want a follow-up
implementation task.

When public commands exist, create preview environments and services with
deterministic IDs and store them under `.yalla.yaml`.
