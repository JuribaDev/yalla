# Scheduled jobs

Scheduled job requests must define command, schedule, timezone, environment, and
failure notification expectations.

If no first-class Yalla command exists for this workflow in `yalla --json
manifest`, do not invent a private API operation. State the missing Yalla
command, stop before mutation, and ask the user whether they want a follow-up
implementation task.

Do not model a scheduled job as a public web service unless the user explicitly
asks for a long-running service.
