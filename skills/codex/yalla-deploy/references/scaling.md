# Scaling

Scaling requests can include replica count, CPU, memory, placement, health
checks, and concurrency expectations.

If no first-class Yalla command exists for this workflow in `yalla --json
manifest`, do not invent a private API operation. State the missing Yalla
command, stop before mutation, and ask the user whether they want a follow-up
implementation task.

If `yalla service update` exposes the needed flags in this CLI build, show the
exact command, ask for confirmation, then deploy or wait as required.
