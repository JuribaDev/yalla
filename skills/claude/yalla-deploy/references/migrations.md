# Migrations

Detect migration requirements from framework files, deployment notes, and user
instructions. Examples include Prisma, Django, Alembic, Rails, and custom release
commands.

If no first-class Yalla command exists for this workflow in `yalla --json
manifest`, do not invent a private API operation. State the missing Yalla
command, stop before mutation, and ask the user whether they want a follow-up
implementation task.

When a public migration command exists, run it before traffic-changing deploys
unless the user explicitly asks for a post-deploy migration.
