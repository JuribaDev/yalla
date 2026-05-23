# Detect

Detect enough to produce a reviewable plan; do not mutate during detection.

## Inputs to inspect

- Git remote and current branch.
- Dockerfile, compose files, static build output, package manifests, and README.
- `.env.example`, `.env.sample`, deployment notes, and user-specified secrets.
- `.yalla.yaml` for stable project, environment, service, and backup IDs.
- `.yalla.yaml.local` for untracked local notes if present.

## Build type priority

1. User-specified build type.
2. Compose file for stack deploys.
3. Dockerfile for container builds.
4. Static build when the output directory is already known or the project has a
   clear static build command.
5. Image when the user provides a container image reference.

When multiple options are present, choose the safest explicit option and say why.
For example, if a Dockerfile and static build output both exist, prefer the
Dockerfile unless the user asked for a static service.

## Plan fields

```text
project_id
project_name
environment_id
environment_name
service_id
service_name
kind
build_type
source
build_config
env_vars
database_needs
domain
verification
```

Use deterministic IDs when the user has not supplied them, then surface those IDs
in the plan before creating resources.
