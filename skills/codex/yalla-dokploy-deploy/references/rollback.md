# Rollback: reverting a bad deploy

Use this when the **latest deploy is broken** and the previous one was healthy. The goal: get back to the known-good version with minimal blast radius and no destructive ops on the project/env/app shell.

There are two flavours:
1. **Image-tag rollback** (pre-built docker image source) — switch the `dockerImage` ref back to a previous tag, redeploy.
2. **Commit-rollback** (git source) — point the git source at a previous commit/tag, redeploy.

Both keep the project, environment, application, domains, env vars, and databases intact. Only the **source pointer** moves.

## Pre-conditions

Rollback only makes sense when:
- An application already exists (you're not creating fresh).
- You have a reference to the previous-good version. The state file should record this:

```yaml
# .dokploy.yaml (iteration-2)
last_deploy:
  env: production
  at: 2026-05-11T08:00:00Z
  build_type: dockerfile
  image: ghcr.io/acme/api:v2.4.1        # currently broken
  previous_image: ghcr.io/acme/api:v2.4.0  # known-good
  # OR
  commit: abc123def                    # currently broken
  previous_commit: 78fa901bc            # known-good
```

If the user invokes rollback without a recorded previous-good, ask them which version to roll back to. Inspecting `application-one` returns the current image/commit; their git log or container registry tag list gives them the previous.

## Image-tag rollback workflow

```
1. Read state file → confirm we have an applicationId + previous_image
2. Refetch the app via `application-one` to see the current state — sanity-check it's the broken version we think it is
3. Swap the source pointer:
   application-saveDockerProvider {
     applicationId, dockerImage: <previous_image>,
     username, password, registryUrl    (carry over from current config)
   }
4. Trigger redeploy:
   application-redeploy { applicationId }
5. Verify (two-phase per verification.md): status poll, then HTTP probe
6. If the probe is healthy, swap `image` ↔ `previous_image` in .dokploy.yaml so the NEXT rollback would revert to v2.4.1 (the broken one) — UNLESS the user has tagged a different known-good
7. Surface a clear "rollback complete" message with the rolled-back-to version
```

Yalla calls in order:

```sh
APP_ID="APP-ROLL-CCC"
ROLLBACK_TO="ghcr.io/acme/api:v2.4.0"

yalla --json --no-input api call application-saveDockerProvider --input <(echo "{\"body\":{\"applicationId\":\"$APP_ID\",\"dockerImage\":\"$ROLLBACK_TO\",\"username\":null,\"password\":null,\"registryUrl\":null}}")
yalla --json --no-input api call application-redeploy --input <(echo "{\"body\":{\"applicationId\":\"$APP_ID\"}}")
# verification: poll application-one until status=done, then curl the domain
```

## Commit-rollback workflow

For git sources, swap the branch / build path / commit pin via `application-saveGitProvider` (or the matching provider-specific op):

```sh
APP_ID="APP-…"
GIT_URL="https://github.com/acme/api.git"
ROLLBACK_BRANCH="v2.4.0"   # or a specific commit-ish tag

yalla --json --no-input api call application-saveGitProvider --input <(echo "{\"body\":{\"applicationId\":\"$APP_ID\",\"customGitUrl\":\"$GIT_URL\",\"customGitBranch\":\"$ROLLBACK_BRANCH\",\"customGitBuildPath\":\"/\",\"watchPaths\":[],\"customGitSSHKeyId\":null,\"enableSubmodules\":false}}")
yalla --json --no-input api call application-redeploy --input <(echo "{\"body\":{\"applicationId\":\"$APP_ID\"}}")
```

Caveats for git rollback:
- Dokploy must rebuild the image from the rolled-back source. Slower than image-tag rollback (which is just a `docker pull`).
- If you've rolled back the branch pointer at the git remote (e.g., `git revert HEAD && git push`), the next `application-redeploy` against the same branch picks up the revert automatically — no `application-saveGitProvider` needed.
- Schema migrations and rollback DON'T compose cleanly: if the broken version ran an irreversible migration, rolling back the code without rolling back the DB will fail at startup. See `migrations.md` § Anti-patterns.

## After rollback

Update `.dokploy.yaml`:

```yaml
last_deploy:
  env: production
  at: 2026-05-11T09:15:00Z
  rollback: true                         # mark this as a rollback, not a regular deploy
  image: ghcr.io/acme/api:v2.4.0         # what's now live
  previous_image: ghcr.io/acme/api:v2.4.1 # what was live before (the broken release)
  status: done
```

This way the **next** rollback knows to revert from v2.4.0 → v2.4.1 (the most recent prior), avoiding an undo loop where users accidentally re-roll-back to the broken version they just escaped from.

## When NOT to use rollback

- **Migration is at fault**: rolling back the code without rolling back the migration leaves a forward-incompatible schema. Either:
  - The migration is backward-compatible → safe to roll back code, leave the migration in place.
  - The migration is not backward-compatible → don't roll back code; fix forward with a new commit that handles the new schema.
- **Database state has diverged**: writes happened against the broken version. Rolling back code preserves those writes; whether they're valid depends on the bug.
- **You only need to stop traffic**: use `application-stop` (see `operations.md`), don't roll back. Rollback is for "the new version is broken AND the old version still works" — if the old version also can't run (DB schema changed), you don't have a rollback option.

## Common confusion

| User says | They actually mean |
|---|---|
| "Roll back the deployment" | Usually image/commit rollback — the recent code is broken |
| "Stop the deployment" | `application-stop` — pause traffic without changing version |
| "Tear down" / "remove" | `project-remove` — destroy everything |
| "Redeploy" | `application-redeploy` of the same code (no version change) — usually for transient build/runtime issues |
| "Revert" | Could mean rollback OR a git revert that the next deploy picks up — disambiguate |

When the user is ambiguous, the safest read is rollback if `.dokploy.yaml.last_deploy.status` is `error` or they mention "broken / bad / hotfix / revert"; otherwise ask.
