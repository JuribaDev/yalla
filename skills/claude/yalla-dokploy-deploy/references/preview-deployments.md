# Preview deployments: per-PR ephemeral environments

Use this when the user wants every pull request to get its own deployed URL (e.g., `myapp-pr-42.preview.acme.com`) that lives only until the PR closes. The pattern is sometimes called "preview environments", "review apps", or "PR previews."

## Pre-conditions

Preview deployments require all of:

1. **A configured git-provider OAuth integration** in Dokploy — `application-saveGithubProvider` / `-saveGitlabProvider` / `-saveBitbucketProvider`. Generic `application-saveGitProvider` does **not** work — Dokploy needs webhook visibility into PR events, which only the provider-specific apps deliver.
2. **A working wildcard DNS** record pointing at the Dokploy host. For PR URLs of the form `<project>-pr-<num>.preview.acme.com`, you need a `*.preview.acme.com` wildcard A/AAAA record. Without it, Let's Encrypt cert issuance fails on every preview.
3. **An application** that's already created and has its source wired up — preview deployments inherit the source from the parent app.

If any prerequisite is missing, surface it and stop — there's no value in calling `application-savePreviewDeployment` against an app that can't receive PR events.

## Op family

| Op | Purpose |
|---|---|
| `application-savePreviewDeployment` | Toggle previews on/off for an application; configure wildcard, limit, cert type |
| `previewDeployment-create` | Manually create a preview deployment (usually Dokploy creates these automatically on `pull_request.opened`) |
| `previewDeployment-deploy` | Manually trigger a deploy on an existing preview |
| `previewDeployment-remove` | Manually tear down a preview |
| `previewDeployment-all` | List all preview deployments for an application |
| `previewDeployment-one` | Read a single preview deployment's state |

The skill's job is mostly to call `application-savePreviewDeployment` correctly — the per-PR `previewDeployment-*` calls fire automatically server-side once previews are enabled.

## `application-savePreviewDeployment` body

```json
{
  "body": {
    "applicationId": "<id>",
    "isPreviewDeploymentsActive": true,
    "previewLimit": 5,
    "previewHttps": true,
    "previewPath": "/",
    "previewBuildPath": "/",
    "previewWildcard": "${pr}.preview.acme.com",
    "previewPort": 3000,
    "previewCertificateType": "letsencrypt",
    "previewCustomCertResolver": null
  }
}
```

Field meanings:
- `isPreviewDeploymentsActive` — master switch. `false` disables PR previews entirely.
- `previewLimit` — maximum concurrent preview deployments. Older previews are auto-evicted when a new PR opens and the limit is reached. `5` is the Dokploy default; raise for high-velocity teams, lower for cost control.
- `previewHttps`, `previewCertificateType`, `previewCustomCertResolver` — TLS setup, mirrors the regular `domain-create` semantics. Use `letsencrypt` if `*.preview.acme.com` wildcard DNS is set, `custom` with a wildcard cert if you have one, or `none` for internal-only previews.
- `previewPath`, `previewBuildPath` — usually `/`. Override for monorepo subpath builds.
- `previewPort` — the container port the preview app exposes. Same logic as `domain-create.port` (read `EXPOSE` from Dockerfile, common defaults: 3000 for Node, 8000 for Python, 8080 for Go).
- `previewWildcard` — **the load-bearing token**. Dokploy substitutes per-PR tokens into this string when materialising each preview. Common substitutions: `${pr}` (the PR number), `${branch}` (the branch name, kebab-cased), `${project}` (the application's slug). The exact token set varies by Dokploy version — verify via `yalla --json schema get application-savePreviewDeployment` before guessing.

If the schema field documentation is sparse, default to `${pr}` and verify by opening a test PR after configuration.

## Order of operations

```
1. Confirm prerequisites (GitHub App installed, wildcard DNS live, app exists with provider-specific source).
2. application-savePreviewDeployment (toggle on, set wildcard).
3. Open a test PR against the configured branch (manually, or via gh CLI).
4. Wait ~30s; check previewDeployment-all for a new entry.
5. Probe the preview URL — should return the same content as the parent app's domain.
6. Close the test PR; verify previewDeployment-all shrinks back.
```

The skill should plan up to step 2 and leave 3-6 as **post-deploy validation** for the user. Don't open test PRs from the skill — that touches the user's GitHub.

## State file integration

```yaml
preview_deployments:
  enabled: true
  wildcard: "${pr}.preview.acme.com"
  limit: 5
  cert: letsencrypt
  port: 3000
```

Persist so future `application-update` calls don't accidentally toggle previews off.

## Triggering: how Dokploy gets the PR webhook

When `isPreviewDeploymentsActive` is true and the application uses a provider-specific source (`saveGithubProvider` etc.), Dokploy's webhook receiver listens for:

- `pull_request: opened` / `reopened` / `synchronize` → calls `previewDeployment-create` + `previewDeployment-deploy` server-side
- `pull_request: closed` → calls `previewDeployment-remove` server-side

The GitHub App's webhook secret + permissions are owned by Dokploy's UI configuration — not exposed via yalla. If previews don't trigger, the likely cause is misconfigured GitHub App, not a yalla issue. Direct the user to Dokploy → Settings → Git Providers to verify.

## Cost surfaces

Previews consume cluster resources — CPU, memory, disk, and (if Let's Encrypt) cert issuance rate limits. For active teams:
- `previewLimit: 10-20` is usually fine for small services.
- LE certificate rate limit is **50 certs/registered-domain/week**. A team with 20 PRs/week against `*.preview.acme.com` consumes 20 of those. Beyond ~30 PRs/week, switch `previewCertificateType: "custom"` with a wildcard cert.
- Each preview is a full deploy — buildArgs, env vars, mounts all inherit from the parent. If the parent provisions a database, **the preview does too** (separate `postgres-*` instances per preview). For DB-heavy apps, this multiplies storage costs. Consider a shared dev DB for previews — surface as a follow-up.

## Anti-patterns

- **Enabling previews on prod apps**: previews of `prod-api` would deploy against prod env vars and (worse) prod databases. Always enable previews on a **staging-shaped** application that points at safe data.
- **Long-lived previews**: once `previewLimit` is hit, the oldest auto-evicts. Lower the limit if old previews are accumulating because PRs never close.
- **Wildcard DNS via CNAME**: doesn't work for Let's Encrypt HTTP-01. Use A/AAAA records pointing directly at the Dokploy server's IPs.
