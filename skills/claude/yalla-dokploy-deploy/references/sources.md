# Sources: configuring where the code comes from

Dokploy applications need exactly one source. The skill always picks one of:

| Source | yalla operation | When to use |
|---|---|---|
| Pre-built docker image | `application-saveDockerProvider` | The user has an image already published (Docker Hub, GHCR, registry). No build happens on Dokploy. |
| Generic git URL | `application-saveGitProvider` | The repo has a reachable origin URL (https or ssh). Works without any provider OAuth — Dokploy clones the URL directly. |
| GitHub provider | `application-saveGithubProvider` | Push-triggered redeploys via the Dokploy ↔ GitHub App. Requires the install knows the `githubId`. |
| GitLab / Bitbucket / Gitea | `application-saveGitlab/Bitbucket/GiteaProvider` | Same idea, different forge. Requires the matching `*Id`. |
| Pre-built local artifact (zip) | `application-dropDeployment` (multipart upload) | The user already has a build on disk (`dist/`, `build/`, an exported SPA, a Lambda zip). No clone, no build on Dokploy. **Full recipe in `references/drop-deploy.md` — read that file before driving the upload, the wire shape is `multipart/form-data` and the input JSON has its own `files` map.** |

For a fresh skill run with no Dokploy-side OAuth setup, **default to generic git** for repos, **docker image** for image-only flows, and **drop** when the user hands you a zip / a pre-built folder and doesn't want Dokploy to build from source. The skill can switch up to a provider-specific operation later if the user confirms the OAuth is wired.

Drop is *not* mutually exclusive with the other sources at the app level — Dokploy stores the most recent source-provider config, but a drop overwrites the running filesystem in place. If the user wants to switch from drop back to git, save a git provider on the same app and run `application-deploy`; the next push wins.

## Body templates

### `application-saveDockerProvider`

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "dockerImage": "ghcr.io/owner/repo:v1.2.3",
    "username": null,
    "password": null,
    "registryUrl": null
  }
}
```

For private registries, fill `username`, `password`, `registryUrl` (e.g., `https://ghcr.io`). Keep credentials out of the chat — accept them via env vars or have the user paste them inside the user's own terminal, never in a transcript.

`dockerImage` accepts:
- `image` (Docker Hub, latest tag): `nginx`
- `image:tag`: `nginx:alpine`
- `registry/owner/image:tag`: `ghcr.io/JuribaDev/yalla:v1.0`
- `registry/owner/image@sha256:...`: pinned by digest (best for reproducibility)

### `application-saveGitProvider` (the universal git path)

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "customGitUrl": "https://github.com/owner/repo.git",
    "customGitBranch": "main",
    "customGitBuildPath": "/",
    "watchPaths": [],
    "customGitSSHKeyId": null,
    "enableSubmodules": false
  }
}
```

- `customGitUrl` accepts https or ssh. Use https for public repos, ssh + an SSH key registered on Dokploy for private.
- `customGitBranch` is the branch Dokploy will check out and redeploy from.
- `customGitBuildPath` is the **subdirectory inside the repo** that contains the project. `/` for repos that are the project. `/apps/web` for monorepos.
- `watchPaths` is a list of path globs that trigger a redeploy when a webhook fires. Empty array = redeploy on every push to the configured branch.
- `customGitSSHKeyId` is the ID of an SSH key the user registered in Dokploy → SSH Keys. Required for ssh URLs against private repos. Skip for https/public.
- `enableSubmodules` if the repo uses git submodules.

### `application-saveGithubProvider`

Only use when the user confirms a GitHub App is installed in Dokploy (Settings → Git Providers → GitHub).

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "githubId": "<GH_PROVIDER_ID>",
    "owner": "JuribaDev",
    "repository": "yalla",
    "branch": "main",
    "buildPath": "/",
    "triggerType": "push",
    "enableSubmodules": false,
    "watchPaths": []
  }
}
```

The `githubId` is the Dokploy-side identifier for the configured App, NOT the GitHub repo ID. The skill currently has no operation to list providers; if the user wants this path, they need to fetch the ID from the Dokploy UI and paste it.

`triggerType`: `"push"` (any push to branch redeploys) or `"tag"` (only tag pushes redeploy).

### `application-saveGitlabProvider`

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "gitlabId": "<GL_PROVIDER_ID>",
    "gitlabOwner": "owner",
    "gitlabRepository": "repo",
    "gitlabBranch": "main",
    "gitlabBuildPath": "/",
    "gitlabProjectId": 12345,
    "gitlabPathNamespace": "group/subgroup",
    "enableSubmodules": false,
    "watchPaths": []
  }
}
```

`gitlabProjectId` is GitLab's numeric project ID. `gitlabPathNamespace` is the URL-style path with all groups (e.g., `mygroup/myteam`).

### `application-saveBitbucketProvider`

Mirrors the GitHub shape with `bitbucketId`, `bitbucketOwner`, `bitbucketRepository`, `bitbucketBranch`, `bitbucketBuildPath`. Same caveat about needing the provider ID from Dokploy.

## Env vars: composing the `application-saveEnvironment` body

The `env`, `buildArgs`, and `buildSecrets` fields are **multi-line strings**, not key-value maps:

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "env": "PORT=8080\nNODE_ENV=production\nDATABASE_URL=postgres://...\n",
    "buildArgs": "NEXT_PUBLIC_API_URL=https://api.example.com\n",
    "buildSecrets": "STRIPE_SECRET_KEY=sk_live_...\n",
    "createEnvFile": true
  }
}
```

Rules:
- One `KEY=value` per line, terminated with `\n` (literal newline in the JSON string).
- No quotes around values unless the value itself needs them (e.g., `MULTI_WORD_VALUE="hello world"`).
- `createEnvFile: true` makes Dokploy write the parsed `env` into a `.env` file inside the container at runtime, so apps using `dotenv`-style libraries see them. Default to `true`.
- `buildArgs` are passed as `--build-arg` to the Docker build (visible at build time only). Only meaningful when buildType is `dockerfile` — Nixpacks/Railpack/etc handle their own build envs.
- `buildSecrets` are mounted as files at `/run/secrets/<KEY>` during build. They never end up baked into the image. Use for build-time secrets that shouldn't leak (registry tokens, npm tokens for private packages).
- Runtime `env` is what the running container sees. Most things go here.

## Updating env later

`application-saveEnvironment` is a *replace* operation, not a *merge*. To add one variable, the body must contain every existing variable too — otherwise they get dropped.

Pattern:
1. Capture current state from `application-one`.
2. Parse `application.env` (the multi-line string).
3. Splice in the new line.
4. Send the full new string back.

Same applies to `buildArgs` and `buildSecrets`.

## Source switching

Switching sources later (e.g., docker image → git) is done by calling the new `application-save*Provider` op. The previous source is replaced — only the latest call's source is active at deploy time. The build type is independent and persists across source switches.
