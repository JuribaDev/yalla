# Build types: per-type request bodies for `application-saveBuildType`

The `application-saveBuildType` schema is **flat** — one body covers every build type, and the `buildType` field selects the active one. Unused fields must still be present (set to `null`). The required-field list per the spec is:

```
applicationId  buildType  dockerfile  dockerContextPath  dockerBuildStage
herokuVersion  railpackVersion
```

Optional but useful: `publishDirectory`, `isStaticSpa`.

## Why every field shows up in every body

Dokploy's POST surface uses tRPC under the hood; absent required fields fail validation with `E_INVALID_INPUT`. The pattern is "always send everything, set the inactive parts to null." Each template below follows that pattern.

## Per-type templates

Treat these as starting points, not invariants. Adjust paths to match the project layout you detected.

### dockerfile

For projects with a `Dockerfile` at the repo root.

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "buildType": "dockerfile",
    "dockerfile": "./Dockerfile",
    "dockerContextPath": ".",
    "dockerBuildStage": null,
    "herokuVersion": null,
    "railpackVersion": null,
    "publishDirectory": null,
    "isStaticSpa": null
  }
}
```

- `dockerfile` is a path relative to the repo root.
- `dockerContextPath` is the build context, also relative. `.` is the default.
- `dockerBuildStage` targets a specific stage in a multi-stage build (`AS prod` → `"prod"`). Leave `null` for the last stage.
- For Dockerfile in a subdirectory: `dockerfile = "./apps/api/Dockerfile"`, `dockerContextPath = "./apps/api"` (or `.` if the build needs the whole repo).

### nixpacks

The most forgiving option. Nixpacks introspects the project and builds a buildpack-style image automatically. Use for any modern app without a Dockerfile.

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "buildType": "nixpacks",
    "dockerfile": null,
    "dockerContextPath": null,
    "dockerBuildStage": null,
    "herokuVersion": null,
    "railpackVersion": null,
    "publishDirectory": null,
    "isStaticSpa": null
  }
}
```

Languages it covers cleanly: Node/Bun (any framework), Python, Go, Rust, Ruby, PHP, Java, Deno, Elixir, Clojure, Crystal, Swift. If the user has a non-standard build (e.g. monorepo with custom workspace tooling), prefer `dockerfile` instead.

### railpack

Newer alternative to Nixpacks. Use when the project has a `railpack.json` or `railpack.toml`.

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "buildType": "railpack",
    "dockerfile": null,
    "dockerContextPath": null,
    "dockerBuildStage": null,
    "herokuVersion": null,
    "railpackVersion": "latest",
    "publishDirectory": null,
    "isStaticSpa": null
  }
}
```

`railpackVersion` accepts `"latest"` or a specific tag. Default to `"latest"` unless the user pins it.

### heroku_buildpacks

Heroku-style buildpacks. Use for projects that already work on Heroku — `Procfile` + standard language detection.

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "buildType": "heroku_buildpacks",
    "dockerfile": null,
    "dockerContextPath": null,
    "dockerBuildStage": null,
    "herokuVersion": "heroku-22",
    "railpackVersion": null,
    "publishDirectory": null,
    "isStaticSpa": null
  }
}
```

`herokuVersion` is the stack image. Common values: `"heroku-22"` (default, Ubuntu 22.04 base), `"heroku-24"` (Ubuntu 24.04). Pin if the project is sensitive to base-image changes.

### paketo_buildpacks

Cloud Native Buildpacks (CNCF). Generally only needed when the project ships a `project.toml` declaring CNB groups — that's the explicit signal. Otherwise prefer Nixpacks.

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "buildType": "paketo_buildpacks",
    "dockerfile": null,
    "dockerContextPath": null,
    "dockerBuildStage": null,
    "herokuVersion": null,
    "railpackVersion": null,
    "publishDirectory": null,
    "isStaticSpa": null
  }
}
```

### static

For pre-built static sites. Dokploy serves the contents of `publishDirectory` through Traefik; no language runtime is started.

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "buildType": "static",
    "dockerfile": null,
    "dockerContextPath": null,
    "dockerBuildStage": null,
    "herokuVersion": null,
    "railpackVersion": null,
    "publishDirectory": "./dist",
    "isStaticSpa": true
  }
}
```

- `publishDirectory` points at the directory containing `index.html` after build (`dist`, `build`, `public`, `out`, etc.).
- `isStaticSpa = true` makes Traefik route every unmatched path back to `index.html` — required for client-side routers (React Router, Vue Router, etc.). For non-SPA static sites (mkdocs, hugo, plain html) set `false`.

If the project ships a Dockerfile that ends with `nginx` or `caddy` serving the assets, use `dockerfile` instead — that's strictly equivalent and the user might be intentionally using that flow for SSL termination or custom rewrites.

## Decision flowchart

```
Has Dockerfile?
├── yes → buildType = "dockerfile"
└── no
    Has compose file?
    ├── yes → not a single app; use compose flow (see lifecycle.md)
    └── no
        Has railpack.json/toml?
        ├── yes → buildType = "railpack"
        └── no
            Has Procfile + language manifest?
            ├── yes → buildType = "heroku_buildpacks"
            └── no
                Has project.toml with CNB groups?
                ├── yes → buildType = "paketo_buildpacks"
                └── no
                    Has language manifest (package.json, requirements.txt, go.mod, etc.)?
                    ├── yes → buildType = "nixpacks"
                    └── no
                        Has only static assets (index.html, dist/, etc.)?
                        ├── yes → buildType = "static"
                        └── no  → ASK USER
```

## After saveBuildType

`application-saveBuildType` returns `{}` on success. The build type is stored on the app and used the next time `application-deploy` runs. To change the build type later, just call `application-saveBuildType` again with a different body — Dokploy overwrites.
