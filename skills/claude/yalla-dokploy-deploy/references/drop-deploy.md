# Drop deploy: ship a pre-built artifact (zip)

`application-dropDeployment` is the "I already built it locally, just put it
on the server" path. Dokploy receives a zip, unpacks it inside the
application's working directory, and runs the container as-is — no clone,
no build, no Dockerfile. It is a `multipart/form-data` upload and yalla's
CLI handles the multipart envelope for you (`yalla api call
application-dropDeployment` now ships a real multipart body with the file
part on the wire; before this you would have seen a 400 from Dokploy).

## When to pick drop over git/image

Use drop when **any** of these is true and there is no separate ask for
ongoing CI-driven redeploys:

- The user has a build artifact in hand (a `dist/` folder, a `build/`
  folder, an exported SPA, a Lambda zip, a CI artifact) and does not want
  to (or cannot) commit it to git or push an image.
- The repo cannot reach a Dokploy-side build environment (private deps
  not on the build agent, secrets-baked artifacts, weird native toolchain).
- The user says "deploy this folder", "ship this zip", "upload my build",
  "drop it on", "I built it locally already".
- The artifact is the source of truth and the source code is not on this
  machine (handing over a zip from someone else's pipeline).

Pick git when the user wants Dokploy to redeploy on each push. Pick a
docker image when the artifact is a built container. Drop is for the
"manual handoff" case — concise, but the user owns the rebuild step.

## Pre-flight: drop targets an *existing* application

Drop does not create the application; it deploys onto one that exists.
The required upstream call order is:

1. `project-create` (or look up an existing project via `project-all`).
2. `environment-create` for any missing environment.
3. `application-create` under the chosen project + env. Capture
   `applicationId` from the returned envelope.
4. (Optional, recommended.) `application-saveEnvironment` to push the
   runtime env vars before the drop — the drop deploy will start the
   container with whatever env is currently saved.
5. `application-saveBuildType` with `buildType: "static"` or
   `"dockerfile"` depending on what is inside the zip. Drop respects
   the saved build type because the unpacked zip is what the build type
   reads from. If the zip is a static site, `static`. If the zip
   contains a `Dockerfile` at `dropBuildPath`, `dockerfile`.
6. `application-dropDeployment` — the upload itself. **This step is what
   the multipart fix unlocks.**

If the user wants drop redeploys driven by a webhook, that is a different
story — Dokploy has no "drop-on-push" trigger because drop is by
definition a client-side upload. Tell the user to keep running step 6
manually or to wire it into their CI as a curl-equivalent of step 6.

## The exact `--input` JSON shape

```json
{
  "body": {
    "applicationId": "<APP_ID>",
    "dropBuildPath": "build/output"
  },
  "files": {
    "zip": "/absolute/path/to/dist.zip"
  }
}
```

Field rules — these reflect the OpenAPI `multipart/form-data` schema and
the CLI's input contract:

- `body.applicationId` — required. The application the zip will land on.
  Recover it from `application-create` or `application-all`.
- `body.dropBuildPath` — optional. The subdirectory **inside the zip**
  that Dokploy should treat as the root. Omit or set to `""` to use the
  zip root. Use `"build"` / `"dist"` / `"build/output"` when the zip
  wraps an extra folder.
- `files.zip` — required. The local path to the zip. The CLI streams the
  bytes into a real `multipart/form-data` part on the wire.

The `files` value can be either of these shapes (the CLI accepts both
via the same `apiCallFile` decoder):

- Shorthand: `"zip": "/abs/path/to/dist.zip"` — filename defaults to the
  basename of the path and Content-Type defaults to
  `application/octet-stream`.
- Verbose: `"zip": {"path": "/abs/path/to/dist.zip", "filename":
  "release-v2.zip", "content_type": "application/zip"}` — use when you
  want the upstream to see a specific filename or media type.

Unknown keys under `files."<field>"` are rejected with `E_INVALID_INPUT`
to keep typos out of the wire.

## Producing the zip

If the user has not produced the zip yet, build then package — both
steps on the user's machine, not Dokploy's:

```sh
# Example: SPA produced into ./dist
npm ci
npm run build
( cd dist && zip -r ../release.zip . )

# Example: Python lambda
pip install -r requirements.txt -t ./build
( cd build && zip -r ../release.zip . )
```

Two reasons to `cd` into the build folder before zipping: it avoids a
leading `dist/` inside the zip (so you can leave `dropBuildPath` empty),
and it keeps the zip self-contained.

## The call itself (concrete)

```sh
# Stage the multipart input — files map keyed by the spec's "zip" field.
cat > /tmp/drop.json <<EOF
{
  "body":  {"applicationId": "${APP_ID}", "dropBuildPath": ""},
  "files": {"zip": "$(pwd)/release.zip"}
}
EOF

# Dry-run first — see the wire shape without uploading anything.
yalla --json api call application-dropDeployment --input /tmp/drop.json --dry-run

# Ship it.
yalla --json --no-input api call application-dropDeployment --input /tmp/drop.json
```

The dry-run output uses a deterministic boundary (`yalla-dryrun-boundary`)
and replaces the file bytes with `[REDACTED] file="..." size=<n>` so it
is safe to paste into a chat or log. Live invocations use a random
boundary the same way every other multipart client does.

After the drop returns 2xx, go through the standard verification step
(`references/verification.md`) — poll `application-one` until status is
`done` or `error`, then HTTP-probe the domain.

## Redeploy and rollback

- **Redeploy.** Run `application-dropDeployment` again with a fresh zip
  pointing at the same `applicationId`. The previous drop is replaced
  in-place; Dokploy does not keep an artifact archive. If the user wants
  to redeploy the *same* zip without rebuilding, just re-upload it.
- **Rollback.** Drop deploys have **no server-side rollback**. The only
  way back is to re-upload an older zip. Strongly suggest the user keep
  zips for releases they care about reverting to:
  ```sh
  mv release.zip release-v2-$(date +%Y%m%d-%H%M%S).zip
  ```
  When the user asks to "roll back the last drop", confirm they have the
  previous zip on disk before doing anything.

## Failure modes worth pre-checking

- **Zip is empty or not a zip.** Dokploy will accept the upload and then
  fail at unpack time, leaving the app in a half-deployed state. Before
  calling, verify with `unzip -t release.zip` and surface the result.
- **`dropBuildPath` does not exist inside the zip.** The container starts
  but cannot find the entrypoint. If unsure, omit `dropBuildPath` so the
  zip root is used.
- **App has no build type saved.** Dokploy treats the unpacked zip as a
  raw filesystem and the container will likely refuse to start. Always
  set `application-saveBuildType` before the first drop on a new app.
- **Missing file.** The CLI returns `E_INVALID_INPUT` with a hint
  pointing at the input file shape. This applies both to a missing path
  and to an empty `path` string under the verbose object form.
- **Wrong endpoint shape.** Passing a `files` map to a JSON-bodied
  operation (anything that is not `application-dropDeployment`) returns
  `E_INVALID_INPUT` immediately — the registry decides per spec.

## Quick check before you call

1. `applicationId` recovered and verified via `application-one`.
2. `application-saveBuildType` saved (matches what is inside the zip).
3. Zip exists and `unzip -t` is clean.
4. `dropBuildPath` either empty or matches a real directory inside the
   zip.
5. Domain configured if you want the verify probe to hit something
   meaningful.
