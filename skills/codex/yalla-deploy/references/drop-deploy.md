# Local artifact handoff

Use this when the user has a local build output, zip, or release artifact and no
repo or image source should be built by Yalla.

Current Yalla manifests may not expose a first-class artifact upload command. If
no upload command exists in `yalla --json manifest`, stop before mutation and
ask whether the user wants a follow-up implementation task for first-class local
artifact deploys.

## If a first-class artifact command exists

Use only the public command shown in the manifest. The plan still follows the
same resource order:

```sh
yalla project create --project-id proj_site --name site --json
yalla environment create --environment-id env_site_prod --project-id proj_site --name production --json
yalla service create --service-id svc_site_web --environment-id env_site_prod --name web --kind application --build-type static --json
yalla service build set --service-id svc_site_web --build-type static --output-dir dist --json
```

Then run the public artifact command and verify with wait-enabled Yalla commands
plus an HTTP probe.

## Rollback

Local artifact deploys need an explicit previous artifact path or image/tag
rollback path. Do not promise server-side rollback unless the manifest exposes a
public Yalla rollback command.
