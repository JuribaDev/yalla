# Persistent storage: volumes, bind mounts, file mounts

Use this when the app needs state that survives redeploy — database data, uploaded files, cache, certificates fetched from disk, anything written by the container that can't be rebuilt from the source.

## The real op is `mounts-create` (plural)

The Dokploy spec uses the plural `mounts` namespace, not `mount`. The op family:

| Op | Purpose |
|---|---|
| `mounts-create` | Create a new mount (volume, bind, or file) on an application/compose service |
| `mounts-allNamedByApplicationId` | List the named volumes attached to an app |
| `mounts-one` | Read a single mount's config |
| `mounts-update` | Update an existing mount |
| `mounts-remove` | Detach + remove a mount |
| `mounts-listByServiceId` | List every mount attached to a service (any type) |

**Common mistake**: typing `mount-create` (singular) — returns `E_NOT_FOUND`. The skill must use the plural form.

## Three mount types

`mounts-create.body.type` is an enum: `"volume"` | `"bind"` | `"file"`. Pick by use case:

### Volume (recommended for most stateful apps)

A named Docker volume managed by the swarm. Survives redeploys; only the explicit `mounts-remove` op detaches it.

```json
{
  "body": {
    "type": "volume",
    "volumeName": "app-data",
    "mountPath": "/data",
    "serviceType": "application",
    "serviceId": "<applicationId>",
    "hostPath": null,
    "content": null,
    "filePath": null
  }
}
```

- `volumeName` is the Docker volume name (Dokploy creates it if missing).
- `mountPath` is where the container sees it (e.g., `/data`, `/var/lib/postgresql/data`).
- `serviceType: "application"` for single apps, `"compose"` for compose stacks (then use `composeId` for `serviceId`).
- `hostPath`, `content`, `filePath` are for the other mount types — set `null`.

### Bind mount (point at a host path)

Pins a container path to an explicit host path. Use this only when the data lives at a specific host location (legacy migration, host-side log forwarding, hardware-pinned paths).

```json
{
  "body": {
    "type": "bind",
    "hostPath": "/srv/app/data",
    "mountPath": "/data",
    "serviceType": "application",
    "serviceId": "<applicationId>",
    "volumeName": null,
    "content": null,
    "filePath": null
  }
}
```

Caveats:
- The host directory must exist (or be createable) on the Dokploy server before the first deploy.
- Bind mounts break server-portability — if you migrate the app to another Dokploy server, the bind path may not exist there.
- For multi-server clusters, bind mounts pin the app to the server where the host path exists, even without `serverId`.

### File mount (inline config)

Inject a small text file (config, cert, env-style YAML) into the container without rebuilding the image.

```json
{
  "body": {
    "type": "file",
    "filePath": "/etc/app/config.yaml",
    "content": "key: value\nfoo: bar\n",
    "serviceType": "application",
    "serviceId": "<applicationId>",
    "volumeName": null,
    "hostPath": null,
    "mountPath": null
  }
}
```

- `filePath` is where the container sees the file.
- `content` is the literal text contents (escape newlines as `\n` in JSON).
- The file is read-only inside the container.
- Updating the file (via `mounts-update`) requires a redeploy to take effect — Docker secrets / configs aren't live-reloadable through this path.

Don't use file mounts for secrets larger than ~1KB; use `application-saveEnvironment.buildSecrets` for those (see `sources.md`).

## Ordering: mount before first deploy

`mounts-create` must run **before** the application's first `application-deploy`. If you deploy first, the container starts without the mount; subsequent `mounts-create` + `application-redeploy` add it, but the container has already written data to the unmounted path — that data is in the container's writable layer and disappears at next restart.

Correct order:
```
1. application-create
2. application-save<Source>Provider
3. application-saveBuildType
4. application-saveEnvironment
5. mounts-create  ←  before deploy
6. application-deploy
```

For redeploys, mounts persist — no need to re-create them. The state file should record the mount so future runs don't accidentally double-create:

```yaml
mounts:
  - type: volume
    name: app-data
    path: /data
    mountId: MOUNT-…
```

## Size and quota

**The Dokploy mounts API has no size attribute.** If the user asks for "20Gi", the volume is created with no size limit (it grows until the host disk fills). Surface that explicitly:

> "Dokploy doesn't expose a per-volume size limit through the API. If you need a hard cap, set it host-side (e.g., LVM thin-provisioning, `docker volume create --opt size=...` directly, or a separate filesystem). yalla will create the volume without a size constraint."

For shared storage that needs replication or backup-at-volume-level, use a different storage class (NFS, S3-backed, etc.) configured outside yalla.

## Removing a mount

`mounts-remove` deletes the mount entry **without** deleting the underlying volume — Docker keeps the data even after detach. To wipe data, use `docker volume rm` host-side after `mounts-remove`.

Be careful: deleting an app via `application-delete` does *not* remove its mounts — the volumes persist as orphan state. Either remove mounts first, or run `mounts-listByServiceId` + bulk-remove before deleting the app.

## Compose-shape mounts

For compose stacks, the **user owns mount declarations in the compose file itself** — don't call `mounts-create` for compose. Their `volumes:` block declares everything:

```yaml
services:
  postgres:
    volumes:
      - postgres_data:/var/lib/postgresql/data
volumes:
  postgres_data:
```

The skill should call out: "Your compose file declares its own volumes. yalla isn't managing them." If the user wants a volume Dokploy can list via `mounts-*`, they need to call `mounts-create` with `serviceType: "compose"` AFTER the compose stack is created — but that's belt-and-braces and rarely useful.

## Database volumes are automatic

When you call `yalla database create <engine> ... --deploy` (postgres, mysql, etc.), Dokploy creates a named volume for the data directory **automatically**. You do not need to call `mounts-create` for `/var/lib/postgresql/data` — it's already done. The volume is named `<dbAppName>-data` or similar; inspect via `<engine>-one` if the user wants to know.

Only call `mounts-create` for **application-level** state that the app writes itself (uploads, cache, generated files).
