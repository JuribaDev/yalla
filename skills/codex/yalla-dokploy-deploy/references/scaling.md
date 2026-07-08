# Scaling, resource limits, and placement

How to configure replicas, memory/CPU caps, and multi-server placement for an application. All of this rides on `application-update` — there's no separate "scale" or "resources" op.

## When to use this file

The user says things like:
- "Run 3 replicas of the API"
- "Cap it at 512Mi memory"
- "Reserve 0.5 CPU"
- "Deploy on the GPU node only"
- "Why is my single-replica app getting OOM-killed?"

## The single op: `application-update`

`application-update` is a multi-purpose op that accepts a partial body — only the fields you set get updated. Body schema (subset; full schema via `yalla --json schema get application-update`):

```json
{
  "body": {
    "applicationId": "<id>",

    "replicas": 3,

    "memoryLimit": "512m",
    "memoryReservation": "256m",
    "cpuLimit": "0.5",
    "cpuReservation": "0.25",

    "command": null,
    "healthCheckSwarm": null,

    "modeSwarm": null,
    "labelsSwarm": null,
    "networkSwarm": null,
    "restartPolicySwarm": null,
    "placementSwarm": null,
    "updateConfigSwarm": null,
    "rollbackConfigSwarm": null
  }
}
```

The top-level `replicas` is what Dokploy's UI writes — it eventually flows into `modeSwarm.Replicated.Replicas`. Prefer the top-level field unless you need to express something the simple field can't (parallelism, sticky updates).

## Units

| Field | Format | Examples |
|---|---|---|
| `memoryLimit` / `memoryReservation` | Docker memory-string | `"128m"`, `"512m"`, `"2g"`, `"1024k"` |
| `cpuLimit` / `cpuReservation` | Decimal CPU count as string | `"0.25"`, `"0.5"`, `"1"`, `"2"` |

A Docker swarm node with 4 cores supports up to `cpuLimit: "4"` per container. Going over fails at scheduling.

`memoryReservation` is the **soft** floor (Docker won't schedule containers below it). `memoryLimit` is the **hard** ceiling (OOM-killed above it). For most apps, set both to the same value to avoid scheduling surprises.

## Ordering

`application-update` is idempotent — call it any time. Common patterns:

### Configure at create time (recommended)

After `application-create` but before the first `application-deploy`:

```
1. application-create
2. application-save<Source>Provider
3. application-saveBuildType
4. application-saveEnvironment
5. application-update     ← replicas + resources
6. (mounts-create if needed)
7. application-deploy
```

This way the first deploy ships at the configured scale. If you skip step 5, the first deploy runs as a single replica with no resource limits (Dokploy's defaults), and you'll redeploy after step 5 — wasted build.

### Adjust on a running app

`application-update` followed by `application-redeploy` picks up the new config without a rebuild:

```sh
yalla --json --no-input api call application-update --input <(echo "{\"body\":{\"applicationId\":\"$APP_ID\",\"replicas\":5}}")
yalla --json --no-input api call application-redeploy --input <(echo "{\"body\":{\"applicationId\":\"$APP_ID\"}}")
```

`application-update` alone doesn't restart running containers — the swarm sees the new desired-state at the next deploy. Use `application-redeploy` to roll the change out immediately.

## Multi-server placement: `serverId`

If the Dokploy cluster has multiple servers (configured in Settings → Servers), you can pin an app to a specific one via `serverId` on `application-create`:

```json
{
  "body": {
    "name": "<app>",
    "environmentId": "<env_id>",
    "serverId": "SERVER-GPU-01",
    "description": null,
    "appName": null
  }
}
```

Set `serverId` when:
- The app needs hardware that's only on certain servers (GPU, more RAM, specific kernel modules).
- The app must be co-located with another app it talks to.
- The app must be isolated from noisy neighbours on the default server.

`serverId` is settable at create time. To change it later, the cleanest path is `application-delete` + `application-create` with the new `serverId` — Dokploy doesn't expose a "move app to other server" op that preserves the deploy history.

For multi-replica apps with `serverId`, all replicas land on that server. To spread replicas across servers, leave `serverId: null` and use `placementSwarm` constraints on `application-update`:

```json
{
  "body": {
    "applicationId": "<id>",
    "placementSwarm": {
      "Constraints": ["node.role==worker"],
      "Preferences": [{"Spread": {"SpreadDescriptor": "node.id"}}]
    }
  }
}
```

The `placementSwarm` shape mirrors Docker Swarm's service-spec — refer to swarm docs for the full grammar.

## Health checks

`healthCheckSwarm` on `application-update` configures how the swarm decides when a replica is "ready":

```json
{
  "body": {
    "applicationId": "<id>",
    "healthCheckSwarm": {
      "Test": ["CMD-SHELL", "curl -fsS http://localhost:3000/healthz || exit 1"],
      "Interval": 30000000000,
      "Timeout":   5000000000,
      "Retries":   3,
      "StartPeriod": 60000000000
    }
  }
}
```

Units are **nanoseconds** (swarm's spec) — `30 * 1e9 = 30000000000` for 30 seconds. Common settings:
- Short-running web apps: 10s interval, 3 retries, 30s start period.
- Slow-starting apps (Java, large Python): 60s start period, 30s interval.
- Apps that don't expose a `/healthz` endpoint: drop the `Test` and let the swarm rely on TCP-port checks (set via `placementSwarm` instead — rare).

## Anti-patterns

- **Setting `replicas` without setting `memoryLimit`**: one replica gets the node's full memory, the others starve. Always set memory limits + reservations together.
- **High `replicas` on a single-server cluster**: the server gets all of them. Either add servers to the cluster (Dokploy → Settings → Servers) or accept that scaling is bounded by one node's resources.
- **Updating `command` to chain migrations**: see `migrations.md` § Mechanism 2 — works but has race conditions for replicas > 1.
- **Trying to `serverId` an existing app**: not supported in-place. `application-delete` + recreate, or migrate via tear-down + fresh deploy.

## What this skill does NOT do

- Horizontal autoscaling (CPU/QPS-based) — Dokploy doesn't expose an autoscaler; replicas are a fixed integer.
- Vertical autoscaling — same story.
- Per-environment scale differences via a single op — apply different `application-update` bodies per environment's app (staging at 1 replica, prod at 5).
- Custom scheduler hints beyond `placementSwarm` — Dokploy doesn't expose taints/tolerations like Kubernetes.
