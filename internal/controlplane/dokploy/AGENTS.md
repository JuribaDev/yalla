# dokploy

Wraps Dokploy as the private provisioning backend. Customer-facing code never
calls Dokploy directly — only worker/provisioner code, through the typed
client.

## Package split

- `dokploy` (this package) will hold the typed Dokploy client wrapper: Yalla
  intents (ensure project, ensure environment, deploy service, read logs, ...)
  mapped onto Dokploy operations. The Dokploy token is injected into the client
  and must never reach handlers.
- `dokployfake` is the deterministic, in-memory HTTP test double. It is the
  default Dokploy for **every** normal test — a live Dokploy server is an
  opt-in external smoke test only.

## dokployfake conventions

- It mimics **Dokploy's** JSON shapes, not Yalla's `yalla.output.v1` /
  `yalla.error.v1` envelopes: it stands in for the upstream provisioning API,
  not a Yalla public surface. Do not "fix" it to emit Yalla envelopes.
- IDs are deterministic per-kind counters (`org_1`, `proj_1`, ...); a fixed
  call sequence always yields the same IDs. Keep new resources deterministic.
- `QueueFault` arms a FIFO fault queue (status codes, timeout, malformed JSON);
  each request consumes one. Faults are applied before auth and routing.
- Every recorded request is scrubbed: sensitive header values become
  `output.Sentinel` and the body runs through a redactor seeded with the
  bearer token. Anything new the recorder captures must stay redaction-safe.
- The fake takes no `testing.TB`; callers `defer srv.Close()`. It depends only
  on `internal/output` + stdlib, so any package's tests can import it without
  a cycle.
