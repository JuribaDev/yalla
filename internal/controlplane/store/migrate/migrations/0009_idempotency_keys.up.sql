-- Idempotency keys: the durable record that makes mutating control-plane
-- endpoints safe for agent and CI retries.
--
-- Design rules enforced here:
--
--   * Replay, not re-execute. A client sends an Idempotency-Key with a
--     mutating request; the first request claims the key (status 'pending'),
--     runs the handler, and records the rendered response envelope (status
--     'completed'). A retry with the same key and the same request replays the
--     stored envelope instead of running the handler a second time.
--   * Same key, different request is a conflict. request_hash pins the key to
--     one canonical request (method, path, query, body). A retry whose hash
--     differs is rejected by the middleware as E_IDEMPOTENCY_CONFLICT.
--   * Scoped to a principal within a tenant. UNIQUE (organization_id,
--     principal_id, idempotency_key): one principal's key can never collide
--     with another's, and a key never crosses a tenant boundary.
--   * Expiring. expires_at bounds how long a key is honoured; an expired row is
--     transparently taken over by a fresh claim, and a janitor can purge it.
--   * No secrets. response_body stores the already-rendered yalla.output.v1 /
--     yalla.error.v1 envelope, which the apienvelope renderer has already run
--     through the output redactor; request_hash is a sha256 digest, never the
--     raw request body.

CREATE TABLE idempotency_keys (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    -- The principal that claimed the key. A key is scoped to its principal, so
    -- two principals in the same organization may independently use the same
    -- key string without colliding.
    principal_id    text        NOT NULL CHECK (length(principal_id) > 0),
    idempotency_key text        NOT NULL CHECK (length(idempotency_key) > 0),
    -- method + ' ' + path of the claiming request, kept human-readable for
    -- audit and debugging.
    route           text        NOT NULL CHECK (length(route) > 0),
    -- sha256 hex digest of the canonical request (method, path, query, body).
    -- A retry whose digest differs is a different request under the same key.
    request_hash    text        NOT NULL CHECK (length(request_hash) > 0),
    -- request_id of the claiming request, so a replay can be correlated back to
    -- the original.
    request_id      text        NOT NULL DEFAULT '',
    status          text        NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'completed')),
    -- The recorded response. Both columns are NULL while the claim is pending
    -- and NOT NULL once completed, enforced by the CHECK below.
    response_status integer     CHECK (response_status IS NULL OR (response_status BETWEEN 100 AND 599)),
    response_body   bytea,
    created_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz,
    expires_at      timestamptz NOT NULL,
    -- A completed claim always carries its response and completion time; a
    -- pending one never does.
    CONSTRAINT idempotency_keys_completion_consistent CHECK (
        (status = 'completed' AND response_status IS NOT NULL
            AND response_body IS NOT NULL AND completed_at IS NOT NULL) OR
        (status = 'pending' AND response_status IS NULL
            AND response_body IS NULL AND completed_at IS NULL)
    ),
    -- One principal's idempotency key maps to exactly one request within a
    -- tenant.
    UNIQUE (organization_id, principal_id, idempotency_key)
);

-- A janitor purges expired rows; the index keeps that scan off a sequential
-- pass.
CREATE INDEX idempotency_keys_expires_at_idx ON idempotency_keys (expires_at);
