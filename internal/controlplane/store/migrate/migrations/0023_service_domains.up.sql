-- Service-scoped domains: the public-facing hostname routes that map an
-- inbound HTTP request to the running Dokploy service. A row here binds a
-- (hostname, path) tuple to a single service inside a single tenant, so a
-- record can never sit under a foreign tenant's service (the FK refuses
-- the insert structurally before the application layer's tenant predicate
-- runs).
--
-- Design rules enforced here:
--
--   * Tenant-scoped at the database. The composite FK
--     (organization_id, service_id) references the matching composite
--     UNIQUE (organization_id, id) on services with ON DELETE CASCADE, so
--     a service teardown removes its domains and a row can never sit
--     under a foreign tenant's service. The transitive parents
--     (environment, project) are reached through services — this table
--     does not duplicate environment_id or project_id, the same way
--     service_variables does not.
--   * (hostname, path) uniqueness is global. A (hostname, path) tuple
--     names one routable address on the public internet — two services in
--     two tenants cannot both claim the same address — so the uniqueness
--     constraint is on (hostname, path) ONLY, NOT scoped by
--     organization_id or service_id. The application layer surfaces the
--     conflict as a typed apierr.Conflict; this constraint is the
--     authoritative guard.
--   * Composite uniqueness (organization_id, id) is exposed as the FK
--     target any future audit or override table can use to enforce
--     "an override row's organization_id must match its referenced
--     parent domain's organization_id".
--   * Optimistic concurrency. Every row carries a bigint version that the
--     bump_version() trigger from migration 0011 maintains, mirroring
--     services / environments / projects / *_variables / *_grants.
--     Future PATCH / DELETE stories will accept If-Match against this
--     column.
--   * No secrets in the schema. The certificate_type column drives TLS
--     issuance behavior in the worker (let's-encrypt, custom-cert,
--     none); the actual certificate material is held by the worker /
--     Dokploy layer and never round-tripped through this table.

CREATE TABLE service_domains (
    id               text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id  text        NOT NULL,
    service_id       text        NOT NULL,
    hostname         text        NOT NULL CHECK (length(hostname) > 0),
    path             text        NOT NULL DEFAULT '/',
    port             integer     NOT NULL CHECK (port > 0 AND port < 65536),
    https            boolean     NOT NULL DEFAULT true,
    certificate_type text        NOT NULL DEFAULT 'lets-encrypt'
                                 CHECK (certificate_type IN ('lets-encrypt', 'custom', 'none')),
    version          bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, service_id)
        REFERENCES services (organization_id, id) ON DELETE CASCADE,
    UNIQUE (hostname, path),
    UNIQUE (organization_id, id)
);

CREATE INDEX service_domains_service_idx
    ON service_domains (organization_id, service_id);

CREATE TRIGGER service_domains_set_updated_at
    BEFORE UPDATE ON service_domains
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER service_domains_bump_version
    BEFORE UPDATE ON service_domains
    FOR EACH ROW EXECUTE FUNCTION bump_version();
