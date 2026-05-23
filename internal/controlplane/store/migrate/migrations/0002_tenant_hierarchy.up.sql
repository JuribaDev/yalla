-- Tenant hierarchy: the source-of-truth tables for Yalla's
-- Organization -> Project -> Environment -> Service model, plus the user /
-- membership tables and the dokploy_refs mapping table.
--
-- Design rules enforced here:
--
--   * The hierarchy is represented EXACTLY: every child row carries its
--     parent IDs and a foreign key back to the parent.
--   * Every customer-data row is tenant-scoped: it carries organization_id
--     (directly, or through a verified composite parent foreign key) so a
--     query can always scope by organization ID before resource ID.
--   * Composite foreign keys (organization_id, parent_id) make it impossible
--     to attach a child to a parent in a different organization — the tenant
--     boundary is enforced by the database, not just the application.
--   * Slugs are unique WITHIN their parent scope, never globally.
--   * Resource IDs are opaque text minted by internal/controlplane/domain;
--     the schema does not pin the prefix format so test fixtures and the
--     domain package can evolve independently.
--   * No table stores secrets, tokens, API keys, or rendered environment
--     variable values — those live in later, dedicated migrations and are
--     redacted everywhere they are handled.

-- organizations is the tenant root. Every other customer-data row is scoped
-- to exactly one organization.
CREATE TABLE organizations (
    id           text        PRIMARY KEY CHECK (length(id) > 0),
    slug         citext      NOT NULL UNIQUE CHECK (length(slug::text) > 0),
    display_name text        NOT NULL CHECK (length(display_name) > 0),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER organizations_set_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- users is a global identity table. A user is linked to organizations through
-- memberships, never owned by a single organization directly.
CREATE TABLE users (
    id           text        PRIMARY KEY CHECK (length(id) > 0),
    email        citext      NOT NULL UNIQUE CHECK (length(email::text) > 0),
    display_name text        NOT NULL CHECK (length(display_name) > 0),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- memberships joins users to organizations and carries the user's role within
-- that organization. The (organization_id, user_id) pair is the primary key:
-- a user has at most one membership row per organization.
CREATE TABLE memberships (
    organization_id text        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    user_id         text        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role            text        NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);

-- Reverse lookup: "which organizations is this user a member of".
CREATE INDEX memberships_user_id_idx ON memberships (user_id);

CREATE TRIGGER memberships_set_updated_at
    BEFORE UPDATE ON memberships
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- projects belong to exactly one organization. The slug is unique within the
-- owning organization, never globally. The (organization_id, id) unique
-- constraint is the target of the environments composite foreign key.
CREATE TABLE projects (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    slug            citext      NOT NULL CHECK (length(slug::text) > 0),
    display_name    text        NOT NULL CHECK (length(display_name) > 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, slug),
    UNIQUE (organization_id, id)
);

CREATE INDEX projects_organization_id_idx ON projects (organization_id);

CREATE TRIGGER projects_set_updated_at
    BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- environments belong to exactly one project. The composite foreign key on
-- (organization_id, project_id) guarantees an environment's organization_id
-- always matches its project's organization_id — a child can never cross the
-- tenant boundary. The slug is unique within the owning project.
CREATE TABLE environments (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    project_id      text        NOT NULL,
    slug            citext      NOT NULL CHECK (length(slug::text) > 0),
    display_name    text        NOT NULL CHECK (length(display_name) > 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects (organization_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, slug),
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, project_id, id)
);

CREATE INDEX environments_organization_id_idx ON environments (organization_id);
CREATE INDEX environments_project_id_idx ON environments (project_id);

CREATE TRIGGER environments_set_updated_at
    BEFORE UPDATE ON environments
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- services belong to exactly one environment. The composite foreign key on
-- (organization_id, project_id, environment_id) walks the whole hierarchy, so
-- a service's organization_id and project_id always match its environment's.
-- kind mirrors Dokploy's service taxonomy. The slug is unique within the
-- owning environment.
CREATE TABLE services (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    project_id      text        NOT NULL,
    environment_id  text        NOT NULL,
    slug            citext      NOT NULL CHECK (length(slug::text) > 0),
    display_name    text        NOT NULL CHECK (length(display_name) > 0),
    kind            text        NOT NULL CHECK (kind IN ('application', 'database', 'compose')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id, environment_id)
        REFERENCES environments (organization_id, project_id, id) ON DELETE CASCADE,
    UNIQUE (environment_id, slug),
    UNIQUE (organization_id, id)
);

CREATE INDEX services_organization_id_idx ON services (organization_id);
CREATE INDEX services_project_id_idx ON services (project_id);
CREATE INDEX services_environment_id_idx ON services (environment_id);

CREATE TRIGGER services_set_updated_at
    BEFORE UPDATE ON services
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- dokploy_refs maps a Yalla resource to the Dokploy object that provisions it.
-- The mapping is polymorphic (a yalla_id may name an organization, project,
-- environment, or service), so it cannot be a single foreign key column; the
-- organization_id foreign key keeps every row tenant-scoped regardless.
--
--   * dokploy_resource enumerates every Dokploy object kind Yalla maps onto:
--     organization, project, environment, application, compose, database,
--     domain, and backup.
--   * UNIQUE (dokploy_resource, dokploy_id) ensures one Dokploy object is
--     never claimed by two Yalla resources.
--   * UNIQUE (organization_id, yalla_id, dokploy_resource, dokploy_id)
--     prevents duplicate mapping rows while still allowing a resource to own
--     several objects of the same kind (e.g. multiple domains or backups).
CREATE TABLE dokploy_refs (
    id               bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id  text        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    yalla_kind       text        NOT NULL CHECK (
        yalla_kind IN ('organization', 'project', 'environment', 'service')
    ),
    yalla_id         text        NOT NULL CHECK (length(yalla_id) > 0),
    dokploy_resource text        NOT NULL CHECK (
        dokploy_resource IN (
            'organization', 'project', 'environment', 'application',
            'compose', 'database', 'domain', 'backup'
        )
    ),
    dokploy_id       text        NOT NULL CHECK (length(dokploy_id) > 0),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (dokploy_resource, dokploy_id),
    UNIQUE (organization_id, yalla_id, dokploy_resource, dokploy_id)
);

CREATE INDEX dokploy_refs_organization_id_idx ON dokploy_refs (organization_id);
CREATE INDEX dokploy_refs_yalla_id_idx ON dokploy_refs (yalla_id);

CREATE TRIGGER dokploy_refs_set_updated_at
    BEFORE UPDATE ON dokploy_refs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
