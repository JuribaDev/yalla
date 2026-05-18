ALTER TABLE dokploy_refs
    DROP CONSTRAINT dokploy_refs_yalla_kind_check;

ALTER TABLE dokploy_refs
    ADD CONSTRAINT dokploy_refs_yalla_kind_check CHECK (
        yalla_kind IN ('organization', 'project', 'environment', 'service', 'service_domain')
    );
