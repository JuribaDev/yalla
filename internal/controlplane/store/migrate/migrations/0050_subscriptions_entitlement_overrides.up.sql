-- Subscription and entitlement override schema. Organizations accept an exact
-- immutable plan row, while entitlement overrides layer on top with explicit
-- source and effective windows so runtime resolution is reproducible.

CREATE DOMAIN subscription_status AS text
    CHECK (VALUE IN ('trialing', 'active', 'past_due', 'canceled'));

CREATE DOMAIN subscription_entitlement_source AS text
    CHECK (VALUE IN ('subscription_override', 'emergency_admin'));

CREATE TABLE subscriptions (
    id                        text                PRIMARY KEY CHECK (length(id) > 0),
    organization_id           text                NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    plan_id                   text                NOT NULL REFERENCES plans (id) ON DELETE RESTRICT,
    status                    subscription_status NOT NULL,
    current_period_start      timestamptz         NOT NULL,
    current_period_end        timestamptz         NOT NULL,
    provider                  text                NOT NULL DEFAULT 'manual' CHECK (provider ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    provider_customer_id      text,
    provider_subscription_id  text,
    cancel_at_period_end      boolean             NOT NULL DEFAULT false,
    canceled_at               timestamptz,
    trial_ends_at             timestamptz,
    metadata                  jsonb               NOT NULL DEFAULT '{}'::jsonb,
    created_at                timestamptz         NOT NULL DEFAULT now(),
    updated_at                timestamptz         NOT NULL DEFAULT now(),
    CONSTRAINT subscriptions_period_valid CHECK (current_period_end > current_period_start),
    CONSTRAINT subscriptions_canceled_at_consistent CHECK (
        (status = 'canceled' AND canceled_at IS NOT NULL) OR
        (status <> 'canceled')
    ),
    CONSTRAINT subscriptions_trial_ends_at_consistent CHECK (
        (status = 'trialing' AND trial_ends_at IS NOT NULL) OR
        (status <> 'trialing')
    ),
    UNIQUE (organization_id, id)
);

CREATE UNIQUE INDEX subscriptions_current_org_idx
    ON subscriptions (organization_id)
    WHERE status IN ('trialing', 'active', 'past_due');

CREATE INDEX subscriptions_org_status_idx ON subscriptions (organization_id, status);
CREATE INDEX subscriptions_plan_id_idx ON subscriptions (plan_id);
CREATE INDEX subscriptions_provider_subscription_idx
    ON subscriptions (provider, provider_subscription_id)
    WHERE provider_subscription_id IS NOT NULL;

CREATE TRIGGER subscriptions_set_updated_at
    BEFORE UPDATE ON subscriptions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE subscription_entitlements (
    id                 text                            PRIMARY KEY CHECK (length(id) > 0),
    organization_id    text                            NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    subscription_id    text,
    source             subscription_entitlement_source NOT NULL,
    entitlement_key    text                            NOT NULL CHECK (entitlement_key ~ '^[a-z0-9][a-z0-9_.-]{0,127}$'),
    limit_value        bigint                          CHECK (limit_value IS NULL OR limit_value >= 0),
    enforcement_mode   quota_enforcement_mode          NOT NULL,
    reason             text                            NOT NULL CHECK (length(btrim(reason)) BETWEEN 1 AND 500),
    actor_id           text                            NOT NULL CHECK (length(btrim(actor_id)) BETWEEN 1 AND 128),
    actor_kind         text                            NOT NULL CHECK (actor_kind IN ('user', 'api_key', 'service_account', 'worker', 'system')),
    request_id         text                            NOT NULL CHECK (length(btrim(request_id)) BETWEEN 1 AND 128),
    correlation_id     text                            NOT NULL CHECK (length(btrim(correlation_id)) BETWEEN 1 AND 128),
    effective_from     timestamptz                     NOT NULL,
    effective_until    timestamptz,
    metadata           jsonb                           NOT NULL DEFAULT '{}'::jsonb,
    created_at         timestamptz                     NOT NULL DEFAULT now(),
    updated_at         timestamptz                     NOT NULL DEFAULT now(),
    CONSTRAINT subscription_entitlements_window_valid CHECK (
        effective_until IS NULL OR effective_until > effective_from
    ),
    CONSTRAINT subscription_entitlements_source_consistent CHECK (
        (source = 'subscription_override' AND subscription_id IS NOT NULL) OR
        (source = 'emergency_admin' AND subscription_id IS NULL)
    ),
    FOREIGN KEY (organization_id, subscription_id)
        REFERENCES subscriptions (organization_id, id)
        MATCH SIMPLE
        ON DELETE CASCADE
);

CREATE INDEX subscription_entitlements_resolution_idx
    ON subscription_entitlements (organization_id, entitlement_key, source, effective_from DESC, created_at DESC);
CREATE INDEX subscription_entitlements_subscription_idx
    ON subscription_entitlements (organization_id, subscription_id);

CREATE TRIGGER subscription_entitlements_set_updated_at
    BEFORE UPDATE ON subscription_entitlements
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
