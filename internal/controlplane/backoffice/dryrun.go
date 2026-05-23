// Package backoffice validates and projects admin-owned runtime configuration
// before it is published into the control-plane source of truth.
package backoffice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/metering"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/output"
)

// DryRunInput is the public validation request for one candidate backoffice
// runtime configuration payload.
type DryRunInput struct {
	ConfigSetID             string
	Domain                  store.AdminConfigDomain
	Payload                 []byte
	SimulateOrganizationIDs []string
}

// Issue is one stable warning or blocking validation error.
type Issue struct {
	Kind    string `json:"kind"`
	Code    string `json:"code"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// OrganizationImpact describes how the candidate configuration would affect
// one selected organization.
type OrganizationImpact struct {
	OrganizationID  string  `json:"organization_id"`
	Status          string  `json:"status"`
	EntitlementKey  string  `json:"entitlement_key,omitempty"`
	CurrentUsage    float64 `json:"current_usage,omitempty"`
	CandidateLimit  *int64  `json:"candidate_limit,omitempty"`
	EnforcementMode string  `json:"enforcement_mode,omitempty"`
	Message         string  `json:"message,omitempty"`
}

// DryRunResult is the stable success-envelope data for config validation.
type DryRunResult struct {
	Valid                   bool                 `json:"valid"`
	Domain                  string               `json:"domain"`
	ConfigSetID             string               `json:"config_set_id,omitempty"`
	Warnings                []Issue              `json:"warnings"`
	BlockingErrors          []Issue              `json:"blocking_errors"`
	SimulatedOrganizations  []OrganizationImpact `json:"simulated_organizations"`
	ValidatedAt             time.Time            `json:"validated_at"`
	CandidateEntitlementKey []string             `json:"candidate_entitlement_keys"`
	CandidateMetricKeys     []string             `json:"candidate_metric_keys"`
}

// ImpactReader supplies the optional database-backed part of dry-run
// validation: checking organizations exist and reading current usage counters.
type ImpactReader interface {
	UsageByOrganization(ctx context.Context, organizationIDs []string, at time.Time) (map[string]map[string]float64, error)
}

// Validator validates draft backoffice runtime configuration.
type Validator struct {
	now    func() time.Time
	impact ImpactReader
}

// Option customizes a Validator.
type Option func(*Validator)

// WithNow injects a clock for deterministic tests.
func WithNow(now func() time.Time) Option {
	return func(v *Validator) {
		if now != nil {
			v.now = now
		}
	}
}

// WithImpactReader enables selected-organization impact simulation.
func WithImpactReader(reader ImpactReader) Option {
	return func(v *Validator) { v.impact = reader }
}

// NewValidator returns a deterministic dry-run validator.
func NewValidator(opts ...Option) *Validator {
	v := &Validator{now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks one candidate payload. Structural problems in the request
// return typed API errors; candidate config defects are returned as blocking
// issues so operators can see the whole dry-run report at once.
func (v *Validator) Validate(ctx context.Context, in DryRunInput) (DryRunResult, error) {
	at := v.now().UTC()
	input, err := normalizeInput(in)
	if err != nil {
		return DryRunResult{}, err
	}
	candidate, err := parseCandidate(input.Payload)
	if err != nil {
		return DryRunResult{}, err
	}

	result := DryRunResult{
		Domain:                 string(input.Domain),
		ConfigSetID:            input.ConfigSetID,
		Warnings:               []Issue{},
		BlockingErrors:         []Issue{},
		SimulatedOrganizations: []OrganizationImpact{},
		ValidatedAt:            at,
	}
	knownKeys := knownEntitlementKeys(candidate)
	metricKeys := knownMetricKeys(candidate)
	result.CandidateEntitlementKey = sortedKeys(knownKeys)
	result.CandidateMetricKeys = sortedKeys(metricKeys)

	validatePlans(candidate, knownKeys, &result)
	validateMetricDefinitions(candidate, &result)
	validateMeteringSources(candidate, &result)
	validateBillingProviders(candidate, &result)
	validateDeletes(candidate, &result)

	if len(input.SimulateOrganizationIDs) > 0 {
		if v.impact == nil {
			result.Warnings = append(result.Warnings, warning("impact_simulation_unavailable", "simulate_organization_ids", "impact simulation is not configured on this process"))
		} else {
			usage, err := v.impact.UsageByOrganization(ctx, input.SimulateOrganizationIDs, at)
			if err != nil {
				return DryRunResult{}, err
			}
			result.SimulatedOrganizations = simulateImpact(input.SimulateOrganizationIDs, usage, candidate, &result)
		}
	}

	result.Valid = len(result.BlockingErrors) == 0
	return result, nil
}

func normalizeInput(in DryRunInput) (DryRunInput, error) {
	out := DryRunInput{
		ConfigSetID: strings.TrimSpace(in.ConfigSetID),
		Domain:      in.Domain,
		Payload:     in.Payload,
	}
	var violations []apierr.FieldViolation
	if out.ConfigSetID != "" {
		if !strings.HasPrefix(out.ConfigSetID, "cfg_") {
			violations = append(violations, apierr.FieldViolation{Field: "config_set_id", Reason: "must be a valid config set id"})
		}
	}
	if !validDomain(out.Domain) {
		violations = append(violations, apierr.FieldViolation{Field: "domain", Reason: "must be pricing, metering, billing, quota, or features"})
	}
	if len(out.Payload) == 0 {
		out.Payload = []byte(`{}`)
	}
	if !json.Valid(out.Payload) {
		violations = append(violations, apierr.FieldViolation{Field: "payload", Reason: "must be valid JSON"})
	}
	seen := map[string]struct{}{}
	for i, raw := range in.SimulateOrganizationIDs {
		id := strings.TrimSpace(raw)
		field := fmt.Sprintf("simulate_organization_ids[%d]", i)
		if id == "" {
			violations = append(violations, apierr.FieldViolation{Field: field, Reason: "must not be blank"})
			continue
		}
		parsed, err := domain.ParseID(id)
		if err != nil || parsed.Kind() != domain.KindOrganization {
			violations = append(violations, apierr.FieldViolation{Field: field, Reason: "must be a valid organization id"})
			continue
		}
		if _, ok := seen[id]; ok {
			violations = append(violations, apierr.FieldViolation{Field: field, Reason: "must be unique"})
			continue
		}
		seen[id] = struct{}{}
		out.SimulateOrganizationIDs = append(out.SimulateOrganizationIDs, id)
	}
	if len(violations) > 0 {
		return DryRunInput{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func validDomain(domain store.AdminConfigDomain) bool {
	switch domain {
	case store.AdminConfigDomainPricing, store.AdminConfigDomainMetering, store.AdminConfigDomainBilling, store.AdminConfigDomainQuota, store.AdminConfigDomainFeatures:
		return true
	default:
		return false
	}
}

type candidateConfig struct {
	Plans             []planConfig             `json:"plans"`
	MetricDefinitions []metricDefinitionConfig `json:"metric_definitions"`
	MeteringSources   []meteringSourceConfig   `json:"metering_sources"`
	BillingProviders  []billingProviderConfig  `json:"billing_providers"`
	Deletes           []deleteConfig           `json:"deletes"`
}

type planConfig struct {
	Slug          string              `json:"slug"`
	BillingPeriod string              `json:"billing_period"`
	Entitlements  []entitlementConfig `json:"entitlements"`
}

type entitlementConfig struct {
	Key             string `json:"key"`
	LimitValue      *int64 `json:"limit_value"`
	EnforcementMode string `json:"enforcement_mode"`
	Unit            string `json:"unit"`
}

type metricDefinitionConfig struct {
	Key          string `json:"key"`
	Unit         string `json:"unit"`
	Source       string `json:"source"`
	Enforcement  string `json:"enforcement"`
	BillingGrade bool   `json:"billing_grade"`
}

type meteringSourceConfig struct {
	Key           string `json:"key"`
	Type          string `json:"type"`
	Enabled       bool   `json:"enabled"`
	CredentialRef string `json:"credential_ref"`
}

type billingProviderConfig struct {
	Key               string   `json:"key"`
	Type              string   `json:"type"`
	Enabled           bool     `json:"enabled"`
	Currency          string   `json:"currency"`
	CredentialRef     string   `json:"credential_ref"`
	CompatibleSources []string `json:"compatible_sources"`
}

type deleteConfig struct {
	Kind           string `json:"kind"`
	Key            string `json:"key"`
	ReplacementKey string `json:"replacement_key"`
	Force          bool   `json:"force"`
}

func parseCandidate(payload []byte) (candidateConfig, error) {
	var candidate candidateConfig
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&candidate); err != nil {
		return candidateConfig{}, apierr.InvalidInput(apierr.FieldViolation{Field: "payload", Reason: "must match the backoffice dry-run schema"})
	}
	return candidate, nil
}

func validatePlans(candidate candidateConfig, knownKeys map[string]struct{}, result *DryRunResult) {
	seen := map[string]struct{}{}
	for i, plan := range candidate.Plans {
		prefix := fmt.Sprintf("plans[%d]", i)
		slug := strings.TrimSpace(plan.Slug)
		if slug == "" {
			result.BlockingErrors = append(result.BlockingErrors, blocking("plan_slug_required", prefix+".slug", "plan slug is required"))
		}
		period := strings.TrimSpace(plan.BillingPeriod)
		if period != "monthly" && period != "annual" && period != "custom" {
			result.BlockingErrors = append(result.BlockingErrors, blocking("billing_period_invalid", prefix+".billing_period", "billing period must be monthly, annual, or custom"))
		}
		planKey := slug + ":" + period
		if slug != "" && period != "" {
			if _, ok := seen[planKey]; ok {
				result.BlockingErrors = append(result.BlockingErrors, blocking("plan_duplicate", prefix, "plan slug and billing period must be unique"))
			}
			seen[planKey] = struct{}{}
		}
		if len(plan.Entitlements) == 0 {
			result.Warnings = append(result.Warnings, warning("plan_without_entitlements", prefix+".entitlements", "plan has no entitlements"))
		}
		for j, ent := range plan.Entitlements {
			validateEntitlement(prefix+fmt.Sprintf(".entitlements[%d]", j), ent, knownKeys, result)
		}
	}
}

func validateEntitlement(field string, ent entitlementConfig, knownKeys map[string]struct{}, result *DryRunResult) {
	key := strings.TrimSpace(ent.Key)
	if key == "" {
		result.BlockingErrors = append(result.BlockingErrors, blocking("entitlement_key_required", field+".key", "entitlement key is required"))
	} else if _, ok := knownKeys[key]; !ok {
		result.BlockingErrors = append(result.BlockingErrors, blocking("entitlement_key_unknown", field+".key", "entitlement key must reference a quota resource or metric definition"))
	}
	if ent.LimitValue != nil && *ent.LimitValue < 0 {
		result.BlockingErrors = append(result.BlockingErrors, blocking("limit_negative", field+".limit_value", "limit value must be zero or positive"))
	}
	if !validEnforcementMode(ent.EnforcementMode) {
		result.BlockingErrors = append(result.BlockingErrors, blocking("enforcement_mode_invalid", field+".enforcement_mode", "enforcement mode must be hard, soft, metered, or disabled"))
	}
	if ent.Unit != "" && !safeToken(ent.Unit) {
		result.BlockingErrors = append(result.BlockingErrors, blocking("unit_invalid", field+".unit", "unit must be a stable lowercase token"))
	}
}

func validateMetricDefinitions(candidate candidateConfig, result *DryRunResult) {
	seen := map[string]struct{}{}
	for i, metric := range candidate.MetricDefinitions {
		field := fmt.Sprintf("metric_definitions[%d]", i)
		key := strings.TrimSpace(metric.Key)
		if key == "" {
			result.BlockingErrors = append(result.BlockingErrors, blocking("metric_key_required", field+".key", "metric key is required"))
		} else if !safeToken(key) {
			result.BlockingErrors = append(result.BlockingErrors, blocking("metric_key_invalid", field+".key", "metric key must be a stable lowercase token"))
		} else if _, ok := seen[key]; ok {
			result.BlockingErrors = append(result.BlockingErrors, blocking("metric_duplicate", field+".key", "metric key must be unique"))
		}
		seen[key] = struct{}{}
		if strings.TrimSpace(metric.Unit) == "" || !safeToken(metric.Unit) {
			result.BlockingErrors = append(result.BlockingErrors, blocking("metric_unit_invalid", field+".unit", "metric unit must be a stable lowercase token"))
		}
		if strings.TrimSpace(metric.Source) == "" || !safeToken(metric.Source) {
			result.BlockingErrors = append(result.BlockingErrors, blocking("metric_source_invalid", field+".source", "metric source must be a stable lowercase token"))
		}
		if !validMetricEnforcement(metric.Enforcement) {
			result.BlockingErrors = append(result.BlockingErrors, blocking("metric_enforcement_invalid", field+".enforcement", "metric enforcement must be hard, soft, metered, hard_or_metered, or observability"))
		}
		if metric.BillingGrade && metric.Enforcement == string(metering.MetricEnforcementObservability) {
			result.BlockingErrors = append(result.BlockingErrors, blocking("billing_grade_observability", field+".billing_grade", "observability metrics cannot be billing grade"))
		}
	}
}

func validateMeteringSources(candidate candidateConfig, result *DryRunResult) {
	seen := map[string]struct{}{}
	for i, source := range candidate.MeteringSources {
		field := fmt.Sprintf("metering_sources[%d]", i)
		key := strings.TrimSpace(source.Key)
		if key == "" || !safeToken(key) {
			result.BlockingErrors = append(result.BlockingErrors, blocking("metering_source_key_invalid", field+".key", "metering source key must be a stable lowercase token"))
		} else if _, ok := seen[key]; ok {
			result.BlockingErrors = append(result.BlockingErrors, blocking("metering_source_duplicate", field+".key", "metering source key must be unique"))
		}
		seen[key] = struct{}{}
		sourceType := strings.TrimSpace(source.Type)
		if sourceType == "" || !safeToken(sourceType) {
			result.BlockingErrors = append(result.BlockingErrors, blocking("metering_source_type_invalid", field+".type", "metering source type must be a stable lowercase token"))
		}
		if source.Enabled && strings.TrimSpace(source.CredentialRef) == "" {
			result.BlockingErrors = append(result.BlockingErrors, blocking("metering_source_credentials_missing", field+".credential_ref", "enabled metering sources must reference stored credentials"))
		}
		if looksSecret(source.CredentialRef) {
			result.BlockingErrors = append(result.BlockingErrors, blocking("secret_value_rejected", field+".credential_ref", "credential_ref must name a stored secret reference, not include a secret value"))
		}
	}
}

func validateBillingProviders(candidate candidateConfig, result *DryRunResult) {
	sourceKeys := map[string]struct{}{}
	for _, source := range candidate.MeteringSources {
		sourceKeys[strings.TrimSpace(source.Key)] = struct{}{}
	}
	for i, provider := range candidate.BillingProviders {
		field := fmt.Sprintf("billing_providers[%d]", i)
		if strings.TrimSpace(provider.Key) == "" || !safeToken(provider.Key) {
			result.BlockingErrors = append(result.BlockingErrors, blocking("billing_provider_key_invalid", field+".key", "billing provider key must be a stable lowercase token"))
		}
		if provider.Type != "stripe" && provider.Type != "manual" {
			result.BlockingErrors = append(result.BlockingErrors, blocking("billing_provider_type_invalid", field+".type", "billing provider type must be stripe or manual"))
		}
		if provider.Enabled && strings.TrimSpace(provider.CredentialRef) == "" {
			result.BlockingErrors = append(result.BlockingErrors, blocking("billing_provider_credentials_missing", field+".credential_ref", "enabled billing providers must reference stored credentials"))
		}
		if looksSecret(provider.CredentialRef) {
			result.BlockingErrors = append(result.BlockingErrors, blocking("secret_value_rejected", field+".credential_ref", "credential_ref must name a stored secret reference, not include a secret value"))
		}
		if provider.Currency != "" && len(provider.Currency) != 3 {
			result.BlockingErrors = append(result.BlockingErrors, blocking("billing_currency_invalid", field+".currency", "currency must be an ISO-4217 three-letter code"))
		}
		for j, source := range provider.CompatibleSources {
			if _, ok := sourceKeys[strings.TrimSpace(source)]; !ok {
				result.BlockingErrors = append(result.BlockingErrors, blocking("billing_source_unknown", fmt.Sprintf("%s.compatible_sources[%d]", field, j), "billing provider references an unknown metering source"))
			}
		}
	}
}

func validateDeletes(candidate candidateConfig, result *DryRunResult) {
	entitlements := planEntitlementKeys(candidate)
	metrics := map[string]struct{}{}
	for _, metric := range candidate.MetricDefinitions {
		metrics[strings.TrimSpace(metric.Key)] = struct{}{}
	}
	for i, del := range candidate.Deletes {
		field := fmt.Sprintf("deletes[%d]", i)
		key := strings.TrimSpace(del.Key)
		switch del.Kind {
		case "entitlement_key":
			if _, ok := entitlements[key]; ok && !del.Force {
				result.BlockingErrors = append(result.BlockingErrors, blocking("unsafe_delete", field+".key", "entitlement key is still referenced by candidate plans"))
			}
		case "metric_definition":
			if _, ok := metrics[key]; ok && !del.Force {
				result.BlockingErrors = append(result.BlockingErrors, blocking("unsafe_delete", field+".key", "metric definition is still present in candidate metrics"))
			}
		default:
			result.BlockingErrors = append(result.BlockingErrors, blocking("delete_kind_invalid", field+".kind", "delete kind must be entitlement_key or metric_definition"))
		}
		if key == "" {
			result.BlockingErrors = append(result.BlockingErrors, blocking("delete_key_required", field+".key", "delete key is required"))
		}
		if del.Force && strings.TrimSpace(del.ReplacementKey) == "" {
			result.Warnings = append(result.Warnings, warning("forced_delete_without_replacement", field+".replacement_key", "forced deletes without a replacement can change billing and quota behavior"))
		}
	}
}

func simulateImpact(orgIDs []string, usage map[string]map[string]float64, candidate candidateConfig, result *DryRunResult) []OrganizationImpact {
	limits := candidateHardLimits(candidate)
	impacts := make([]OrganizationImpact, 0, len(orgIDs))
	for _, orgID := range orgIDs {
		status := "unchanged"
		impact := OrganizationImpact{OrganizationID: orgID, Status: status}
		for key, limit := range limits {
			current := usage[orgID][key]
			if current > float64(limit) {
				candidateLimit := limit
				impact = OrganizationImpact{
					OrganizationID:  orgID,
					Status:          "would_exceed_limit",
					EntitlementKey:  key,
					CurrentUsage:    current,
					CandidateLimit:  &candidateLimit,
					EnforcementMode: "hard",
					Message:         "current usage exceeds the candidate hard limit",
				}
				result.BlockingErrors = append(result.BlockingErrors, blocking("impact_limit_exceeded", "simulate_organization_ids", "one or more selected organizations exceed candidate hard limits"))
				break
			}
		}
		impacts = append(impacts, impact)
	}
	return impacts
}

func knownEntitlementKeys(candidate candidateConfig) map[string]struct{} {
	keys := map[string]struct{}{}
	for _, resource := range allQuotaResources() {
		keys[resource] = struct{}{}
	}
	for _, metric := range candidate.MetricDefinitions {
		if key := strings.TrimSpace(metric.Key); key != "" {
			keys[key] = struct{}{}
		}
	}
	return keys
}

func knownMetricKeys(candidate candidateConfig) map[string]struct{} {
	keys := map[string]struct{}{}
	for _, key := range builtinMetricKeys() {
		keys[key] = struct{}{}
	}
	for _, metric := range candidate.MetricDefinitions {
		if key := strings.TrimSpace(metric.Key); key != "" {
			keys[key] = struct{}{}
		}
	}
	return keys
}

func planEntitlementKeys(candidate candidateConfig) map[string]struct{} {
	keys := map[string]struct{}{}
	for _, plan := range candidate.Plans {
		for _, ent := range plan.Entitlements {
			if key := strings.TrimSpace(ent.Key); key != "" {
				keys[key] = struct{}{}
			}
		}
	}
	return keys
}

func candidateHardLimits(candidate candidateConfig) map[string]int64 {
	limits := map[string]int64{}
	for _, plan := range candidate.Plans {
		for _, ent := range plan.Entitlements {
			if ent.LimitValue == nil || ent.EnforcementMode != string(store.EnforcementModeHard) {
				continue
			}
			key := strings.TrimSpace(ent.Key)
			if current, ok := limits[key]; !ok || *ent.LimitValue < current {
				limits[key] = *ent.LimitValue
			}
		}
	}
	return limits
}

func allQuotaResources() []string {
	return []string{
		store.QuotaResourceProjects.String(),
		store.QuotaResourceEnvironments.String(),
		store.QuotaResourceServices.String(),
		store.QuotaResourceApplications.String(),
		store.QuotaResourceComposeStacks.String(),
		store.QuotaResourceDatabases.String(),
		store.QuotaResourceDomains.String(),
		store.QuotaResourcePreviewEnvironments.String(),
		store.QuotaResourceCPUMillicores.String(),
		store.QuotaResourceMemoryMB.String(),
		store.QuotaResourceStorageGB.String(),
		store.QuotaResourceBackups.String(),
		store.QuotaResourceBackupSchedules.String(),
		store.QuotaResourceAPIKeys.String(),
		store.QuotaResourceMembers.String(),
		store.QuotaResourceConcurrentDeployments.String(),
		store.QuotaResourceMonthlyDeployments.String(),
		store.QuotaResourceDeployments.String(),
		store.QuotaResourceFailedDeployments.String(),
		store.QuotaResourceBuildMinutes.String(),
		store.QuotaResourceHTTPRequests.String(),
		store.QuotaResourceHTTPResponseBytes.String(),
		store.QuotaResourceHTTPRequestBytes.String(),
		store.QuotaResourceHTTPBandwidthTotal.String(),
		store.QuotaResourceContainerCPUMillicoreSeconds.String(),
		store.QuotaResourceContainerMemoryMBHours.String(),
		store.QuotaResourceStorageGBMonth.String(),
		store.QuotaResourceBackupStorageGBMonth.String(),
	}
}

func builtinMetricKeys() []string {
	keys := []string{
		"http_requests",
		"http_response_bytes",
		"http_request_bytes",
		"http_bandwidth_total",
		"container_cpu_millicore_seconds",
		"container_memory_mb_hours",
		"storage_gb_month",
		"backup_storage_gb_month",
		"build_minutes",
		"deployments",
	}
	sort.Strings(keys)
	return keys
}

func validEnforcementMode(mode string) bool {
	switch store.EnforcementMode(mode) {
	case store.EnforcementModeHard, store.EnforcementModeSoft, store.EnforcementModeMetered, store.EnforcementModeDisabled:
		return true
	default:
		return false
	}
}

func validMetricEnforcement(mode string) bool {
	switch metering.MetricEnforcement(mode) {
	case metering.MetricEnforcementHard, metering.MetricEnforcementSoft, metering.MetricEnforcementMetered, metering.MetricEnforcementHardOrMetered, metering.MetricEnforcementObservability:
		return true
	default:
		return false
	}
}

func safeToken(s string) bool {
	if s == "" || len(s) > 96 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func looksSecret(s string) bool {
	value := strings.TrimSpace(strings.ToLower(s))
	if value == "" {
		return false
	}
	return strings.HasPrefix(value, "yka_") ||
		strings.HasPrefix(value, "bearer ") ||
		strings.Contains(value, "://") ||
		strings.Contains(value, "token=") ||
		strings.Contains(value, "apikey=") ||
		strings.Contains(value, "api_key=") ||
		len(value) > 120
}

func blocking(code, field, message string) Issue {
	return Issue{Kind: "blocking_error", Code: code, Field: field, Message: message}
}

func warning(code, field, message string) Issue {
	return Issue{Kind: "warning", Code: code, Field: field, Message: message}
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// StoreImpactReader is a Postgres-backed impact simulator. It validates every
// selected organization and reads current-period usage counters without
// requiring live Dokploy.
type StoreImpactReader struct {
	store *store.Store
}

// NewStoreImpactReader returns a database-backed dry-run impact reader.
func NewStoreImpactReader(s *store.Store) (*StoreImpactReader, error) {
	if s == nil {
		return nil, errors.New("backoffice: nil store")
	}
	return &StoreImpactReader{store: s}, nil
}

// UsageByOrganization validates selected organization IDs and returns
// current-period usage quantities grouped by organization and key.
func (r *StoreImpactReader) UsageByOrganization(ctx context.Context, organizationIDs []string, at time.Time) (map[string]map[string]float64, error) {
	out := make(map[string]map[string]float64, len(organizationIDs))
	err := r.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		for _, orgID := range organizationIDs {
			var exists bool
			if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organizations WHERE id = $1)`, orgID).Scan(&exists); err != nil {
				return apierr.StoreUnavailable(err)
			}
			if !exists {
				return apierr.NotFound("organization", orgID)
			}
			rows, err := q.Query(ctx,
				`SELECT key, COALESCE(SUM(quantity), 0)::double precision
				   FROM usage_counters
				  WHERE organization_id = $1
				    AND period_start <= $2
				    AND period_end > $2
				  GROUP BY key
				  ORDER BY key`,
				orgID, at,
			)
			if err != nil {
				return apierr.StoreUnavailable(err)
			}
			usage := map[string]float64{}
			for rows.Next() {
				var key string
				var quantity float64
				if err := rows.Scan(&key, &quantity); err != nil {
					rows.Close()
					return apierr.StoreUnavailable(err)
				}
				usage[key] = quantity
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return apierr.StoreUnavailable(err)
			}
			rows.Close()
			out[orgID] = usage
		}
		return nil
	})
	return out, err
}

// RedactIssueMessages is a test helper and defensive projection for callers
// that need to guard against accidental secret reflection.
func RedactIssueMessages(result DryRunResult) DryRunResult {
	redactor := output.NewRedactor()
	for i := range result.Warnings {
		result.Warnings[i].Message = redactor.Redact(result.Warnings[i].Message)
	}
	for i := range result.BlockingErrors {
		result.BlockingErrors[i].Message = redactor.Redact(result.BlockingErrors[i].Message)
	}
	for i := range result.SimulatedOrganizations {
		result.SimulatedOrganizations[i].Message = redactor.Redact(result.SimulatedOrganizations[i].Message)
	}
	return result
}
