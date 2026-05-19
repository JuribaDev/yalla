package store

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// AttributionRuleSource identifies the metering source a rule can evaluate.
type AttributionRuleSource string

const (
	// AttributionRuleSourceTraefik evaluates metrics collected from Traefik.
	AttributionRuleSourceTraefik AttributionRuleSource = "traefik"
	// AttributionRuleSourceDokploy evaluates private Dokploy operational labels.
	AttributionRuleSourceDokploy AttributionRuleSource = "dokploy"
)

// AttributionRuleMatchKind identifies the stable extraction strategy.
type AttributionRuleMatchKind string

const (
	// AttributionRuleMatchTraefikServiceLabel extracts a Yalla service id from a label value.
	AttributionRuleMatchTraefikServiceLabel AttributionRuleMatchKind = "traefik_service_label"
	// AttributionRuleMatchDokployAppName extracts a service id from a Dokploy appName pattern.
	AttributionRuleMatchDokployAppName AttributionRuleMatchKind = "dokploy_app_name_pattern"
	// AttributionRuleMatchExplicitDokployRef trusts an explicit dokploy_refs identifier.
	AttributionRuleMatchExplicitDokployRef AttributionRuleMatchKind = "explicit_dokploy_ref"
)

// AttributionRuleConfidence is the minimum trust level required for billing.
type AttributionRuleConfidence string

const (
	// AttributionRuleConfidenceLow is the lowest accepted dry-run confidence.
	AttributionRuleConfidenceLow AttributionRuleConfidence = "low"
	// AttributionRuleConfidenceMedium is used for deterministic name-derived attribution.
	AttributionRuleConfidenceMedium AttributionRuleConfidence = "medium"
	// AttributionRuleConfidenceHigh is used for explicit source-of-truth labels or refs.
	AttributionRuleConfidenceHigh AttributionRuleConfidence = "high"
)

// AttributionRule is a global backoffice-owned attribution contract.
type AttributionRule struct {
	ID                  string
	RuleKey             string
	Source              AttributionRuleSource
	Priority            int
	MatchKind           AttributionRuleMatchKind
	LabelKey            string
	Pattern             string
	DokployResource     string
	MinConfidence       AttributionRuleConfidence
	QuarantineUnmatched bool
	QuarantineAmbiguous bool
	Enabled             bool
	Revision            int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// UpsertAttributionRuleInput is the validated write contract for rules.
type UpsertAttributionRuleInput struct {
	Source              AttributionRuleSource
	Priority            int
	MatchKind           AttributionRuleMatchKind
	LabelKey            string
	Pattern             string
	DokployResource     string
	MinConfidence       AttributionRuleConfidence
	QuarantineUnmatched bool
	QuarantineAmbiguous bool
	Enabled             bool
}

// AttributionDryRunSample is a side-effect-free sample evaluated against rules.
type AttributionDryRunSample struct {
	Source       AttributionRuleSource `json:"source"`
	MetricName   string                `json:"metric_name"`
	Service      string                `json:"service,omitempty"`
	AppName      string                `json:"app_name,omitempty"`
	DokployRefID string                `json:"dokploy_ref_id,omitempty"`
	Labels       map[string]string     `json:"labels,omitempty"`
}

// AttributionDryRunInput evaluates candidate rules without publishing them.
type AttributionDryRunInput struct {
	Rules   []UpsertAttributionRuleInput `json:"rules,omitempty"`
	Samples []AttributionDryRunSample    `json:"samples"`
}

// AttributionDryRunDecision is the stable dry-run result for one sample.
type AttributionDryRunDecision struct {
	Index       int                       `json:"index"`
	MetricName  string                    `json:"metric_name"`
	Decision    string                    `json:"decision"`
	Reason      string                    `json:"reason,omitempty"`
	RuleKey     string                    `json:"rule_key,omitempty"`
	Source      AttributionRuleSource     `json:"source"`
	Confidence  AttributionRuleConfidence `json:"confidence,omitempty"`
	ServiceID   string                    `json:"service_id,omitempty"`
	DokployRef  string                    `json:"dokploy_ref_id,omitempty"`
	Billable    bool                      `json:"billable"`
	Quarantined bool                      `json:"quarantined"`
}

// AttributionDryRunResult reports deterministic attribution and quarantine
// decisions. A well-shaped dry-run with quarantined samples is still success.
type AttributionDryRunResult struct {
	Decisions []AttributionDryRunDecision `json:"decisions"`
	Summary   map[string]int              `json:"summary"`
}

// AttributionRuleRepository persists global attribution rules.
type AttributionRuleRepository struct{}

// NewAttributionRuleRepository returns a stateless rule repository.
func NewAttributionRuleRepository() *AttributionRuleRepository { return &AttributionRuleRepository{} }

const attributionRuleColumns = `id, rule_key, source, priority, match_kind, label_key, pattern, dokploy_resource, min_confidence, quarantine_unmatched, quarantine_ambiguous, enabled, revision, created_at, updated_at`

var attributionRuleKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Upsert creates or replaces one attribution rule.
func (r *AttributionRuleRepository) Upsert(ctx context.Context, tx *Tx, key string, in UpsertAttributionRuleInput) (AttributionRule, error) {
	if tx == nil {
		return AttributionRule{}, apierr.Internal(errors.New("store: AttributionRuleRepository.Upsert called with a nil transaction"))
	}
	key, input, err := validateAttributionRuleUpsert(key, in)
	if err != nil {
		return AttributionRule{}, err
	}
	id, err := newOpaqueStoreID("arule")
	if err != nil {
		return AttributionRule{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO admin_attribution_rules
		    (id, rule_key, source, priority, match_kind, label_key, pattern, dokploy_resource,
		     min_confidence, quarantine_unmatched, quarantine_ambiguous, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT (rule_key) DO UPDATE
		    SET source = EXCLUDED.source,
		        priority = EXCLUDED.priority,
		        match_kind = EXCLUDED.match_kind,
		        label_key = EXCLUDED.label_key,
		        pattern = EXCLUDED.pattern,
		        dokploy_resource = EXCLUDED.dokploy_resource,
		        min_confidence = EXCLUDED.min_confidence,
		        quarantine_unmatched = EXCLUDED.quarantine_unmatched,
		        quarantine_ambiguous = EXCLUDED.quarantine_ambiguous,
		        enabled = EXCLUDED.enabled,
		        revision = admin_attribution_rules.revision + 1
		 RETURNING `+attributionRuleColumns,
		id, key, input.Source, input.Priority, input.MatchKind, input.LabelKey, input.Pattern, input.DokployResource,
		input.MinConfidence, input.QuarantineUnmatched, input.QuarantineAmbiguous, input.Enabled)
	rule, err := scanAttributionRule(row)
	if err != nil {
		return AttributionRule{}, mapWriteError(err, "the attribution rule could not be saved")
	}
	return rule, nil
}

// Get returns a configured attribution rule by stable key.
func (r *AttributionRuleRepository) Get(ctx context.Context, q Querier, key string) (AttributionRule, error) {
	key = strings.TrimSpace(key)
	rule, err := scanAttributionRule(q.QueryRow(ctx,
		`SELECT `+attributionRuleColumns+`
		   FROM admin_attribution_rules
		  WHERE rule_key = $1`,
		key))
	if errors.Is(err, pgx.ErrNoRows) {
		return AttributionRule{}, apierr.NotFound("attribution_rule", key)
	}
	if err != nil {
		return AttributionRule{}, apierr.StoreUnavailable(err)
	}
	return rule, nil
}

// ListRuntimeEnabled returns enabled rules in deterministic evaluation order.
func (r *AttributionRuleRepository) ListRuntimeEnabled(ctx context.Context, q Querier, _ time.Time) ([]AttributionRule, error) {
	rows, err := q.Query(ctx,
		`SELECT `+attributionRuleColumns+`
		   FROM admin_attribution_rules
		  WHERE enabled = true
		  ORDER BY priority ASC, rule_key ASC`)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	var out []AttributionRule
	for rows.Next() {
		rule, scanErr := scanAttributionRule(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

func validateAttributionRuleUpsert(key string, in UpsertAttributionRuleInput) (string, UpsertAttributionRuleInput, error) {
	key = strings.TrimSpace(key)
	var violations []apierr.FieldViolation
	if !attributionRuleKeyPattern.MatchString(key) {
		violations = append(violations, apierr.FieldViolation{Field: "rule_key", Reason: "must be a lowercase slug"})
	}
	if !in.Source.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "source", Reason: "must be one of traefik, dokploy"})
	}
	if in.Priority == 0 {
		in.Priority = 100
	}
	if in.Priority < 1 || in.Priority > 10000 {
		violations = append(violations, apierr.FieldViolation{Field: "priority", Reason: "must be between 1 and 10000"})
	}
	if !in.MatchKind.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "match_kind", Reason: "must be one of traefik_service_label, dokploy_app_name_pattern, explicit_dokploy_ref"})
	}
	in.LabelKey = strings.TrimSpace(in.LabelKey)
	in.Pattern = strings.TrimSpace(in.Pattern)
	in.DokployResource = strings.TrimSpace(in.DokployResource)
	if in.MinConfidence == "" {
		in.MinConfidence = AttributionRuleConfidenceMedium
	}
	if !in.MinConfidence.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "min_confidence", Reason: "must be one of low, medium, high"})
	}
	switch in.MatchKind {
	case AttributionRuleMatchTraefikServiceLabel:
		if in.LabelKey == "" {
			violations = append(violations, apierr.FieldViolation{Field: "label_key", Reason: "must not be blank for traefik service label rules"})
		}
		if in.Pattern != "" || in.DokployResource != "" {
			violations = append(violations, apierr.FieldViolation{Field: "match_kind", Reason: "traefik service label rules cannot set pattern or dokploy_resource"})
		}
	case AttributionRuleMatchDokployAppName:
		if in.Pattern == "" {
			violations = append(violations, apierr.FieldViolation{Field: "pattern", Reason: "must not be blank for Dokploy appName rules"})
		}
		if in.LabelKey != "" || in.DokployResource != "" {
			violations = append(violations, apierr.FieldViolation{Field: "match_kind", Reason: "Dokploy appName rules cannot set label_key or dokploy_resource"})
		}
	case AttributionRuleMatchExplicitDokployRef:
		switch in.DokployResource {
		case "application", "compose", "database":
		default:
			violations = append(violations, apierr.FieldViolation{Field: "dokploy_resource", Reason: "must be one of application, compose, database"})
		}
		if in.LabelKey != "" || in.Pattern != "" {
			violations = append(violations, apierr.FieldViolation{Field: "match_kind", Reason: "explicit dokploy_ref rules cannot set label_key or pattern"})
		}
	}
	if len(violations) > 0 {
		return "", UpsertAttributionRuleInput{}, apierr.InvalidInput(violations...)
	}
	return key, in, nil
}

func (s AttributionRuleSource) valid() bool {
	switch s {
	case AttributionRuleSourceTraefik, AttributionRuleSourceDokploy:
		return true
	default:
		return false
	}
}

func (k AttributionRuleMatchKind) valid() bool {
	switch k {
	case AttributionRuleMatchTraefikServiceLabel, AttributionRuleMatchDokployAppName, AttributionRuleMatchExplicitDokployRef:
		return true
	default:
		return false
	}
}

func (c AttributionRuleConfidence) valid() bool {
	switch c {
	case AttributionRuleConfidenceLow, AttributionRuleConfidenceMedium, AttributionRuleConfidenceHigh:
		return true
	default:
		return false
	}
}

func scanAttributionRule(row pgx.Row) (AttributionRule, error) {
	var rule AttributionRule
	if err := row.Scan(
		&rule.ID,
		&rule.RuleKey,
		&rule.Source,
		&rule.Priority,
		&rule.MatchKind,
		&rule.LabelKey,
		&rule.Pattern,
		&rule.DokployResource,
		&rule.MinConfidence,
		&rule.QuarantineUnmatched,
		&rule.QuarantineAmbiguous,
		&rule.Enabled,
		&rule.Revision,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	); err != nil {
		return AttributionRule{}, err
	}
	return rule, nil
}

func attributionRulesFromInputs(inputs []UpsertAttributionRuleInput) ([]AttributionRule, error) {
	out := make([]AttributionRule, 0, len(inputs))
	for i, in := range inputs {
		key := "candidate-" + itoa(i+1)
		key, normalized, err := validateAttributionRuleUpsert(key, in)
		if err != nil {
			return nil, err
		}
		out = append(out, AttributionRule{
			RuleKey:             key,
			Source:              normalized.Source,
			Priority:            normalized.Priority,
			MatchKind:           normalized.MatchKind,
			LabelKey:            normalized.LabelKey,
			Pattern:             normalized.Pattern,
			DokployResource:     normalized.DokployResource,
			MinConfidence:       normalized.MinConfidence,
			QuarantineUnmatched: normalized.QuarantineUnmatched,
			QuarantineAmbiguous: normalized.QuarantineAmbiguous,
			Enabled:             normalized.Enabled,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority == out[j].Priority {
			return out[i].RuleKey < out[j].RuleKey
		}
		return out[i].Priority < out[j].Priority
	})
	return out, nil
}
