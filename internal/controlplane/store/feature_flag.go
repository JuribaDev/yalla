package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// FeatureFlagValueType identifies the JSON variant a flag returns.
type FeatureFlagValueType string

const (
	// FeatureFlagBoolean returns a JSON boolean value.
	FeatureFlagBoolean FeatureFlagValueType = "boolean"
	// FeatureFlagString returns a JSON string value.
	FeatureFlagString FeatureFlagValueType = "string"
	// FeatureFlagNumber returns a JSON number value.
	FeatureFlagNumber FeatureFlagValueType = "number"
	// FeatureFlagJSON returns an arbitrary JSON value.
	FeatureFlagJSON FeatureFlagValueType = "json"
)

// FeatureFlagTargetScope identifies the highest matching scope for a rule.
type FeatureFlagTargetScope string

const (
	// FeatureFlagScopeGlobal applies to every evaluation context.
	FeatureFlagScopeGlobal FeatureFlagTargetScope = "global"
	// FeatureFlagScopePlan applies to one pricing plan.
	FeatureFlagScopePlan FeatureFlagTargetScope = "plan"
	// FeatureFlagScopeOrganization applies to one organization.
	FeatureFlagScopeOrganization FeatureFlagTargetScope = "organization"
	// FeatureFlagScopeProject applies to one project.
	FeatureFlagScopeProject FeatureFlagTargetScope = "project"
	// FeatureFlagScopeEnvironment applies to one environment.
	FeatureFlagScopeEnvironment FeatureFlagTargetScope = "environment"
	// FeatureFlagScopeService applies to one service.
	FeatureFlagScopeService FeatureFlagTargetScope = "service"
)

// FeatureFlagRule is one scoped override. RolloutPercentage is basis points:
// 10000 means 100%.
type FeatureFlagRule struct {
	Scope             FeatureFlagTargetScope `json:"scope"`
	PlanID            string                 `json:"plan_id,omitempty"`
	OrganizationID    string                 `json:"organization_id,omitempty"`
	ProjectID         string                 `json:"project_id,omitempty"`
	EnvironmentID     string                 `json:"environment_id,omitempty"`
	ServiceID         string                 `json:"service_id,omitempty"`
	Value             json.RawMessage        `json:"value"`
	RolloutPercentage int                    `json:"rollout_percentage,omitempty"`
}

// FeatureFlag is a global backoffice-owned runtime contract.
type FeatureFlag struct {
	ID                string
	FlagKey           string
	ValueType         FeatureFlagValueType
	DefaultValue      json.RawMessage
	TargetingRules    []FeatureFlagRule
	RolloutPercentage int
	AdminSensitive    bool
	Enabled           bool
	Revision          int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// UpsertFeatureFlagInput is the backoffice write contract.
type UpsertFeatureFlagInput struct {
	ValueType         FeatureFlagValueType
	DefaultValue      json.RawMessage
	TargetingRules    []FeatureFlagRule
	RolloutPercentage int
	AdminSensitive    bool
	Enabled           bool
}

// FeatureFlagEvaluationContext names the runtime subject being evaluated.
type FeatureFlagEvaluationContext struct {
	PlanID         string `json:"plan_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	EnvironmentID  string `json:"environment_id,omitempty"`
	ServiceID      string `json:"service_id,omitempty"`
	SubjectID      string `json:"subject_id,omitempty"`
}

// FeatureFlagEvaluation reports the deterministic result for one flag.
type FeatureFlagEvaluation struct {
	FlagKey            string          `json:"flag_key"`
	ValueType          string          `json:"value_type"`
	Value              json.RawMessage `json:"value"`
	Enabled            bool            `json:"enabled"`
	MatchedScope       string          `json:"matched_scope"`
	MatchedRuleIndex   int             `json:"matched_rule_index"`
	RolloutPercentage  int             `json:"rollout_percentage"`
	RolloutIncluded    bool            `json:"rollout_included"`
	AdminSensitive     bool            `json:"admin_sensitive"`
	Revision           int64           `json:"revision"`
	EvaluationAudited  bool            `json:"evaluation_audited"`
	SafeDefaultApplied bool            `json:"safe_default_applied"`
}

// FeatureFlagRepository persists global feature flags.
type FeatureFlagRepository struct{}

// NewFeatureFlagRepository returns a stateless repository.
func NewFeatureFlagRepository() *FeatureFlagRepository { return &FeatureFlagRepository{} }

const featureFlagColumns = `id, flag_key, value_type, default_value, targeting_rules, rollout_percentage, admin_sensitive, enabled, revision, created_at, updated_at`

var featureFlagKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)

// Upsert creates or replaces one feature flag.
func (r *FeatureFlagRepository) Upsert(ctx context.Context, tx *Tx, key string, in UpsertFeatureFlagInput) (FeatureFlag, error) {
	if tx == nil {
		return FeatureFlag{}, apierr.Internal(errors.New("store: FeatureFlagRepository.Upsert called with a nil transaction"))
	}
	key, input, err := validateFeatureFlagUpsert(key, in)
	if err != nil {
		return FeatureFlag{}, err
	}
	id, err := newOpaqueStoreID("fflag")
	if err != nil {
		return FeatureFlag{}, apierr.Internal(err)
	}
	rules, err := json.Marshal(input.TargetingRules)
	if err != nil {
		return FeatureFlag{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO admin_feature_flags
		    (id, flag_key, value_type, default_value, targeting_rules, rollout_percentage, admin_sensitive, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (flag_key) DO UPDATE
		    SET value_type = EXCLUDED.value_type,
		        default_value = EXCLUDED.default_value,
		        targeting_rules = EXCLUDED.targeting_rules,
		        rollout_percentage = EXCLUDED.rollout_percentage,
		        admin_sensitive = EXCLUDED.admin_sensitive,
		        enabled = EXCLUDED.enabled,
		        revision = admin_feature_flags.revision + 1
		 RETURNING `+featureFlagColumns,
		id, key, input.ValueType, input.DefaultValue, rules, input.RolloutPercentage, input.AdminSensitive, input.Enabled)
	out, scanErr := scanFeatureFlag(row)
	if scanErr != nil {
		return FeatureFlag{}, mapWriteError(scanErr, "the feature flag could not be saved")
	}
	return out, nil
}

// Get returns a configured feature flag by stable key.
func (r *FeatureFlagRepository) Get(ctx context.Context, q Querier, key string) (FeatureFlag, error) {
	key = strings.TrimSpace(key)
	out, err := scanFeatureFlag(q.QueryRow(ctx,
		`SELECT `+featureFlagColumns+`
		   FROM admin_feature_flags
		  WHERE flag_key = $1`,
		key))
	if errors.Is(err, pgx.ErrNoRows) {
		return FeatureFlag{}, apierr.NotFound("feature_flag", key)
	}
	if err != nil {
		return FeatureFlag{}, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// ListRuntimeEnabled returns enabled flags in deterministic key order.
func (r *FeatureFlagRepository) ListRuntimeEnabled(ctx context.Context, q Querier, _ time.Time) ([]FeatureFlag, error) {
	rows, err := q.Query(ctx,
		`SELECT `+featureFlagColumns+`
		   FROM admin_feature_flags
		  WHERE enabled = true
		  ORDER BY flag_key ASC`)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	var out []FeatureFlag
	for rows.Next() {
		flag, scanErr := scanFeatureFlag(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, flag)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

func validateFeatureFlagUpsert(key string, in UpsertFeatureFlagInput) (string, UpsertFeatureFlagInput, error) {
	key = strings.TrimSpace(key)
	var violations []apierr.FieldViolation
	if !featureFlagKeyPattern.MatchString(key) {
		violations = append(violations, apierr.FieldViolation{Field: "flag_key", Reason: "must be a stable lowercase feature key"})
	}
	if !in.ValueType.valid() {
		violations = append(violations, apierr.FieldViolation{Field: "value_type", Reason: "must be one of boolean, string, number, json"})
	}
	if len(in.DefaultValue) == 0 {
		if in.ValueType == FeatureFlagBoolean {
			in.DefaultValue = json.RawMessage("false")
		} else {
			violations = append(violations, apierr.FieldViolation{Field: "default_value", Reason: "must be valid JSON for this value_type"})
		}
	}
	if len(in.DefaultValue) > 0 && !json.Valid(in.DefaultValue) {
		violations = append(violations, apierr.FieldViolation{Field: "default_value", Reason: "must be valid JSON"})
	}
	if json.Valid(in.DefaultValue) && !featureFlagValueMatchesType(in.ValueType, in.DefaultValue) {
		violations = append(violations, apierr.FieldViolation{Field: "default_value", Reason: "must match value_type"})
	}
	if in.RolloutPercentage < 0 || in.RolloutPercentage > 10000 {
		violations = append(violations, apierr.FieldViolation{Field: "rollout_percentage", Reason: "must be between 0 and 10000"})
	}
	for i := range in.TargetingRules {
		normalizeFeatureFlagRule(&in.TargetingRules[i])
		field := "targeting_rules[" + itoa(i) + "]"
		if !in.TargetingRules[i].Scope.valid() {
			violations = append(violations, apierr.FieldViolation{Field: field + ".scope", Reason: "must be one of global, plan, organization, project, environment, service"})
		}
		if len(in.TargetingRules[i].Value) == 0 || !json.Valid(in.TargetingRules[i].Value) {
			violations = append(violations, apierr.FieldViolation{Field: field + ".value", Reason: "must be valid JSON"})
		} else if !featureFlagValueMatchesType(in.ValueType, in.TargetingRules[i].Value) {
			violations = append(violations, apierr.FieldViolation{Field: field + ".value", Reason: "must match value_type"})
		}
		if in.TargetingRules[i].RolloutPercentage < 0 || in.TargetingRules[i].RolloutPercentage > 10000 {
			violations = append(violations, apierr.FieldViolation{Field: field + ".rollout_percentage", Reason: "must be between 0 and 10000"})
		}
		if err := validateFeatureFlagRuleScope(field, in.TargetingRules[i]); err != nil {
			violations = append(violations, err...)
		}
	}
	if len(violations) > 0 {
		return "", UpsertFeatureFlagInput{}, apierr.InvalidInput(violations...)
	}
	return key, in, nil
}

func normalizeFeatureFlagRule(rule *FeatureFlagRule) {
	rule.Scope = FeatureFlagTargetScope(strings.TrimSpace(string(rule.Scope)))
	rule.PlanID = strings.TrimSpace(rule.PlanID)
	rule.OrganizationID = strings.TrimSpace(rule.OrganizationID)
	rule.ProjectID = strings.TrimSpace(rule.ProjectID)
	rule.EnvironmentID = strings.TrimSpace(rule.EnvironmentID)
	rule.ServiceID = strings.TrimSpace(rule.ServiceID)
}

func validateFeatureFlagRuleScope(field string, rule FeatureFlagRule) []apierr.FieldViolation {
	required := ""
	switch rule.Scope {
	case FeatureFlagScopePlan:
		required = "plan_id"
	case FeatureFlagScopeOrganization:
		required = "organization_id"
	case FeatureFlagScopeProject:
		required = "project_id"
	case FeatureFlagScopeEnvironment:
		required = "environment_id"
	case FeatureFlagScopeService:
		required = "service_id"
	case FeatureFlagScopeGlobal:
		return nil
	default:
		return nil
	}
	values := map[string]string{
		"plan_id":         rule.PlanID,
		"organization_id": rule.OrganizationID,
		"project_id":      rule.ProjectID,
		"environment_id":  rule.EnvironmentID,
		"service_id":      rule.ServiceID,
	}
	if values[required] == "" {
		return []apierr.FieldViolation{{Field: field + "." + required, Reason: "must not be blank for this scope"}}
	}
	return nil
}

func featureFlagValueMatchesType(t FeatureFlagValueType, raw json.RawMessage) bool {
	var v any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return false
	}
	switch t {
	case FeatureFlagBoolean:
		_, ok := v.(bool)
		return ok
	case FeatureFlagString:
		_, ok := v.(string)
		return ok
	case FeatureFlagNumber:
		_, ok := v.(json.Number)
		return ok
	case FeatureFlagJSON:
		return true
	default:
		return false
	}
}

func (t FeatureFlagValueType) valid() bool {
	switch t {
	case FeatureFlagBoolean, FeatureFlagString, FeatureFlagNumber, FeatureFlagJSON:
		return true
	default:
		return false
	}
}

func (s FeatureFlagTargetScope) valid() bool {
	switch s {
	case FeatureFlagScopeGlobal, FeatureFlagScopePlan, FeatureFlagScopeOrganization, FeatureFlagScopeProject, FeatureFlagScopeEnvironment, FeatureFlagScopeService:
		return true
	default:
		return false
	}
}

func scanFeatureFlag(row pgx.Row) (FeatureFlag, error) {
	var out FeatureFlag
	var def []byte
	var rulesBytes []byte
	if err := row.Scan(&out.ID, &out.FlagKey, &out.ValueType, &def, &rulesBytes, &out.RolloutPercentage, &out.AdminSensitive, &out.Enabled, &out.Revision, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return FeatureFlag{}, err
	}
	out.DefaultValue = append(json.RawMessage(nil), def...)
	if len(rulesBytes) > 0 {
		if err := json.Unmarshal(rulesBytes, &out.TargetingRules); err != nil {
			return FeatureFlag{}, err
		}
	}
	return out, nil
}

func evaluateFeatureFlag(flag FeatureFlag, ctx FeatureFlagEvaluationContext) FeatureFlagEvaluation {
	ctx = normalizeFeatureFlagEvaluationContext(ctx)
	value := append(json.RawMessage(nil), flag.DefaultValue...)
	matchedScope := "default"
	matchedRuleIndex := -1
	rollout := flag.RolloutPercentage
	rule, idx, ok := bestFeatureFlagRule(flag.TargetingRules, ctx)
	if ok {
		value = append(json.RawMessage(nil), rule.Value...)
		matchedScope = string(rule.Scope)
		matchedRuleIndex = idx
		rollout = rule.RolloutPercentage
	}
	included := rolloutIncluded(flag.FlagKey, ctx.rolloutSubject(), rollout)
	if !included {
		value = append(json.RawMessage(nil), flag.DefaultValue...)
		matchedScope = "default"
		matchedRuleIndex = -1
	}
	return FeatureFlagEvaluation{
		FlagKey:           flag.FlagKey,
		ValueType:         string(flag.ValueType),
		Value:             value,
		Enabled:           flag.Enabled,
		MatchedScope:      matchedScope,
		MatchedRuleIndex:  matchedRuleIndex,
		RolloutPercentage: rollout,
		RolloutIncluded:   included,
		AdminSensitive:    flag.AdminSensitive,
		Revision:          flag.Revision,
	}
}

func bestFeatureFlagRule(rules []FeatureFlagRule, ctx FeatureFlagEvaluationContext) (FeatureFlagRule, int, bool) {
	type match struct {
		rule  FeatureFlagRule
		index int
		rank  int
	}
	matches := make([]match, 0, len(rules))
	for i, rule := range rules {
		if rank, ok := ruleMatchesFeatureFlagContext(rule, ctx); ok {
			matches = append(matches, match{rule: rule, index: i, rank: rank})
		}
	}
	if len(matches) == 0 {
		return FeatureFlagRule{}, -1, false
	}
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].rank > matches[j].rank })
	return matches[0].rule, matches[0].index, true
}

func ruleMatchesFeatureFlagContext(rule FeatureFlagRule, ctx FeatureFlagEvaluationContext) (int, bool) {
	switch rule.Scope {
	case FeatureFlagScopeService:
		return 6, rule.ServiceID != "" && rule.ServiceID == ctx.ServiceID
	case FeatureFlagScopeEnvironment:
		return 5, rule.EnvironmentID != "" && rule.EnvironmentID == ctx.EnvironmentID
	case FeatureFlagScopeProject:
		return 4, rule.ProjectID != "" && rule.ProjectID == ctx.ProjectID
	case FeatureFlagScopeOrganization:
		return 3, rule.OrganizationID != "" && rule.OrganizationID == ctx.OrganizationID
	case FeatureFlagScopePlan:
		return 2, rule.PlanID != "" && rule.PlanID == ctx.PlanID
	case FeatureFlagScopeGlobal:
		return 1, true
	default:
		return 0, false
	}
}

func normalizeFeatureFlagEvaluationContext(ctx FeatureFlagEvaluationContext) FeatureFlagEvaluationContext {
	ctx.PlanID = strings.TrimSpace(ctx.PlanID)
	ctx.OrganizationID = strings.TrimSpace(ctx.OrganizationID)
	ctx.ProjectID = strings.TrimSpace(ctx.ProjectID)
	ctx.EnvironmentID = strings.TrimSpace(ctx.EnvironmentID)
	ctx.ServiceID = strings.TrimSpace(ctx.ServiceID)
	ctx.SubjectID = strings.TrimSpace(ctx.SubjectID)
	return ctx
}

func (ctx FeatureFlagEvaluationContext) rolloutSubject() string {
	for _, v := range []string{ctx.SubjectID, ctx.ServiceID, ctx.EnvironmentID, ctx.ProjectID, ctx.OrganizationID, ctx.PlanID} {
		if v != "" {
			return v
		}
	}
	return "global"
}

func rolloutIncluded(flagKey, subject string, pct int) bool {
	if pct >= 10000 {
		return true
	}
	if pct <= 0 {
		return false
	}
	sum := sha256.Sum256([]byte(flagKey + "\x00" + subject))
	bucket := int(binary.BigEndian.Uint32(sum[:4]) % 10000)
	return bucket < pct
}
