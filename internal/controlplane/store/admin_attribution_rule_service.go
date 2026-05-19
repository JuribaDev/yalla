package store

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
)

const adminAttributionRuleResourceKind = "attribution_rule"

// AdminAttributionRuleAuditContext carries operator identity for rule changes.
type AdminAttributionRuleAuditContext struct {
	ActorOrgID    string
	ActorID       string
	ActorKind     string
	RequestID     string
	CorrelationID string
	Reason        string
}

// AdminAttributionRuleService composes rule writes with immutable audit events.
type AdminAttributionRuleService struct {
	store *Store
	orgs  *OrganizationRepository
	rules *AttributionRuleRepository
	audit *AuditRepository
}

// NewAdminAttributionRuleService builds an audited attribution-rule manager.
func NewAdminAttributionRuleService(s *Store, orgs *OrganizationRepository, rules *AttributionRuleRepository, audit *AuditRepository) (*AdminAttributionRuleService, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	if orgs == nil {
		return nil, errors.New("store: nil organization repository")
	}
	if rules == nil {
		return nil, errors.New("store: nil attribution rule repository")
	}
	if audit == nil {
		return nil, errors.New("store: nil audit repository")
	}
	return &AdminAttributionRuleService{store: s, orgs: orgs, rules: rules, audit: audit}, nil
}

// UpsertAttributionRule creates or replaces one rule and records an audit row.
func (svc *AdminAttributionRuleService) UpsertAttributionRule(ctx context.Context, key string, in UpsertAttributionRuleInput, auditCtx AdminAttributionRuleAuditContext) (AttributionRule, error) {
	auditCtx, err := validateAdminAttributionRuleAuditContext(auditCtx)
	if err != nil {
		return AttributionRule{}, err
	}
	var out AttributionRule
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		rule, err := svc.rules.Upsert(ctx, tx, key, in)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, adminAttributionRuleAuditEvent(auditCtx, rule, "admin.attribution_rule.upsert", "upsert"))
		if err != nil {
			return err
		}
		out = rule
		return nil
	})
	if err != nil {
		return AttributionRule{}, err
	}
	return out, nil
}

// GetAttributionRule returns one current rule.
func (svc *AdminAttributionRuleService) GetAttributionRule(ctx context.Context, key string) (AttributionRule, error) {
	var out AttributionRule
	err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var err error
		out, err = svc.rules.Get(ctx, q, key)
		return err
	})
	if err != nil {
		return AttributionRule{}, err
	}
	return out, nil
}

// DryRunAttributionRules evaluates candidate or published rules without
// mutating state. Quarantined samples remain a successful dry-run result.
func (svc *AdminAttributionRuleService) DryRunAttributionRules(ctx context.Context, in AttributionDryRunInput) (AttributionDryRunResult, error) {
	if len(in.Samples) == 0 {
		return AttributionDryRunResult{}, apierr.InvalidInput(apierr.FieldViolation{Field: "samples", Reason: "must contain at least one sample"})
	}
	for i, sample := range in.Samples {
		if !sample.Source.valid() {
			return AttributionDryRunResult{}, apierr.InvalidInput(apierr.FieldViolation{Field: "samples[" + itoa(i) + "].source", Reason: "must be one of traefik, dokploy"})
		}
	}
	var rules []AttributionRule
	var err error
	if len(in.Rules) > 0 {
		rules, err = attributionRulesFromInputs(in.Rules)
		if err != nil {
			return AttributionDryRunResult{}, err
		}
	} else {
		err = svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
			var err error
			rules, err = svc.rules.ListRuntimeEnabled(ctx, q, time.Now().UTC())
			return err
		})
		if err != nil {
			return AttributionDryRunResult{}, err
		}
	}
	result := AttributionDryRunResult{
		Decisions: make([]AttributionDryRunDecision, 0, len(in.Samples)),
		Summary:   map[string]int{"attributed": 0, "quarantined": 0, "ignored": 0},
	}
	for i, sample := range in.Samples {
		decision := evaluateAttributionSample(i, sample, rules)
		if decision.Quarantined {
			result.Summary["quarantined"]++
		}
		if decision.Billable {
			result.Summary["attributed"]++
		}
		if !decision.Billable && !decision.Quarantined {
			result.Summary["ignored"]++
		}
		result.Decisions = append(result.Decisions, decision)
	}
	return result, nil
}

type attributionMatch struct {
	rule       AttributionRule
	serviceID  string
	dokployRef string
	confidence AttributionRuleConfidence
}

func evaluateAttributionSample(index int, sample AttributionDryRunSample, rules []AttributionRule) AttributionDryRunDecision {
	source := sample.Source
	matches := make([]attributionMatch, 0, 2)
	quarantineUnmatched := true
	for _, rule := range rules {
		if !rule.Enabled || rule.Source != source {
			continue
		}
		quarantineUnmatched = quarantineUnmatched && rule.QuarantineUnmatched
		if match, ok := rule.match(sample); ok {
			matches = append(matches, match)
		}
	}
	base := AttributionDryRunDecision{Index: index, MetricName: strings.TrimSpace(sample.MetricName), Source: source}
	if len(matches) == 0 {
		base.Reason = "unmatched"
		if quarantineUnmatched {
			base.Decision = "quarantine"
			base.Quarantined = true
		} else {
			base.Decision = "ignore"
		}
		return base
	}
	if ambiguousAttribution(matches) {
		base.Reason = "ambiguous"
		if matches[0].rule.QuarantineAmbiguous {
			base.Decision = "quarantine"
			base.Quarantined = true
		} else {
			base.Decision = "ignore"
		}
		return base
	}
	match := matches[0]
	base.RuleKey = match.rule.RuleKey
	base.Confidence = match.confidence
	base.ServiceID = match.serviceID
	base.DokployRef = match.dokployRef
	if !confidenceAtLeast(match.confidence, match.rule.MinConfidence) {
		base.Decision = "quarantine"
		base.Reason = "confidence_below_minimum"
		base.Quarantined = true
		return base
	}
	base.Decision = "attribute"
	base.Billable = true
	return base
}

func (r AttributionRule) match(sample AttributionDryRunSample) (attributionMatch, bool) {
	switch r.MatchKind {
	case AttributionRuleMatchTraefikServiceLabel:
		value := strings.TrimSpace(sample.Labels[r.LabelKey])
		if value == "" {
			return attributionMatch{}, false
		}
		return attributionMatch{rule: r, serviceID: normalizeAttributionServiceID(value), confidence: AttributionRuleConfidenceHigh}, true
	case AttributionRuleMatchDokployAppName:
		for _, value := range []string{sample.AppName, sample.Service, sample.Labels["appName"], sample.Labels["app_name"], sample.Labels["com.dokploy.appname"]} {
			if serviceID := serviceIDFromPattern(value, r.Pattern); serviceID != "" {
				return attributionMatch{rule: r, serviceID: serviceID, confidence: AttributionRuleConfidenceMedium}, true
			}
		}
	case AttributionRuleMatchExplicitDokployRef:
		ref := strings.TrimSpace(sample.DokployRefID)
		if ref == "" {
			ref = strings.TrimSpace(sample.Labels["dokploy_ref_id"])
		}
		if ref == "" {
			return attributionMatch{}, false
		}
		return attributionMatch{rule: r, dokployRef: ref, confidence: AttributionRuleConfidenceHigh}, true
	}
	return attributionMatch{}, false
}

func serviceIDFromPattern(value, pattern string) string {
	value = strings.TrimSpace(value)
	pattern = strings.TrimSpace(pattern)
	if value == "" || pattern == "" {
		return ""
	}
	if strings.Contains(pattern, "{service_id}") {
		prefix, suffix, _ := strings.Cut(pattern, "{service_id}")
		if strings.HasPrefix(value, prefix) && strings.HasSuffix(value, suffix) {
			id := strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix)
			return normalizeAttributionServiceID(id)
		}
		return ""
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	match := re.FindStringSubmatch(value)
	if len(match) < 2 {
		return ""
	}
	return normalizeAttributionServiceID(match[1])
}

func ambiguousAttribution(matches []attributionMatch) bool {
	if len(matches) < 2 {
		return false
	}
	firstService, firstRef := matches[0].serviceID, matches[0].dokployRef
	for _, match := range matches[1:] {
		if match.serviceID != firstService || match.dokployRef != firstRef {
			return true
		}
	}
	return false
}

func confidenceAtLeast(got, min AttributionRuleConfidence) bool {
	rank := map[AttributionRuleConfidence]int{
		AttributionRuleConfidenceLow:    1,
		AttributionRuleConfidenceMedium: 2,
		AttributionRuleConfidenceHigh:   3,
	}
	return rank[got] >= rank[min]
}

func normalizeAttributionServiceID(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "svc-") {
		return "svc_" + strings.TrimPrefix(value, "svc-")
	}
	return value
}

func validateAdminAttributionRuleAuditContext(in AdminAttributionRuleAuditContext) (AdminAttributionRuleAuditContext, error) {
	out := AdminAttributionRuleAuditContext{
		ActorOrgID:    strings.TrimSpace(in.ActorOrgID),
		ActorID:       strings.TrimSpace(in.ActorID),
		ActorKind:     strings.TrimSpace(in.ActorKind),
		RequestID:     strings.TrimSpace(in.RequestID),
		CorrelationID: strings.TrimSpace(in.CorrelationID),
		Reason:        strings.TrimSpace(in.Reason),
	}
	var violations []apierr.FieldViolation
	if out.ActorOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_org_id", Reason: "must not be blank"})
	}
	if out.ActorID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_id", Reason: "must not be blank"})
	}
	if out.ActorKind == "" {
		out.ActorKind = "user"
	}
	if out.RequestID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "request_id", Reason: "must not be blank"})
	}
	if out.CorrelationID == "" {
		out.CorrelationID = out.RequestID
	}
	if len(violations) > 0 {
		return AdminAttributionRuleAuditContext{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func adminAttributionRuleAuditEvent(auditCtx AdminAttributionRuleAuditContext, rule AttributionRule, action, operation string) AuditEvent {
	redactor := output.NewRedactor()
	return AuditEvent{
		OrganizationID: auditCtx.ActorOrgID,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditCtx.ActorKind,
		Action:         action,
		ResourceKind:   adminAttributionRuleResourceKind,
		ResourceID:     rule.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         redactor.Redact(auditCtx.Reason),
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
		Metadata: map[string]string{
			"operation":            operation,
			"rule_key":             rule.RuleKey,
			"source":               string(rule.Source),
			"match_kind":           string(rule.MatchKind),
			"min_confidence":       string(rule.MinConfidence),
			"enabled":              boolString(rule.Enabled),
			"quarantine_unmatched": boolString(rule.QuarantineUnmatched),
			"quarantine_ambiguous": boolString(rule.QuarantineAmbiguous),
			"reason":               redactor.Redact(auditCtx.Reason),
		},
	}
}
