package store

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/output"
)

const adminMeteringSourceResourceKind = "metering_source"

// AdminMeteringSourceAuditContext carries operator identity for metering
// source changes and connection tests.
type AdminMeteringSourceAuditContext struct {
	ActorOrgID    string
	ActorID       string
	ActorKind     string
	RequestID     string
	CorrelationID string
	Reason        string
}

// AdminMeteringSourceService composes metering source writes with encrypted
// credential handling and immutable audit records.
type AdminMeteringSourceService struct {
	store    *Store
	orgs     *OrganizationRepository
	sources  *MeteringSourceRepository
	audit    *AuditRepository
	provider secrets.Provider
	client   *http.Client
}

// NewAdminMeteringSourceService builds an audited source manager.
func NewAdminMeteringSourceService(s *Store, orgs *OrganizationRepository, sources *MeteringSourceRepository, audit *AuditRepository, provider secrets.Provider) (*AdminMeteringSourceService, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	if orgs == nil {
		return nil, errors.New("store: nil organization repository")
	}
	if sources == nil {
		return nil, errors.New("store: nil metering source repository")
	}
	if audit == nil {
		return nil, errors.New("store: nil audit repository")
	}
	if provider == nil {
		return nil, errors.New("store: nil secrets provider")
	}
	return &AdminMeteringSourceService{store: s, orgs: orgs, sources: sources, audit: audit, provider: provider, client: http.DefaultClient}, nil
}

// UpsertMeteringSource creates or replaces one source config. CredentialValue
// is write-only and is sealed before the transaction opens.
func (svc *AdminMeteringSourceService) UpsertMeteringSource(ctx context.Context, key string, in UpsertMeteringSourceInput, auditCtx AdminMeteringSourceAuditContext) (MeteringSource, error) {
	auditCtx, err := validateAdminMeteringSourceAuditContext(auditCtx)
	if err != nil {
		return MeteringSource{}, err
	}
	credential, err := svc.sealMeteringCredential(in.CredentialValue)
	if err != nil {
		return MeteringSource{}, err
	}
	redactor := output.NewRedactor(pointerString(in.CredentialValue))
	var out MeteringSource
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		source, err := svc.sources.Upsert(ctx, tx, key, in, credential)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, adminMeteringSourceAuditEvent(auditCtx, source, "admin.metering_source.upsert", "upsert", redactor))
		if err != nil {
			return err
		}
		out = source
		return nil
	})
	if err != nil {
		return MeteringSource{}, err
	}
	return out, nil
}

// AuditMeteringSourceTest records a side-effect-free connection test result.
func (svc *AdminMeteringSourceService) AuditMeteringSourceTest(ctx context.Context, source MeteringSource, auditCtx AdminMeteringSourceAuditContext, status string) error {
	auditCtx, err := validateAdminMeteringSourceAuditContext(auditCtx)
	if err != nil {
		return err
	}
	status = strings.TrimSpace(status)
	if status == "" {
		status = "unknown"
	}
	return svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		if _, err := svc.sources.Get(ctx, tx, source.SourceKey); err != nil {
			return err
		}
		event := adminMeteringSourceAuditEvent(auditCtx, source, "admin.metering_source.test", "test", output.NewRedactor())
		event.Metadata["status"] = status
		_, err := svc.audit.Append(ctx, tx, event)
		return err
	})
}

// TestMeteringSource performs a side-effect-free HTTP reachability probe
// against the configured endpoint and audits the result.
func (svc *AdminMeteringSourceService) TestMeteringSource(ctx context.Context, key string, in MeteringSourceTestInput, auditCtx AdminMeteringSourceAuditContext) (MeteringSourceTestResult, error) {
	auditCtx, err := validateAdminMeteringSourceAuditContext(auditCtx)
	if err != nil {
		return MeteringSourceTestResult{}, err
	}
	var source MeteringSource
	if err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var err error
		source, err = svc.sources.Get(ctx, q, key)
		return err
	}); err != nil {
		return MeteringSourceTestResult{}, err
	}
	timeout := time.Duration(source.TimeoutSeconds) * time.Second
	if in.TimeoutSeconds > 0 {
		if in.TimeoutSeconds > 300 {
			return MeteringSourceTestResult{}, apierr.InvalidInput(apierr.FieldViolation{Field: "timeout_seconds", Reason: "must be between 1 and 300"})
		}
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
	}
	started := time.Now().UTC()
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodHead, source.EndpointURL, nil)
	if err != nil {
		return MeteringSourceTestResult{}, apierr.InvalidInput(apierr.FieldViolation{Field: "endpoint_url", Reason: "must be a valid URL"})
	}
	resp, err := svc.client.Do(req)
	latency := time.Since(started).Milliseconds()
	result := MeteringSourceTestResult{
		SourceKey:     source.SourceKey,
		Status:        "ok",
		CheckedAt:     started,
		LatencyMillis: latency,
	}
	if err != nil {
		result.Status = "failed"
		result.Message = output.NewRedactor().Redact(err.Error())
	} else {
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			result.Status = "failed"
			result.Message = "source returned HTTP " + itoa(resp.StatusCode)
		}
	}
	if auditErr := svc.AuditMeteringSourceTest(ctx, source, auditCtx, result.Status); auditErr != nil {
		return MeteringSourceTestResult{}, auditErr
	}
	return result, nil
}

func (svc *AdminMeteringSourceService) sealMeteringCredential(value *string) (MeteringSourceCredential, error) {
	if value == nil {
		return MeteringSourceCredential{}, nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return MeteringSourceCredential{Touched: true}, nil
	}
	ciphertext, keyID, err := svc.provider.Seal([]byte(*value))
	if err != nil {
		return MeteringSourceCredential{}, apierr.SecretDecryption(err)
	}
	return MeteringSourceCredential{
		Touched:          true,
		SecretProvider:   svc.provider.ProviderID(),
		SecretKeyID:      keyID,
		SecretCiphertext: ciphertext,
	}, nil
}

func validateAdminMeteringSourceAuditContext(in AdminMeteringSourceAuditContext) (AdminMeteringSourceAuditContext, error) {
	out := AdminMeteringSourceAuditContext{
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
		return AdminMeteringSourceAuditContext{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func adminMeteringSourceAuditEvent(auditCtx AdminMeteringSourceAuditContext, source MeteringSource, action, operation string, redactor *output.Redactor) AuditEvent {
	if redactor == nil {
		redactor = output.NewRedactor()
	}
	return AuditEvent{
		OrganizationID: auditCtx.ActorOrgID,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditEventActorKind(auditCtx.ActorKind),
		Action:         action,
		ResourceKind:   adminMeteringSourceResourceKind,
		ResourceID:     source.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         redactor.Redact(auditCtx.Reason),
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
		Metadata: map[string]string{
			"operation":               operation,
			"source_key":              source.SourceKey,
			"source_type":             string(source.SourceType),
			"enabled":                 boolString(source.Enabled),
			"credential_set":          boolString(source.CredentialSet),
			"scrape_interval_seconds": itoa(source.ScrapeIntervalSeconds),
			"query_interval_seconds":  itoa(source.QueryIntervalSeconds),
			"timeout_seconds":         itoa(source.TimeoutSeconds),
			"reason":                  redactor.Redact(auditCtx.Reason),
		},
	}
}

func pointerString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
