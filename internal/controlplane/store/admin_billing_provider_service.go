package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/output"
)

const adminBillingProviderResourceKind = "billing_provider"

// AdminBillingProviderAuditContext carries operator identity for billing
// provider changes and side-effect-free tests.
type AdminBillingProviderAuditContext struct {
	ActorOrgID    string
	ActorID       string
	ActorKind     string
	RequestID     string
	CorrelationID string
	Reason        string
}

// AdminBillingProviderService composes billing provider writes with encrypted
// credential handling and immutable audit records.
type AdminBillingProviderService struct {
	store     *Store
	orgs      *OrganizationRepository
	providers *BillingProviderConfigRepository
	audit     *AuditRepository
	secrets   secrets.Provider
}

// NewAdminBillingProviderService builds an audited billing provider manager.
func NewAdminBillingProviderService(s *Store, orgs *OrganizationRepository, providers *BillingProviderConfigRepository, audit *AuditRepository, provider secrets.Provider) (*AdminBillingProviderService, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	if orgs == nil {
		return nil, errors.New("store: nil organization repository")
	}
	if providers == nil {
		return nil, errors.New("store: nil billing provider repository")
	}
	if audit == nil {
		return nil, errors.New("store: nil audit repository")
	}
	if provider == nil {
		return nil, errors.New("store: nil secrets provider")
	}
	return &AdminBillingProviderService{store: s, orgs: orgs, providers: providers, audit: audit, secrets: provider}, nil
}

// UpsertBillingProvider creates or updates one provider config and records the
// change in the audit log. CredentialValue is write-only and sealed before the
// transaction opens.
func (svc *AdminBillingProviderService) UpsertBillingProvider(ctx context.Context, key string, in UpsertBillingProviderInput, auditCtx AdminBillingProviderAuditContext) (BillingProviderConfig, error) {
	auditCtx, err := validateAdminBillingProviderAuditContext(auditCtx)
	if err != nil {
		return BillingProviderConfig{}, err
	}
	credential, err := svc.sealBillingCredential(in.CredentialValue)
	if err != nil {
		return BillingProviderConfig{}, err
	}
	redactor := output.NewRedactor(pointerString(in.CredentialValue))
	var out BillingProviderConfig
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		provider, err := svc.providers.Upsert(ctx, tx, key, in, credential)
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, adminBillingProviderAuditEvent(auditCtx, provider, "admin.billing_provider.upsert", "upsert", redactor))
		if err != nil {
			return err
		}
		out = provider
		return nil
	})
	if err != nil {
		return BillingProviderConfig{}, err
	}
	return out, nil
}

// GetBillingProvider returns the current provider config by key.
func (svc *AdminBillingProviderService) GetBillingProvider(ctx context.Context, key string) (BillingProviderConfig, error) {
	var out BillingProviderConfig
	err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var err error
		out, err = svc.providers.Get(ctx, q, key)
		return err
	})
	if err != nil {
		return BillingProviderConfig{}, err
	}
	return out, nil
}

// TestBillingProvider performs a side-effect-free configuration/mapping check
// and records the result. It never calls an external billing provider.
func (svc *AdminBillingProviderService) TestBillingProvider(ctx context.Context, key string, in BillingProviderTestInput, auditCtx AdminBillingProviderAuditContext) (BillingProviderTestResult, error) {
	auditCtx, err := validateAdminBillingProviderAuditContext(auditCtx)
	if err != nil {
		return BillingProviderTestResult{}, err
	}
	if in.FakeCounterCount < 0 || in.FakeCounterCount > 1000 {
		return BillingProviderTestResult{}, apierr.InvalidInput(apierr.FieldViolation{Field: "fake_counter_count", Reason: "must be between 0 and 1000"})
	}
	var provider BillingProviderConfig
	if err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var err error
		provider, err = svc.providers.Get(ctx, q, key)
		return err
	}); err != nil {
		return BillingProviderTestResult{}, err
	}
	result := BillingProviderTestResult{
		ProviderKey:      provider.ProviderKey,
		ProviderType:     string(provider.ProviderType),
		Status:           "ok",
		CheckedAt:        time.Now().UTC(),
		FakeCounterCount: in.FakeCounterCount,
	}
	switch provider.ProviderType {
	case BillingProviderTypeDisabled:
		result.Status = "skipped"
		result.Message = "provider is disabled"
	case BillingProviderTypeManual:
		result.Message = "manual export mapping accepted"
	case BillingProviderTypeStripe:
		if provider.Enabled && !provider.DryRun && !provider.CredentialSet && provider.SecretReference == "" {
			result.Status = "failed"
			result.Message = "stripe provider requires a stored credential reference before live exports"
		} else {
			result.Message = "stripe placeholder mapping accepted"
		}
	default:
		result.Status = "failed"
		result.Message = "provider type is not supported"
	}
	if auditErr := svc.auditBillingProviderTest(ctx, provider, auditCtx, result.Status); auditErr != nil {
		return BillingProviderTestResult{}, auditErr
	}
	return result, nil
}

func (svc *AdminBillingProviderService) auditBillingProviderTest(ctx context.Context, provider BillingProviderConfig, auditCtx AdminBillingProviderAuditContext, status string) error {
	return svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, auditCtx.ActorOrgID); err != nil {
			return err
		}
		if _, err := svc.providers.Get(ctx, tx, provider.ProviderKey); err != nil {
			return err
		}
		event := adminBillingProviderAuditEvent(auditCtx, provider, "admin.billing_provider.test", "test", output.NewRedactor())
		event.Metadata["status"] = strings.TrimSpace(status)
		_, err := svc.audit.Append(ctx, tx, event)
		return err
	})
}

func (svc *AdminBillingProviderService) sealBillingCredential(value *string) (BillingProviderCredential, error) {
	if value == nil {
		return BillingProviderCredential{}, nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return BillingProviderCredential{Touched: true}, nil
	}
	ciphertext, keyID, err := svc.secrets.Seal([]byte(*value))
	if err != nil {
		return BillingProviderCredential{}, apierr.SecretDecryption(err)
	}
	return BillingProviderCredential{
		Touched:          true,
		SecretProvider:   svc.secrets.ProviderID(),
		SecretKeyID:      keyID,
		SecretCiphertext: ciphertext,
	}, nil
}

func validateAdminBillingProviderAuditContext(in AdminBillingProviderAuditContext) (AdminBillingProviderAuditContext, error) {
	out := AdminBillingProviderAuditContext{
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
		return AdminBillingProviderAuditContext{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func adminBillingProviderAuditEvent(auditCtx AdminBillingProviderAuditContext, provider BillingProviderConfig, action, operation string, redactor *output.Redactor) AuditEvent {
	if redactor == nil {
		redactor = output.NewRedactor()
	}
	return AuditEvent{
		OrganizationID: auditCtx.ActorOrgID,
		ActorID:        auditCtx.ActorID,
		ActorKind:      auditEventActorKind(auditCtx.ActorKind),
		Action:         action,
		ResourceKind:   adminBillingProviderResourceKind,
		ResourceID:     provider.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         redactor.Redact(auditCtx.Reason),
		RequestID:      auditCtx.RequestID,
		CorrelationID:  auditCtx.CorrelationID,
		Metadata: map[string]string{
			"operation":                     operation,
			"provider_key":                  provider.ProviderKey,
			"provider_type":                 string(provider.ProviderType),
			"enabled":                       boolString(provider.Enabled),
			"credential_set":                boolString(provider.CredentialSet),
			"export_cadence_seconds":        itoa(provider.ExportCadenceSeconds),
			"retry_max_attempts":            itoa(provider.RetryMaxAttempts),
			"retry_initial_backoff_seconds": itoa(provider.RetryInitialBackoffSeconds),
			"dry_run":                       boolString(provider.DryRun),
			"reason":                        redactor.Redact(auditCtx.Reason),
		},
	}
}
