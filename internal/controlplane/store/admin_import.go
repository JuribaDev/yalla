package store

import (
	"context"
	"errors"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

const (
	adminImportAction  = "admin.import"
	adminImportJobType = "import_dokploy_resource"
)

// ImportDokployInput is the validated support request to materialize a
// Dokploy organization into Yalla's source of truth through a durable worker
// job. The service verifies the target organization exists, appends the audit
// event, and inserts the queued job in one transaction.
type ImportDokployInput struct {
	OrganizationID         string
	YallaOrganizationID    string
	DokployOrganizationID  string
	AssignmentDokployOrgID string
	IdempotencyKey         string
	ActorID                string
	ActorKind              string
	ActorOrgID             string
	RequestID              string
	CorrelationID          string
}

// AdminImportService is the store-backed implementation of the support-only
// Dokploy import endpoint. It deliberately enqueues only the typed worker job;
// the worker owns scanning Dokploy and applying imported hierarchy rows.
type AdminImportService struct {
	store *Store
	orgs  *OrganizationRepository
	jobs  *JobRepository
	audit *AuditRepository
}

// NewAdminImportService builds an AdminImportService over the given store.
func NewAdminImportService(s *Store, orgs *OrganizationRepository, jobs *JobRepository, audit *AuditRepository) (*AdminImportService, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	if orgs == nil {
		return nil, errors.New("store: nil organization repository")
	}
	if jobs == nil {
		return nil, errors.New("store: nil job repository")
	}
	if audit == nil {
		return nil, errors.New("store: nil audit repository")
	}
	return &AdminImportService{store: s, orgs: orgs, jobs: jobs, audit: audit}, nil
}

// ImportDokploy verifies the owner organization and queues the import job.
func (svc *AdminImportService) ImportDokploy(ctx context.Context, in ImportDokployInput) (ProvisioningJob, error) {
	validated, err := validateImportDokployInput(in)
	if err != nil {
		return ProvisioningJob{}, err
	}

	var out ProvisioningJob
	err = svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.orgs.Get(ctx, tx, validated.OrganizationID); err != nil {
			return err
		}
		job, err := svc.jobs.Insert(ctx, tx, ProvisioningJob{
			OrganizationID: validated.OrganizationID,
			JobType:        adminImportJobType,
			IdempotencyKey: validated.IdempotencyKey,
			Payload: map[string]string{
				"organization_id":           validated.OrganizationID,
				"yalla_organization_id":     validated.YallaOrganizationID,
				"dokploy_organization_id":   validated.DokployOrganizationID,
				"assignment_dokploy_org_id": validated.AssignmentDokployOrgID,
			},
			RequestID:     validated.RequestID,
			CorrelationID: validated.CorrelationID,
		})
		if err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, AuditEvent{
			OrganizationID: validated.ActorOrgID,
			ActorID:        validated.ActorID,
			ActorKind:      validated.ActorKind,
			Action:         adminImportAction,
			ResourceKind:   string(domain.KindOrganization),
			ResourceID:     validated.OrganizationID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for admin.import",
			RequestID:      validated.RequestID,
			CorrelationID:  validated.CorrelationID,
			Metadata: map[string]string{
				"job_id":                  job.ID,
				"dokploy_organization_id": validated.DokployOrganizationID,
			},
		}); err != nil {
			return err
		}
		out = job
		return nil
	})
	if err != nil {
		return ProvisioningJob{}, err
	}
	return out, nil
}

func validateImportDokployInput(in ImportDokployInput) (ImportDokployInput, error) {
	out := ImportDokployInput{
		OrganizationID:         strings.TrimSpace(in.OrganizationID),
		YallaOrganizationID:    strings.TrimSpace(in.YallaOrganizationID),
		DokployOrganizationID:  strings.TrimSpace(in.DokployOrganizationID),
		AssignmentDokployOrgID: strings.TrimSpace(in.AssignmentDokployOrgID),
		IdempotencyKey:         strings.TrimSpace(in.IdempotencyKey),
		ActorID:                strings.TrimSpace(in.ActorID),
		ActorKind:              strings.TrimSpace(in.ActorKind),
		ActorOrgID:             strings.TrimSpace(in.ActorOrgID),
		RequestID:              strings.TrimSpace(in.RequestID),
		CorrelationID:          strings.TrimSpace(in.CorrelationID),
	}
	if out.YallaOrganizationID == "" {
		out.YallaOrganizationID = out.OrganizationID
	}
	if out.AssignmentDokployOrgID == "" {
		out.AssignmentDokployOrgID = out.DokployOrganizationID
	}
	if out.ActorOrgID == "" {
		out.ActorOrgID = out.OrganizationID
	}

	var violations []apierr.FieldViolation
	if err := validateImportOrgID("organization_id", out.OrganizationID); err != nil {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must be a valid organization id"})
	}
	if err := validateImportOrgID("yalla_organization_id", out.YallaOrganizationID); err != nil {
		violations = append(violations, apierr.FieldViolation{Field: "yalla_organization_id", Reason: "must be a valid organization id"})
	}
	if out.OrganizationID != "" && out.YallaOrganizationID != "" && out.OrganizationID != out.YallaOrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "yalla_organization_id", Reason: "must match organization_id"})
	}
	if out.DokployOrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "dokploy_organization_id", Reason: "required"})
	}
	if out.AssignmentDokployOrgID != "" && out.DokployOrganizationID != "" && out.AssignmentDokployOrgID != out.DokployOrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "assignment_dokploy_org_id", Reason: "must match dokploy_organization_id"})
	}
	if out.IdempotencyKey == "" {
		violations = append(violations, apierr.FieldViolation{Field: "idempotency_key", Reason: "must not be blank"})
	}
	if len(out.IdempotencyKey) > 128 {
		violations = append(violations, apierr.FieldViolation{Field: "idempotency_key", Reason: "must be at most 128 characters"})
	}
	if out.ActorID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_id", Reason: "is required"})
	}
	if out.ActorKind == "" {
		violations = append(violations, apierr.FieldViolation{Field: "actor_kind", Reason: "is required"})
	}
	if len(violations) > 0 {
		return ImportDokployInput{}, apierr.InvalidInput(violations...)
	}
	return out, nil
}

func validateImportOrgID(field, value string) error {
	parsed, err := domain.ParseID(value)
	if err != nil || parsed.Kind() != domain.KindOrganization {
		return apierr.InvalidInput(apierr.FieldViolation{Field: field, Reason: "must be a valid organization id"})
	}
	return nil
}
