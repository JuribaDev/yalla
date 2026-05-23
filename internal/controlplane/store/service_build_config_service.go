package store

import (
	"context"
	"errors"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

const (
	serviceBuildReadAction   = "service.build.read"
	serviceBuildUpdateAction = "service.build.update"
	serviceBuildUpdateJob    = "service.build.update"
)

// ServiceBuildConfigService coordinates build-config reads and writes with
// service existence checks, audit events, and reconciliation jobs.
type ServiceBuildConfigService struct {
	store    *Store
	services *ServiceRepository
	configs  *ServiceBuildConfigRepository
	jobs     JobEnqueuer
	audit    AuditAppender
}

// NewServiceBuildConfigService constructs the build-config application service.
func NewServiceBuildConfigService(s *Store, services *ServiceRepository, configs *ServiceBuildConfigRepository, jobs JobEnqueuer, audit AuditAppender) (*ServiceBuildConfigService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case services == nil:
		return nil, errors.New("store: nil service repository")
	case configs == nil:
		return nil, errors.New("store: nil service build config repository")
	case jobs == nil:
		return nil, errors.New("store: nil job enqueuer")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &ServiceBuildConfigService{store: s, services: services, configs: configs, jobs: jobs, audit: audit}, nil
}

// GetServiceBuildConfig returns the build config for an existing service.
func (svc *ServiceBuildConfigService) GetServiceBuildConfig(ctx context.Context, organizationID, serviceID string) (ServiceBuildConfig, error) {
	var out ServiceBuildConfig
	err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, err := svc.services.GetByID(ctx, q, strings.TrimSpace(organizationID), strings.TrimSpace(serviceID)); err != nil {
			return err
		}
		cfg, err := svc.configs.Get(ctx, q, strings.TrimSpace(organizationID), strings.TrimSpace(serviceID))
		if err != nil {
			return err
		}
		out = cfg
		return nil
	})
	return out, err
}

// SetServiceBuildConfigInput captures one build-config replacement request.
type SetServiceBuildConfigInput struct {
	OrganizationID string
	ServiceID      string
	BuildConfig    ServiceBuildConfigInput
	IfMatchVersion *int64
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// SetServiceBuildConfig replaces one service build config, audits the change,
// and enqueues service reconciliation.
func (svc *ServiceBuildConfigService) SetServiceBuildConfig(ctx context.Context, in SetServiceBuildConfigInput) (ServiceBuildConfig, error) {
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return ServiceBuildConfig{}, apierr.Internal(errors.New("store: ServiceBuildConfigService.Set requires actor organization"))
	}
	var out ServiceBuildConfig
	err := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		service, err := svc.services.GetByID(ctx, tx, strings.TrimSpace(in.OrganizationID), strings.TrimSpace(in.ServiceID))
		if err != nil {
			return err
		}
		cfg, err := svc.configs.Upsert(ctx, tx, service.OrganizationID, service.ID, in.BuildConfig, in.IfMatchVersion)
		if err != nil {
			return err
		}
		if err := svc.jobs.Enqueue(ctx, tx, EnqueueJobInput{
			OrganizationID: service.OrganizationID,
			JobKind:        serviceBuildUpdateJob,
			ResourceID:     service.ID,
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
		}); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         serviceBuildUpdateAction,
			ResourceKind:   string(domain.KindService),
			ResourceID:     service.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for service.build.update",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			Metadata: map[string]string{
				"build_type":     cfg.BuildType,
				"source_type":    cfg.SourceType,
				"environment_id": service.EnvironmentID,
				"project_id":     service.ProjectID,
			},
		}); err != nil {
			return err
		}
		out = cfg
		return nil
	})
	return out, err
}
