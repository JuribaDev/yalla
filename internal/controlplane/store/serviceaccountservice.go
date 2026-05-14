package store

import (
	"context"
	"errors"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// The action and quota resource a service-account creation composes against.
// They are duplicated as plain strings here on purpose: the policy action
// catalog and the quota schema are later stories, and the store layer must not
// take a build dependency on them. When those packages land they own these
// constants; the store layer keeps only the Authorizer / QuotaReserver ports.
const (
	serviceAccountCreateAction  = "service_account.create"
	serviceAccountQuotaResource = "service_accounts"
)

// CreateServiceAccountInput is the unvalidated input to
// ServiceAccountService.Create.
type CreateServiceAccountInput struct {
	OrganizationID   string
	ServiceAccountID string
	Slug             string
	DisplayName      string
}

// ServiceAccountService is the unit-of-work orchestrator for creating service
// accounts. Create composes — in this fixed order, inside one transaction — an
// authorization check, a quota reservation, and the desired-state write.
// Because every step shares the *Tx opened by Store.Write, a failure in any
// step rolls back every other step: the authorization and quota checks are
// impossible to bypass.
//
// Unlike ProjectService it enqueues no provisioning job: a service account is
// pure Yalla identity with no Dokploy object to mirror.
type ServiceAccountService struct {
	store *Store
	repo  *ServiceAccountRepository
	authz Authorizer
	quota QuotaReserver
}

// NewServiceAccountService wires a ServiceAccountService from its
// dependencies. It returns a typed error if any dependency is nil, so a
// misconfigured service fails at construction rather than on its first
// request.
func NewServiceAccountService(s *Store, repo *ServiceAccountRepository, authz Authorizer, quota QuotaReserver) (*ServiceAccountService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case repo == nil:
		return nil, errors.New("store: nil service account repository")
	case authz == nil:
		return nil, errors.New("store: nil authorizer")
	case quota == nil:
		return nil, errors.New("store: nil quota reserver")
	}
	return &ServiceAccountService{store: s, repo: repo, authz: authz, quota: quota}, nil
}

// Create validates in, then runs the create-service-account unit of work
// inside one transaction: authorize, reserve quota, write the service account
// row. Validation runs before the transaction is opened, so an invalid request
// never touches the database. Every failure after that point — a denied
// authorization decision, an exhausted quota, or a slug conflict — rolls the
// whole transaction back, so the checks can never be skipped.
func (svc *ServiceAccountService) Create(ctx context.Context, in CreateServiceAccountInput) (ServiceAccount, error) {
	account, err := validateCreateServiceAccountInput(in)
	if err != nil {
		return ServiceAccount{}, err
	}

	var created ServiceAccount
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if err := svc.authz.Authorize(ctx, tx, serviceAccountCreateAction, account.OrganizationID); err != nil {
			return err
		}
		if err := svc.quota.Reserve(ctx, tx, account.OrganizationID, serviceAccountQuotaResource); err != nil {
			return err
		}
		row, err := svc.repo.Insert(ctx, tx, account)
		if err != nil {
			return err
		}
		created = row
		return nil
	})
	if txErr != nil {
		return ServiceAccount{}, txErr
	}
	return created, nil
}

// validateCreateServiceAccountInput checks in and returns the ServiceAccount
// row it would persist. It is split out from Create so the validation rules
// are unit testable without a database, and so an invalid request is rejected
// before a transaction is ever opened. On failure it returns a typed
// apierr.InvalidInput carrying stable field paths — never the submitted values
// — so the rejection can name the offending field without leaking input.
func validateCreateServiceAccountInput(in CreateServiceAccountInput) (ServiceAccount, error) {
	var violations []apierr.FieldViolation

	orgID := strings.TrimSpace(in.OrganizationID)
	if id, err := domain.ParseID(orgID); err != nil || id.Kind() != domain.KindOrganization {
		violations = append(violations, apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization id",
		})
	}

	serviceAccountID := strings.TrimSpace(in.ServiceAccountID)
	if id, err := domain.ParseID(serviceAccountID); err != nil || id.Kind() != domain.KindServiceAccount {
		violations = append(violations, apierr.FieldViolation{
			Field:  "service_account_id",
			Reason: "must be a valid service account id",
		})
	}

	slug, err := domain.ParseSlug(in.Slug)
	if err != nil {
		violations = append(violations, apierr.FieldViolation{
			Field:  "slug",
			Reason: "must be a canonical slug",
		})
	}

	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		violations = append(violations, apierr.FieldViolation{
			Field:  "display_name",
			Reason: "must not be empty",
		})
	}

	if len(violations) > 0 {
		return ServiceAccount{}, apierr.InvalidInput(violations...)
	}
	return ServiceAccount{
		ID:             serviceAccountID,
		OrganizationID: orgID,
		Slug:           slug.String(),
		DisplayName:    displayName,
	}, nil
}
