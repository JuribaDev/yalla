package store

import (
	"context"
	"errors"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// CredentialReader is the store-backed implementation of auth.CredentialStore:
// the read-only persistence surface the request Authenticator
// (internal/controlplane/auth) needs to turn an inbound credential into a
// policy.Principal. It is the BE-0020 "store wiring" for the auth middleware.
//
// The dependency direction is deliberate: auth defines the narrow
// CredentialStore port and never imports store, which keeps the Authenticator
// unit-testable with fakes. CredentialReader is the single production adapter,
// and it composes the existing tenant-scoped repository methods rather than
// issuing its own SQL — so the tenant-scoping guarantees those repositories
// already prove in their integration tests are inherited for free. Every
// method opens its own short-lived read transaction through Store.Read.
type CredentialReader struct {
	store    *Store
	apiKeys  *APIKeyRepository
	accounts *ServiceAccountRepository
	members  *MembershipRepository
}

// NewCredentialReader builds a CredentialReader over store. It returns an error
// for a nil store so a misconfigured adapter fails at construction rather than
// on its first request.
func NewCredentialReader(s *Store) (*CredentialReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &CredentialReader{
		store:    s,
		apiKeys:  NewAPIKeyRepository(),
		accounts: NewServiceAccountRepository(),
		members:  NewMembershipRepository(),
	}, nil
}

// FindAPIKeyByPrefix implements auth.CredentialStore. The lookup is by the
// globally-unique public prefix and is intentionally not tenant scoped —
// authentication runs before the caller's tenant is known. A missing prefix is
// returned as the typed not-found error APIKeyRepository.FindByPrefix produces,
// so the Authenticator can collapse it into a generic invalid-credentials
// result without revealing whether the prefix exists.
func (c *CredentialReader) FindAPIKeyByPrefix(ctx context.Context, prefix string) (auth.APIKeyRecord, error) {
	var rec auth.APIKeyRecord
	err := c.store.Read(ctx, func(ctx context.Context, q Querier) error {
		k, err := c.apiKeys.FindByPrefix(ctx, q, prefix)
		if err != nil {
			return err
		}
		rec = auth.APIKeyRecord{
			KeyID:            k.ID,
			OrganizationID:   k.OrganizationID,
			SecretHash:       k.SecretHash,
			ServiceAccountID: k.ServiceAccountID,
			CreatedBy:        k.CreatedBy,
			RevokedAt:        k.RevokedAt,
			ExpiresAt:        k.ExpiresAt,
		}
		return nil
	})
	if err != nil {
		return auth.APIKeyRecord{}, err
	}
	return rec, nil
}

// FindServiceAccount implements auth.CredentialStore. It is tenant scoped by
// organizationID, so a service account id from another organization does not
// match and is reported as the typed not-found error
// ServiceAccountRepository.Get produces.
func (c *CredentialReader) FindServiceAccount(ctx context.Context, organizationID, serviceAccountID string) (auth.ServiceAccountRecord, error) {
	var rec auth.ServiceAccountRecord
	err := c.store.Read(ctx, func(ctx context.Context, q Querier) error {
		sa, err := c.accounts.Get(ctx, q, organizationID, serviceAccountID)
		if err != nil {
			return err
		}
		rec = auth.ServiceAccountRecord{ID: sa.ID, Disabled: sa.IsDisabled()}
		return nil
	})
	if err != nil {
		return auth.ServiceAccountRecord{}, err
	}
	return rec, nil
}

// OrganizationRoleVersion implements auth.CredentialStore. It returns the
// current role/revocation version for (organizationID, userID). A user with no
// membership in the organization is the not-found case and returns
// (0, false, nil); a datastore failure is propagated as a non-nil error and is
// never disguised as ok == false, so a transient outage surfaces as a
// dependency failure rather than a silent authentication denial.
func (c *CredentialReader) OrganizationRoleVersion(ctx context.Context, organizationID, userID string) (int64, bool, error) {
	var (
		version int64
		found   bool
	)
	err := c.store.Read(ctx, func(ctx context.Context, q Querier) error {
		m, err := c.members.Get(ctx, q, organizationID, userID)
		if err != nil {
			if isNotFoundError(err) {
				return nil
			}
			return err
		}
		version = m.RoleVersion
		found = true
		return nil
	})
	if err != nil {
		return 0, false, err
	}
	return version, found, nil
}

// isNotFoundError reports whether err is a typed not-found error. It lets
// OrganizationRoleVersion tell "no such membership" (a clean ok == false) apart
// from a datastore failure (propagated to the caller).
func isNotFoundError(err error) bool {
	var ye *yerr.Error
	return errors.As(err, &ye) && ye.Code == yerr.CodeNotFound
}
