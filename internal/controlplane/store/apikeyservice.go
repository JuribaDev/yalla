package store

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// The policy action a key mint records on its audit event. It is duplicated
// as a plain string here on purpose: the policy action catalog is owned by
// internal/controlplane/policy and the store layer must not take a build
// dependency on it. When a key.create story refines the action it lives in
// one place — the policy package; the store layer keeps the audited verb.
const keysManageAction = "keys.manage"

// apiKeyNameMaxLen bounds the human-authored name on an api_keys row. It
// mirrors validate.MaxNameLen but is repeated here so the store-layer
// validator stays a unit-testable, dependency-free contract — the database
// also enforces length(name) > 0 as defence-in-depth.
const apiKeyNameMaxLen = 100

// apiKeyScopeMaxLen bounds one scope string. Scopes are non-secret machine
// tokens (for example "projects:read"), so a 64-byte cap is loose enough for
// every catalogued action and tight enough to bound an audit/log line.
const apiKeyScopeMaxLen = 64

// apiKeyMaxScopes bounds the size of the scopes array on a single key. A key
// that grants a very large number of capabilities is almost always either a
// configuration mistake or a privilege-escalation attempt; the bound keeps
// either from reaching the database.
const apiKeyMaxScopes = 64

// CreateAPIKeyInput is the unvalidated input to APIKeyService.Create.
// OrganizationID names the tenant the new key belongs to. Name is a
// human-authored label. Scopes is the machine-readable capability list (may
// be empty). ExpiresAt is optional; a nil pointer means the key does not
// expire. ServiceAccountID is optional; an empty string means the key is
// owned by the principal named in CreatedBy rather than by a non-human
// service account. CreatedBy is the id of the user who minted the key; it
// is empty when the actor is itself a service account so the api_keys row
// stores SQL NULL.
//
// Prefix and SecretHash are the credential primitives produced by
// internal/controlplane/auth.Generate. They are passed in by the handler so
// the store layer never touches the plaintext Token and never imports the
// auth package. A blank Prefix or SecretHash is a wiring error and is
// reported as Internal.
//
// The Actor* and correlation fields describe the authenticated principal
// performing the mint and are recorded verbatim on the audit event. They are
// plain strings so the store layer takes no build dependency on the policy
// or telemetry packages — the httpapi handler, which already holds the
// resolved principal and the request correlation, fills them in.
type CreateAPIKeyInput struct {
	OrganizationID   string
	Name             string
	Scopes           []string
	ExpiresAt        *time.Time
	ServiceAccountID string
	CreatedBy        string
	Prefix           string
	SecretHash       string

	ActorID       string
	ActorKind     string
	ActorOrgID    string
	RequestID     string
	CorrelationID string
}

// RevokeAPIKeyInput is the unvalidated input to APIKeyService.Revoke.
// OrganizationID and KeyID name the api_keys row to revoke. Revocation is the
// customer-facing soft delete for an API key: the row stays in the database
// (so authentication continues to reject the key with the same uniform
// invalid-credentials result, and so the audit trail of who minted it stays
// linked to a live row) but its revoked_at column is stamped and the
// credential is permanently unusable from that moment on. There is no
// "un-revoke" — a revoked key cannot be re-activated, only replaced by a fresh
// mint.
//
// The credential primitives (prefix and secret_hash) and the immutable
// identity fields are deliberately not on this struct: revocation does not
// rotate, rename, or rescope a key — it only flips it to revoked. Re-revoking
// an already-revoked key is rejected by the service as a typed Conflict
// (the caller's view of the resource lifecycle is stale), even though the
// underlying repository remains silently idempotent at the SQL layer.
//
// The Actor* and correlation fields describe the authenticated principal
// performing the revocation and are recorded verbatim on the audit event.
// They are plain strings so the store layer takes no build dependency on
// the policy or telemetry packages — the httpapi handler, which already
// holds the resolved principal and the request correlation, fills them in.
type RevokeAPIKeyInput struct {
	OrganizationID string
	KeyID          string

	ActorID       string
	ActorKind     string
	ActorOrgID    string
	RequestID     string
	CorrelationID string
}

// RotateAPIKeyInput is the unvalidated input to APIKeyService.Rotate.
// OrganizationID and KeyID name the api_keys row whose credential primitives
// are being swapped. Rotation is the customer-facing operation for swapping
// the credential body of an existing key without minting a new identity: the
// key id, name, scopes, ownership identifiers (created_by, service_account_id),
// and the expires_at lifecycle stamp are deliberately preserved across the
// rotation. The old credential body becomes unusable from the moment the row
// is committed — every subsequent FindByPrefix that runs against the old
// prefix simply misses, falling through to the same uniform
// invalid-credentials path that revoked or non-existent keys produce.
//
// Prefix and SecretHash are the new credential primitives produced by
// internal/controlplane/auth.Generate. They are passed in by the handler so
// the store layer never touches the plaintext Token and never imports the
// auth package. A blank Prefix or SecretHash is a wiring error and is
// reported as Internal.
//
// The credential-identity fields (id, organization_id), the immutable
// ownership fields (created_by, service_account_id), and the lifecycle
// stamps (expires_at, revoked_at) are deliberately not on this struct:
// rotation replaces the credential body in place — the key still has the
// same identity, the same ownership, and the same lifecycle. A rotation of
// a revoked or expired key is rejected at the service layer as a typed
// Conflict, because the caller's view of the resource lifecycle is stale:
// a key that can no longer authenticate cannot be revived by minting a
// fresh credential body; it can only be replaced by a fresh mint through
// the Create endpoint.
//
// The Actor* and correlation fields describe the authenticated principal
// performing the rotation and are recorded verbatim on the audit event.
// They are plain strings so the store layer takes no build dependency on
// the policy or telemetry packages — the httpapi handler, which already
// holds the resolved principal and the request correlation, fills them in.
type RotateAPIKeyInput struct {
	OrganizationID string
	KeyID          string

	Prefix     string
	SecretHash string

	ActorID       string
	ActorKind     string
	ActorOrgID    string
	RequestID     string
	CorrelationID string
}

// UpdateAPIKeyInput is the unvalidated input to APIKeyService.Update.
// OrganizationID and KeyID name the api_keys row to update. Name and Scopes
// are optional: a nil pointer means the caller did not include the field and
// it is left unchanged, which is what makes the operation a partial update.
// A patch that names no updatable field is itself a validation failure — a
// mutation that changes nothing is a client error, not a silent success.
//
// The credential primitives (prefix and secret_hash) and the immutable
// identity fields (id, organization_id, created_by, service_account_id,
// expires_at, revoked_at) are deliberately not on this struct: the credential
// is minted once at create time and never re-written, ownership is fixed at
// mint, and lifecycle stamps (expiry/revocation) are owned by their own
// dedicated stories (PATCH does not rotate, revoke, or extend a key — the
// rotate and delete endpoints do).
//
// The Actor* and correlation fields describe the authenticated principal
// performing the update and are recorded verbatim on the audit event. They
// are plain strings so the store layer takes no build dependency on the
// policy or telemetry packages — the httpapi handler, which already holds
// the resolved principal and the request correlation, fills them in.
type UpdateAPIKeyInput struct {
	OrganizationID string
	KeyID          string
	Name           *string
	Scopes         *[]string

	ActorID       string
	ActorKind     string
	ActorOrgID    string
	RequestID     string
	CorrelationID string
}

// APIKeyService is the unit-of-work orchestrator for minting API keys. Create
// composes — in a fixed order, inside one transaction — the existence checks
// for the target organization and (when supplied) the service account, the
// insert of the api_keys row, and the immutable audit record. Because every
// step shares the *Tx opened by Store.Write, a failure in any rolls the
// others back: a key is never persisted without its audit event, and an
// audit event is never written for a mint that did not happen.
//
// The plaintext credential is never visible to this layer. The handler calls
// auth.Generate to mint the credential, then passes the (Prefix, SecretHash)
// pair into CreateAPIKeyInput; the persisted row only ever carries the
// public Prefix and the one-way SecretHash, so a database read can never
// recover a usable token.
//
// It enqueues no provisioning job: an API key is pure Yalla identity with
// no Dokploy object to mirror.
//
// The quota port reserves one unit on the QuotaResourceAPIKeys dimension
// inside the same *Tx as the desired-state insert and the audit append, so
// an organization that exhausts its api_keys limit can never half-write a
// row whose reservation rolled back. The reservation runs AFTER the
// existence checks so a 404 on the parent organization is never disguised
// as a quota rejection, and BEFORE the Insert so a prefix collision can
// never consume a reservation slot the row never reached.
type APIKeyService struct {
	store           *Store
	orgs            *OrganizationRepository
	serviceAccounts *ServiceAccountRepository
	apiKeys         *APIKeyRepository
	quota           QuotaReserver
	audit           AuditAppender
}

// NewAPIKeyService wires an APIKeyService from its dependencies. It returns
// a typed error if any dependency is nil, so a misconfigured service fails
// at construction rather than on its first request.
func NewAPIKeyService(s *Store, orgs *OrganizationRepository, serviceAccounts *ServiceAccountRepository, apiKeys *APIKeyRepository, quota QuotaReserver, audit AuditAppender) (*APIKeyService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case orgs == nil:
		return nil, errors.New("store: nil organization repository")
	case serviceAccounts == nil:
		return nil, errors.New("store: nil service account repository")
	case apiKeys == nil:
		return nil, errors.New("store: nil api key repository")
	case quota == nil:
		return nil, errors.New("store: nil quota reserver")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &APIKeyService{
		store:           s,
		orgs:            orgs,
		serviceAccounts: serviceAccounts,
		apiKeys:         apiKeys,
		quota:           quota,
		audit:           audit,
	}, nil
}

// Create validates in, then runs the mint-api-key unit of work inside one
// transaction: confirm the organization exists; if a service account is
// named, confirm it exists in that organization; insert the api_keys row
// with the caller-supplied Prefix and SecretHash; append the audit event.
// Validation runs before the transaction is opened, so an invalid request
// never touches the database. A missing organization or service account is
// the typed NotFound the existence checks produce. A prefix collision —
// which is astronomically unlikely with the auth-layer entropy budget — is
// reported as a typed Conflict; everything rolls back together.
//
// now is the wall-clock the validator uses to reject an expires_at that is
// not strictly in the future. It is plumbed in so a unit test can pin time
// without monkey-patching time.Now.
func (svc *APIKeyService) Create(ctx context.Context, in CreateAPIKeyInput, now time.Time) (APIKey, error) {
	key, err := buildAPIKeyToCreate(in, now)
	if err != nil {
		return APIKey{}, err
	}

	// The audit record is filed under the actor's home organization — the
	// tenant the principal authenticated into — while its resource id names
	// the api key that was minted. A missing actor organization is a wiring
	// error (an authenticated request always carries one), not client input,
	// so it is reported as Internal rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return APIKey{}, apierr.Internal(errors.New("store: APIKeyService.Create requires an actor organization for the audit record"))
	}

	metadata := map[string]string{
		"organization_id": key.OrganizationID,
		"scope_count":     strconv.Itoa(len(key.Scopes)),
		"has_expiry":      strconv.FormatBool(key.ExpiresAt != nil),
	}
	if key.ServiceAccountID != "" {
		metadata["service_account_id"] = key.ServiceAccountID
	}

	var created APIKey
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Confirm the organization exists inside the transaction. The
		// repository returns a typed NotFound that the HTTP layer maps to a
		// deterministic 404; the tenant boundary itself is enforced by the
		// policy engine at the request edge.
		if _, getErr := svc.orgs.Get(ctx, tx, key.OrganizationID); getErr != nil {
			return getErr
		}
		// If the key is being minted for a service account, confirm the
		// service account exists in the same organization. The repository
		// read is tenant scoped, so a cross-tenant service-account id can
		// never match.
		if key.ServiceAccountID != "" {
			if _, getErr := svc.serviceAccounts.Get(ctx, tx, key.OrganizationID, key.ServiceAccountID); getErr != nil {
				return getErr
			}
		}
		// Reserve one unit on the api_keys quota dimension inside the same
		// transaction as the desired-state insert and the audit append. The
		// SELECT FOR UPDATE on the quota_usage counter row serialises
		// concurrent reservers against one another, so the limit can never
		// be over-allocated even under parallel mint requests. A rejection
		// here surfaces as a typed apierr.QuotaExceeded whose
		// ExceededDetail.Resource is "api_keys" — the wire-stable dimension
		// label customers see on E_QUOTA_EXCEEDED. The reservation runs
		// AFTER the existence checks (so a 404 on the org or the named
		// service account is never disguised as a quota rejection) and
		// BEFORE the Insert (so a prefix collision rolls the reservation
		// back with the rest of the unit of work).
		if err := svc.quota.Reserve(ctx, tx, key.OrganizationID, string(QuotaResourceAPIKeys)); err != nil {
			return err
		}
		row, insErr := svc.apiKeys.Insert(ctx, tx, key)
		if insErr != nil {
			return insErr
		}
		event := AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         keysManageAction,
			ResourceKind:   string(domain.KindAPIKey),
			ResourceID:     row.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for keys.manage",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			Metadata:       metadata,
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		created = row
		return nil
	})
	if txErr != nil {
		return APIKey{}, txErr
	}
	return created, nil
}

// Update validates in, then runs the update-api-key unit of work inside one
// transaction: read the current row, apply the caller-supplied fields, write
// the row back, append the audit event. Validation of every supplied field
// runs before the transaction is opened, so an invalid request never touches
// the database. A patch that names no updatable field is itself a validation
// failure — a mutation that changes nothing is a client error, not a silent
// success. A {key_id} with no row in the target tenant is the typed NotFound
// the repository produces (the tenant-scoped read filters by organization_id
// first, so a cross-tenant key_id is indistinguishable from a missing row),
// and the audit record is rolled back with it, so an audit trail can never
// name a mutation that did not happen.
//
// The audit record is filed under the actor's home organization — the tenant
// the principal authenticated into — while its resource id names the api key
// that was updated. metadata captures the target tenant and the stable wire
// names of the fields the patch changed (never the submitted values), so the
// trail records the shape of the mutation without leaking input.
func (svc *APIKeyService) Update(ctx context.Context, in UpdateAPIKeyInput) (APIKey, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	keyID := strings.TrimSpace(in.KeyID)

	// Path-parameter ids are treated as opaque identifiers the caller already
	// has, so the rules mirror validateMembershipUpdate: require the
	// kind-prefix as a defensive guard and let the in-transaction tenant-
	// scoped read enforce the rest. Format strictness is the job of
	// internal/controlplane/domain when an id is minted; the auth/HTTP
	// layer's earlier 403/404 also shields this layer from arbitrary
	// cross-tenant probes.
	var idViolations []apierr.FieldViolation
	if organizationID == "" || !strings.HasPrefix(organizationID, string(domain.KindOrganization)+"_") {
		idViolations = append(idViolations, apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization identifier",
		})
	}
	if keyID == "" || !strings.HasPrefix(keyID, string(domain.KindAPIKey)+"_") {
		idViolations = append(idViolations, apierr.FieldViolation{
			Field:  "key_id",
			Reason: "must be a valid api key identifier",
		})
	}
	if len(idViolations) > 0 {
		return APIKey{}, apierr.InvalidInput(idViolations...)
	}

	change, err := buildAPIKeyUpdate(in)
	if err != nil {
		return APIKey{}, err
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return APIKey{}, apierr.Internal(errors.New("store: APIKeyService.Update requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         keysManageAction,
		ResourceKind:   string(domain.KindAPIKey),
		ResourceID:     keyID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for keys.manage",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// updated_fields names which fields the patch changed — stable wire
		// names, never the submitted values — so the audit trail records the
		// shape of the mutation without carrying any input verbatim.
		// organization_id is the target tenant of the update.
		Metadata: map[string]string{
			"organization_id": organizationID,
			"updated_fields":  strings.Join(change.fields, ","),
		},
	}

	var updated APIKey
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Read the current row inside the same transaction so a missing key
		// in this tenant is reported as NotFound without relying on the
		// UPDATE's no-rows path, and so the projected fields the patch does
		// not name are preserved verbatim from the row Postgres holds rather
		// than from a value the client supplied.
		current, getErr := svc.apiKeys.Get(ctx, tx, organizationID, keyID)
		if getErr != nil {
			return getErr
		}

		name := current.Name
		if change.name != nil {
			name = *change.name
		}
		scopes := current.Scopes
		if change.scopes != nil {
			scopes = *change.scopes
		}

		row, updErr := svc.apiKeys.UpdateMutable(ctx, tx, organizationID, keyID, name, scopes)
		if updErr != nil {
			return updErr
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		updated = row
		return nil
	})
	if txErr != nil {
		return APIKey{}, txErr
	}
	return updated, nil
}

// Revoke validates in, then runs the revoke-api-key unit of work inside one
// transaction: read the current row, reject the call as a typed Conflict when
// the key is already revoked, mark it revoked at now, append the audit event.
// Validation runs before the transaction is opened, so an invalid request
// never touches the database. A {key_id} with no row in the target tenant is
// the typed NotFound the repository produces (the tenant-scoped read filters
// by organization_id first, so a cross-tenant key_id is indistinguishable
// from a missing row), and the audit record is rolled back with it, so an
// audit trail can never name a revocation that did not happen.
//
// Revocation is the customer-facing soft delete: the api_keys row stays in
// the database — the prefix-lookup authentication path keeps surfacing the
// row, the IsUsable check rejects it as revoked, and the audit trail of who
// minted it stays linked to a live row — but the credential is permanently
// unusable. Re-revoking an already-revoked key is rejected as a typed
// Conflict at the service layer (the caller's view of the resource lifecycle
// is stale, so it is a typed Conflict, not a silent success that would write
// a misleading audit record), mirroring the organization scheduled-deletion
// contract. The underlying repository remains silently idempotent at the SQL
// layer, so a non-customer caller (a worker or admin job) that does not need
// the conflict signal can call APIKeyRepository.Revoke directly.
//
// The audit record is filed under the actor's home organization — the tenant
// the principal authenticated into — while its resource id names the api key
// that was revoked. metadata captures the target tenant and the resolved
// revocation timestamp (a non-secret value), so the trail records exactly
// when the key was retired without carrying any input verbatim.
//
// now is the wall-clock the unit of work stamps the api_keys.revoked_at
// column with. It is plumbed in so a unit test can pin time without
// monkey-patching time.Now.
func (svc *APIKeyService) Revoke(ctx context.Context, in RevokeAPIKeyInput, now time.Time) (APIKey, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	keyID := strings.TrimSpace(in.KeyID)

	// Path-parameter ids are treated as opaque identifiers the caller already
	// has, so the rules mirror Update: require the kind-prefix as a defensive
	// guard and let the in-transaction tenant-scoped read enforce the rest.
	// Format strictness is the job of internal/controlplane/domain when an id
	// is minted; the auth/HTTP layer's earlier 403/404 also shields this
	// layer from arbitrary cross-tenant probes.
	var idViolations []apierr.FieldViolation
	if organizationID == "" || !strings.HasPrefix(organizationID, string(domain.KindOrganization)+"_") {
		idViolations = append(idViolations, apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization identifier",
		})
	}
	if keyID == "" || !strings.HasPrefix(keyID, string(domain.KindAPIKey)+"_") {
		idViolations = append(idViolations, apierr.FieldViolation{
			Field:  "key_id",
			Reason: "must be a valid api key identifier",
		})
	}
	if len(idViolations) > 0 {
		return APIKey{}, apierr.InvalidInput(idViolations...)
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return APIKey{}, apierr.Internal(errors.New("store: APIKeyService.Revoke requires an actor organization for the audit record"))
	}

	revokedAt := now.UTC()

	var revoked APIKey
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Read the current row inside the same transaction so a missing key
		// in this tenant is reported as NotFound without relying on the
		// UPDATE's no-rows path, and so the "already revoked" decision sees
		// the same row the UPDATE would lock. A cross-tenant key_id is
		// indistinguishable from a missing row — exactly what every other
		// read endpoint of this resource guarantees.
		current, getErr := svc.apiKeys.Get(ctx, tx, organizationID, keyID)
		if getErr != nil {
			return getErr
		}
		if current.IsRevoked() {
			// Re-revoking changes nothing: the caller's view of the resource
			// lifecycle is stale, so it is a typed Conflict, not a silent
			// success that would write a misleading audit record.
			return apierr.Conflict("api key is already revoked")
		}

		row, _, revErr := svc.apiKeys.Transition(ctx, tx, APIKeyTransition{
			OrganizationID: organizationID,
			KeyID:          keyID,
			NextStatus:     APIKeyStatusRevoked,
			ActorID:        in.ActorID,
			ActorKind:      in.ActorKind,
			RequestID:      in.RequestID,
			CorrelationID:  in.CorrelationID,
			Reason:         "api key revoked",
			Now:            revokedAt,
		})
		if revErr != nil {
			return revErr
		}

		event := AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         keysManageAction,
			ResourceKind:   string(domain.KindAPIKey),
			ResourceID:     keyID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for keys.manage",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			// organization_id is the target tenant of the revocation; the
			// revoked_at stamp is the resolved revocation timestamp (a
			// non-secret value) — both are safe to record verbatim. The
			// captured timestamp is the audit-grade record of when the key
			// became unusable.
			Metadata: map[string]string{
				"organization_id": organizationID,
				"revoked_at":      revokedAt.Format(time.RFC3339Nano),
			},
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		revoked = row
		return nil
	})
	if txErr != nil {
		return APIKey{}, txErr
	}
	return revoked, nil
}

// Rotate runs the rotate-api-key unit of work for in inside one transaction:
// confirm the key exists in the named tenant, reject the call as a typed
// Conflict when the key is already revoked or expired (the caller's view of
// the resource lifecycle is stale), swap the credential primitives on the
// api_keys row, and append the immutable audit record naming the rotation.
// Validation runs before any database work so an invalid request never opens
// a transaction. A missing or cross-tenant key surfaces as the typed
// NotFound the repository produces (the tenant-scoped read filters by
// organization_id first, so a cross-tenant key_id is indistinguishable from
// a missing row), and the audit record is rolled back with it, so an audit
// trail can never name a rotation that did not happen.
//
// Rotation swaps the credential body in place: the api_keys row keeps its
// id, name, scopes, ownership identifiers (created_by, service_account_id),
// and lifecycle stamps (expires_at) — only the prefix and secret_hash change.
// The old credential body becomes permanently unusable from the moment the
// row is committed, because the prefix-lookup authentication path only ever
// sees the row's current prefix. There is no "undo rotation" — the previous
// secret never leaves the auth layer and is never persisted, so the old
// body cannot be reconstructed even by the operator.
//
// A rotation against a key whose revoked_at is set, or whose expires_at has
// already passed at now, is rejected as a typed Conflict at the service
// layer. Both conditions render the key unusable for authentication: a
// fresh credential body cannot rescue an identity whose lifecycle the
// customer or the calendar already ended. The customer must mint a new
// key through Create instead. The conflict check runs in the same
// transaction as the read so the verdict cannot race a concurrent revoke
// or update.
//
// The audit record is filed under the actor's home organization — the tenant
// the principal authenticated into — while its resource id names the api key
// that was rotated. metadata captures the target tenant and the rotated
// prefix (non-secret, the public lookup id the caller now holds) so the
// trail records exactly which credential body the row now serves without
// carrying any secret material verbatim.
//
// now is the wall-clock the validator uses to reject a rotation of a key
// whose expires_at is already past. It is plumbed in so a unit test can
// pin time without monkey-patching time.Now.
func (svc *APIKeyService) Rotate(ctx context.Context, in RotateAPIKeyInput, now time.Time) (APIKey, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	keyID := strings.TrimSpace(in.KeyID)

	// Path-parameter ids are treated as opaque identifiers the caller already
	// has, so the rules mirror Update and Revoke: require the kind-prefix as
	// a defensive guard and let the in-transaction tenant-scoped read enforce
	// the rest. Format strictness is the job of internal/controlplane/domain
	// when an id is minted.
	var idViolations []apierr.FieldViolation
	if organizationID == "" || !strings.HasPrefix(organizationID, string(domain.KindOrganization)+"_") {
		idViolations = append(idViolations, apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization identifier",
		})
	}
	if keyID == "" || !strings.HasPrefix(keyID, string(domain.KindAPIKey)+"_") {
		idViolations = append(idViolations, apierr.FieldViolation{
			Field:  "key_id",
			Reason: "must be a valid api key identifier",
		})
	}
	if len(idViolations) > 0 {
		return APIKey{}, apierr.InvalidInput(idViolations...)
	}

	// The credential primitives are minted by the handler through
	// auth.Generate; an empty value here means the handler skipped that step,
	// which is a wiring error rather than client input. Surfacing it as a
	// typed Internal keeps a client from believing it caused the failure and
	// keeps the handler honest about always minting before delegating.
	prefix := strings.TrimSpace(in.Prefix)
	secretHash := strings.TrimSpace(in.SecretHash)
	if prefix == "" {
		return APIKey{}, apierr.Internal(errors.New("store: APIKeyService.Rotate requires a non-empty prefix"))
	}
	if secretHash == "" {
		return APIKey{}, apierr.Internal(errors.New("store: APIKeyService.Rotate requires a non-empty secret hash"))
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return APIKey{}, apierr.Internal(errors.New("store: APIKeyService.Rotate requires an actor organization for the audit record"))
	}

	whenUTC := now.UTC()

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         keysManageAction,
		ResourceKind:   string(domain.KindAPIKey),
		ResourceID:     keyID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for keys.manage",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// organization_id is the target tenant of the rotation; rotated_prefix
		// is the public, non-secret lookup id the row now serves. The audit
		// trail records which credential body is now authoritative without
		// carrying any secret material verbatim — the secret hash never
		// appears in the metadata.
		Metadata: map[string]string{
			"organization_id": organizationID,
			"rotated_prefix":  prefix,
		},
	}

	var rotated APIKey
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Read the current row inside the same transaction so a missing key
		// in this tenant is reported as NotFound without relying on the
		// UPDATE's no-rows path, and so the lifecycle decision sees the same
		// row the UPDATE would lock. A cross-tenant key_id is
		// indistinguishable from a missing row — exactly what every other
		// read endpoint of this resource guarantees.
		current, getErr := svc.apiKeys.Get(ctx, tx, organizationID, keyID)
		if getErr != nil {
			return getErr
		}
		if current.IsRevoked() {
			// Rotating a revoked key cannot revive it — the row is permanently
			// out of authentication service, so a fresh credential body would
			// be silently unusable. Surface a stable Conflict so the caller
			// learns to mint a new key through Create instead.
			return apierr.Conflict("api key is revoked")
		}
		if current.IsExpired(whenUTC) {
			// Same reasoning for an expired key: the calendar has already
			// taken the row out of authentication service.
			return apierr.Conflict("api key is expired")
		}

		row, rotErr := svc.apiKeys.RotateCredential(ctx, tx, organizationID, keyID, prefix, secretHash)
		if rotErr != nil {
			return rotErr
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		rotated = row
		return nil
	})
	if txErr != nil {
		return APIKey{}, txErr
	}
	return rotated, nil
}

// apiKeyUpdate is the validated, normalised result of buildAPIKeyUpdate: a
// list of the field names the patch changed (in a stable wire shape) and the
// normalised values for each non-nil field. A nil pointer in change.name or
// change.scopes means the caller did not supply that field and the unit of
// work must preserve the current row's value.
type apiKeyUpdate struct {
	fields []string
	name   *string
	scopes *[]string
}

// buildAPIKeyUpdate validates the caller-supplied mutable fields of in and
// returns the apiKeyUpdate the unit of work applies. It is split out from
// Update so the validation rules are unit testable without a database, and
// so an invalid request is rejected before a transaction is ever opened. On
// failure it returns a typed apierr.InvalidInput carrying stable field
// paths — never the submitted values — so the rejection can name the
// offending field without leaking input.
func buildAPIKeyUpdate(in UpdateAPIKeyInput) (apiKeyUpdate, error) {
	var (
		change     apiKeyUpdate
		violations []apierr.FieldViolation
	)

	if in.Name != nil {
		change.fields = append(change.fields, "name")
		name := strings.TrimSpace(*in.Name)
		switch {
		case name == "":
			violations = append(violations, apierr.FieldViolation{
				Field:  "name",
				Reason: "must not be blank",
			})
		case !utf8.ValidString(name):
			violations = append(violations, apierr.FieldViolation{
				Field:  "name",
				Reason: "must be valid UTF-8",
			})
		case utf8.RuneCountInString(name) > apiKeyNameMaxLen:
			violations = append(violations, apierr.FieldViolation{
				Field:  "name",
				Reason: "must be at most 100 characters",
			})
		case apiKeyHasControlRune(name):
			violations = append(violations, apierr.FieldViolation{
				Field:  "name",
				Reason: "must not contain control characters",
			})
		default:
			change.name = &name
		}
	}

	if in.Scopes != nil {
		change.fields = append(change.fields, "scopes")
		scopes, scopeViolations := validateAPIKeyScopes(*in.Scopes)
		if len(scopeViolations) > 0 {
			violations = append(violations, scopeViolations...)
		} else {
			change.scopes = &scopes
		}
	}

	if len(change.fields) == 0 {
		violations = append(violations, apierr.FieldViolation{
			Field:  "name",
			Reason: "at least one of name or scopes must be provided",
		})
	}

	if len(violations) > 0 {
		return apiKeyUpdate{}, apierr.InvalidInput(violations...)
	}
	return change, nil
}

// buildAPIKeyToCreate validates in and returns the APIKey row it would
// persist, with a freshly minted, non-guessable id. It is split out from
// Create so the validation rules are unit testable without a database, and
// so an invalid request is rejected before a transaction is ever opened. On
// failure it returns a typed apierr.InvalidInput carrying stable field
// paths — never the submitted values — so the rejection can name the
// offending field without leaking input (in particular it never echoes
// the rejected name or scope string into the response body).
func buildAPIKeyToCreate(in CreateAPIKeyInput, now time.Time) (APIKey, error) {
	var violations []apierr.FieldViolation

	orgID := strings.TrimSpace(in.OrganizationID)
	if id, err := domain.ParseID(orgID); err != nil || id.Kind() != domain.KindOrganization {
		violations = append(violations, apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization id",
		})
	}

	name := strings.TrimSpace(in.Name)
	switch {
	case name == "":
		violations = append(violations, apierr.FieldViolation{
			Field:  "name",
			Reason: "must not be blank",
		})
	case !utf8.ValidString(name):
		violations = append(violations, apierr.FieldViolation{
			Field:  "name",
			Reason: "must be valid UTF-8",
		})
	case utf8.RuneCountInString(name) > apiKeyNameMaxLen:
		violations = append(violations, apierr.FieldViolation{
			Field:  "name",
			Reason: "must be at most 100 characters",
		})
	case apiKeyHasControlRune(name):
		violations = append(violations, apierr.FieldViolation{
			Field:  "name",
			Reason: "must not contain control characters",
		})
	}

	scopes, scopeViolations := validateAPIKeyScopes(in.Scopes)
	violations = append(violations, scopeViolations...)

	if in.ExpiresAt != nil && !in.ExpiresAt.After(now) {
		violations = append(violations, apierr.FieldViolation{
			Field:  "expires_at",
			Reason: "must be strictly in the future",
		})
	}

	serviceAccountID := strings.TrimSpace(in.ServiceAccountID)
	if serviceAccountID != "" {
		if id, err := domain.ParseID(serviceAccountID); err != nil || id.Kind() != domain.KindServiceAccount {
			violations = append(violations, apierr.FieldViolation{
				Field:  "service_account_id",
				Reason: "must be a valid service account id",
			})
		}
	}

	createdBy := strings.TrimSpace(in.CreatedBy)
	if createdBy != "" {
		if id, err := domain.ParseID(createdBy); err != nil || id.Kind() != domain.KindUser {
			violations = append(violations, apierr.FieldViolation{
				Field:  "created_by",
				Reason: "must be a valid user id",
			})
		}
	}

	// Prefix/SecretHash are not client input: they come from the auth-layer
	// credential mint. A blank pair is a wiring error in the calling handler,
	// not a validation failure, so it is reported as Internal — and never as
	// an InvalidInput that could let a buggy client believe the request was
	// rejected on a field they control.
	prefix := strings.TrimSpace(in.Prefix)
	secretHash := strings.TrimSpace(in.SecretHash)
	if prefix == "" || secretHash == "" {
		return APIKey{}, apierr.Internal(errors.New("store: APIKeyService.Create requires a non-empty prefix and secret hash from the auth layer"))
	}

	if len(violations) > 0 {
		return APIKey{}, apierr.InvalidInput(violations...)
	}

	id, err := domain.NewID(domain.KindAPIKey)
	if err != nil {
		// A crypto/rand failure is an environment fault, not client input.
		return APIKey{}, apierr.Internal(err)
	}

	row := APIKey{
		ID:               id.String(),
		OrganizationID:   orgID,
		Prefix:           prefix,
		SecretHash:       secretHash,
		Name:             name,
		Scopes:           scopes,
		CreatedBy:        createdBy,
		ServiceAccountID: serviceAccountID,
	}
	if in.ExpiresAt != nil {
		expires := in.ExpiresAt.UTC()
		row.ExpiresAt = &expires
	}
	return row, nil
}

// validateAPIKeyScopes checks every scope string and returns the trimmed
// list ready to persist. Per-scope rejections name the indexed field path
// (for example "scopes[2]") so a caller can fix the right element; the
// rejected value itself is never echoed. A nil or empty input is allowed —
// a key may be minted with no scopes — and is normalised to an empty
// (non-nil) slice so the api_keys.scopes column receives '{}' instead of
// SQL NULL.
func validateAPIKeyScopes(in []string) ([]string, []apierr.FieldViolation) {
	if len(in) == 0 {
		return []string{}, nil
	}
	if len(in) > apiKeyMaxScopes {
		return nil, []apierr.FieldViolation{{
			Field:  "scopes",
			Reason: "must contain at most 64 entries",
		}}
	}

	var violations []apierr.FieldViolation
	seen := make(map[string]struct{}, len(in))
	normalised := make([]string, 0, len(in))
	for i, raw := range in {
		field := "scopes[" + strconv.Itoa(i) + "]"
		s := strings.TrimSpace(raw)
		switch {
		case s == "":
			violations = append(violations, apierr.FieldViolation{Field: field, Reason: "must not be blank"})
			continue
		case !utf8.ValidString(s):
			violations = append(violations, apierr.FieldViolation{Field: field, Reason: "must be valid UTF-8"})
			continue
		case len(s) > apiKeyScopeMaxLen:
			violations = append(violations, apierr.FieldViolation{Field: field, Reason: "must be at most 64 bytes"})
			continue
		case !isAPIKeyScope(s):
			violations = append(violations, apierr.FieldViolation{Field: field, Reason: "must contain only lowercase letters, digits, '_', ':', '.', or '-'"})
			continue
		}
		if _, dup := seen[s]; dup {
			violations = append(violations, apierr.FieldViolation{Field: field, Reason: "must be unique within scopes"})
			continue
		}
		seen[s] = struct{}{}
		normalised = append(normalised, s)
	}
	if len(violations) > 0 {
		return nil, violations
	}
	return normalised, nil
}

// isAPIKeyScope reports whether s is composed of the conservative scope
// alphabet: lowercase letters, digits, and the punctuation characters used
// by every catalogued capability ("_", ":", ".", "-"). It bounds the
// scope-string surface to a printable, non-control, log-safe set so an
// attacker cannot inject a control character into a scope name and have it
// surface in metadata or a log line.
func isAPIKeyScope(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '_' || c == ':' || c == '.' || c == '-':
		default:
			return false
		}
	}
	return true
}

// apiKeyHasControlRune reports whether s contains any Unicode control rune.
// It is the same predicate validate.Name uses, repeated here so the store
// layer does not import the http-flavoured validate package.
func apiKeyHasControlRune(s string) bool {
	for _, r := range s {
		if r == utf8.RuneError {
			return true
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
