package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// ServiceVariableReplace is one entry in the caller-supplied replacement
// set. Key, Value, and IsSecret are the closed-set fields a customer can
// submit. The service validates every field before any database work — an
// invalid request never opens a transaction — so the repository layer can
// trust that the values it persists are POSIX environment-variable names
// paired with UTF-8 values within the size ceilings the validate package
// enforces.
//
// Value is the literal value the caller asks to persist. It is never echoed
// back into an apierr.FieldViolation reason (validation reports
// classification, not content), is redacted at the slog boundary when
// logged through ServiceVariable.LogValue, is replaced wholesale with the
// redaction sentinel in audit metadata, and (for IsSecret=true) is
// replaced wholesale on the wire by the HTTP projection.
type ServiceVariableReplace struct {
	Key      string
	Value    string
	IsSecret bool
}

// ReplaceServiceVariablesInput is the typed input to
// ServiceVariableService.Replace. OrganizationID and ServiceID name the
// service whose variables are being replaced. Variables is the
// replacement set — possibly empty (a deliberate clear). The Actor* and
// correlation fields describe the authenticated principal and are
// recorded verbatim on the audit event; they are plain strings so the
// store layer takes no build dependency on the policy or telemetry
// packages — the httpapi handler, which already holds the resolved
// principal and the request correlation, fills them in.
type ReplaceServiceVariablesInput struct {
	OrganizationID string
	ServiceID      string
	Variables      []ServiceVariableReplace
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// ServiceVariableService is the unit-of-work orchestrator for PUT
// /v1/services/{service_id}/variables. Replace composes — in a fixed
// order, inside one transaction opened by Store.Write — a tenant-scoped
// existence check on the target service, one upsert per caller-supplied
// variable, a delete for every variable not in the replacement set, the
// immutable audit record, and a re-read of the committed variables in
// deterministic (key, id) order. Because every step shares the *Tx, a
// failure in any of them rolls the others back: a partial replace and an
// orphaned audit record are both impossible.
//
// The service also re-reads the committed variables inside the same
// transaction so the response always reflects exactly the state that
// just persisted — the same coherence guarantee
// EnvironmentVariableService.Replace gives PUT
// /v1/environments/{environment_id}/variables.
type ServiceVariableService struct {
	store     *Store
	services  *ServiceRepository
	variables *ServiceVariableRepository
	audit     AuditAppender
	provider  secrets.Provider
}

// NewServiceVariableService wires a ServiceVariableService from its
// dependencies. It returns a typed error if any dependency is nil, so a
// misconfigured service fails at construction rather than on its first
// request — the same fail-fast posture every other unit-of-work
// orchestrator in this package takes.
//
// provider is the secrets.Provider that seals every secret value before
// it is persisted and opens sealed values for internal-only read paths.
// It is required: a nil provider is rejected at construction so a
// production process cannot accidentally start with the at-rest seam
// disabled. Tests that do not exercise the encryption seam directly
// pass secrets.NewPlaintext() — the plaintext provider is acceptable
// in local/test profiles only and cmd/yalla-api rejects it for
// staging/production.
func NewServiceVariableService(s *Store, services *ServiceRepository, variables *ServiceVariableRepository, audit AuditAppender, provider secrets.Provider) (*ServiceVariableService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case services == nil:
		return nil, errors.New("store: nil service repository")
	case variables == nil:
		return nil, errors.New("store: nil service variable repository")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	case provider == nil:
		return nil, errors.New("store: nil secrets provider")
	}
	return &ServiceVariableService{store: s, services: services, variables: variables, audit: audit, provider: provider}, nil
}

// sealVariableValue projects a ServiceVariableReplace onto the
// repository's upsert tuple, calling secrets.Provider.Seal for
// IsSecret = true items. Non-secret items pass through with empty
// encryption-at-rest columns. Seal failures surface as apierr.Internal
// — a sealing error is a server-side problem, never a customer
// instruction, and the wrapped cause is value-free (the secrets package
// contract).
func (svc *ServiceVariableService) sealVariableValue(item ServiceVariableReplace) (ServiceVariableUpsert, error) {
	if !item.IsSecret {
		return ServiceVariableUpsert{Value: item.Value, IsSecret: false}, nil
	}
	ciphertext, keyID, err := svc.provider.Seal([]byte(item.Value))
	if err != nil {
		return ServiceVariableUpsert{}, apierr.Internal(fmt.Errorf("seal service variable: %w", err))
	}
	return ServiceVariableUpsert{
		Value:            "",
		IsSecret:         true,
		SecretProvider:   svc.provider.ProviderID(),
		SecretKeyID:      keyID,
		SecretCiphertext: ciphertext,
	}, nil
}

// Replace validates in, then runs the replace-variables unit of work
// inside one transaction: verify the service exists in the target
// organization (so a missing service is a typed NotFound rather than the
// generic FK conflict the upsert would otherwise produce), upsert each
// caller-supplied variable, delete every variable not in the replacement
// set, append the audit record, and re-read the committed state in
// deterministic (key, id) order. Validation runs before the transaction
// is opened, so an invalid request never touches the database.
//
// An empty Variables list is allowed and means "clear every
// service-scoped variable": a customer explicitly asking for an empty
// state is meaningful, not a silent no-op. A duplicate key, a non-POSIX
// key, an over-sized value, an invalid-UTF-8 value, or a value carrying
// a NUL byte each surfaces as apierr.InvalidInput with a stable,
// value-free field path. A {service_id} that does not exist in the
// actor's organization is the typed apierr.NotFound the repository
// produces. Any database constraint violation rolls the whole
// transaction back as a typed apierr.Conflict, so a misleading partial
// replace and an orphaned audit record are both impossible.
//
// The audit event is filed under the actor's home organization (the
// tenant the principal authenticated into) with resource_kind=svc and
// resource_id={service_id}, mirroring how the service lifecycle
// endpoints file mutations against the service rather than the per-row
// variable id. Metadata records only counts — never variable keys or
// values — so the audit row is auditable without ever leaking a
// customer-supplied name or secret.
func (svc *ServiceVariableService) Replace(ctx context.Context, in ReplaceServiceVariablesInput) ([]ServiceVariable, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return nil, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	serviceID := strings.TrimSpace(in.ServiceID)
	if serviceID == "" {
		return nil, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must not be blank",
		})
	}

	items, err := buildServiceVariableReplace(in.Variables)
	if err != nil {
		return nil, err
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return nil, apierr.Internal(errors.New("store: ServiceVariableService.Replace requires an actor organization for the audit record"))
	}

	keepKeys := make([]string, 0, len(items))
	secretCount := 0
	for _, item := range items {
		keepKeys = append(keepKeys, item.Key)
		if item.IsSecret {
			secretCount++
		}
	}
	// Sort so the SQL plan is deterministic on hot paths where pgx can
	// cache it. The keys are never projected onto the audit metadata or
	// back to the customer through this layer.
	sort.Strings(keepKeys)

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         serviceVariablesWriteAction,
		ResourceKind:   string(domain.KindService),
		ResourceID:     serviceID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for env.write",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// Counts are safe to record verbatim: they are integers, never the
		// caller-supplied key or value strings. The audit reader sees the
		// shape of the change without ever observing a secret. The audit
		// Auditor's redactor still scrubs values pattern-by-pattern as a
		// second line of defence.
		Metadata: map[string]string{
			"variable_count": strconv.Itoa(len(items)),
			"secret_count":   strconv.Itoa(secretCount),
		},
	}

	var committed []ServiceVariable
	if txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Existence check first so a missing service is the typed
		// NotFound the repository produces, not the generic FK conflict
		// the upsert would otherwise yield. The GetByID call shares the
		// *Tx so a row that vanishes between this check and the upserts
		// is not possible. It also rejects a cross-tenant service_id:
		// ServiceRepository.GetByID filters by organization_id first, so
		// a service owned by another tenant is indistinguishable from a
		// missing row.
		if _, getErr := svc.services.GetByID(ctx, tx, organizationID, serviceID); getErr != nil {
			return getErr
		}
		for _, item := range items {
			id, idErr := domain.NewID(domain.KindServiceVariable)
			if idErr != nil {
				return apierr.Internal(idErr)
			}
			sealed, sealErr := svc.sealVariableValue(item)
			if sealErr != nil {
				return sealErr
			}
			if _, upErr := svc.variables.Upsert(ctx, tx, id.String(), organizationID, serviceID, item.Key, sealed); upErr != nil {
				return upErr
			}
		}
		if delErr := svc.variables.DeleteByServiceExceptKeys(ctx, tx, organizationID, serviceID, keepKeys); delErr != nil {
			return delErr
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		// Re-read the committed variables inside the same transaction so
		// the response always reflects exactly the state that just
		// persisted.
		list, listErr := svc.variables.ListByService(ctx, tx, organizationID, serviceID)
		if listErr != nil {
			return listErr
		}
		committed = list
		return nil
	}); txErr != nil {
		return nil, txErr
	}
	return committed, nil
}

// buildServiceVariableReplace validates and normalises the caller-
// supplied items. It is split out from Replace so the validation rules
// are unit testable without a database, and so an invalid request is
// rejected before a transaction is ever opened.
//
// An empty list is allowed: the caller explicitly asked to clear every
// service-scoped variable, which is a meaningful (extreme) operation,
// not a silent no-op. A duplicate key, a non-POSIX key, an over-sized
// value, an invalid UTF-8 value, or a NUL byte in a value each surfaces
// as a typed apierr.InvalidInput carrying stable, value-free field paths
// — never the submitted value.
//
// Field-path shape mirrors the JSON request body: "variables[i].key" for
// key violations, "variables[i].value" for value violations. is_secret
// is a boolean and so cannot itself be invalid; it only routes a value's
// size ceiling (MaxSecretValueLen for is_secret=true, MaxEnvVarValueLen
// otherwise). The reason text classifies the failure (bounds, character
// class, duplicate) but never echoes the offending value — a secret can
// never reach a violation reason.
func buildServiceVariableReplace(in []ServiceVariableReplace) ([]ServiceVariableReplace, error) {
	collector := validate.New()
	seen := make(map[string]struct{}, len(in))
	out := make([]ServiceVariableReplace, 0, len(in))
	for i, item := range in {
		path := "variables[" + itoaVariableIndex(i) + "]"
		key := strings.TrimSpace(item.Key)
		validKey := true
		if !posixEnvVarName(key) {
			collector.Add(path+".key", "must be a POSIX environment variable name ([A-Za-z_][A-Za-z0-9_]*)")
			validKey = false
		} else if len(key) > validate.MaxEnvVarNameLen {
			collector.Addf(path+".key", "must be at most %d characters", validate.MaxEnvVarNameLen)
			validKey = false
		} else if _, dup := seen[key]; dup {
			collector.Add(path+".key", "duplicates another variable key")
			validKey = false
		}
		if validKey {
			seen[key] = struct{}{}
		}

		maxValue := validate.MaxEnvVarValueLen
		if item.IsSecret {
			maxValue = validate.MaxSecretValueLen
		}
		switch {
		case !utf8.ValidString(item.Value):
			collector.Add(path+".value", "must be valid UTF-8")
		case strings.ContainsRune(item.Value, 0):
			collector.Add(path+".value", "must not contain NUL bytes")
		case len(item.Value) > maxValue:
			collector.Addf(path+".value", "must be at most %d bytes", maxValue)
		}

		out = append(out, ServiceVariableReplace{
			Key:      key,
			Value:    item.Value,
			IsSecret: item.IsSecret,
		})
	}
	if err := collector.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
