package store

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// itoa renders a non-negative array index as a decimal string. It is the
// store-package counterpart of the httpapi/limits.go itoaIndex helper, kept
// here so the "variables[i].field" field paths the service emits match the
// httpapi layer's shape byte-for-byte.
func itoaVariableIndex(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// envWriteAction is the action recorded on the audit event for PUT
// /v1/organizations/{org_id}/variables. It is kept as a plain string here
// so the store layer takes no build dependency on
// internal/controlplane/policy; the HTTP authorization middleware authorizes
// the same action before the handler is reached, and the policy matrix tests
// keep the two values in sync.
const envWriteAction = "env.write"

// OrganizationVariableReplace is one entry in the caller-supplied
// replacement set. Key, Value, and IsSecret are the closed-set fields a
// customer can submit. The service validates every field before any
// database work — an invalid request never opens a transaction — so the
// repository layer can trust that the values it persists are POSIX
// environment-variable names paired with UTF-8 values within the size
// ceilings the validate package enforces.
//
// Value is the literal value the caller asks to persist. It is never
// echoed back into an apierr.FieldViolation reason (validation reports
// classification, not content), is redacted at the slog boundary when
// logged through OrganizationVariable.LogValue, is replaced wholesale with
// the redaction sentinel in audit metadata, and (for IsSecret=true) is
// replaced wholesale on the wire by the HTTP projection.
type OrganizationVariableReplace struct {
	Key      string
	Value    string
	IsSecret bool
}

// ReplaceOrganizationVariablesInput is the typed input to
// OrganizationVariableService.Replace. OrganizationID names the tenant
// whose organization-scoped variables are being replaced. Variables is the
// replacement set — possibly empty (a deliberate clear). The Actor* and
// correlation fields describe the authenticated principal and are recorded
// verbatim on the audit event; they are plain strings so the store layer
// takes no build dependency on the policy or telemetry packages — the
// httpapi handler, which already holds the resolved principal and the
// request correlation, fills them in.
type ReplaceOrganizationVariablesInput struct {
	OrganizationID string
	Variables      []OrganizationVariableReplace
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// OrganizationVariableService is the unit-of-work orchestrator for PUT
// /v1/organizations/{org_id}/variables. Replace composes — in a fixed
// order, inside one transaction opened by Store.Write — a tenant-scoped
// existence check on the target organization, one upsert per
// caller-supplied variable, a delete for every variable not in the
// replacement set, the immutable audit record, and a re-read of the
// committed variables in deterministic (key, id) order. Because every
// step shares the *Tx, a failure in any of them rolls the others back: a
// partial replace and an orphaned audit record are both impossible.
//
// The service also re-reads the committed variables inside the same
// transaction so the response always reflects exactly the state that just
// persisted — the same coherence guarantee LimitsService.UpdateLimits
// gives PATCH /v1/organizations/{org_id}/limits.
type OrganizationVariableService struct {
	store *Store
	orgs  *OrganizationRepository
	vars  *OrganizationVariableRepository
	audit AuditAppender
}

// NewOrganizationVariableService wires an OrganizationVariableService from
// its dependencies. It returns a typed error if any dependency is nil, so a
// misconfigured service fails at construction rather than on its first
// request — the same fail-fast posture every other unit-of-work
// orchestrator in this package takes.
func NewOrganizationVariableService(s *Store, orgs *OrganizationRepository, vars *OrganizationVariableRepository, audit AuditAppender) (*OrganizationVariableService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case orgs == nil:
		return nil, errors.New("store: nil organization repository")
	case vars == nil:
		return nil, errors.New("store: nil organization variable repository")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &OrganizationVariableService{store: s, orgs: orgs, vars: vars, audit: audit}, nil
}

// Replace validates in, then runs the replace-variables unit of work
// inside one transaction: verify the organization exists (so a missing
// tenant is a typed NotFound rather than the generic FK conflict the
// upsert would otherwise produce), upsert each caller-supplied variable,
// delete every variable not in the replacement set, append the audit
// record, and re-read the committed state in deterministic (key, id)
// order. Validation runs before the transaction is opened, so an invalid
// request never touches the database.
//
// An empty Variables list is allowed and means "clear every
// organization-scoped variable": a customer explicitly asking for an
// empty state is meaningful, not a silent no-op. A duplicate key, a
// non-POSIX key, an over-sized value, an invalid-UTF-8 value, or a
// value carrying a NUL byte each surfaces as apierr.InvalidInput with a
// stable, value-free field path. An {org_id} with no organizations row is
// the typed apierr.NotFound the repository produces. Any database
// constraint violation rolls the whole transaction back as a typed
// apierr.Conflict, so a misleading partial replace and an orphaned audit
// record are both impossible.
//
// The audit event is filed under the actor's home organization (the
// tenant the principal authenticated into) with resource_kind=org and
// resource_id={org_id}, mirroring how LimitsService.UpdateLimits files
// a bulk operation against the organization rather than the per-row id.
// Metadata records only counts — never variable keys or values — so the
// audit row is auditable without ever leaking a customer-supplied name
// or secret.
func (svc *OrganizationVariableService) Replace(ctx context.Context, in ReplaceOrganizationVariablesInput) ([]OrganizationVariable, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return nil, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}

	items, err := buildOrganizationVariableReplace(in.Variables)
	if err != nil {
		return nil, err
	}

	// The audit record is filed under the actor's home organization — the
	// tenant the principal authenticated into — while its resource id names
	// the organization whose variables were replaced. A missing actor
	// organization is a wiring error (an authenticated request always
	// carries one), not client input, so it is reported as Internal rather
	// than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return nil, apierr.Internal(errors.New("store: OrganizationVariableService.Replace requires an actor organization for the audit record"))
	}

	// keepKeys is the set of keys the caller asked to retain, populated in
	// caller order. It is used twice: as the SQL parameter to the bulk
	// delete that drops the rest, and (sorted, lower-cased on the caller
	// side already through validate.EnvVars uppercase rules — no, env var
	// names ARE case-sensitive: we keep verbatim) for the audit metadata.
	// The audit metadata records only COUNTS, never the keys themselves,
	// so a customer-supplied variable name cannot leak into the audit row.
	keepKeys := make([]string, 0, len(items))
	secretCount := 0
	for _, item := range items {
		keepKeys = append(keepKeys, item.Key)
		if item.IsSecret {
			secretCount++
		}
	}
	// The keep-set is delete-by-exclusion: we never project the keys onto
	// audit or back to the customer through this metadata layer. Sorting
	// keeps the SQL plan deterministic on hot paths where pgx can cache it.
	sort.Strings(keepKeys)

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         envWriteAction,
		ResourceKind:   string(domain.KindOrganization),
		ResourceID:     organizationID,
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

	var committed []OrganizationVariable
	if txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Existence check first so a missing tenant is the typed NotFound
		// the repository produces, not the generic FK conflict the upsert
		// would otherwise yield. The Get call shares the *Tx so a row that
		// vanishes between this check and the upsert is not possible.
		if _, getErr := svc.orgs.Get(ctx, tx, organizationID); getErr != nil {
			return getErr
		}
		for _, item := range items {
			id, idErr := domain.NewID(domain.KindOrganizationVariable)
			if idErr != nil {
				return apierr.Internal(idErr)
			}
			if _, upErr := svc.vars.Upsert(ctx, tx, id.String(), organizationID, item.Key, item.Value, item.IsSecret); upErr != nil {
				return upErr
			}
		}
		if delErr := svc.vars.DeleteByOrganizationExceptKeys(ctx, tx, organizationID, keepKeys); delErr != nil {
			return delErr
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		// Re-read the committed variables inside the same transaction so
		// the response always reflects exactly the state that just
		// persisted — the same coherence guarantee LimitsService's
		// post-write re-read carries.
		list, listErr := svc.vars.ListByOrganization(ctx, tx, organizationID)
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

// buildOrganizationVariableReplace validates and normalises the
// caller-supplied items. It is split out from Replace so the validation
// rules are unit testable without a database, and so an invalid request is
// rejected before a transaction is ever opened.
//
// An empty list is allowed: the caller explicitly asked to clear every
// organization-scoped variable, which is a meaningful (extreme) operation,
// not a silent no-op. A duplicate key, a non-POSIX key, an over-sized
// value, an invalid UTF-8 value, or a NUL byte in a value each surfaces as
// a typed apierr.InvalidInput carrying stable, value-free field paths —
// never the submitted value.
//
// Field-path shape mirrors the JSON request body: "variables[i].key" for
// key violations, "variables[i].value" for value violations. is_secret is
// a boolean and so cannot itself be invalid; it only routes a value's
// size ceiling (MaxSecretValueLen for is_secret=true,
// MaxEnvVarValueLen otherwise). The reason text classifies the failure
// (bounds, character class, duplicate) but never echoes the offending
// value — a secret can never reach a violation reason.
func buildOrganizationVariableReplace(in []OrganizationVariableReplace) ([]OrganizationVariableReplace, error) {
	collector := validate.New()
	seen := make(map[string]struct{}, len(in))
	out := make([]OrganizationVariableReplace, 0, len(in))
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

		out = append(out, OrganizationVariableReplace{
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

// posixEnvVarName reports whether name is a POSIX shell environment
// variable name: a non-empty string of [A-Za-z0-9_] that does not start
// with a digit. It is the same rule validate.EnvVars enforces; replicated
// locally so the field-path shape stays "variables[i].key" without going
// through validate.EnvVars' ".secret[i]" / "[i]" routing (which suits a
// caller that submits secret and non-secret entries in separate lists, not
// the unified shape this PUT endpoint accepts).
func posixEnvVarName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch == '_':
			// always allowed
		case ch >= '0' && ch <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
