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

// ProjectVariableReplace is one entry in the caller-supplied replacement set.
// Key, Value, and IsSecret are the closed-set fields a customer can submit.
// The service validates every field before any database work — an invalid
// request never opens a transaction — so the repository layer can trust
// that the values it persists are POSIX environment-variable names paired
// with UTF-8 values within the size ceilings the validate package enforces.
//
// Value is the literal value the caller asks to persist. It is never echoed
// back into an apierr.FieldViolation reason (validation reports
// classification, not content), is redacted at the slog boundary when
// logged through ProjectVariable.LogValue, is replaced wholesale with the
// redaction sentinel in audit metadata, and (for IsSecret=true) is replaced
// wholesale on the wire by the HTTP projection.
type ProjectVariableReplace struct {
	Key      string
	Value    string
	IsSecret bool
}

// ReplaceProjectVariablesInput is the typed input to
// ProjectVariableService.Replace. OrganizationID and ProjectID name the
// project whose variables are being replaced. Variables is the replacement
// set — possibly empty (a deliberate clear). The Actor* and correlation
// fields describe the authenticated principal and are recorded verbatim on
// the audit event; they are plain strings so the store layer takes no build
// dependency on the policy or telemetry packages — the httpapi handler,
// which already holds the resolved principal and the request correlation,
// fills them in.
type ReplaceProjectVariablesInput struct {
	OrganizationID string
	ProjectID      string
	Variables      []ProjectVariableReplace
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// ProjectVariableService is the unit-of-work orchestrator for PUT
// /v1/projects/{project_id}/variables. Replace composes — in a fixed order,
// inside one transaction opened by Store.Write — a tenant-scoped existence
// check on the target project, one upsert per caller-supplied variable, a
// delete for every variable not in the replacement set, the immutable audit
// record, and a re-read of the committed variables in deterministic (key,
// id) order. Because every step shares the *Tx, a failure in any of them
// rolls the others back: a partial replace and an orphaned audit record are
// both impossible.
//
// The service also re-reads the committed variables inside the same
// transaction so the response always reflects exactly the state that just
// persisted — the same coherence guarantee
// OrganizationVariableService.Replace gives PUT
// /v1/organizations/{org_id}/variables.
type ProjectVariableService struct {
	store     *Store
	projects  *ProjectRepository
	variables *ProjectVariableRepository
	audit     AuditAppender
}

// NewProjectVariableService wires a ProjectVariableService from its
// dependencies. It returns a typed error if any dependency is nil, so a
// misconfigured service fails at construction rather than on its first
// request — the same fail-fast posture every other unit-of-work
// orchestrator in this package takes.
func NewProjectVariableService(s *Store, projects *ProjectRepository, variables *ProjectVariableRepository, audit AuditAppender) (*ProjectVariableService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case projects == nil:
		return nil, errors.New("store: nil project repository")
	case variables == nil:
		return nil, errors.New("store: nil project variable repository")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &ProjectVariableService{store: s, projects: projects, variables: variables, audit: audit}, nil
}

// Replace validates in, then runs the replace-variables unit of work inside
// one transaction: verify the project exists in the target organization
// (so a missing project is a typed NotFound rather than the generic FK
// conflict the upsert would otherwise produce), upsert each caller-supplied
// variable, delete every variable not in the replacement set, append the
// audit record, and re-read the committed state in deterministic (key, id)
// order. Validation runs before the transaction is opened, so an invalid
// request never touches the database.
//
// An empty Variables list is allowed and means "clear every project-scoped
// variable": a customer explicitly asking for an empty state is meaningful,
// not a silent no-op. A duplicate key, a non-POSIX key, an over-sized
// value, an invalid-UTF-8 value, or a value carrying a NUL byte each
// surfaces as apierr.InvalidInput with a stable, value-free field path. A
// {project_id} that does not exist in the actor's organization is the typed
// apierr.NotFound the repository produces. Any database constraint
// violation rolls the whole transaction back as a typed apierr.Conflict, so
// a misleading partial replace and an orphaned audit record are both
// impossible.
//
// The audit event is filed under the actor's home organization (the tenant
// the principal authenticated into) with resource_kind=project and
// resource_id={project_id}, mirroring how the project lifecycle endpoints
// file mutations against the project rather than the per-row variable id.
// Metadata records only counts — never variable keys or values — so the
// audit row is auditable without ever leaking a customer-supplied name or
// secret.
func (svc *ProjectVariableService) Replace(ctx context.Context, in ReplaceProjectVariablesInput) ([]ProjectVariable, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return nil, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	projectID := strings.TrimSpace(in.ProjectID)
	if projectID == "" {
		return nil, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "project_id",
			Reason: "must not be blank",
		})
	}

	items, err := buildProjectVariableReplace(in.Variables)
	if err != nil {
		return nil, err
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return nil, apierr.Internal(errors.New("store: ProjectVariableService.Replace requires an actor organization for the audit record"))
	}

	keepKeys := make([]string, 0, len(items))
	secretCount := 0
	for _, item := range items {
		keepKeys = append(keepKeys, item.Key)
		if item.IsSecret {
			secretCount++
		}
	}
	// Sort so the SQL plan is deterministic on hot paths where pgx can cache
	// it. The keys are never projected onto the audit metadata or back to the
	// customer through this layer.
	sort.Strings(keepKeys)

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         projectVariablesWriteAction,
		ResourceKind:   string(domain.KindProject),
		ResourceID:     projectID,
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

	var committed []ProjectVariable
	if txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Existence check first so a missing project is the typed NotFound
		// the repository produces, not the generic FK conflict the upsert
		// would otherwise yield. The Get call shares the *Tx so a row that
		// vanishes between this check and the upserts is not possible. It
		// also rejects a cross-tenant project_id: ProjectRepository.Get
		// filters by organization_id first, so a project owned by another
		// tenant is indistinguishable from a missing row.
		if _, getErr := svc.projects.Get(ctx, tx, organizationID, projectID); getErr != nil {
			return getErr
		}
		for _, item := range items {
			id, idErr := domain.NewID(domain.KindProjectVariable)
			if idErr != nil {
				return apierr.Internal(idErr)
			}
			if _, upErr := svc.variables.Upsert(ctx, tx, id.String(), organizationID, projectID, item.Key, item.Value, item.IsSecret); upErr != nil {
				return upErr
			}
		}
		if delErr := svc.variables.DeleteByProjectExceptKeys(ctx, tx, organizationID, projectID, keepKeys); delErr != nil {
			return delErr
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		// Re-read the committed variables inside the same transaction so
		// the response always reflects exactly the state that just
		// persisted.
		list, listErr := svc.variables.ListByProject(ctx, tx, organizationID, projectID)
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

// buildProjectVariableReplace validates and normalises the caller-supplied
// items. It is split out from Replace so the validation rules are unit
// testable without a database, and so an invalid request is rejected before
// a transaction is ever opened.
//
// An empty list is allowed: the caller explicitly asked to clear every
// project-scoped variable, which is a meaningful (extreme) operation, not a
// silent no-op. A duplicate key, a non-POSIX key, an over-sized value, an
// invalid UTF-8 value, or a NUL byte in a value each surfaces as a typed
// apierr.InvalidInput carrying stable, value-free field paths — never the
// submitted value.
//
// Field-path shape mirrors the JSON request body: "variables[i].key" for
// key violations, "variables[i].value" for value violations. is_secret is
// a boolean and so cannot itself be invalid; it only routes a value's size
// ceiling (MaxSecretValueLen for is_secret=true, MaxEnvVarValueLen
// otherwise). The reason text classifies the failure (bounds, character
// class, duplicate) but never echoes the offending value — a secret can
// never reach a violation reason.
func buildProjectVariableReplace(in []ProjectVariableReplace) ([]ProjectVariableReplace, error) {
	collector := validate.New()
	seen := make(map[string]struct{}, len(in))
	out := make([]ProjectVariableReplace, 0, len(in))
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

		out = append(out, ProjectVariableReplace{
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
