package audit

import (
	"context"
	"errors"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/output"
)

// Recorder is the narrow persistence port the Auditor depends on. It is
// satisfied by *store.AuditRepository; the indirection keeps the audit service
// unit-testable without a database and lets the package depend on a behaviour
// rather than a concrete repository.
type Recorder interface {
	Append(ctx context.Context, tx *store.Tx, e store.AuditEvent) (store.AuditEvent, error)
}

// Entry is the request-side description of a security-relevant authorization
// decision to be recorded. The Auditor enriches it with the principal and
// correlation identifiers carried on the request context, redacts the
// metadata, and persists the resulting immutable audit record.
type Entry struct {
	// Action is the policy action the decision was made for.
	Action policy.Action
	// Resource is the resource the action targeted; its Kind and Scope locate
	// the audited resource in the organization hierarchy.
	Resource policy.Resource
	// Decision is the policy verdict. Both allow and deny are recorded.
	Decision policy.Decision
	// IPAddress is the client IP the request arrived from, if known.
	IPAddress string
	// UserAgent is the client user agent the request arrived with, if known.
	UserAgent string
	// Metadata is free-form diff / context detail. Every value is redacted
	// before it is persisted: a value under a secret-shaped key is replaced
	// wholesale, and every other value is scrubbed of known secret transport
	// patterns. Keys are never redacted, so the shape of the diff stays
	// auditable.
	Metadata map[string]string
}

// Auditor records authorization decisions to the immutable audit log. It is
// the single place application code turns a policy decision into an audit
// record, so redaction and field mapping are applied uniformly.
type Auditor struct {
	recorder Recorder
	redactor *output.Redactor
}

// NewAuditor constructs an Auditor over recorder. It returns an error for a nil
// recorder so a misconfigured auditor fails at construction rather than on the
// first decision it is asked to record.
func NewAuditor(recorder Recorder) (*Auditor, error) {
	if recorder == nil {
		return nil, apierr.Internal(errors.New("audit: NewAuditor called with a nil recorder"))
	}
	// The redactor carries no registered literal secrets — it is a structural
	// backstop that scrubs known secret transport patterns (Authorization
	// headers, token-bearing query parameters) from metadata values and the
	// user agent. Secret-shaped keys are handled separately, by redactMetadata.
	return &Auditor{recorder: recorder, redactor: output.NewRedactor()}, nil
}

// Record writes one audit record for entry inside tx and returns the persisted
// row. It records both allowed and denied decisions: a denied decision is as
// much a part of the trail as an allowed one. The metadata and user agent are
// redacted before anything is persisted, so a secret can never reach the audit
// log through this path.
//
// tx is the caller's transaction: pass the unit-of-work transaction to audit a
// mutation atomically with it, or a short dedicated transaction to audit a
// decision that performs no mutation (a denial at the HTTP boundary).
func (a *Auditor) Record(ctx context.Context, tx *store.Tx, entry Entry) (store.AuditEvent, error) {
	event, err := a.buildEvent(ctx, entry)
	if err != nil {
		return store.AuditEvent{}, err
	}
	return a.recorder.Append(ctx, tx, event)
}

// buildEvent is the pure mapping from an Entry — plus the principal and
// correlation identifiers carried on ctx — to a redacted store.AuditEvent. It
// is separated from Record so the mapping and redaction are unit-testable
// without a transaction. A non-empty error is always a typed apierr.
func (a *Auditor) buildEvent(ctx context.Context, entry Entry) (store.AuditEvent, error) {
	action := strings.TrimSpace(string(entry.Action))
	if action == "" {
		return store.AuditEvent{}, apierr.Invalid("audit: an audit entry must name an action")
	}
	if entry.Resource.Kind == "" {
		return store.AuditEvent{}, apierr.Invalid("audit: an audit entry must name a resource kind")
	}
	reason := strings.TrimSpace(string(entry.Decision.Reason))
	if reason == "" {
		return store.AuditEvent{}, apierr.Invalid("audit: an audit entry must carry a decision reason")
	}

	// The audit record is filed under the actor's organization when a principal
	// was resolved, and under the targeted resource's organization otherwise
	// (an unauthenticated, denied request still names the org it tried to
	// reach). If neither is known the entry cannot be tenant-scoped and is
	// rejected rather than written to an unknown tenant.
	principal, _ := policy.PrincipalFromContext(ctx)
	orgID := principal.OrganizationID
	if orgID == "" {
		orgID = entry.Resource.Scope.OrganizationID
	}
	if orgID == "" {
		return store.AuditEvent{}, apierr.Invalid("audit: an audit entry must resolve an organization")
	}

	correlation := telemetry.FromContext(ctx)

	decision := store.AuditDecisionDenied
	if entry.Decision.Allow {
		decision = store.AuditDecisionAllowed
	}

	return store.AuditEvent{
		OrganizationID: orgID,
		ActorID:        principal.ID,
		ActorKind:      string(principal.Kind),
		Action:         action,
		ResourceKind:   string(entry.Resource.Kind),
		ResourceID:     resourceID(entry.Resource),
		Decision:       decision,
		Reason:         reason,
		RequestID:      correlation.RequestID,
		CorrelationID:  correlation.CorrelationID,
		IPAddress:      strings.TrimSpace(entry.IPAddress),
		UserAgent:      a.redactor.Redact(strings.TrimSpace(entry.UserAgent)),
		Metadata:       a.redactMetadata(entry.Metadata),
	}, nil
}

// resourceID returns the most specific identifier locating the audited
// resource. For a resource on the Organization -> Project -> Environment ->
// Service hierarchy it is the id at the resource's own level; for any other
// kind it is the deepest scoped id available.
func resourceID(r policy.Resource) string {
	switch r.Kind {
	case domain.KindOrganization:
		return r.Scope.OrganizationID
	case domain.KindProject:
		return r.Scope.ProjectID
	case domain.KindEnvironment:
		return r.Scope.EnvironmentID
	case domain.KindService:
		return r.Scope.ServiceID
	default:
		switch {
		case r.Scope.ServiceID != "":
			return r.Scope.ServiceID
		case r.Scope.EnvironmentID != "":
			return r.Scope.EnvironmentID
		case r.Scope.ProjectID != "":
			return r.Scope.ProjectID
		default:
			return r.Scope.OrganizationID
		}
	}
}

// sensitiveKeyFragments are lowercased substrings that mark a metadata key as
// secret-bearing. A value under such a key is replaced wholesale with the
// redaction sentinel rather than scrubbed pattern-by-pattern, because the
// value itself is the secret, not a string that happens to contain one.
var sensitiveKeyFragments = []string{
	"secret",
	"password",
	"passwd",
	"token",
	"api_key",
	"apikey",
	"api-key",
	"access_key",
	"cookie",
	"authorization",
	"credential",
	"private_key",
	"dsn",
	"database_url",
	"connection_string",
}

// isSensitiveKey reports whether key names a metadata field whose value must be
// redacted wholesale.
func isSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	for _, frag := range sensitiveKeyFragments {
		if strings.Contains(k, frag) {
			return true
		}
	}
	return false
}

// redactMetadata returns a copy of m with every value redacted: a value under a
// secret-shaped key is replaced wholesale with output.Sentinel; every other
// value is scrubbed of known secret transport patterns. Keys are preserved
// as-is so the shape of the diff stays auditable. It returns nil for nil or
// empty input so the persisted metadata is a clean empty object.
func (a *Auditor) redactMetadata(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if isSensitiveKey(k) {
			out[k] = output.Sentinel
			continue
		}
		out[k] = a.redactor.Redact(v)
	}
	return out
}
