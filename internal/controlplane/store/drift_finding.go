package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
	"github.com/jackc/pgx/v5"
)

// DriftFindingStatus is the closed-set lifecycle for a drift finding.
// Open findings require triage; resolved findings are terminal historical
// records. The transition table is deliberately small because the table is a
// triage queue, not a workflow engine.
type DriftFindingStatus string

const (
	// DriftFindingStatusOpen records a finding that still requires triage.
	DriftFindingStatusOpen DriftFindingStatus = "open"
	// DriftFindingStatusResolved records a terminal finding that was acknowledged
	// or repaired by an operator/worker.
	DriftFindingStatusResolved DriftFindingStatus = "resolved"
)

func (s DriftFindingStatus) String() string { return string(s) }

// driftFindingTransitions is the documented drift finding lifecycle table.
// Existing rows are backfilled from resolved_at: unresolved rows are open,
// resolved rows are terminal.
var driftFindingTransitions = map[DriftFindingStatus]map[DriftFindingStatus]struct{}{
	DriftFindingStatusOpen: {
		DriftFindingStatusResolved: {},
	},
	DriftFindingStatusResolved: {},
}

// CanTransitionTo reports whether the drift finding state machine permits a
// status change from s to next. Repository mutations call this before touching
// the drift_findings row.
func (s DriftFindingStatus) CanTransitionTo(next DriftFindingStatus) bool {
	allowed, ok := driftFindingTransitions[s]
	if !ok {
		return false
	}
	_, ok = allowed[next]
	return ok
}

func (s DriftFindingStatus) driftFindingEventType() DriftFindingEventType {
	switch s {
	case DriftFindingStatusOpen:
		return DriftFindingEventTypeOpen
	case DriftFindingStatusResolved:
		return DriftFindingEventTypeResolved
	default:
		return ""
	}
}

// DriftKind is the closed-set classification a reconcile planner emits
// for a row in the drift_findings table. The string values match the
// drift_findings.kind CHECK constraint verbatim and are stable public
// compatibility contract for any future drift triage endpoint or
// reconcile report. They mirror the same taxonomy in
// internal/controlplane/reconcile.DriftKind so the planner can hand its
// detection straight to the repository without remapping.
type DriftKind string

const (
	// DriftKindSafe marks drift that may be auto-repaired: converging
	// actual back to desired is reversible and cannot cause data loss.
	DriftKindSafe DriftKind = "safe"
	// DriftKindDangerous marks drift the reconcile engine refuses to
	// auto-repair; a row of this kind is recorded for human triage.
	DriftKindDangerous DriftKind = "dangerous"
	// DriftKindUnmanaged marks a Dokploy resource without a Yalla
	// counterpart. The row records the resource for operator review and
	// never exposes it to customers by default.
	DriftKindUnmanaged DriftKind = "unmanaged"
)

// driftKinds is the membership set behind DriftKind.Valid.
var driftKinds = map[DriftKind]struct{}{
	DriftKindSafe:      {},
	DriftKindDangerous: {},
	DriftKindUnmanaged: {},
}

// Valid reports whether k is one of the closed set of drift kinds.
func (k DriftKind) Valid() bool {
	_, ok := driftKinds[k]
	return ok
}

// String returns the kind's stable string value, matching the database
// CHECK constraint verbatim.
func (k DriftKind) String() string { return string(k) }

// DriftReason is the closed-set, value-free reason a reconcile planner
// emits for a row in the drift_findings table. The string values match
// the drift_findings.reason CHECK constraint verbatim and mirror the
// reconcile.DriftReason taxonomy. Reasons name *what* drifted, never the
// value that drifted, so a row can never hold a token, API key, cookie,
// or rendered environment variable value.
type DriftReason string

const (
	// DriftReasonEnvVarChanged is emitted when a desired env var's value
	// differs from the actual value on Dokploy. The row carries the key,
	// never the value.
	DriftReasonEnvVarChanged DriftReason = "env_var_changed"
	// DriftReasonEnvVarMissing is emitted when a desired env var is
	// absent on Dokploy.
	DriftReasonEnvVarMissing DriftReason = "env_var_missing"
	// DriftReasonEnvVarExtra is emitted when Dokploy carries an env var
	// the desired state does not.
	DriftReasonEnvVarExtra DriftReason = "env_var_extra"
	// DriftReasonDomainMissing is emitted when a desired domain is
	// absent on Dokploy.
	DriftReasonDomainMissing DriftReason = "domain_missing"
	// DriftReasonDomainRenamed is emitted when a known domain ID exists
	// on Dokploy but its host no longer matches desired.
	DriftReasonDomainRenamed DriftReason = "domain_renamed"
	// DriftReasonServiceMissing is emitted when a managed application or
	// compose service is absent on Dokploy.
	DriftReasonServiceMissing DriftReason = "service_missing"
	// DriftReasonDatabaseMissing is emitted when a managed database
	// service is absent on Dokploy.
	DriftReasonDatabaseMissing DriftReason = "database_missing"
	// DriftReasonServiceTypeChanged is emitted when a known service's
	// type differs between desired and actual.
	DriftReasonServiceTypeChanged DriftReason = "service_type_changed"
	// DriftReasonResourceUnmanaged is emitted for a Dokploy resource
	// that has no Yalla counterpart.
	DriftReasonResourceUnmanaged DriftReason = "resource_unmanaged"
)

// driftReasons is the membership set behind DriftReason.Valid.
var driftReasons = map[DriftReason]struct{}{
	DriftReasonEnvVarChanged:      {},
	DriftReasonEnvVarMissing:      {},
	DriftReasonEnvVarExtra:        {},
	DriftReasonDomainMissing:      {},
	DriftReasonDomainRenamed:      {},
	DriftReasonServiceMissing:     {},
	DriftReasonDatabaseMissing:    {},
	DriftReasonServiceTypeChanged: {},
	DriftReasonResourceUnmanaged:  {},
}

// Valid reports whether r is one of the closed set of drift reasons.
func (r DriftReason) Valid() bool {
	_, ok := driftReasons[r]
	return ok
}

// String returns the reason's stable string value, matching the database
// CHECK constraint verbatim.
func (r DriftReason) String() string { return string(r) }

// DriftLevel names which level of the Yalla hierarchy a drift finding
// applies to. The string values match the drift_findings.level CHECK
// constraint verbatim and mirror reconcile.ResourceLevel.
type DriftLevel string

const (
	// DriftLevelOrganization marks a finding scoped to the organization
	// as a whole (for example an unmanaged Dokploy project that has no
	// Yalla project counterpart).
	DriftLevelOrganization DriftLevel = "organization"
	// DriftLevelProject marks a finding scoped to a single Yalla
	// project.
	DriftLevelProject DriftLevel = "project"
	// DriftLevelEnvironment marks a finding scoped to a single Yalla
	// environment under a project.
	DriftLevelEnvironment DriftLevel = "environment"
	// DriftLevelService marks a finding scoped to a single Yalla
	// service under an environment.
	DriftLevelService DriftLevel = "service"
	// DriftLevelDomain marks a finding scoped to a single managed
	// service domain.
	DriftLevelDomain DriftLevel = "domain"
)

// driftLevels is the membership set behind DriftLevel.Valid.
var driftLevels = map[DriftLevel]struct{}{
	DriftLevelOrganization: {},
	DriftLevelProject:      {},
	DriftLevelEnvironment:  {},
	DriftLevelService:      {},
	DriftLevelDomain:       {},
}

// Valid reports whether l is one of the closed set of drift levels.
func (l DriftLevel) Valid() bool {
	_, ok := driftLevels[l]
	return ok
}

// String returns the level's stable string value, matching the database
// CHECK constraint verbatim.
func (l DriftLevel) String() string { return string(l) }

// driftFindingListMaxLimit caps how many drift_findings rows a single
// ListByOrganization call returns, so an unbounded query can never be
// issued by accident. A non-positive or larger requested limit is
// clamped to this value. An HTTP layer that wants pagination later will
// add an explicit cursor parameter rather than relax this ceiling.
const driftFindingListMaxLimit = 200

// DriftFindingListQuery carries the bounded, tenant-scoped filters supported
// by the admin drift-list API. Empty resource legs mean "all descendants" at
// that level. Status is optional; the zero value returns both open and resolved
// findings.
type DriftFindingListQuery struct {
	ProjectID     string
	EnvironmentID string
	ServiceID     string
	Status        DriftFindingStatus
	Limit         int
}

// DriftFinding is the source-of-truth representation of a row in the
// drift_findings table -- one detected divergence between Yalla's
// desired state and Dokploy's actual state, recorded for operator
// triage. A finding is written once when the reconcile planner detects
// drift; the only mutation the repository performs is resolution, which
// stamps ResolvedAt and ResolvedByActorID together.
//
// The struct carries no credential material -- EnvVarKey is a key only
// (never a value), DokployResourceID / ParentDokployID are non-secret
// Dokploy object identifiers, and Reason / Kind / Level are value-free
// classifications. No field stores tokens, API keys, cookies, or
// rendered environment variable values.
type DriftFinding struct {
	ID                string
	OrganizationID    string
	Status            DriftFindingStatus
	Kind              DriftKind
	Reason            DriftReason
	Level             DriftLevel
	ProjectID         string
	EnvironmentID     string
	ServiceID         string
	ServiceDomainID   string
	EnvVarKey         string
	DokployResourceID string
	ParentDokployID   string
	RequestID         string
	CorrelationID     string
	DetectedAt        time.Time
	ResolvedAt        *time.Time
	ResolvedByActorID string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// DriftFindingTransition is the audited state-machine mutation input for a
// drift_findings row. Actor and request fields are persisted into the
// drift_finding_events row emitted atomically with the status update.
type DriftFindingTransition struct {
	OrganizationID string
	FindingID      string
	NextStatus     DriftFindingStatus
	ActorID        string
	ActorKind      string
	RequestID      string
	CorrelationID  string
	Reason         string
	ResolvedAt     time.Time
}

// LogValue keeps a stray slog record that captures a DriftFinding safe.
// Every field on the struct is non-secret by construction (the table's
// schema cannot hold a token, key, cookie, or rendered env var value),
// but LogValue still projects only the structural identifiers and the
// closed-set classifications so a panic stack trace that happens to
// include a finding payload cannot inadvertently widen the redaction
// surface for a future schema addition.
func (f DriftFinding) LogValue() slog.Value {
	resolved := ""
	if f.ResolvedAt != nil {
		resolved = f.ResolvedAt.UTC().Format(time.RFC3339Nano)
	}
	return slog.GroupValue(
		slog.String("id", f.ID),
		slog.String("organization_id", f.OrganizationID),
		slog.String("status", f.Status.String()),
		slog.String("kind", f.Kind.String()),
		slog.String("reason", f.Reason.String()),
		slog.String("level", f.Level.String()),
		slog.String("project_id", f.ProjectID),
		slog.String("environment_id", f.EnvironmentID),
		slog.String("service_id", f.ServiceID),
		slog.String("service_domain_id", f.ServiceDomainID),
		slog.String("env_var_key", f.EnvVarKey),
		slog.String("dokploy_resource_id", f.DokployResourceID),
		slog.String("parent_dokploy_id", f.ParentDokployID),
		slog.String("request_id", f.RequestID),
		slog.String("correlation_id", f.CorrelationID),
		slog.String("resolved_at", resolved),
		slog.String("resolved_by_actor_id", f.ResolvedByActorID),
	)
}

// driftFindingColumns is the SELECT projection used by every read in
// this repository. Keeping it as a single string keeps the column list
// in lockstep with scanDriftFinding.
const driftFindingColumns = `id, organization_id, kind, reason, level,
	project_id, environment_id, service_id, service_domain_id,
	env_var_key, dokploy_resource_id, parent_dokploy_id,
	request_id, correlation_id,
	detected_at, status, resolved_at, resolved_by_actor_id,
	created_at, updated_at`

// DriftFindingRepository is the persistence half of the drift_findings
// surface. Every read and every write is tenant-scoped: the
// organization_id leg of the predicate is non-optional, so a missing or
// cross-tenant id matches no rows -- never another tenant's findings.
// The repository is stateless; the constructor exists so call sites
// depend on a value rather than a bare struct literal.
//
// The surface is deliberately narrow: Append writes a finding inside a
// transaction, GetByID and ListByOrganization read tenant-scoped, and
// MarkResolved is the one mutation -- a finding's only legal
// state-transition is to be resolved. There is no per-row Delete: row
// removal is reachable only through ON DELETE CASCADE when the parent
// organization (or any scoped parent) is removed.
type DriftFindingRepository struct{}

// NewDriftFindingRepository returns a DriftFindingRepository.
func NewDriftFindingRepository() *DriftFindingRepository {
	return &DriftFindingRepository{}
}

// Append persists f as a new drift_findings row inside tx and returns
// the committed row (including the database-owned created_at /
// updated_at and id when blank). It requires a *Tx -- not a bare
// Querier -- so a finding can be written in the same transaction as the
// reconcile sweep's audit record, and so the write commits or rolls
// back atomically with that mutation. A blank ID is minted here with
// the drft_ prefix. A blank Kind / Reason / Level / OrganizationID, a
// non-canonical taxonomy value, or a zero DetectedAt are all rejected
// as typed apierr.InvalidInput at the application boundary; a non-zero
// ResolvedAt at append time -- the only legal lifecycle entry point is
// an open finding -- is rejected the same way.
//
// The schema enforces the tenant invariant -- the composite foreign
// keys (organization_id, project_id|environment_id|service_id|
// service_domain_id) reference the parents' matching composite UNIQUEs
// so a finding can never reference another tenant's row -- and the
// kind / reason / level CHECKs reject an unknown taxonomy as a
// deterministic apierr.Conflict through mapWriteError; the raw
// constraint name never leaks into the user-facing message.
func (r *DriftFindingRepository) Append(ctx context.Context, tx *Tx, f DriftFinding) (DriftFinding, error) {
	if tx == nil {
		return DriftFinding{}, apierr.Internal(errors.New("store: DriftFindingRepository.Append called with a nil transaction"))
	}
	var violations []apierr.FieldViolation
	if f.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if f.Kind == "" {
		violations = append(violations, apierr.FieldViolation{Field: "kind", Reason: "is required"})
	} else if !f.Kind.Valid() {
		violations = append(violations, apierr.FieldViolation{Field: "kind", Reason: "is not a recognised drift kind"})
	}
	if f.Reason == "" {
		violations = append(violations, apierr.FieldViolation{Field: "reason", Reason: "is required"})
	} else if !f.Reason.Valid() {
		violations = append(violations, apierr.FieldViolation{Field: "reason", Reason: "is not a recognised drift reason"})
	}
	if f.Level == "" {
		violations = append(violations, apierr.FieldViolation{Field: "level", Reason: "is required"})
	} else if !f.Level.Valid() {
		violations = append(violations, apierr.FieldViolation{Field: "level", Reason: "is not a recognised drift level"})
	}
	if f.DetectedAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "detected_at", Reason: "is required"})
	}
	if f.ResolvedAt != nil {
		violations = append(violations, apierr.FieldViolation{Field: "resolved_at", Reason: "must not be set on a new finding"})
	}
	if f.ResolvedByActorID != "" {
		violations = append(violations, apierr.FieldViolation{Field: "resolved_by_actor_id", Reason: "must be empty on a new finding"})
	}
	if len(violations) > 0 {
		return DriftFinding{}, apierr.InvalidInput(violations...)
	}

	if f.ID == "" {
		id, err := newDriftFindingID()
		if err != nil {
			return DriftFinding{}, apierr.Internal(err)
		}
		f.ID = id
	}

	row := tx.QueryRow(ctx,
		`INSERT INTO drift_findings
		   (id, organization_id, kind, reason, level,
		    project_id, environment_id, service_id, service_domain_id,
		    env_var_key, dokploy_resource_id, parent_dokploy_id,
		    request_id, correlation_id,
		    detected_at)
		 VALUES ($1, $2, $3, $4, $5,
		         $6, $7, $8, $9,
		         $10, $11, $12,
		         $13, $14,
		         $15)
		 RETURNING `+driftFindingColumns,
		f.ID, f.OrganizationID, f.Kind.String(), f.Reason.String(), f.Level.String(),
		nullIfEmpty(f.ProjectID), nullIfEmpty(f.EnvironmentID), nullIfEmpty(f.ServiceID), nullIfEmpty(f.ServiceDomainID),
		f.EnvVarKey, f.DokployResourceID, f.ParentDokployID,
		f.RequestID, f.CorrelationID,
		f.DetectedAt)
	created, err := scanDriftFinding(row)
	if err != nil {
		return DriftFinding{}, mapWriteError(err, "a drift finding with this id already exists for this organization")
	}
	return created, nil
}

// GetByID returns the single drift_findings row identified by
// (organizationID, findingID), tenant-scoped at the SQL predicate. The
// composite predicate is non-optional: a missing or cross-tenant
// organizationID matches no row even when a finding with the same id
// exists in another tenant -- the response is never an oracle that
// reveals another organization's finding ids. A row that does not
// exist surfaces as the same typed apierr.NotFound, never as a 500
// leaking the cause; the not-found payload names only the finding id
// the caller already supplied.
func (r *DriftFindingRepository) GetByID(ctx context.Context, q Querier, organizationID, findingID string) (DriftFinding, error) {
	row := q.QueryRow(ctx,
		`SELECT `+driftFindingColumns+`
		   FROM drift_findings
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, findingID)
	f, err := scanDriftFinding(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return DriftFinding{}, apierr.NotFound("drift_finding", findingID)
	}
	if err != nil {
		return DriftFinding{}, apierr.StoreUnavailable(err)
	}
	return f, nil
}

// ListByOrganization returns the most recent drift_findings rows owned
// by organizationID, newest first (detected_at DESC, id DESC on tie).
// The read is tenant-scoped at the SQL predicate, so a missing or
// cross-tenant organizationID matches no rows. limit is clamped to
// (1, driftFindingListMaxLimit]: a non-positive or above-cap value is
// silently clamped, and the query is always bounded so an unbounded
// scan can never be issued by accident.
//
// The returned slice is always non-nil; an unknown or empty organization
// surfaces as an empty slice, never an error -- callers that need to
// distinguish "tenant has no findings" from "tenant does not exist"
// must Get the organization first.
func (r *DriftFindingRepository) ListByOrganization(ctx context.Context, q Querier, organizationID string, limit int) ([]DriftFinding, error) {
	return r.List(ctx, q, organizationID, DriftFindingListQuery{Limit: limit})
}

// List returns the most recent drift_findings rows owned by organizationID and
// matching the optional resource/status filters, newest first. The SQL remains
// a constant statement with nullable predicates, so caller input can only bind
// parameters, never alter the query shape.
func (r *DriftFindingRepository) List(ctx context.Context, q Querier, organizationID string, query DriftFindingListQuery) ([]DriftFinding, error) {
	limit := query.Limit
	if limit <= 0 || limit > driftFindingListMaxLimit {
		limit = driftFindingListMaxLimit
	}
	rows, err := q.Query(ctx,
		`SELECT `+driftFindingColumns+`
		   FROM drift_findings
		  WHERE organization_id = $1
		    AND ($2 = '' OR project_id = $2)
		    AND ($3 = '' OR environment_id = $3)
		    AND ($4 = '' OR service_id = $4)
		    AND ($5 = '' OR status = $5)
		  ORDER BY detected_at DESC, id DESC
		  LIMIT $6`,
		organizationID, query.ProjectID, query.EnvironmentID, query.ServiceID, query.Status.String(), limit)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]DriftFinding, 0)
	for rows.Next() {
		f, scanErr := scanDriftFinding(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// MarkResolved stamps the finding's resolved_at and resolved_by_actor_id
// inside tx and returns the updated row. It requires a *Tx because the
// transition is typically composed with the resolving audit event in a
// single unit of work. The mutation is tenant-scoped at the SQL
// predicate, so a missing or cross-tenant (organizationID, findingID)
// tuple updates no row.
//
// Lifecycle precondition: an already-resolved finding cannot be
// re-resolved -- the SQL predicate filters on resolved_at IS NULL so
// the UPDATE updates zero rows, and the method then distinguishes
// "finding does not exist for this tenant" (typed apierr.NotFound,
// caller-supplied id) from "finding is already resolved" (typed
// apierr.Conflict) with a follow-up tenant-scoped Get inside the same
// transaction.
//
// resolvedAt is taken from the caller (so a worker can pass the
// reconcile sweep's clock) and a zero value is rejected as typed
// apierr.InvalidInput. resolverActorID must be non-empty so the audit
// trail names not only when but who acknowledged the finding -- the
// drift_findings_resolved_consistent CHECK in the schema enforces the
// same invariant as belt-and-braces.
func (r *DriftFindingRepository) MarkResolved(ctx context.Context, tx *Tx, organizationID, findingID, resolverActorID string, resolvedAt time.Time) (DriftFinding, error) {
	if tx == nil {
		return DriftFinding{}, apierr.Internal(errors.New("store: DriftFindingRepository.MarkResolved called with a nil transaction"))
	}
	var violations []apierr.FieldViolation
	if organizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if findingID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "id", Reason: "is required"})
	}
	if resolverActorID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "resolved_by_actor_id", Reason: "is required"})
	}
	if resolvedAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "resolved_at", Reason: "is required"})
	}
	if len(violations) > 0 {
		return DriftFinding{}, apierr.InvalidInput(violations...)
	}

	row := tx.QueryRow(ctx,
		`UPDATE drift_findings
		    SET resolved_at = $3,
		        resolved_by_actor_id = $4,
		        status = 'resolved'
		  WHERE organization_id = $1
		    AND id = $2
		    AND resolved_at IS NULL
		  RETURNING `+driftFindingColumns,
		organizationID, findingID, resolvedAt, resolverActorID)
	updated, err := scanDriftFinding(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// Distinguish "missing" from "already resolved": a tenant-scoped
		// Get tells us whether the row exists at all for this tenant.
		// A cross-tenant id and a truly-missing id collapse to the same
		// apierr.NotFound, never an oracle that reveals another
		// tenant's finding ids.
		existing, getErr := r.GetByID(ctx, tx, organizationID, findingID)
		if getErr != nil {
			return DriftFinding{}, getErr
		}
		if existing.ResolvedAt != nil {
			return DriftFinding{}, apierr.Conflict("drift finding is already resolved")
		}
		// The row exists and is open, but the UPDATE matched no rows --
		// this should not happen with the predicate above, but surfacing
		// it as a transient dependency failure beats silently lying to
		// the caller.
		return DriftFinding{}, apierr.StoreUnavailable(errors.New("store: drift finding resolve raced with another writer"))
	}
	if err != nil {
		return DriftFinding{}, mapWriteError(err, "drift finding could not be resolved due to a schema constraint")
	}
	if _, err := NewDriftFindingEventRepository().Append(ctx, tx, DriftFindingEvent{
		OrganizationID: organizationID,
		FindingID:      findingID,
		EventType:      DriftFindingEventTypeResolved,
		Message:        "resolved",
		Metadata: map[string]string{
			"actor_id":       resolverActorID,
			"actor_kind":     "",
			"previous_state": DriftFindingStatusOpen.String(),
			"next_state":     DriftFindingStatusResolved.String(),
			"reason":         "resolved",
		},
	}); err != nil {
		return DriftFinding{}, err
	}
	return updated, nil
}

// Transition moves a drift finding through the documented drift_finding state
// machine and appends the matching drift_finding_events row in the same
// transaction. Invalid edges return E_INVALID_STATE_TRANSITION before any
// update, so the finding row and timeline remain unchanged.
func (r *DriftFindingRepository) Transition(ctx context.Context, tx *Tx, in DriftFindingTransition) (DriftFinding, DriftFindingEvent, error) {
	if tx == nil {
		return DriftFinding{}, DriftFindingEvent{}, apierr.Internal(errors.New("store: DriftFindingRepository.Transition called with a nil transaction"))
	}
	orgID := strings.TrimSpace(in.OrganizationID)
	findingID := strings.TrimSpace(in.FindingID)
	next := in.NextStatus
	if next.driftFindingEventType() == "" {
		return DriftFinding{}, DriftFindingEvent{}, apierr.InvalidStateTransition("drift_finding", "", next.String())
	}

	current, err := scanDriftFinding(tx.QueryRow(ctx,
		`SELECT `+driftFindingColumns+`
		   FROM drift_findings
		  WHERE organization_id = $1 AND id = $2
		  FOR UPDATE`,
		orgID, findingID))
	if errors.Is(err, pgx.ErrNoRows) {
		return DriftFinding{}, DriftFindingEvent{}, apierr.NotFound("drift_finding", findingID)
	}
	if err != nil {
		return DriftFinding{}, DriftFindingEvent{}, apierr.StoreUnavailable(err)
	}
	if !current.Status.CanTransitionTo(next) {
		return DriftFinding{}, DriftFindingEvent{}, apierr.InvalidStateTransition("drift_finding", current.Status.String(), next.String())
	}

	resolvedAt := in.ResolvedAt
	if next == DriftFindingStatusResolved && resolvedAt.IsZero() {
		resolvedAt = time.Now().UTC()
	}
	actorID := strings.TrimSpace(in.ActorID)
	actorKind := strings.TrimSpace(in.ActorKind)
	row := tx.QueryRow(ctx,
		`UPDATE drift_findings
		    SET status = $3,
		        resolved_at = CASE WHEN $3 = 'resolved' THEN $4 ELSE resolved_at END,
		        resolved_by_actor_id = CASE WHEN $3 = 'resolved' THEN $5 ELSE resolved_by_actor_id END
		  WHERE organization_id = $1 AND id = $2
		  RETURNING `+driftFindingColumns,
		orgID, findingID, next.String(), nullableOccurredAt(resolvedAt), actorID)
	updated, err := scanDriftFinding(row)
	if err != nil {
		return DriftFinding{}, DriftFindingEvent{}, mapWriteError(err, "drift finding could not transition due to a schema constraint")
	}

	reason := output.NewRedactor().Redact(strings.TrimSpace(in.Reason))
	event, err := NewDriftFindingEventRepository().Append(ctx, tx, DriftFindingEvent{
		OrganizationID: orgID,
		FindingID:      findingID,
		EventType:      next.driftFindingEventType(),
		Message:        reason,
		Metadata: map[string]string{
			"actor_id":       actorID,
			"actor_kind":     actorKind,
			"previous_state": current.Status.String(),
			"next_state":     next.String(),
			"reason":         reason,
		},
		RequestID:     strings.TrimSpace(in.RequestID),
		CorrelationID: strings.TrimSpace(in.CorrelationID),
	})
	if err != nil {
		return DriftFinding{}, DriftFindingEvent{}, err
	}
	return updated, event, nil
}

// scanDriftFinding scans one drift_findings row in driftFindingColumns
// order. Nullable optional resource legs and resolved_at are read into
// *string / *time.Time scratch and projected onto the struct after the
// scan so the caller sees a uniform zero-value-for-absent shape.
func scanDriftFinding(row scanRow) (DriftFinding, error) {
	var (
		f               DriftFinding
		kindStr         string
		reasonStr       string
		levelStr        string
		statusStr       string
		projectID       *string
		environmentID   *string
		serviceID       *string
		serviceDomainID *string
		resolvedAt      *time.Time
	)
	if err := row.Scan(
		&f.ID,
		&f.OrganizationID,
		&kindStr,
		&reasonStr,
		&levelStr,
		&projectID,
		&environmentID,
		&serviceID,
		&serviceDomainID,
		&f.EnvVarKey,
		&f.DokployResourceID,
		&f.ParentDokployID,
		&f.RequestID,
		&f.CorrelationID,
		&f.DetectedAt,
		&statusStr,
		&resolvedAt,
		&f.ResolvedByActorID,
		&f.CreatedAt,
		&f.UpdatedAt,
	); err != nil {
		return DriftFinding{}, err
	}
	f.Kind = DriftKind(kindStr)
	f.Reason = DriftReason(reasonStr)
	f.Level = DriftLevel(levelStr)
	f.Status = DriftFindingStatus(statusStr)
	if projectID != nil {
		f.ProjectID = *projectID
	}
	if environmentID != nil {
		f.EnvironmentID = *environmentID
	}
	if serviceID != nil {
		f.ServiceID = *serviceID
	}
	if serviceDomainID != nil {
		f.ServiceDomainID = *serviceDomainID
	}
	if resolvedAt != nil {
		t := *resolvedAt
		f.ResolvedAt = &t
	}
	return f, nil
}

// nullIfEmpty returns nil for an empty string so a blank optional
// resource leg lands as SQL NULL (and thus does not engage the
// composite foreign key) rather than as an empty-string id that would
// fail the parent-table lookup with a CHECK / FK violation.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// newDriftFindingID mints an opaque, non-guessable id for a
// drift_findings row. Drift findings are an internal triage queue
// rather than a customer-facing addressable resource, so -- like
// audit_events, quota_reservations, deployment_events, and
// job_attempts -- they carry their own prefixed id rather than a
// domain.Kind id.
func newDriftFindingID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("store: generating drift finding id entropy: %w", err)
	}
	return "drft_" + hex.EncodeToString(buf[:]), nil
}
