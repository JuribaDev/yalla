package store

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// environmentGrantsWriteAction is the action recorded on the audit event for
// PUT /v1/environments/{environment_id}/grants. It is kept as a plain string
// here so the store layer takes no build dependency on
// internal/controlplane/policy; the HTTP authorization middleware authorizes
// the same action before the handler is reached, and the policy matrix tests
// keep the two values in sync.
const environmentGrantsWriteAction = "environment.grants.write"

// environmentGrantPrincipalKinds is the closed set of principal kinds an
// environment grant can confer a role on. It mirrors the table's CHECK
// constraint exactly so the service layer rejects an invalid kind with a typed
// apierr.InvalidInput (naming "principal_kind") before the database does —
// agents read one stable enum, never a generic constraint-violation error.
var environmentGrantPrincipalKinds = map[string]struct{}{
	string(domain.KindUser):           {},
	string(domain.KindServiceAccount): {},
}

// environmentGrantBuiltinRoles is the closed set of built-in role names an
// environment grant can confer. It mirrors the table's CHECK constraint
// exactly so the service layer rejects an unknown role with a typed
// apierr.InvalidInput (naming "role") before the database does — a future
// custom-role migration is the only path that widens this set.
var environmentGrantBuiltinRoles = map[string]struct{}{
	"owner":     {},
	"admin":     {},
	"developer": {},
	"viewer":    {},
	"ci":        {},
	"support":   {},
}

// EnvironmentGrant is the source-of-truth representation of a row in the
// environment_grants table — a scoped grant that confers a built-in role on a
// principal at a specific (environment, optional service) target. The policy
// engine consumes the same shape through policy.Grant on the resolved
// Principal; this struct is the persistence-layer mirror and carries no HTTP
// concerns of its own.
//
// PrincipalKind is closed to domain.KindUser ("usr") or
// domain.KindServiceAccount ("sa") — the two principal kinds the policy
// engine resolves. Role is closed to one of the six built-in role names
// ('owner','admin','developer','viewer','ci','support'); a future custom-role
// migration is the only path that widens the column.
//
// ServiceID is a pointer so the wire and audit layers can distinguish
// "environment-scoped grant" (nil) from "service-scoped grant" (set). The
// persistence layer treats it as a plain text identifier without an FK — a
// grant must outlive a recreated service of the same id, and a grant whose
// nested id no longer resolves is simply unreachable through the policy
// engine (a defensive ignore, not a hard error).
//
// Version is the database-owned optimistic-concurrency token: it starts at 1
// on INSERT and is bumped by the environment_grants_bump_version trigger on
// every UPDATE. Callers must not mutate it; the trigger is the only writer.
type EnvironmentGrant struct {
	ID             string
	OrganizationID string
	EnvironmentID  string
	PrincipalID    string
	PrincipalKind  string
	Role           string
	ServiceID      *string
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// EnvironmentGrantRepository is the persistence half of the
// environment-grants surface. It follows the same conventions as
// ProjectGrantRepository — mutations require a *Tx so they cannot be
// separated from the authorization checks that share the transaction, reads
// accept a Querier so they work against a read-only or open write
// transaction, and every query is tenant scoped by organization_id first so
// a resource id from another organization can never match. The repository is
// stateless; the constructor exists so call sites depend on a value rather
// than a bare struct literal.
type EnvironmentGrantRepository struct{}

// NewEnvironmentGrantRepository returns a stateless EnvironmentGrantRepository.
func NewEnvironmentGrantRepository() *EnvironmentGrantRepository {
	return &EnvironmentGrantRepository{}
}

// environmentGrantColumns is the column list returned by every
// environment_grants query, in the order scanEnvironmentGrant expects.
const environmentGrantColumns = `id, organization_id, environment_id, principal_id, principal_kind, role, service_id, version, created_at, updated_at`

// environmentGrantListMaxRows caps how many rows a single ListByEnvironment
// call returns. An unbounded query can never be issued by accident; an HTTP
// layer that wants pagination later will add an explicit offset or cursor
// parameter rather than relax this ceiling.
const environmentGrantListMaxRows = 500

// ListByEnvironment returns every grant attached to the environment
// identified by (organizationID, environmentID), ordered deterministically by
// (principal_id, service_id NULLS FIRST, id) so a given set of rows always
// renders the same response. The query is tenant scoped at the persistence
// layer: it filters by organization_id and environment_id, so a cross-tenant
// id simply matches no rows and yields an empty slice — a cross-tenant id
// can never reveal another organization's grants. The result is always a
// non-nil slice (possibly empty) so callers can iterate it without a nil
// check.
//
// This method does NOT verify the environment exists; callers that need to
// distinguish "environment missing" from "environment has no grants" must
// GetByID the environment first (the EnvironmentGrantReader adapter does so
// in the same short-lived transaction).
func (r *EnvironmentGrantRepository) ListByEnvironment(ctx context.Context, q Querier, organizationID, environmentID string) ([]EnvironmentGrant, error) {
	rows, err := q.Query(ctx,
		`SELECT `+environmentGrantColumns+`
		   FROM environment_grants
		  WHERE organization_id = $1 AND environment_id = $2
		  ORDER BY principal_id ASC,
		           service_id ASC NULLS FIRST,
		           id ASC
		  LIMIT $3`,
		organizationID, environmentID, environmentGrantListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	grants := make([]EnvironmentGrant, 0)
	for rows.Next() {
		g, scanErr := scanEnvironmentGrant(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return grants, nil
}

// Upsert inserts a single environment_grants row, or — if a row already
// exists at the same (organization_id, environment_id, principal_id,
// COALESCE(service_id, ”)) scope tuple — updates that row's role in place.
// The unique index environment_grants_principal_scope_idx is the upsert
// target; COALESCE makes a NULL service_id deduplicate cleanly across rows,
// so a single principal has at most one grant at any given (environment,
// svc?) target. The returned row is the persisted state: a fresh INSERT
// returns the caller-minted id at version 1; an UPDATE returns the existing
// id at the bumped version (the environment_grants_bump_version trigger
// refreshes version on every UPDATE). Callers must use the returned id —
// never the caller-supplied id — when collecting the survive-set for
// DeleteByEnvironmentExceptIDs, so a row that was already present at the
// scope tuple is correctly retained.
//
// The mutation requires a *Tx so it cannot be separated from the
// authorization checks that share the transaction; a nil transaction is a
// programming error. id is the caller-minted (or service-supplied) id used
// only when the upsert resolves to an INSERT — an existing row keeps its
// own id, which is why the caller must trust the RETURNING value rather than
// the input id.
func (r *EnvironmentGrantRepository) Upsert(ctx context.Context, tx *Tx, id, organizationID, environmentID, principalID, principalKind, role string, serviceID *string) (EnvironmentGrant, error) {
	if tx == nil {
		return EnvironmentGrant{}, apierr.Internal(errors.New("store: EnvironmentGrantRepository.Upsert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO environment_grants
		   (id, organization_id, environment_id, principal_id, principal_kind, role,
		    service_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (organization_id, environment_id, principal_id,
		              COALESCE(service_id, ''))
		 DO UPDATE SET role = EXCLUDED.role
		 RETURNING `+environmentGrantColumns,
		id, organizationID, environmentID, principalID, principalKind, role, serviceID)
	g, err := scanEnvironmentGrant(row)
	if err != nil {
		return EnvironmentGrant{}, mapWriteError(err, "an environment grant with this id already exists")
	}
	return g, nil
}

// DeleteByEnvironmentExceptIDs removes every environment_grants row owned by
// (organizationID, environmentID) whose id is NOT in keepIDs. It is the bulk
// delete-by-exclusion half of the PUT replace contract: callers Upsert the
// replacement rows first, then call this method with the persisted ids of
// the rows to retain, and any row whose id is absent is dropped. The query
// is tenant scoped (filters by organization_id AND environment_id) so a
// cross-tenant id can never reach into another organization's grants.
//
// keepIDs may be empty — that means "drop every grant of this environment",
// which is the deliberate semantic of a PUT with grants:[]: a customer
// explicitly asking to clear every grant of an environment is meaningful
// (extreme), not a silent no-op. nil and an empty slice are treated
// identically: every row at (organizationID, environmentID) is removed. The
// mutation requires a *Tx so it cannot be separated from the audit append;
// a nil transaction is a programming error.
func (r *EnvironmentGrantRepository) DeleteByEnvironmentExceptIDs(ctx context.Context, tx *Tx, organizationID, environmentID string, keepIDs []string) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: EnvironmentGrantRepository.DeleteByEnvironmentExceptIDs called with a nil transaction"))
	}
	if len(keepIDs) == 0 {
		_, err := tx.Exec(ctx,
			`DELETE FROM environment_grants
			  WHERE organization_id = $1 AND environment_id = $2`,
			organizationID, environmentID)
		if err != nil {
			return apierr.StoreUnavailable(err)
		}
		return nil
	}
	_, err := tx.Exec(ctx,
		`DELETE FROM environment_grants
		  WHERE organization_id = $1 AND environment_id = $2
		    AND NOT (id = ANY($3::text[]))`,
		organizationID, environmentID, keepIDs)
	if err != nil {
		return apierr.StoreUnavailable(err)
	}
	return nil
}

// EnvironmentGrantReplace is one entry in the caller-supplied replacement set.
// PrincipalID names the user or service-account the grant confers a role on;
// PrincipalKind is closed to "usr" / "sa" so the persistence layer can trust
// the value it persists; Role is closed to one of the six built-in role names;
// ServiceID is a pointer so the caller can distinguish an environment-scoped
// grant (nil) from a service-scoped grant (set) without needing a sentinel
// empty string.
//
// The service layer validates every field before any database work — an
// invalid request never opens a transaction — so the repository layer can
// trust the values it persists. The principal kind and role enums are
// duplicated as closed sets at this layer so the service can surface a
// stable apierr.InvalidInput naming the offending field path before the
// database CHECK constraint runs.
type EnvironmentGrantReplace struct {
	PrincipalID   string
	PrincipalKind string
	Role          string
	ServiceID     *string
}

// ReplaceEnvironmentGrantsInput is the typed input to
// EnvironmentGrantService.Replace. OrganizationID and EnvironmentID name the
// environment whose grants are being replaced; Grants is the replacement set
// — possibly empty (a deliberate clear). The Actor* and correlation fields
// describe the authenticated principal and are recorded verbatim on the
// audit event; they are plain strings so the store layer takes no build
// dependency on the policy or telemetry packages — the httpapi handler,
// which already holds the resolved principal and the request correlation,
// fills them in.
type ReplaceEnvironmentGrantsInput struct {
	OrganizationID string
	EnvironmentID  string
	Grants         []EnvironmentGrantReplace
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// EnvironmentGrantService is the unit-of-work orchestrator for PUT
// /v1/environments/{environment_id}/grants. Replace composes — in a fixed
// order, inside one transaction opened by Store.Write — a tenant-scoped
// existence check on the target environment, one upsert per caller-supplied
// grant, a delete for every grant not in the replacement set, the immutable
// audit record, and a re-read of the committed grants in deterministic
// (principal_id, service_id NULLS FIRST, id) order. Because every step
// shares the *Tx, a failure in any of them rolls the others back: a partial
// replace and an orphaned audit record are both impossible.
//
// The service also re-reads the committed grants inside the same
// transaction so the response always reflects exactly the state that just
// persisted — the same coherence guarantee ProjectGrantService.Replace
// gives PUT /v1/projects/{project_id}/grants.
type EnvironmentGrantService struct {
	store        *Store
	environments *EnvironmentRepository
	grants       *EnvironmentGrantRepository
	audit        AuditAppender
}

// NewEnvironmentGrantService wires an EnvironmentGrantService from its
// dependencies. It returns a typed error if any dependency is nil, so a
// misconfigured service fails at construction rather than on its first
// request — the same fail-fast posture every other unit-of-work
// orchestrator in this package takes.
func NewEnvironmentGrantService(s *Store, environments *EnvironmentRepository, grants *EnvironmentGrantRepository, audit AuditAppender) (*EnvironmentGrantService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case environments == nil:
		return nil, errors.New("store: nil environment repository")
	case grants == nil:
		return nil, errors.New("store: nil environment grant repository")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &EnvironmentGrantService{store: s, environments: environments, grants: grants, audit: audit}, nil
}

// Replace validates in, then runs the replace-grants unit of work inside
// one transaction: verify the environment exists in the target organization
// (so a missing environment is a typed NotFound rather than the generic FK
// conflict the upsert would otherwise produce), upsert each caller-supplied
// grant (idempotent on its scope tuple), delete every grant whose scope
// tuple is not in the replacement set, append the audit record, and re-read
// the committed state in deterministic order. Validation runs before the
// transaction is opened, so an invalid request never touches the database.
//
// An empty Grants list is allowed and means "clear every grant of this
// environment": a customer explicitly asking for an empty state is
// meaningful, not a silent no-op. A duplicate scope tuple (same principal
// at the same service_id target), an invalid principal_kind, or an unknown
// role each surfaces as apierr.InvalidInput with a stable, value-free field
// path. An {environment_id} that does not exist in the actor's organization
// is the typed apierr.NotFound the repository produces.
//
// The audit event is filed under the actor's home organization (the tenant
// the principal authenticated into) with resource_kind=env and
// resource_id={environment_id}, mirroring how ProjectGrantService files
// mutations against the project rather than the per-row grant id. Metadata
// records only counts — never principal ids, role names, or service
// identifiers — so the audit row is auditable without ever leaking a
// customer-supplied identifier.
func (svc *EnvironmentGrantService) Replace(ctx context.Context, in ReplaceEnvironmentGrantsInput) ([]EnvironmentGrant, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		return nil, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	environmentID := strings.TrimSpace(in.EnvironmentID)
	if environmentID == "" {
		return nil, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "environment_id",
			Reason: "must not be blank",
		})
	}

	items, err := buildEnvironmentGrantReplace(in.Grants)
	if err != nil {
		return nil, err
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return nil, apierr.Internal(errors.New("store: EnvironmentGrantService.Replace requires an actor organization for the audit record"))
	}

	// Per-grant audit counts are the only thing recorded in metadata. The
	// audit record never names a principal id, role, or service — those
	// identifiers are not secrets but a per-row audit trail at this
	// granularity is the GET /v1/environments/{environment_id}/grants
	// surface's job (every grant carries the bump_version stamp and
	// updated_at). Counts let the auditor see the shape of the change
	// without observing any customer-supplied identifier.
	scopeCounts := classifyEnvironmentGrantScopes(items)

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         environmentGrantsWriteAction,
		ResourceKind:   string(domain.KindEnvironment),
		ResourceID:     environmentID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for environment.grants.write",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		Metadata: map[string]string{
			"grant_count":             strconv.Itoa(len(items)),
			"environment_scope_count": strconv.Itoa(scopeCounts.environment),
			"service_scope_count":     strconv.Itoa(scopeCounts.service),
		},
	}

	var committed []EnvironmentGrant
	if txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Existence check first so a missing environment is the typed
		// NotFound the repository produces, not the generic FK conflict
		// the upsert would otherwise yield. The Get call shares the *Tx
		// so a row that vanishes between this check and the upserts is
		// not possible.
		if _, getErr := svc.environments.GetByID(ctx, tx, organizationID, environmentID); getErr != nil {
			return getErr
		}

		// keepIDs collects the id of every row that survives the replace
		// — either a freshly minted INSERT id or the existing id of an
		// already-present row at the same scope tuple. The Upsert RETURNS
		// the persisted id, so we never assume the caller-supplied id is
		// the survivor.
		keepIDs := make([]string, 0, len(items))
		for _, item := range items {
			id, idErr := domain.NewID(domain.KindEnvironmentGrant)
			if idErr != nil {
				return apierr.Internal(idErr)
			}
			row, upErr := svc.grants.Upsert(ctx, tx, id.String(), organizationID, environmentID,
				item.PrincipalID, item.PrincipalKind, item.Role, item.ServiceID)
			if upErr != nil {
				return upErr
			}
			keepIDs = append(keepIDs, row.ID)
		}
		if delErr := svc.grants.DeleteByEnvironmentExceptIDs(ctx, tx, organizationID, environmentID, keepIDs); delErr != nil {
			return delErr
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		// Re-read the committed grants inside the same transaction so the
		// response always reflects exactly the state that just persisted.
		list, listErr := svc.grants.ListByEnvironment(ctx, tx, organizationID, environmentID)
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

// environmentGrantScopeCounts tallies how many grants in a replacement set
// fall into each of the two scope tiers (environment, service). The counts
// are recorded in audit metadata so the auditor sees the shape of a replace
// without observing any customer-supplied identifier.
type environmentGrantScopeCounts struct {
	environment int
	service     int
}

// classifyEnvironmentGrantScopes counts how many entries are
// environment-scoped vs. service-scoped, using the same nullable-pointer
// precedence the wire and persistence layers read with.
func classifyEnvironmentGrantScopes(items []EnvironmentGrantReplace) environmentGrantScopeCounts {
	var c environmentGrantScopeCounts
	for _, item := range items {
		if item.ServiceID != nil {
			c.service++
		} else {
			c.environment++
		}
	}
	return c
}

// buildEnvironmentGrantReplace validates and normalises the caller-supplied
// items. It is split out from Replace so the validation rules are unit
// testable without a database, and so an invalid request is rejected before
// a transaction is ever opened.
//
// An empty list is allowed: the caller explicitly asked to clear every
// grant of this environment, which is a meaningful (extreme) operation, not
// a silent no-op. A blank principal id, an unknown principal kind, an
// unknown role, an id with embedded NUL bytes, or a duplicate scope tuple
// each surfaces as a typed apierr.InvalidInput carrying stable, value-free
// field paths.
//
// Field-path shape mirrors the JSON request body: "grants[i].principal_id",
// "grants[i].principal_kind", "grants[i].role", "grants[i].service_id".
func buildEnvironmentGrantReplace(in []EnvironmentGrantReplace) ([]EnvironmentGrantReplace, error) {
	collector := newEnvironmentGrantViolations()
	seen := make(map[string]struct{}, len(in))
	out := make([]EnvironmentGrantReplace, 0, len(in))
	for i, item := range in {
		path := "grants[" + strconv.Itoa(i) + "]"

		principalID := strings.TrimSpace(item.PrincipalID)
		switch {
		case principalID == "":
			collector.add(path+".principal_id", "must not be blank")
		case strings.ContainsRune(principalID, 0):
			collector.add(path+".principal_id", "must not contain NUL bytes")
		}

		principalKind := strings.TrimSpace(item.PrincipalKind)
		if _, ok := environmentGrantPrincipalKinds[principalKind]; !ok {
			collector.add(path+".principal_kind", "must be one of \"usr\" or \"sa\"")
		}

		role := strings.TrimSpace(item.Role)
		if _, ok := environmentGrantBuiltinRoles[role]; !ok {
			collector.add(path+".role", "must be one of owner, admin, developer, viewer, ci, support")
		}

		svcID, svcOK := normaliseEnvironmentGrantScopeID(item.ServiceID)
		if !svcOK {
			collector.add(path+".service_id", "must not be blank or contain NUL bytes when set")
		}

		dedupKey := principalID + "\x00" + safeEnvironmentGrantScopeID(svcID)
		if _, dup := seen[dedupKey]; dup {
			collector.add(path+".principal_id", "duplicates another grant at the same service_id scope")
		} else if principalID != "" {
			seen[dedupKey] = struct{}{}
		}

		out = append(out, EnvironmentGrantReplace{
			PrincipalID:   principalID,
			PrincipalKind: principalKind,
			Role:          role,
			ServiceID:     svcID,
		})
	}
	if err := collector.err(); err != nil {
		return nil, err
	}
	return out, nil
}

// normaliseEnvironmentGrantScopeID trims a nullable *string scope id and
// reports whether the value is acceptable. A nil pointer is the "unscoped"
// sentinel — perfectly valid. A pointer to a blank or NUL-bearing string is
// rejected; an acceptable non-blank value is normalised through TrimSpace
// and returned as a fresh pointer so the caller's slice is untouched.
func normaliseEnvironmentGrantScopeID(in *string) (*string, bool) {
	if in == nil {
		return nil, true
	}
	v := strings.TrimSpace(*in)
	if v == "" || strings.ContainsRune(v, 0) {
		return nil, false
	}
	return &v, true
}

// safeEnvironmentGrantScopeID renders a nullable scope id as a stable
// string suitable for use in a dedup key. A nil pointer becomes the empty
// string, matching the COALESCE projection the unique index uses at the
// database layer, so the in-memory dedup is byte-equivalent to the SQL
// constraint.
func safeEnvironmentGrantScopeID(in *string) string {
	if in == nil {
		return ""
	}
	return *in
}

// environmentGrantViolations accumulates field-level validation failures
// and surfaces them as one apierr.InvalidInput, sorted by field path so the
// wire error is byte-deterministic across runs. It mirrors the
// internal/controlplane/validate Collector — kept local here to avoid
// pulling the validate package's POSIX-name rules into a service that
// validates a different shape.
type environmentGrantViolations struct {
	violations []apierr.FieldViolation
}

func newEnvironmentGrantViolations() *environmentGrantViolations {
	return &environmentGrantViolations{}
}

func (c *environmentGrantViolations) add(field, reason string) {
	c.violations = append(c.violations, apierr.FieldViolation{Field: field, Reason: reason})
}

func (c *environmentGrantViolations) err() error {
	if len(c.violations) == 0 {
		return nil
	}
	sort.Slice(c.violations, func(i, j int) bool {
		if c.violations[i].Field == c.violations[j].Field {
			return c.violations[i].Reason < c.violations[j].Reason
		}
		return c.violations[i].Field < c.violations[j].Field
	})
	return apierr.InvalidInput(c.violations...)
}

// scanEnvironmentGrant scans one environment_grants row in
// environmentGrantColumns order.
func scanEnvironmentGrant(row pgx.Row) (EnvironmentGrant, error) {
	var g EnvironmentGrant
	err := row.Scan(
		&g.ID,
		&g.OrganizationID,
		&g.EnvironmentID,
		&g.PrincipalID,
		&g.PrincipalKind,
		&g.Role,
		&g.ServiceID,
		&g.Version,
		&g.CreatedAt,
		&g.UpdatedAt,
	)
	return g, err
}

// EnvironmentGrantReader is the store-backed read adapter for
// environment_grants. It mirrors ProjectGrantReader — it composes
// EnvironmentGrantRepository (and EnvironmentRepository, for the
// tenant-scoped environment existence check) through a short-lived
// Store.Read transaction, so the repository's tenant-scoping guarantees are
// inherited for free and the adapter cannot smuggle a mutation past
// Store.Write.
type EnvironmentGrantReader struct {
	store        *Store
	environments *EnvironmentRepository
	grants       *EnvironmentGrantRepository
}

// NewEnvironmentGrantReader builds an EnvironmentGrantReader over store. It
// returns an error for a nil store so a misconfigured adapter fails at
// construction rather than on its first request.
func NewEnvironmentGrantReader(s *Store) (*EnvironmentGrantReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &EnvironmentGrantReader{
		store:        s,
		environments: NewEnvironmentRepository(),
		grants:       NewEnvironmentGrantRepository(),
	}, nil
}

// ListEnvironmentGrants returns every grant of the environment identified by
// (organizationID, environmentID), reading them inside a short-lived
// read-only transaction. The read is tenant scoped at both legs: it
// GetByID's the environment first so a cross-tenant or unknown
// environment_id surfaces as a deterministic apierr.NotFound — never as an
// empty list, which would invite an agent to believe the environment exists
// with no grants. A live environment with no grants is then a deterministic
// empty slice. A datastore failure is propagated as its own typed error.
func (r *EnvironmentGrantReader) ListEnvironmentGrants(ctx context.Context, organizationID, environmentID string) ([]EnvironmentGrant, error) {
	var grants []EnvironmentGrant
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, getErr := r.environments.GetByID(ctx, q, organizationID, environmentID); getErr != nil {
			return getErr
		}
		list, listErr := r.grants.ListByEnvironment(ctx, q, organizationID, environmentID)
		if listErr != nil {
			return listErr
		}
		grants = list
		return nil
	})
	if err != nil {
		return nil, err
	}
	return grants, nil
}
