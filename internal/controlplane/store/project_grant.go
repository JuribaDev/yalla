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

// projectGrantsWriteAction is the action recorded on the audit event for PUT
// /v1/projects/{project_id}/grants. It is kept as a plain string here so the
// store layer takes no build dependency on internal/controlplane/policy; the
// HTTP authorization middleware authorizes the same action before the handler
// is reached, and the policy matrix tests keep the two values in sync.
const projectGrantsWriteAction = "project.grants.write"

// projectGrantPrincipalKinds is the closed set of principal kinds a grant can
// confer a role on. It mirrors the table's CHECK constraint exactly so the
// service layer rejects an invalid kind with a typed apierr.InvalidInput
// (naming "principal_kind") before the database does — agents read one
// stable enum, never a generic constraint-violation error.
var projectGrantPrincipalKinds = map[string]struct{}{
	string(domain.KindUser):           {},
	string(domain.KindServiceAccount): {},
}

// projectGrantBuiltinRoles is the closed set of built-in role names a
// grant can confer. It mirrors the table's CHECK constraint exactly so the
// service layer rejects an unknown role with a typed apierr.InvalidInput
// (naming "role") before the database does — a future custom-role
// migration is the only path that widens this set.
var projectGrantBuiltinRoles = map[string]struct{}{
	"owner":     {},
	"admin":     {},
	"developer": {},
	"viewer":    {},
	"ci":        {},
	"support":   {},
}

// ProjectGrant is the source-of-truth representation of a row in the
// project_grants table — a scoped grant that confers a built-in role on a
// principal at a specific (project, optional environment, optional service)
// target. The policy engine consumes the same shape through policy.Grant on
// the resolved Principal; this struct is the persistence-layer mirror and
// carries no HTTP concerns of its own.
//
// PrincipalKind is closed to domain.KindUser ("usr") or
// domain.KindServiceAccount ("sa") — the two principal kinds the policy
// engine resolves. Role is closed to one of the six built-in role names
// ('owner','admin','developer','viewer','ci','support'); a future custom-role
// migration is the only path that widens the column.
//
// EnvironmentID and ServiceID are pointers so the wire and audit layers can
// distinguish "project-scoped grant" (both nil) from "environment-scoped
// grant" (only EnvironmentID set) from "service-scoped grant" (both set).
// The persistence layer treats them as plain text identifiers without an FK
// — a grant must outlive a recreated environment or service of the same id,
// and a grant whose nested id no longer resolves is simply unreachable
// through the policy engine (a defensive ignore, not a hard error).
//
// Version is the database-owned optimistic-concurrency token: it starts at 1
// on INSERT and is bumped by the project_grants_bump_version trigger on every
// UPDATE. Callers must not mutate it; the trigger is the only writer.
type ProjectGrant struct {
	ID             string
	OrganizationID string
	ProjectID      string
	PrincipalID    string
	PrincipalKind  string
	Role           string
	EnvironmentID  *string
	ServiceID      *string
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ProjectGrantRepository is the persistence half of the project-grants
// surface. It follows the same conventions as ProjectRepository — mutations
// require a *Tx so they cannot be separated from the authorization checks
// that share the transaction, reads accept a Querier so they work against a
// read-only or open write transaction, and every query is tenant scoped by
// organization_id first so a resource id from another organization can never
// match. The repository is stateless; the constructor exists so call sites
// depend on a value rather than a bare struct literal.
type ProjectGrantRepository struct{}

// NewProjectGrantRepository returns a stateless ProjectGrantRepository.
func NewProjectGrantRepository() *ProjectGrantRepository { return &ProjectGrantRepository{} }

// projectGrantColumns is the column list returned by every project_grants
// query, in the order scanProjectGrant expects.
const projectGrantColumns = `id, organization_id, project_id, principal_id, principal_kind, role, environment_id, service_id, version, created_at, updated_at`

// projectGrantListMaxRows caps how many rows a single ListByProject call
// returns. An unbounded query can never be issued by accident; an HTTP layer
// that wants pagination later will add an explicit offset or cursor
// parameter rather than relax this ceiling.
const projectGrantListMaxRows = 500

// ListByProject returns every grant attached to the project identified by
// (organizationID, projectID), ordered deterministically by
// (principal_id, environment_id NULLS FIRST, service_id NULLS FIRST, id) so
// a given set of rows always renders the same response. The query is tenant
// scoped at the persistence layer: it filters by organization_id and
// project_id, so a cross-tenant id simply matches no rows and yields an
// empty slice — a cross-tenant id can never reveal another organization's
// grants. The result is always a non-nil slice (possibly empty) so callers
// can iterate it without a nil check.
//
// This method does NOT verify the project exists; callers that need to
// distinguish "project missing" from "project has no grants" must Get the
// project first (the ProjectGrantReader adapter does so in the same
// short-lived transaction).
func (r *ProjectGrantRepository) ListByProject(ctx context.Context, q Querier, organizationID, projectID string) ([]ProjectGrant, error) {
	rows, err := q.Query(ctx,
		`SELECT `+projectGrantColumns+`
		   FROM project_grants
		  WHERE organization_id = $1 AND project_id = $2
		  ORDER BY principal_id ASC,
		           environment_id ASC NULLS FIRST,
		           service_id ASC NULLS FIRST,
		           id ASC
		  LIMIT $3`,
		organizationID, projectID, projectGrantListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	grants := make([]ProjectGrant, 0)
	for rows.Next() {
		g, scanErr := scanProjectGrant(rows)
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

// scanProjectGrant scans one project_grants row in projectGrantColumns order.
func scanProjectGrant(row pgx.Row) (ProjectGrant, error) {
	var g ProjectGrant
	err := row.Scan(
		&g.ID,
		&g.OrganizationID,
		&g.ProjectID,
		&g.PrincipalID,
		&g.PrincipalKind,
		&g.Role,
		&g.EnvironmentID,
		&g.ServiceID,
		&g.Version,
		&g.CreatedAt,
		&g.UpdatedAt,
	)
	return g, err
}

// Upsert installs the grant identified by the scope-tuple
// (organization_id, project_id, principal_id, COALESCE(environment_id, ”),
// COALESCE(service_id, ”)) — the same composite key the
// project_grants_principal_scope_idx unique index enforces — and returns the
// persisted row. If a row at that scope tuple already exists, only the role
// (the only customer-mutable field) is updated; the immutable identifiers
// (id, organization_id, project_id, principal_id, principal_kind,
// environment_id, service_id) and the lifecycle stamps are preserved. The
// project_grants_bump_version trigger refreshes version + updated_at on the
// UPDATE branch.
//
// The caller-supplied id is used only on the INSERT branch — it is ignored
// when a row already exists at the scope tuple, so a re-upsert is idempotent
// at the customer's view of the resource (same scope tuple = same logical
// grant). principal_kind and role are not part of the scope tuple, so an
// existing row stays at its current principal_kind even if the caller
// supplied a different one for the same principal_id; promoting/demoting a
// principal's grant is therefore a role change, not a principal_kind change
// — a guarantee Replace relies on so cross-kind smuggling is impossible.
//
// The mutation requires a *Tx so it cannot be separated from the
// authorization check or the audit append that share the transaction; a
// nil transaction is a programming error and is reported as Internal.
func (r *ProjectGrantRepository) Upsert(ctx context.Context, tx *Tx, id, organizationID, projectID, principalID, principalKind, role string, environmentID, serviceID *string) (ProjectGrant, error) {
	if tx == nil {
		return ProjectGrant{}, apierr.Internal(errors.New("store: ProjectGrantRepository.Upsert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO project_grants
		   (id, organization_id, project_id, principal_id, principal_kind, role,
		    environment_id, service_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (organization_id, project_id, principal_id,
		              COALESCE(environment_id, ''),
		              COALESCE(service_id, ''))
		 DO UPDATE SET role = EXCLUDED.role
		 RETURNING `+projectGrantColumns,
		id, organizationID, projectID, principalID, principalKind, role, environmentID, serviceID)
	g, err := scanProjectGrant(row)
	if err != nil {
		return ProjectGrant{}, mapWriteError(err, "a project grant with this id already exists")
	}
	return g, nil
}

// DeleteByProjectExceptIDs removes every project_grants row owned by
// (organizationID, projectID) whose id is NOT in keepIDs. It is the bulk
// delete-by-exclusion half of the PUT replace contract: callers Upsert the
// replacement rows first, then call this method with the persisted ids of
// the rows to retain, and any row whose id is absent is dropped. The
// query is tenant scoped (filters by organization_id AND project_id) so a
// cross-tenant id can never reach into another organization's grants.
//
// keepIDs may be empty: a customer explicitly asking to clear every grant
// of a project is meaningful (extreme), not a silent no-op. nil and an
// empty slice are treated identically: every row at (organizationID,
// projectID) is removed. The mutation requires a *Tx so it cannot be
// separated from the audit append; a nil transaction is a programming
// error.
func (r *ProjectGrantRepository) DeleteByProjectExceptIDs(ctx context.Context, tx *Tx, organizationID, projectID string, keepIDs []string) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: ProjectGrantRepository.DeleteByProjectExceptIDs called with a nil transaction"))
	}
	if len(keepIDs) == 0 {
		_, err := tx.Exec(ctx,
			`DELETE FROM project_grants
			  WHERE organization_id = $1 AND project_id = $2`,
			organizationID, projectID)
		if err != nil {
			return apierr.StoreUnavailable(err)
		}
		return nil
	}
	_, err := tx.Exec(ctx,
		`DELETE FROM project_grants
		  WHERE organization_id = $1 AND project_id = $2
		    AND NOT (id = ANY($3::text[]))`,
		organizationID, projectID, keepIDs)
	if err != nil {
		return apierr.StoreUnavailable(err)
	}
	return nil
}

// ProjectGrantReplace is one entry in the caller-supplied replacement set.
// PrincipalID names the user or service-account the grant confers a role on;
// PrincipalKind is closed to "usr" / "sa" so the persistence layer can trust
// the value it persists; Role is closed to one of the six built-in role names;
// EnvironmentID and ServiceID are pointers so the caller can distinguish a
// project-scoped grant (both nil) from an environment-scoped grant (only
// EnvironmentID set) from a service-scoped grant (both set) without needing
// sentinel empty strings.
//
// The service layer validates every field before any database work — an
// invalid request never opens a transaction — so the repository layer can
// trust the values it persists. The principal kind and role enums are
// duplicated as closed sets at this layer so the service can surface a
// stable apierr.InvalidInput naming the offending field path before the
// database CHECK constraint runs.
type ProjectGrantReplace struct {
	PrincipalID   string
	PrincipalKind string
	Role          string
	EnvironmentID *string
	ServiceID     *string
}

// ReplaceProjectGrantsInput is the typed input to
// ProjectGrantService.Replace. OrganizationID and ProjectID name the
// project whose grants are being replaced; Grants is the replacement set
// — possibly empty (a deliberate clear). The Actor* and correlation fields
// describe the authenticated principal and are recorded verbatim on the
// audit event; they are plain strings so the store layer takes no build
// dependency on the policy or telemetry packages — the httpapi handler,
// which already holds the resolved principal and the request correlation,
// fills them in.
type ReplaceProjectGrantsInput struct {
	OrganizationID string
	ProjectID      string
	Grants         []ProjectGrantReplace
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// ProjectGrantService is the unit-of-work orchestrator for PUT
// /v1/projects/{project_id}/grants. Replace composes — in a fixed order,
// inside one transaction opened by Store.Write — a tenant-scoped existence
// check on the target project, one upsert per caller-supplied grant, a
// delete for every grant not in the replacement set, the immutable audit
// record, and a re-read of the committed grants in deterministic
// (principal_id, environment_id NULLS FIRST, service_id NULLS FIRST, id)
// order. Because every step shares the *Tx, a failure in any of them rolls
// the others back: a partial replace and an orphaned audit record are
// both impossible.
//
// The service also re-reads the committed grants inside the same
// transaction so the response always reflects exactly the state that just
// persisted — the same coherence guarantee
// OrganizationVariableService.Replace gives PUT
// /v1/organizations/{org_id}/variables.
type ProjectGrantService struct {
	store    *Store
	projects *ProjectRepository
	grants   *ProjectGrantRepository
	audit    AuditAppender
}

// NewProjectGrantService wires a ProjectGrantService from its dependencies.
// It returns a typed error if any dependency is nil, so a misconfigured
// service fails at construction rather than on its first request — the
// same fail-fast posture every other unit-of-work orchestrator in this
// package takes.
func NewProjectGrantService(s *Store, projects *ProjectRepository, grants *ProjectGrantRepository, audit AuditAppender) (*ProjectGrantService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case projects == nil:
		return nil, errors.New("store: nil project repository")
	case grants == nil:
		return nil, errors.New("store: nil project grant repository")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &ProjectGrantService{store: s, projects: projects, grants: grants, audit: audit}, nil
}

// Replace validates in, then runs the replace-grants unit of work inside
// one transaction: verify the project exists in the target organization
// (so a missing project is a typed NotFound rather than the generic FK
// conflict the upsert would otherwise produce), upsert each caller-supplied
// grant (idempotent on its scope tuple), delete every grant whose scope
// tuple is not in the replacement set, append the audit record, and
// re-read the committed state in deterministic order. Validation runs
// before the transaction is opened, so an invalid request never touches
// the database.
//
// An empty Grants list is allowed and means "clear every grant of this
// project": a customer explicitly asking for an empty state is meaningful,
// not a silent no-op. A duplicate scope tuple (same principal at the same
// (environment_id, service_id) target), an invalid principal_kind, an
// unknown role, or a service-scoped grant that names an environment_id
// without service_id each surfaces as apierr.InvalidInput with a stable,
// value-free field path. A {project_id} that does not exist in the actor's
// organization is the typed apierr.NotFound the repository produces.
//
// The audit event is filed under the actor's home organization (the
// tenant the principal authenticated into) with resource_kind=project and
// resource_id={project_id}, mirroring how the project lifecycle endpoints
// file mutations against the project rather than the per-row grant id.
// Metadata records only counts — never principal ids, role names, or
// environment/service identifiers — so the audit row is auditable without
// ever leaking a customer-supplied identifier.
func (svc *ProjectGrantService) Replace(ctx context.Context, in ReplaceProjectGrantsInput) ([]ProjectGrant, error) {
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

	items, err := buildProjectGrantReplace(in.Grants)
	if err != nil {
		return nil, err
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return nil, apierr.Internal(errors.New("store: ProjectGrantService.Replace requires an actor organization for the audit record"))
	}

	// Per-grant audit counts are the only thing recorded in metadata. The
	// audit record never names a principal id, role, environment, or
	// service — those identifiers are not secrets but a per-row audit
	// trail at this granularity is the GET /v1/projects/{project_id}/grants
	// surface's job (every grant carries the bump_version stamp and
	// updated_at). Counts let the auditor see the shape of the change
	// without observing any customer-supplied identifier.
	scopeCounts := classifyProjectGrantScopes(items)

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         projectGrantsWriteAction,
		ResourceKind:   string(domain.KindProject),
		ResourceID:     projectID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for project.grants.write",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		Metadata: map[string]string{
			"grant_count":             strconv.Itoa(len(items)),
			"project_scope_count":     strconv.Itoa(scopeCounts.project),
			"environment_scope_count": strconv.Itoa(scopeCounts.environment),
			"service_scope_count":     strconv.Itoa(scopeCounts.service),
		},
	}

	var committed []ProjectGrant
	if txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Existence check first so a missing project is the typed NotFound
		// the repository produces, not the generic FK conflict the upsert
		// would otherwise yield. The Get call shares the *Tx so a row that
		// vanishes between this check and the upserts is not possible.
		if _, getErr := svc.projects.Get(ctx, tx, organizationID, projectID); getErr != nil {
			return getErr
		}

		// keepIDs collects the id of every row that survives the replace —
		// either a freshly minted INSERT id or the existing id of an
		// already-present row at the same scope tuple. The Upsert RETURNS
		// the persisted id, so we never assume the caller-supplied id is
		// the survivor.
		keepIDs := make([]string, 0, len(items))
		for _, item := range items {
			id, idErr := domain.NewID(domain.KindProjectGrant)
			if idErr != nil {
				return apierr.Internal(idErr)
			}
			row, upErr := svc.grants.Upsert(ctx, tx, id.String(), organizationID, projectID,
				item.PrincipalID, item.PrincipalKind, item.Role, item.EnvironmentID, item.ServiceID)
			if upErr != nil {
				return upErr
			}
			keepIDs = append(keepIDs, row.ID)
		}
		if delErr := svc.grants.DeleteByProjectExceptIDs(ctx, tx, organizationID, projectID, keepIDs); delErr != nil {
			return delErr
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		// Re-read the committed grants inside the same transaction so the
		// response always reflects exactly the state that just persisted.
		list, listErr := svc.grants.ListByProject(ctx, tx, organizationID, projectID)
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

// projectGrantScopeCounts tallies how many grants in a replacement set fall
// into each of the three scope tiers (project, environment, service). The
// counts are recorded in audit metadata so the auditor sees the shape of a
// replace without observing any customer-supplied identifier.
type projectGrantScopeCounts struct {
	project     int
	environment int
	service     int
}

// classifyProjectGrantScopes counts how many entries are project-scoped,
// environment-scoped, and service-scoped, using the same nullable-pointer
// precedence the wire and persistence layers read with.
func classifyProjectGrantScopes(items []ProjectGrantReplace) projectGrantScopeCounts {
	var c projectGrantScopeCounts
	for _, item := range items {
		switch {
		case item.ServiceID != nil:
			c.service++
		case item.EnvironmentID != nil:
			c.environment++
		default:
			c.project++
		}
	}
	return c
}

// buildProjectGrantReplace validates and normalises the caller-supplied
// items. It is split out from Replace so the validation rules are unit
// testable without a database, and so an invalid request is rejected
// before a transaction is ever opened.
//
// An empty list is allowed: the caller explicitly asked to clear every
// grant of this project, which is a meaningful (extreme) operation, not a
// silent no-op. A blank principal id, an unknown principal kind, an
// unknown role, a service-scoped grant that omits its environment id, an
// id with embedded NUL bytes, or a duplicate scope tuple each surfaces as
// a typed apierr.InvalidInput carrying stable, value-free field paths.
//
// Field-path shape mirrors the JSON request body: "grants[i].principal_id",
// "grants[i].principal_kind", "grants[i].role", "grants[i].environment_id",
// "grants[i].service_id".
func buildProjectGrantReplace(in []ProjectGrantReplace) ([]ProjectGrantReplace, error) {
	collector := newProjectGrantViolations()
	seen := make(map[string]struct{}, len(in))
	out := make([]ProjectGrantReplace, 0, len(in))
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
		if _, ok := projectGrantPrincipalKinds[principalKind]; !ok {
			collector.add(path+".principal_kind", "must be one of \"usr\" or \"sa\"")
		}

		role := strings.TrimSpace(item.Role)
		if _, ok := projectGrantBuiltinRoles[role]; !ok {
			collector.add(path+".role", "must be one of owner, admin, developer, viewer, ci, support")
		}

		envID, envOK := normaliseProjectGrantScopeID(item.EnvironmentID)
		if !envOK {
			collector.add(path+".environment_id", "must not be blank or contain NUL bytes when set")
		}
		svcID, svcOK := normaliseProjectGrantScopeID(item.ServiceID)
		if !svcOK {
			collector.add(path+".service_id", "must not be blank or contain NUL bytes when set")
		}

		// A service-scoped grant requires its environment_id to be set:
		// the (project | environment | service)-scoped distinction is
		// hierarchical, and a service-only grant has no addressable
		// parent environment to scope under. Reject it here so the
		// audit and wire shapes stay coherent.
		if svcID != nil && envID == nil {
			collector.add(path+".environment_id", "must be set when service_id is set")
		}

		dedupKey := principalID + "\x00" + safeProjectGrantScopeID(envID) + "\x00" + safeProjectGrantScopeID(svcID)
		if _, dup := seen[dedupKey]; dup {
			collector.add(path+".principal_id", "duplicates another grant at the same (environment_id, service_id) scope")
		} else if principalID != "" {
			seen[dedupKey] = struct{}{}
		}

		out = append(out, ProjectGrantReplace{
			PrincipalID:   principalID,
			PrincipalKind: principalKind,
			Role:          role,
			EnvironmentID: envID,
			ServiceID:     svcID,
		})
	}
	if err := collector.err(); err != nil {
		return nil, err
	}
	return out, nil
}

// normaliseProjectGrantScopeID trims a nullable *string scope id and
// reports whether the value is acceptable. A nil pointer is the
// "unscoped" sentinel — perfectly valid. A pointer to a blank or
// NUL-bearing string is rejected; an acceptable non-blank value is
// normalised through TrimSpace and returned as a fresh pointer so the
// caller's slice is untouched.
func normaliseProjectGrantScopeID(in *string) (*string, bool) {
	if in == nil {
		return nil, true
	}
	v := strings.TrimSpace(*in)
	if v == "" || strings.ContainsRune(v, 0) {
		return nil, false
	}
	return &v, true
}

// safeProjectGrantScopeID renders a nullable scope id as a stable string
// suitable for use in a dedup key. A nil pointer becomes the empty string,
// matching the COALESCE projection the unique index uses at the database
// layer, so the in-memory dedup is byte-equivalent to the SQL constraint.
func safeProjectGrantScopeID(in *string) string {
	if in == nil {
		return ""
	}
	return *in
}

// projectGrantViolations accumulates field-level validation failures and
// surfaces them as one apierr.InvalidInput, sorted by field path so the
// wire error is byte-deterministic across runs. It mirrors the
// internal/controlplane/validate Collector — kept local here to avoid
// pulling the validate package's POSIX-name rules into a service that
// validates a different shape.
type projectGrantViolations struct {
	violations []apierr.FieldViolation
}

func newProjectGrantViolations() *projectGrantViolations {
	return &projectGrantViolations{}
}

func (c *projectGrantViolations) add(field, reason string) {
	c.violations = append(c.violations, apierr.FieldViolation{Field: field, Reason: reason})
}

func (c *projectGrantViolations) err() error {
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

// ProjectGrantReader is the store-backed read adapter for project_grants. It
// mirrors ProjectReader / OrganizationVariableReader — it composes
// ProjectGrantRepository (and ProjectRepository, for the tenant-scoped
// project existence check) through a short-lived Store.Read transaction, so
// the repository's tenant-scoping guarantees are inherited for free and the
// adapter cannot smuggle a mutation past Store.Write.
type ProjectGrantReader struct {
	store    *Store
	projects *ProjectRepository
	grants   *ProjectGrantRepository
}

// NewProjectGrantReader builds a ProjectGrantReader over store. It returns
// an error for a nil store so a misconfigured adapter fails at construction
// rather than on its first request.
func NewProjectGrantReader(s *Store) (*ProjectGrantReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &ProjectGrantReader{
		store:    s,
		projects: NewProjectRepository(),
		grants:   NewProjectGrantRepository(),
	}, nil
}

// ListProjectGrants returns every grant of the project identified by
// (organizationID, projectID), reading them inside a short-lived read-only
// transaction. The read is tenant scoped at both legs: it Gets the project
// first so a cross-tenant or unknown project_id surfaces as a deterministic
// apierr.NotFound — never as an empty list, which would invite an agent to
// believe the project exists with no grants. A live project with no grants
// is then a deterministic empty slice. A datastore failure is propagated as
// its own typed error.
func (r *ProjectGrantReader) ListProjectGrants(ctx context.Context, organizationID, projectID string) ([]ProjectGrant, error) {
	var grants []ProjectGrant
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, getErr := r.projects.Get(ctx, q, organizationID, projectID); getErr != nil {
			return getErr
		}
		list, listErr := r.grants.ListByProject(ctx, q, organizationID, projectID)
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
