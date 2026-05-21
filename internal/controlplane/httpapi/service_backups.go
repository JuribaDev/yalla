package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// errNoServiceBackupReader is returned when GET
// /v1/services/{service_id}/backups is reached without a
// ServiceBackupReader wired into NewHandler. Like
// errNoServiceDomainReader it can only happen through a wiring error
// — a programming mistake, not a client error — so the handler
// reports it as a typed internal failure rather than serving a
// misleading empty list (which would invite an agent to believe the
// service exists with no backup rows when in fact no backup source is
// configured).
var errNoServiceBackupReader = errors.New("httpapi: no service backup reader configured")

// errNoServiceBackupCreator is returned when POST
// /v1/services/{service_id}/backups is reached without a
// ServiceBackupCreator wired into NewHandler. Like
// errNoServiceBackupReader it can only happen through a wiring error
// — a programming mistake, not a client error — so the handler
// reports it as a typed internal failure rather than serving a
// misleading 2xx with no side effect.
var errNoServiceBackupCreator = errors.New("httpapi: no service backup creator configured")

// errNoServiceBackupRunner is returned when POST
// /v1/services/{service_id}/backups/{backup_id}/run is reached
// without a ServiceBackupRunner wired into NewHandler. Like
// errNoServiceBackupCreator it can only happen through a wiring
// error — a programming mistake, not a client error — so the handler
// reports it as a typed internal failure rather than serving a
// misleading 2xx with no side effect.
var errNoServiceBackupRunner = errors.New("httpapi: no service backup runner configured")

// errNoServiceBackupRestorer is returned when POST
// /v1/services/{service_id}/backups/{backup_id}/restore is reached
// without a ServiceBackupRestorer wired into NewHandler.
var errNoServiceBackupRestorer = errors.New("httpapi: no service backup restorer configured")

// errNoServiceBackupUpdater is returned when PATCH
// /v1/services/{service_id}/backups/{backup_id} is reached without a
// ServiceBackupUpdater wired into NewHandler. Like
// errNoServiceBackupRunner it can only happen through a wiring
// error — a programming mistake, not a client error — so the handler
// reports it as a typed internal failure rather than serving a
// misleading 2xx with no side effect.
var errNoServiceBackupUpdater = errors.New("httpapi: no service backup updater configured")

// errNoServiceBackupDeleter is returned when DELETE
// /v1/services/{service_id}/backups/{backup_id} is reached without
// a ServiceBackupDeleter wired into NewHandler. Like
// errNoServiceBackupUpdater it can only happen through a wiring
// error — a programming mistake, not a client error — so the
// handler reports it as a typed internal failure rather than
// serving a misleading 2xx confirming the destruction of a row
// that was never removed.
var errNoServiceBackupDeleter = errors.New("httpapi: no service backup deleter configured")

// ServiceBackupReader is the narrow persistence port GET
// /v1/services/{service_id}/backups depends on.
// *store.ServiceBackupReader satisfies it in production; tests supply
// a fake. Keeping the dependency an interface keeps the handler
// unit-testable without a real database — the concrete adapter
// performs the tenant-scoped service existence check inside a short-
// lived read-only transaction (so a cross-tenant or unknown
// service_id surfaces as a typed apierr.NotFound before any backup
// fetch runs) and projects the resulting backup set onto the stable
// wire shape this handler returns.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action backup.read against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the reader has already
// cleared the policy boundary. The store layer still re-validates the
// tenant scope at the SQL leg — defense-in-depth against a grant
// change that landed between the HTTP authorize and the read.
type ServiceBackupReader interface {
	ListBackups(ctx context.Context, in store.ListServiceBackupsInput) (store.ServiceBackups, error)
}

// serviceBackup is the wire-shape of one entry in the backup list. It
// is the projection of store.ServiceBackup onto stable JSON tag
// names; an agent reading the payload can branch on enabled, status,
// and retention_count without escape-decoding them. The payload
// carries no credential material: the schedule column is a cron-style
// expression, and the backup artefact bytes themselves never
// round-trip through this endpoint (they live in the worker / Dokploy
// / object-storage layer).
//
// last_run_at and last_succeeded_at are optional — they marshal as
// empty strings when the worker has not yet recorded a run or a
// success — so an agent does not need to special-case the
// absent-vs-zero distinction.
type serviceBackup struct {
	ID              string `json:"id"`
	ServiceID       string `json:"service_id"`
	DisplayName     string `json:"display_name"`
	Schedule        string `json:"schedule"`
	RetentionCount  int    `json:"retention_count"`
	Enabled         bool   `json:"enabled"`
	Status          string `json:"status"`
	LastRunAt       string `json:"last_run_at"`
	LastSucceededAt string `json:"last_succeeded_at"`
	Version         int64  `json:"version"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// listServiceBackupsPayload is the data block of the GET
// /v1/services/{service_id}/backups success envelope: the service id
// the backup policies belong to (echoed back so an agent can
// distinguish a multi-resource batch in a future backups-stream
// endpoint even though today's GET addresses exactly one service) and
// the backups themselves in deterministic (created_at, id) order. An
// empty backups slice marshals as "backups": [] rather than
// "backups": null, which is what every list payload in the API
// surface returns to keep agents from special-casing the
// absent-vs-empty distinction.
type listServiceBackupsPayload struct {
	ServiceID string          `json:"service_id"`
	Backups   []serviceBackup `json:"backups"`
}

// listServiceBackupsHandler builds the GET
// /v1/services/{service_id}/backups handler. It reads the backup
// policy rows for the service named by the {service_id} path
// parameter through the ServiceBackupReader port and renders them in
// a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action backup.read before the
// handler runs — authorized through serviceIDResolver against the
// (principal home organization, {service_id}) resource the path
// names — and attaches the resolved principal to the context.
// backup.read is a CapRead action, so the gate admits the
// principal's organization-wide read roles (owner, admin, developer,
// viewer, ci). The support principal's cross-tenant read exception
// does NOT apply through this endpoint because the resolver pins the
// resource scope to the principal's home organization, not the path
// service's tenant — support cross-tenant backup reads remain
// available through endpoints whose path carries an explicit
// {org_id}. The path carries no parent project_id or environment_id,
// so the policy engine cannot pin those legs of the resource scope
// at authorization time — project-, environment-, and service-scoped
// grants are denied at the boundary by the engine's covers() rule (a
// grant with a pinned ProjectID cannot cover a resource with no
// ProjectID); principals whose only access is a scoped grant must
// use a parent-scoped route to address a service by its (project,
// environment, service) tuple.
//
// The handler reads from the principal's home organization id only —
// it never trusts a caller-supplied organization id — so the tenant
// boundary is structural at the persistence layer too: a cross-tenant
// service_id reaches the store with the principal's home organization
// id and is rejected as a typed NotFound by the tenant-scoped
// existence check. A request that arrives with no principal is a
// wiring error reported as a typed internal error; a reader-store
// outage surfaces as its own typed 5xx; an unknown or cross-tenant
// service_id is a typed 404, never disguised as an empty success.
//
// The response carries no credential material: the schedule column
// is a cron-style expression, the status column is a closed-taxonomy
// enum, and the backup artefact bytes themselves never round-trip
// through this endpoint. The empty Backups slice marshals as
// "backups": [], never "backups": null, so an agent does not need to
// special-case the absent-vs-empty distinction.
func listServiceBackupsHandler(reader ServiceBackupReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceBackupReader))
			return
		}

		result, err := reader.ListBackups(r.Context(), store.ListServiceBackupsInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		payload := listServiceBackupsPayload{
			ServiceID: result.ServiceID,
			Backups:   make([]serviceBackup, 0, len(result.Backups)),
		}
		for _, b := range result.Backups {
			payload.Backups = append(payload.Backups, serviceBackupOf(b))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}

// serviceBackupOf projects a store.ServiceBackup onto the stable wire
// shape. It is the single chokepoint between the persistence layer
// and the response: a future column added to store.ServiceBackup is
// reviewed for its wire exposure here rather than leaking by default.
// Both fixed timestamps (created_at, updated_at) are rendered as RFC
// 3339 strings with nanosecond precision and a "Z" zone — the same
// format every other dated resource in the service-backups surface
// returns. last_run_at and last_succeeded_at are optional in the
// schema and render as empty strings when the worker has not yet
// recorded a run / success, so an agent does not need to special-case
// the absent-vs-zero distinction.
func serviceBackupOf(b store.ServiceBackup) serviceBackup {
	const rfc3339Nano = "2006-01-02T15:04:05.000000000Z07:00"
	lastRunAt := ""
	if b.LastRunAt != nil {
		lastRunAt = b.LastRunAt.UTC().Format(rfc3339Nano)
	}
	lastSucceededAt := ""
	if b.LastSucceededAt != nil {
		lastSucceededAt = b.LastSucceededAt.UTC().Format(rfc3339Nano)
	}
	return serviceBackup{
		ID:              b.ID,
		ServiceID:       b.ServiceID,
		DisplayName:     b.DisplayName,
		Schedule:        b.Schedule,
		RetentionCount:  b.RetentionCount,
		Enabled:         b.Enabled,
		Status:          b.Status,
		LastRunAt:       lastRunAt,
		LastSucceededAt: lastSucceededAt,
		Version:         b.Version,
		CreatedAt:       b.CreatedAt.UTC().Format(rfc3339Nano),
		UpdatedAt:       b.UpdatedAt.UTC().Format(rfc3339Nano),
	}
}

// ServiceBackupCreator is the narrow persistence port POST
// /v1/services/{service_id}/backups depends on.
// *store.ServiceBackupService satisfies it in production; tests supply
// a fake. Keeping the dependency an interface keeps the handler unit-
// testable without a real database — the concrete orchestrator (the
// parent-service existence check / in-transaction authorize /
// desired-state write / audit append composition committed in one
// transaction) lives in the store layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action backup.create against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the creator has already
// cleared the policy boundary. The store layer still re-authorizes
// inside the same *Tx as the desired-state write — defense-in-depth
// against a grant change that landed between the HTTP authorize and
// the backup row write.
type ServiceBackupCreator interface {
	Create(ctx context.Context, in store.CreateServiceBackupInput) (store.ServiceBackup, error)
}

// createServiceBackupRequest is the decoded POST
// /v1/services/{service_id}/backups request body. ID is the caller-
// supplied canonical backup id — the agent contract mints ids client-
// side so a retried POST is structurally idempotent under the primary-
// key uniqueness constraint rather than depending on a header. The
// display_name is a human-authored label; schedule is a cron-style
// expression the worker interprets when it next plans a run;
// retention_count bounds how many succeeded runs the worker retains
// before pruning the oldest; enabled toggles whether the worker takes
// any action on the row.
//
// The request body intentionally exposes no organization_id,
// project_id, environment_id, or service_id field: the organization is
// derived from the authenticated principal's home organization, the
// service comes from the {service_id} path parameter, and the new
// backup row inherits its parent service's transitive parents from
// the persisted services row — there is no caller-supplied parameter
// that could redirect the create at another tenant, another project,
// or another environment.
//
// Enabled is a pointer so the absent-vs-explicit-false distinction is
// visible at this seam: an omitted field defaults to true (the most
// common case — a backup policy is created to run), an explicit
// `false` rides through to the store layer unchanged. RetentionCount
// at zero takes the schema-side default. The store layer validates
// every field before any database work, so an invalid request never
// opens a transaction — and the request body never carries credential
// material (the actual backup artefact bytes live in the worker /
// Dokploy / object-storage layer and never round-trip through this
// endpoint).
type createServiceBackupRequest struct {
	ID             string `json:"id"`
	DisplayName    string `json:"display_name"`
	Schedule       string `json:"schedule"`
	RetentionCount int    `json:"retention_count"`
	Enabled        *bool  `json:"enabled"`
}

// createServiceBackupPayload is the data block of the POST
// /v1/services/{service_id}/backups success envelope: the backup
// that was created, in the same stable wire shape GET
// /v1/services/{service_id}/backups returns. It carries no credential
// material — a service_backups row stores none (the actual backup
// artefact bytes live in the worker / Dokploy / object-storage layer
// and never round-trip through this endpoint).
type createServiceBackupPayload struct {
	Backup serviceBackup `json:"backup"`
}

// createServiceBackupHandler builds the POST
// /v1/services/{service_id}/backups handler. It decodes and delegates:
// the request body is strictly decoded (oversized, malformed, or
// unknown-field bodies become a typed 400 that never echoes the
// input), then the create-backup unit of work — re-authorize, write
// the backup row, append the audit record, all in one transaction —
// runs in the store layer through the ServiceBackupCreator port.
//
// RequireAuth gates the route on action backup.create through
// serviceIDResolver before the handler runs and attaches the resolved
// principal, so a request that reaches the handler with no principal
// is a wiring error reported as a typed internal error.
// backup.create is a CapWrite action evaluated against the (principal
// home organization, {service_id}) resource, so the gate admits the
// principal's organization-wide write roles (owner, admin, developer,
// ci) and denies viewer (CapRead only), denies support (CapRead+
// CapSupport — support is a deliberate cross-tenant READ exception,
// never a write one). The path carries no parent project_id, so the
// policy engine cannot pin the ProjectID leg of the resource scope at
// authorization time — project-, environment-, and service-scoped
// grants are denied at the boundary by the engine's covers() rule (a
// grant scope that pins ProjectID cannot cover a resource scope that
// does not); principals whose only access is a scoped grant must use
// a parent-scoped route to address a service by its (project,
// environment, service) tuple.
//
// The handler resolves the organization id from the authenticated
// principal's home organization and the service id from the
// {service_id} PATH parameter — never from the request body — so the
// tenant boundary is structural here: there is no caller input that
// could point the write at another tenant. A cross-tenant service_id
// reaches the persistence layer with the principal's home
// organization id and is rejected as a deterministic 404 by the
// store-layer's tenant-scoped service existence check (the same
// property GET /v1/services/{service_id}/backups inherits), never
// disguised as a 200 or a 403 that would confirm the foreign
// service's existence. The principal and the request correlation
// identifiers are passed to the creator so the audit record names
// the actor; a validation failure, a duplicate-id conflict, a denied
// in-tx authorize, and a datastore outage each surface as their own
// typed status, never disguised as one another.
func createServiceBackupHandler(creator ServiceBackupCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if creator == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceBackupCreator))
			return
		}

		var req createServiceBackupRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		// Enabled is a pointer so the absent-vs-explicit-false
		// distinction is visible at this seam: an omitted field
		// defaults to true (the most common case — a backup policy is
		// created to run), an explicit `false` rides through to the
		// store layer unchanged.
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}

		correlation := telemetry.FromContext(r.Context())
		created, err := creator.Create(r.Context(), store.CreateServiceBackupInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
			BackupID:       req.ID,
			DisplayName:    req.DisplayName,
			Schedule:       req.Schedule,
			RetentionCount: req.RetentionCount,
			Enabled:        enabled,
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusCreated, requestID(r), createServiceBackupPayload{
			Backup: serviceBackupOf(created),
		})
	}
}

// ServiceBackupRunner is the narrow persistence port POST
// /v1/services/{service_id}/backups/{backup_id}/run depends on.
// *store.ServiceBackupService satisfies it in production; tests
// supply a fake. Keeping the dependency an interface keeps the
// handler unit-testable without a real database — the concrete
// orchestrator (the parent-service existence check, the tenant-
// scoped backup existence check, the disabled/already-running
// preconditions, the in-tx authorize, the status flip to pending,
// and the audit append, all in one transaction) lives in the store
// layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action backup.run against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the runner has
// already cleared the policy boundary. The store layer still
// re-authorizes inside the same *Tx as the status flip —
// defense-in-depth against a grant change that landed between the
// HTTP authorize and the desired-state write.
type ServiceBackupRunner interface {
	Run(ctx context.Context, in store.RunServiceBackupInput) (store.ServiceBackup, error)
}

// runServiceBackupPayload is the data block of the POST
// /v1/services/{service_id}/backups/{backup_id}/run success
// envelope: the backup-policy row whose run was just enqueued, in
// the same stable wire shape GET /v1/services/{service_id}/backups
// and POST /v1/services/{service_id}/backups return. The row's
// status is 'pending' on the way out — the worker will subsequently
// transition it to running, succeeded, or failed — and the row
// carries no credential material (a service_backups row stores
// none; the actual backup artefact bytes live in the worker /
// Dokploy / object-storage layer and never round-trip through this
// endpoint).
type runServiceBackupPayload struct {
	Backup serviceBackup `json:"backup"`
}

// runServiceBackupHandler builds the POST
// /v1/services/{service_id}/backups/{backup_id}/run handler. It
// records the customer's manual-run intent through the
// ServiceBackupRunner port — which flips the row to pending,
// re-authorizes inside the transaction, and appends the immutable
// audit record in one transaction — then renders the backup row in
// a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action backup.run through
// serviceIDResolver before the handler runs and attaches the
// resolved principal, so a request that reaches the handler with
// no principal is a wiring error reported as a typed internal
// error. backup.run is a CapDeploy action evaluated against the
// (principal home organization, {service_id}) resource, so the
// gate admits the principal's organization-wide deploy roles
// (owner, admin, developer, ci) and denies viewer (CapRead only),
// denies support (CapRead+CapSupport — support is a deliberate
// cross-tenant READ exception, never a deploy one). The path
// carries no parent project_id or environment_id, so the policy
// engine cannot pin those legs of the resource scope at
// authorization time — project-, environment-, and service-scoped
// grants are denied at the boundary by the engine's covers() rule
// (a grant with a pinned ProjectID cannot cover a resource with
// no ProjectID); principals whose only access is a scoped grant
// must use a parent-scoped route to address a service by its
// (project, environment, service) tuple.
//
// The handler resolves the organization id from the authenticated
// principal's home organization and the service and backup ids
// from the {service_id} and {backup_id} PATH parameters — never
// from the request body — so the tenant boundary is structural
// here: there is no caller input that could point the write at
// another tenant. A cross-tenant service_id or backup_id reaches
// the persistence layer with the principal's home organization id
// and is rejected as a deterministic 404 by the store-layer's
// tenant-scoped existence checks (the same property GET
// /v1/services/{service_id}/backups inherits), never disguised as
// a 200 or a 403 that would confirm the foreign id's existence. A
// disabled backup or one whose status is already 'running' is a
// deterministic 409 — a manual run cannot land on a disabled
// policy or double-enqueue against a worker-active run. The
// principal and the request correlation identifiers are passed to
// the runner so the audit record names the actor.
//
// The request body is empty: backup.run is a fire-and-forget
// signal that targets one backup-policy row and carries no
// caller-supplied parameters. Requests with a non-empty body are
// accepted to keep the path simple; the worker derives all needed
// context from the persisted backup row.
func runServiceBackupHandler(runner ServiceBackupRunner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if runner == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceBackupRunner))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		// OrganizationID is taken from the principal's home org
		// (never the caller — the request body carries no fields at
		// all), so a cross-tenant service_id or backup_id still hits
		// the tenant-scoped repository queries and surfaces as a 404
		// at the persistence boundary.
		triggered, err := runner.Run(r.Context(), store.RunServiceBackupInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
			BackupID:       r.PathValue("backup_id"),
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusAccepted, requestID(r), runServiceBackupPayload{
			Backup: serviceBackupOf(triggered),
		})
	}
}

// ServiceBackupRestorer is the narrow persistence port POST
// /v1/services/{service_id}/backups/{backup_id}/restore depends on.
// *store.ServiceBackupService satisfies it in production; tests supply a fake.
type ServiceBackupRestorer interface {
	Restore(ctx context.Context, in store.RestoreServiceBackupInput) (store.ServiceBackup, error)
}

// restoreServiceBackupPayload is the data block returned after a restore
// request is accepted. The backup row is unchanged by the control plane; the
// durable restore_backup job carries the actual side effect to the worker.
type restoreServiceBackupPayload struct {
	Backup serviceBackup `json:"backup"`
}

// restoreServiceBackupHandler builds the POST
// /v1/services/{service_id}/backups/{backup_id}/restore handler. The request
// body is intentionally empty: the service and backup ids come from the path,
// and the worker derives all restore context from the persisted backup row.
func restoreServiceBackupHandler(restorer ServiceBackupRestorer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if restorer == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceBackupRestorer))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		restored, err := restorer.Restore(r.Context(), store.RestoreServiceBackupInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
			BackupID:       r.PathValue("backup_id"),
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusAccepted, requestID(r), restoreServiceBackupPayload{
			Backup: serviceBackupOf(restored),
		})
	}
}

// ServiceBackupUpdater is the narrow persistence port PATCH
// /v1/services/{service_id}/backups/{backup_id} depends on.
// *store.ServiceBackupService satisfies it in production; tests
// supply a fake. Keeping the dependency an interface keeps the
// handler unit-testable without a real database — the concrete
// orchestrator (the row read / If-Match precondition / desired-state
// write / audit append composition committed in one transaction)
// lives in the store layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action backup.update against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the updater has
// already cleared the policy boundary. The store layer does not
// re-authorize inside the same *Tx for the update path:
// backup.update is enforced only at the HTTP boundary, matching
// domain.update, service.update, and the other CapWrite partial-
// update endpoints — the in-transaction Authorizer is reserved for
// Create (the create-time race against grant changes during a quota
// reservation).
type ServiceBackupUpdater interface {
	Update(ctx context.Context, in store.UpdateServiceBackupInput) (store.ServiceBackup, error)
}

// updateServiceBackupRequest is the decoded PATCH
// /v1/services/{service_id}/backups/{backup_id} request body. Every
// field is an optional pointer so the absent-vs-zero distinction is
// preserved at the seam — an omitted display_name means "leave the
// display_name alone", and an explicit `"enabled": false` rides
// through to the store layer unchanged. A patch that names no
// updatable field is itself a 400 — a mutation that changes nothing
// is a client error, not a silent success.
//
// The mutable surface is intentionally narrow: only the four
// customer-mutable columns (display_name, schedule, retention_count,
// enabled). status is intentionally NOT exposed — the worker is the
// authority for transitions between Running and {Succeeded, Failed},
// and the customer toggle for "stop running this policy" is the
// enabled flag, not the status enum. A customer-supplied status of
// 'succeeded' would let an agent forge a successful run through the
// public API surface, which is exactly the failure mode the typed
// boundary prevents.
//
// The request body intentionally exposes no organization_id,
// service_id, or id field: the organization is derived from the
// authenticated principal's home organization, the service comes
// from the {service_id} path parameter, and the backup id from the
// {backup_id} path parameter — there is no caller-supplied parameter
// in the body that could redirect the write at another tenant.
type updateServiceBackupRequest struct {
	DisplayName    *string `json:"display_name"`
	Schedule       *string `json:"schedule"`
	RetentionCount *int    `json:"retention_count"`
	Enabled        *bool   `json:"enabled"`
}

// updateServiceBackupPayload is the data block of the PATCH
// /v1/services/{service_id}/backups/{backup_id} success envelope:
// the backup after the update, in the same stable wire shape the
// other service-backups endpoints return. It carries no credential
// material — a service_backups row stores none (the actual backup
// artefact bytes live in the worker / Dokploy / object-storage
// layer and never round-trip through this endpoint).
type updateServiceBackupPayload struct {
	Backup serviceBackup `json:"backup"`
}

// updateServiceBackupHandler builds the PATCH
// /v1/services/{service_id}/backups/{backup_id} handler. It decodes
// and delegates: the request body is strictly decoded (oversized,
// malformed, or unknown-field bodies become a typed 400 that never
// echoes the input), the If-Match header is parsed as an optional
// optimistic-concurrency precondition, and then the update-backup
// unit of work — read the current row, apply the patch, write the
// row back, append the audit record, all in one transaction — runs
// in the store layer through the ServiceBackupUpdater port.
//
// RequireAuth gates the route on action backup.update before the
// handler runs — authorized through serviceIDResolver against the
// (principal home organization, {service_id}) resource the path
// names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the policy boundary.
// backup.update is a CapWrite action, so the gate admits the
// principal's organization-wide write roles (owner, admin,
// developer, ci) and denies viewer (CapRead only), denies support
// (CapRead + CapSupport — support is a deliberate cross-tenant READ
// exception, never a write one). The path carries no parent
// project_id, so the policy engine cannot pin the ProjectID leg of
// the resource scope at authorization time — project-, environment-,
// and service-scoped grants are denied at the boundary by the
// engine's covers() rule (a grant scope that pins ProjectID cannot
// cover a resource scope that does not); principals whose only
// access is a scoped grant must use a parent-scoped route to
// address a service by its (project, environment, service) tuple.
//
// The handler resolves the organization id from the authenticated
// principal's home organization, the service id from the
// {service_id} PATH parameter, and the backup id from the
// {backup_id} PATH parameter — never from the request body — so the
// tenant boundary is structural here: there is no caller input that
// could point the write at another tenant. A cross-tenant
// service_id or backup_id reaches the persistence layer with the
// principal's home organization id and is rejected as a
// deterministic 404 by the store-layer's tenant-scoped GetByID
// query, never disguised as a 200 or a 403 that would confirm the
// foreign row's existence. On success, the handler mirrors the row's
// authoritative version into the ETag response header so the caller
// can echo it back as the next If-Match precondition without
// re-reading the row.
func updateServiceBackupHandler(updater ServiceBackupUpdater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if updater == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceBackupUpdater))
			return
		}

		ifMatchVersion, ifMatchErr := parseIfMatchVersion(r)
		if ifMatchErr != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(ifMatchErr))
			return
		}

		var req updateServiceBackupRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		updated, err := updater.Update(r.Context(), store.UpdateServiceBackupInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
			BackupID:       r.PathValue("backup_id"),
			DisplayName:    req.DisplayName,
			Schedule:       req.Schedule,
			RetentionCount: req.RetentionCount,
			Enabled:        req.Enabled,
			IfMatchVersion: ifMatchVersion,
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		writeOrganizationETag(w, updated.Version)
		apienvelope.WriteData(w, http.StatusOK, requestID(r), updateServiceBackupPayload{
			Backup: serviceBackupOf(updated),
		})
	}
}

// ServiceBackupDeleter is the narrow persistence port DELETE
// /v1/services/{service_id}/backups/{backup_id} depends on.
// *store.ServiceBackupService satisfies it in production; tests
// supply a fake. Keeping the dependency an interface keeps the
// handler unit-testable without a real database — the concrete
// orchestrator (the tenant-scoped DELETE / optional If-Match
// precondition / audit append composition committed in one
// transaction) lives in the store layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action backup.delete against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the deleter has
// already cleared the policy boundary. The store layer does not
// re-authorize inside the same *Tx for the delete path:
// backup.delete is enforced only at the HTTP boundary, matching
// domain.delete, service.delete, and the other CapWrite delete
// endpoints — the in-transaction Authorizer is reserved for Create
// (the create-time race against grant changes during a quota
// reservation).
type ServiceBackupDeleter interface {
	Delete(ctx context.Context, in store.DeleteServiceBackupInput) (store.ServiceBackup, error)
}

// deleteServiceBackupPayload is the data block of the DELETE
// /v1/services/{service_id}/backups/{backup_id} success envelope:
// the backup-policy row as it stood at the moment of removal, in
// the same stable wire shape every other service-backup endpoint
// returns. It carries no credential material — a service_backups
// row stores none (the actual backup artefact bytes live in the
// worker / Dokploy / object-storage layer and never round-trip
// through this endpoint). The row is gone from the database by the
// time this body reaches the wire; an audit trail of the deletion
// lives independently of the row.
type deleteServiceBackupPayload struct {
	Backup serviceBackup `json:"backup"`
}

// deleteServiceBackupHandler builds the DELETE
// /v1/services/{service_id}/backups/{backup_id} handler. It
// delegates to the ServiceBackupDeleter port the tenant-scoped
// delete + audit unit of work, then projects the deleted snapshot
// onto the wire. The optional If-Match header is parsed as an
// optimistic-concurrency precondition before the deleter runs — a
// malformed If-Match becomes a typed 400 that never echoes the
// input, and the deleter never runs (a destructive operation that
// silently degraded into "no precondition" would be a particularly
// load-bearing footgun).
//
// RequireAuth gates the route on action backup.delete before the
// handler runs — authorized through serviceIDResolver against the
// (principal home organization, {service_id}) resource the path
// names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the policy boundary.
// backup.delete is a CapWrite action, so the gate admits the
// principal's organization-wide write roles (owner, admin,
// developer, ci) and denies viewer (CapRead only), denies support
// (CapRead + CapSupport — support is a deliberate cross-tenant READ
// exception, never a write one). The path carries no parent
// project_id, so the policy engine cannot pin the ProjectID leg of
// the resource scope at authorization time — project-, environment-,
// and service-scoped grants are denied at the boundary by the
// engine's covers() rule (a grant scope that pins ProjectID cannot
// cover a resource scope that does not); principals whose only
// access is a scoped grant must use a parent-scoped route to
// address a service by its (project, environment, service) tuple.
//
// The handler resolves the organization id from the authenticated
// principal's home organization, the service id from the
// {service_id} PATH parameter, and the backup id from the
// {backup_id} PATH parameter — never from the request body (a
// DELETE has none) — so the tenant boundary is structural here:
// there is no caller input that could point the delete at another
// tenant. A cross-tenant service_id or backup_id reaches the
// persistence layer with the principal's home organization id and
// is rejected as a deterministic 404 by the store-layer's
// tenant-scoped DELETE predicate, never disguised as a 200 or a
// 403 that would confirm the foreign row's existence.
//
// The response is 200 OK carrying the deleted backup as a snapshot
// — agents can confirm what was destroyed without re-reading. The
// row is gone from the database by the time this body reaches the
// wire; an audit trail of the deletion lives independently of the
// row. A 204 No Content was deliberately not chosen: a body-bearing
// success keeps the wire contract uniform with every other
// service-backup endpoint and prevents agents from special-casing
// the no-body code path.
func deleteServiceBackupHandler(deleter ServiceBackupDeleter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if deleter == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceBackupDeleter))
			return
		}

		ifMatchVersion, ifMatchErr := parseIfMatchVersion(r)
		if ifMatchErr != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(ifMatchErr))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		deleted, err := deleter.Delete(r.Context(), store.DeleteServiceBackupInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
			BackupID:       r.PathValue("backup_id"),
			IfMatchVersion: ifMatchVersion,
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusOK, requestID(r), deleteServiceBackupPayload{
			Backup: serviceBackupOf(deleted),
		})
	}
}
