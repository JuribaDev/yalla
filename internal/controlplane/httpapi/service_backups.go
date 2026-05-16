package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
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
