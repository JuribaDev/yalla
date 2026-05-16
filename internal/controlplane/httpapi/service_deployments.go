package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// errNoDeploymentCreator is returned when POST
// /v1/services/{service_id}/deployments is reached without a
// DeploymentCreator wired into NewHandler. It can only happen through a
// wiring error — a programming mistake, not a client error — so the
// handler reports it as a typed internal failure rather than serving a
// misleading 2xx with no side effect.
var errNoDeploymentCreator = errors.New("httpapi: no deployment creator configured")

// DeploymentCreator is the narrow persistence port POST
// /v1/services/{service_id}/deployments depends on.
// *store.DeploymentService satisfies it in production; tests supply a
// fake. Keeping the dependency an interface keeps the handler unit-
// testable without a real database — the concrete orchestrator (the
// parent-service existence check, the idempotency short-circuit, the
// in-tx authorize, the quota reservation against
// concurrent_deployments, the desired-state write, the provisioning-
// job enqueue, and the audit append, all in one transaction) lives in
// the store layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action deployment.create against the
// (principal home organization, {service_id}) resource the path names
// through serviceIDResolver, so a request that reaches the creator has
// already cleared the policy boundary. The store layer still
// re-authorizes inside the same *Tx as the desired-state write —
// defense-in-depth against a grant change that landed between the HTTP
// authorize and the deployment row write.
type DeploymentCreator interface {
	Create(ctx context.Context, in store.CreateDeploymentInput) (store.Deployment, error)
}

// createServiceDeploymentRequest is the decoded POST
// /v1/services/{service_id}/deployments request body. Source is the
// closed Dokploy-aligned taxonomy ('git', 'image', 'manual'); SourceRef
// names the customer-supplied ref the worker mirrors into Dokploy (a
// branch / commit / image reference, or an optional manual label).
// IdempotencyKey is required — a retried POST with the same key
// returns the previously persisted deployment verbatim, so a network
// hiccup never produces a duplicate Dokploy provisioning job.
//
// The request body intentionally exposes no organization_id,
// project_id, environment_id, or service_id field: the organization is
// derived from the authenticated principal's home organization, the
// service comes from the {service_id} PATH parameter, and the new
// deployment inherits its parent service's project_id and
// environment_id from the persisted row — there is no caller-supplied
// parameter that could redirect the create at another tenant, another
// project, or another environment. Every field is validated in the
// store-layer unit of work before any database write, so an invalid
// request never opens a transaction — and the request body never
// carries credential material.
type createServiceDeploymentRequest struct {
	Source         string `json:"source"`
	SourceRef      string `json:"source_ref"`
	IdempotencyKey string `json:"idempotency_key"`
}

// serviceDeployment is the wire shape of one deployments row, projected
// from store.Deployment by serviceDeploymentOf. The shape carries no
// credential material — the deployments table itself stores only
// structural identifiers, the closed-set source taxonomy, the
// customer-supplied source reference (a branch / commit / image
// reference — never tokens), the closed-set lifecycle status, and the
// redacted error summary the worker writes when a deployment fails.
// CreatedAt and UpdatedAt are RFC 3339 timestamps with the same
// semantics as every other dated resource the API surfaces; StartedAt
// and FinishedAt are omitted entirely while the row is in a state
// where they are NULL (a deployment in 'queued' has no started_at; a
// non-terminal deployment has no finished_at).
type serviceDeployment struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	ProjectID      string    `json:"project_id"`
	EnvironmentID  string    `json:"environment_id"`
	ServiceID      string    `json:"service_id"`
	Source         string    `json:"source"`
	SourceRef      string    `json:"source_ref"`
	Status         string    `json:"status"`
	RequestedBy    string    `json:"requested_by"`
	IdempotencyKey string    `json:"idempotency_key"`
	ErrorCode      string    `json:"error_code,omitempty"`
	ErrorMessage   string    `json:"error_message,omitempty"`
	Version        int64     `json:"version"`
	RequestID      string    `json:"request_id,omitempty"`
	CorrelationID  string    `json:"correlation_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	StartedAt      *string   `json:"started_at,omitempty"`
	FinishedAt     *string   `json:"finished_at,omitempty"`
}

// serviceDeploymentOf projects a store.Deployment onto the stable wire
// shape. The deployments table itself carries no credential material —
// the columns are structural identifiers, closed-set enums, a
// caller-supplied source reference, and a redacted error summary the
// worker writes through the output redactor — but the projection
// remains the single chokepoint so a future column added to
// store.Deployment is reviewed for its wire exposure here rather than
// leaking by default. A nil StartedAt or FinishedAt — a deployment
// that has not yet started, or has not yet finished — is omitted from
// the wire shape entirely, matching the lifecycle-timestamp omitempty
// convention every other resource uses.
func serviceDeploymentOf(d store.Deployment) serviceDeployment {
	out := serviceDeployment{
		ID:             d.ID,
		OrganizationID: d.OrganizationID,
		ProjectID:      d.ProjectID,
		EnvironmentID:  d.EnvironmentID,
		ServiceID:      d.ServiceID,
		Source:         d.Source.String(),
		SourceRef:      d.SourceRef,
		Status:         d.Status.String(),
		RequestedBy:    d.RequestedBy,
		IdempotencyKey: d.IdempotencyKey,
		ErrorCode:      d.ErrorCode,
		ErrorMessage:   d.ErrorMessage,
		Version:        d.Version,
		RequestID:      d.RequestID,
		CorrelationID:  d.CorrelationID,
		CreatedAt:      d.CreatedAt,
		UpdatedAt:      d.UpdatedAt,
	}
	if d.StartedAt != nil {
		started := d.StartedAt.UTC().Format(time.RFC3339Nano)
		out.StartedAt = &started
	}
	if d.FinishedAt != nil {
		finished := d.FinishedAt.UTC().Format(time.RFC3339Nano)
		out.FinishedAt = &finished
	}
	return out
}

// createServiceDeploymentPayload is the data block of the POST
// /v1/services/{service_id}/deployments success envelope: the
// deployment that was created (or, on an idempotent retry, the
// previously persisted deployment that matched the supplied
// idempotency_key), in the same stable wire shape later GET endpoints
// will return.
type createServiceDeploymentPayload struct {
	Deployment serviceDeployment `json:"deployment"`
}

// createServiceDeploymentHandler builds the POST
// /v1/services/{service_id}/deployments handler. It decodes and
// delegates: the request body is strictly decoded (oversized,
// malformed, or unknown-field bodies become a typed 400 that never
// echoes the input), then the create-deployment unit of work — re-
// authorize, reserve quota, write the deployment, enqueue the
// provisioning job, append the audit record, all in one transaction —
// runs in the store layer through the DeploymentCreator port.
//
// RequireAuth gates the route on action deployment.create through
// serviceIDResolver before the handler runs and attaches the resolved
// principal, so a request that reaches the handler with no principal
// is a wiring error reported as a typed internal error.
// deployment.create is a CapDeploy action evaluated against the
// (principal home organization, {service_id}) resource, so the gate
// admits the principal's organization-wide deploy roles (owner,
// admin, developer, ci) and denies viewer (CapRead only), denies
// support (CapRead+CapSupport — support is a deliberate cross-tenant
// READ exception, never a deploy one). The path carries no parent
// project_id or environment_id, so the policy engine cannot pin those
// legs of the resource scope at authorization time — project-,
// environment-, and service-scoped grants are denied at the boundary
// by the engine's covers() rule (a grant scope that pins ProjectID
// cannot cover a resource scope that does not); principals whose only
// access is a scoped grant must use a parent-scoped route to address
// a service by its (project, environment, service) tuple.
//
// The handler resolves the organization id from the authenticated
// principal's home organization and the service id from the
// {service_id} PATH parameter — never from the request body — so the
// tenant boundary is structural here: there is no caller input that
// could point the write at another tenant. A cross-tenant service_id
// reaches the persistence layer with the principal's home
// organization id and is rejected as a deterministic 404 by the
// store-layer's tenant-scoped service existence check (the same
// property GET /v1/services/{service_id} inherits), never disguised as
// a 200 or a 403 that would confirm the foreign service's existence.
// The principal and the request correlation identifiers are passed to
// the creator so the audit record names the actor; a validation
// failure, an idempotency-key shape error, an exhausted quota, a
// denied in-tx authorize, and a datastore outage each surface as
// their own typed status, never disguised as one another.
func createServiceDeploymentHandler(creator DeploymentCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if creator == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoDeploymentCreator))
			return
		}

		var req createServiceDeploymentRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		// OrganizationID is taken from the principal's home org (never
		// the caller — the request body carries no organization id),
		// so a cross-tenant service_id still hits the tenant-scoped
		// repository query and surfaces as a 404 at the persistence
		// boundary.
		deployment, err := creator.Create(r.Context(), store.CreateDeploymentInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
			Source:         store.DeploymentSource(req.Source),
			SourceRef:      req.SourceRef,
			IdempotencyKey: req.IdempotencyKey,
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

		apienvelope.WriteData(w, http.StatusAccepted, requestID(r), createServiceDeploymentPayload{
			Deployment: serviceDeploymentOf(deployment),
		})
	}
}
