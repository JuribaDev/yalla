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

// errNoDeploymentRollbacker is returned when POST
// /v1/services/{service_id}/rollback is reached without a
// DeploymentRollbacker wired into NewHandler. It can only happen
// through a wiring error — a programming mistake, not a client error —
// so the handler reports it as a typed internal failure rather than
// serving a misleading 2xx with no side effect.
var errNoDeploymentRollbacker = errors.New("httpapi: no deployment rollbacker configured")

// DeploymentRollbacker is the narrow persistence port POST
// /v1/services/{service_id}/rollback depends on.
// *store.DeploymentService satisfies it in production; tests supply a
// fake. Keeping the dependency an interface keeps the handler
// unit-testable without a real database — the concrete orchestrator
// (the parent-service existence check, the idempotency short-circuit,
// the in-tx authorize, the target-deployment lookup constrained by
// (organization, service) and lifecycle status, the quota reservation
// against concurrent_deployments, the desired-state write copying the
// target's source / source_ref, the provisioning-job enqueue, and the
// audit append, all in one transaction) lives in the store layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action deployment.rollback against the
// (principal home organization, {service_id}) resource the path names
// through serviceIDResolver, so a request that reaches the rollbacker
// has already cleared the policy boundary. The store layer still
// re-authorizes inside the same *Tx as the desired-state write —
// defense-in-depth against a grant change that landed between the
// HTTP authorize and the rollback row write.
type DeploymentRollbacker interface {
	Rollback(ctx context.Context, in store.RollbackDeploymentInput) (store.Deployment, error)
}

// rollbackServiceDeploymentRequest is the decoded POST
// /v1/services/{service_id}/rollback request body. TargetDeploymentID
// names the previously persisted terminal-succeeded deployment whose
// source / source_ref the new rollback deployment will copy verbatim —
// the target MUST belong to the same (organization, service) as the
// service the path names, otherwise the store layer reports a typed
// NotFound rather than disclose cross-service deployment ids.
// IdempotencyKey is required — a retried POST with the same key
// returns the previously persisted rollback deployment verbatim, so a
// network hiccup never produces a duplicate Dokploy provisioning job.
//
// The request body intentionally exposes no organization_id,
// project_id, environment_id, or service_id field: the organization is
// derived from the authenticated principal's home organization, the
// service comes from the {service_id} PATH parameter, and the new
// deployment inherits its parent service's project_id and
// environment_id from the persisted row — there is no caller-supplied
// parameter that could redirect the rollback at another tenant,
// another project, or another environment. Every field is validated
// in the store-layer unit of work before any database write, so an
// invalid request never opens a transaction — and the request body
// never carries credential material.
type rollbackServiceDeploymentRequest struct {
	TargetDeploymentID string `json:"target_deployment_id"`
	IdempotencyKey     string `json:"idempotency_key"`
}

// rollbackServiceDeploymentPayload is the data block of the POST
// /v1/services/{service_id}/rollback success envelope: the new
// deployment that was created (or, on an idempotent retry, the
// previously persisted rollback deployment that matched the supplied
// idempotency_key), in the same stable wire shape every other
// deployment endpoint returns. The new deployment's source and
// source_ref fields are the values the rollback unit of work copied
// verbatim from the persisted target deployment row, so the response
// shape is byte-identical to a fresh-create response and an agent
// does not need to re-parse a different shape to address the rollback
// deployment by id later.
type rollbackServiceDeploymentPayload struct {
	Deployment serviceDeployment `json:"deployment"`
}

// rollbackServiceDeploymentHandler builds the POST
// /v1/services/{service_id}/rollback handler. It decodes and
// delegates: the request body is strictly decoded (oversized,
// malformed, or unknown-field bodies become a typed 400 that never
// echoes the input), then the rollback-deployment unit of work —
// parent-service existence check, idempotency short-circuit,
// re-authorize, target-deployment lookup with service / status
// constraints, reserve quota, write the deployment, enqueue the
// provisioning job, append the audit record, all in one transaction —
// runs in the store layer through the DeploymentRollbacker port.
//
// RequireAuth gates the route on action deployment.rollback through
// serviceIDResolver before the handler runs and attaches the resolved
// principal, so a request that reaches the handler with no principal
// is a wiring error reported as a typed internal error.
// deployment.rollback is a CapDeploy action evaluated against the
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
// property GET /v1/services/{service_id} inherits), never disguised
// as a 200 or a 403 that would confirm the foreign service's
// existence. A target_deployment_id that belongs to ANOTHER tenant —
// or to a different service in the same tenant — is also reported as
// 404, never disguised as a 200 that would let a caller probe for
// cross-service deployment ids through this endpoint. A target in any
// non-succeeded lifecycle state ('queued', 'running', 'failed',
// 'cancelled', or 'rolled_back') is rejected as a deterministic 409 —
// a rollback target must be a known-good deployment. The principal
// and the request correlation identifiers are passed to the
// rollbacker so the audit record names the actor.
func rollbackServiceDeploymentHandler(rollbacker DeploymentRollbacker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if rollbacker == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoDeploymentRollbacker))
			return
		}

		var req rollbackServiceDeploymentRequest
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
		deployment, err := rollbacker.Rollback(r.Context(), store.RollbackDeploymentInput{
			OrganizationID:     p.OrganizationID,
			ServiceID:          r.PathValue("service_id"),
			TargetDeploymentID: req.TargetDeploymentID,
			IdempotencyKey:     req.IdempotencyKey,
			ActorID:            p.ID,
			ActorKind:          string(p.Kind),
			ActorOrgID:         p.OrganizationID,
			RequestID:          correlation.RequestID,
			CorrelationID:      correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusAccepted, requestID(r), rollbackServiceDeploymentPayload{
			Deployment: serviceDeploymentOf(deployment),
		})
	}
}
