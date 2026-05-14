package httpapi

import (
	"errors"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
)

// errNoPrincipalOnContext is returned when GET /v1/me runs without an
// authenticated principal on the request context. It can only happen if the
// route is wired without RequireAuth in front of it — a programming error, not
// a client error — so the handler reports it as a typed internal failure
// rather than serving a misleading identity body.
var errNoPrincipalOnContext = errors.New("httpapi: no principal on request context")

// mePayload is the data block of the GET /v1/me success envelope: the
// authenticated principal's own identity as the control plane sees it. Every
// field is a non-secret identifier, role name, or scope id — the endpoint
// never returns credential material, so the payload is safe to log and audit
// verbatim.
type mePayload struct {
	// PrincipalID is the principal's domain ID — a user or service-account id.
	PrincipalID string `json:"principal_id"`
	// Kind is the principal's domain kind: "usr" for a human, "sa" for
	// automation.
	Kind string `json:"kind"`
	// OrganizationID is the principal's home organization.
	OrganizationID string `json:"organization_id"`
	// Role is the principal's organization-wide role. It is omitted when the
	// principal has no organization role and is authorized purely by grants.
	Role string `json:"role,omitempty"`
	// Grants are the principal's scoped grants. It is always present (never
	// null) so agents can iterate it without a nil check.
	Grants []meGrant `json:"grants"`
	// Disabled reports whether the principal's access has been revoked.
	Disabled bool `json:"disabled"`
}

// meGrant is one scoped grant in a mePayload: the role it confers and the
// resource subtree it applies to. The deeper scope ids are omitted when the
// grant covers a wider subtree (an organization- or project-level grant).
type meGrant struct {
	Role           string `json:"role"`
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id,omitempty"`
	EnvironmentID  string `json:"environment_id,omitempty"`
	ServiceID      string `json:"service_id,omitempty"`
}

// principalPayload projects an authenticated policy.Principal into the stable
// GET /v1/me wire shape. Grants is always a non-nil slice so the rendered
// JSON carries [] rather than null when the principal holds no grants.
func principalPayload(p policy.Principal) mePayload {
	grants := make([]meGrant, 0, len(p.Grants))
	for _, g := range p.Grants {
		grants = append(grants, meGrant{
			Role:           string(g.Role),
			OrganizationID: g.Scope.OrganizationID,
			ProjectID:      g.Scope.ProjectID,
			EnvironmentID:  g.Scope.EnvironmentID,
			ServiceID:      g.Scope.ServiceID,
		})
	}
	return mePayload{
		PrincipalID:    p.ID,
		Kind:           string(p.Kind),
		OrganizationID: p.OrganizationID,
		Role:           string(p.Role),
		Grants:         grants,
		Disabled:       p.Disabled,
	}
}

// meHandler builds the GET /v1/me handler. It reports the identity of the
// authenticated principal — resolved by RequireAuth and carried on the request
// context — without touching the database: every field the endpoint returns
// is already established by authentication, so the read is pure and cannot
// reveal another tenant's data. RequireAuth gates the route on action
// auth.me before the handler runs, so a request that reaches the handler with
// no principal is a wiring error and is reported as a typed internal error.
func meHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), principalPayload(p))
	}
}
