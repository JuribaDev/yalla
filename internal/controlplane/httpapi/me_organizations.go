package httpapi

import (
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
)

// meOrganizationsPayload is the data block of the GET /v1/me/organizations
// success envelope: every organization the authenticated principal can see
// through the control plane, with the principal's authority in each one. Every
// field is a non-secret identifier, role name, or scope id — the endpoint
// never returns credential material, so the payload is safe to log and audit
// verbatim. Organizations is always a non-nil slice so agents can iterate it
// without a nil check.
type meOrganizationsPayload struct {
	Organizations []meOrganization `json:"organizations"`
}

// meOrganization is one organization in a meOrganizationsPayload: its id, the
// principal's organization-wide role within it (omitted when the principal has
// no role and is authorized purely by grants), and the scoped grants the
// principal holds inside it. The grants are echoed verbatim from the
// authenticated principal — never widened — so the endpoint can never report
// more authority than the policy engine would actually honour.
type meOrganization struct {
	// OrganizationID is the organization's domain id.
	OrganizationID string `json:"organization_id"`
	// Role is the principal's organization-wide role in this organization. It
	// is omitted when the principal has no organization role here.
	Role string `json:"role,omitempty"`
	// Grants are the principal's scoped grants confined to this organization.
	// It is always present (never null).
	Grants []meGrant `json:"grants"`
}

// principalOrganizationsPayload projects an authenticated policy.Principal into
// the stable GET /v1/me/organizations wire shape.
//
// A principal is bound to exactly one home organization, and every scoped grant
// it carries narrows or widens its authority *within* that organization — the
// policy engine denies any resource outside it (the lone support-read /
// break-glass exception never reaches this self endpoint). So the set of
// organizations a principal can see through its own credential is precisely its
// home organization: the response is a single-element list. The list shape is
// deliberate forward-compatibility — if a credential is ever allowed to span
// organizations, the contract already carries an array — but today it never
// fabricates a second entry, and a grant that somehow references a foreign
// organization is dropped rather than surfaced as a visible tenant.
func principalOrganizationsPayload(p policy.Principal) meOrganizationsPayload {
	orgs := make([]meOrganization, 0, 1)
	if p.OrganizationID != "" {
		// Confine the echoed grants to the home organization. In the current
		// single-organization principal model every grant already lives here;
		// the filter is defence-in-depth so a foreign-scoped grant can never be
		// presented as access to another tenant.
		homeGrants := make([]policy.Grant, 0, len(p.Grants))
		for _, g := range p.Grants {
			if g.Scope.OrganizationID == p.OrganizationID {
				homeGrants = append(homeGrants, g)
			}
		}
		orgs = append(orgs, meOrganization{
			OrganizationID: p.OrganizationID,
			Role:           string(p.Role),
			Grants:         meGrantsOf(homeGrants),
		})
	}
	return meOrganizationsPayload{Organizations: orgs}
}

// meOrganizationsHandler builds the GET /v1/me/organizations handler. It lists
// the organizations visible to the authenticated principal — resolved by
// RequireAuth and carried on the request context — without touching the
// database: a principal's visible organizations are fully determined by its own
// home organization and scoped grants, both established at authentication, so
// the read is pure and cannot reveal another tenant's data. RequireAuth gates
// the route on action auth.orgs before the handler runs, so a request that
// reaches the handler with no principal is a wiring error and is reported as a
// typed internal error rather than serving an empty list.
func meOrganizationsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), principalOrganizationsPayload(p))
	}
}
