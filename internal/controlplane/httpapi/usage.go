package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// errNoUsageReader is returned when GET /v1/organizations/{org_id}/usage is
// reached without a usage reader wired into NewHandler. Like
// errNoLimitsReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it as a
// typed internal failure rather than serving an empty or misleading list.
var errNoUsageReader = errors.New("httpapi: no usage reader configured")

// UsageReader is the narrow persistence port GET
// /v1/organizations/{org_id}/usage depends on. *store.UsageReader satisfies
// it in production; tests supply a fake. Keeping the dependency an
// interface keeps the handler unit-testable without a real database, the
// same way LimitsReader does for the limits endpoint.
//
// The read is tenant scoped at the persistence layer: the repository
// filters by organization_id for both the policy and the usage leg of the
// resolution, so a cross-tenant {org_id} simply matches no rows and yields
// an empty list, never another organization's counters. The
// organizationIDResolver this route uses authorizes the call against the
// {org_id} path parameter before the handler runs, so a cross-tenant id is
// rejected as a 403 long before this port is reached (with the support
// principal's deliberate cross-tenant read exception preserved by the
// policy engine, exactly as the matrix specifies for CapRead actions).
type UsageReader interface {
	ListOrganizationUsage(ctx context.Context, organizationID string) ([]store.OrganizationResourceUsage, error)
}

// listUsagePayload is the data block of the GET
// /v1/organizations/{org_id}/usage success envelope: one entry per resource
// that has either a live usage counter for the organization or a configured
// limit at the tenant's scope, in deterministic resource order. Usage is
// always a non-nil slice so agents can iterate it without a nil check;
// resources with neither a counter nor a configured limit are omitted.
type listUsagePayload struct {
	Period         *periodResource `json:"period,omitempty"`
	Usage          []resourceUsage `json:"usage"`
	TrendSummaries []usageTrend    `json:"trend_summaries"`
}

// resourceUsage is one entry in a listUsagePayload: the current usage of a
// resource dimension paired with the effective limit (when any is
// configured at all). UsedValue is the live counter — zero when no
// reservation has materialized the counter row yet — and Limit is the
// effective limit projection: nil marks the dimension as unconstrained (no
// plan default and no organization override), exactly the same semantics
// the limits endpoint uses when it omits a resource. None of the fields
// carries credential material: quota dimensions, counts, and ceilings are
// not sensitive.
type resourceUsage struct {
	Resource          string            `json:"resource"`
	UsedValue         int64             `json:"used_value"`
	Limit             *resourceUsageCap `json:"limit"`
	WarningThresholds []int             `json:"warning_thresholds"`
}

type usageTrend struct {
	Resource string `json:"resource"`
	Window   string `json:"window"`
	Delta    int64  `json:"delta"`
}

var envelopeWarningResources = map[store.QuotaResource]struct{}{
	store.QuotaResourceHTTPBandwidthTotal:   {},
	store.QuotaResourceHTTPRequests:         {},
	store.QuotaResourceBuildMinutes:         {},
	store.QuotaResourceBackupStorageGBMonth: {},
	store.QuotaResourceMonthlyDeployments:   {},
}

// resourceUsageCap is the limit half of a resourceUsage: the numeric
// ceiling, the enforcement mode, and the source scope that produced the
// value. The three fields always travel together — they are projected from
// the same effective-limit row — so they are nested under a single nullable
// object on the wire rather than spread across three coupled-nullable
// fields, which keeps "limit configured or not" a single boolean for an
// agent reading the response. EnforcementMode is one of hard, soft, metered,
// or disabled — the same closed set the database enforces through the
// quota_enforcement_mode domain — and Source is one of "plan_default" or
// "organization", verbatim from quota_policies.scope_kind.
type resourceUsageCap struct {
	LimitValue      int64  `json:"limit_value"`
	EnforcementMode string `json:"enforcement_mode"`
	Source          string `json:"source"`
}

// resourceUsageOf projects a store.OrganizationResourceUsage into the
// stable wire shape. The wire field names are the stable contract; the
// persistence shape can evolve without changing the response.
func resourceUsageOf(u store.OrganizationResourceUsage) resourceUsage {
	out := resourceUsage{
		Resource:          u.Resource.String(),
		UsedValue:         u.UsedValue,
		WarningThresholds: []int{},
	}
	if u.LimitValue != nil && u.EnforcementMode != nil && u.Scope != nil {
		out.Limit = &resourceUsageCap{
			LimitValue:      *u.LimitValue,
			EnforcementMode: string(*u.EnforcementMode),
			Source:          string(*u.Scope),
		}
		out.WarningThresholds = warningThresholds(u.WarningThresholds, *u.LimitValue)
	}
	return out
}

func usageEnvelopeWarnings(usage []store.OrganizationResourceUsage) []apienvelope.Warning {
	warnings := make([]apienvelope.Warning, 0)
	for _, row := range usage {
		if _, ok := envelopeWarningResources[row.Resource]; !ok {
			continue
		}
		if row.LimitValue == nil || *row.LimitValue <= 0 || row.EnforcementMode == nil || *row.EnforcementMode == store.EnforcementModeDisabled {
			continue
		}
		thresholds := warningThresholds(row.WarningThresholds, *row.LimitValue)
		threshold := highestReachedThreshold(row.UsedValue, *row.LimitValue, thresholds)
		if threshold == 0 {
			continue
		}
		code := "ENTITLEMENT_THRESHOLD_WARNING"
		message := fmt.Sprintf("%s usage reached %d%% of its configured limit", row.Resource, threshold)
		if row.UsedValue >= *row.LimitValue {
			code = "ENTITLEMENT_LIMIT_EXCEEDED"
			message = fmt.Sprintf("%s usage exceeded its configured limit", row.Resource)
		}
		warning := apienvelope.Warning{
			Code:           code,
			Message:        message,
			EntitlementKey: row.Resource.String(),
			Usage:          row.UsedValue,
			Threshold:      threshold,
			Limit:          *row.LimitValue,
			Hint:           "reduce usage before the period resets or upgrade the organization's entitlement",
		}
		if row.PeriodStart != nil && row.PeriodEnd != nil {
			warning.Period = warningPeriodOf(*row.PeriodStart, *row.PeriodEnd)
		}
		warnings = append(warnings, warning)
	}
	return warnings
}

func highestReachedThreshold(used, limit int64, thresholds []int) int {
	if limit <= 0 || used <= 0 {
		return 0
	}
	highest := 0
	for _, threshold := range thresholds {
		if threshold <= 0 {
			continue
		}
		if threshold > 100 {
			threshold = 100
		}
		if used*100 >= limit*int64(threshold) && threshold > highest {
			highest = threshold
		}
	}
	return highest
}

func warningPeriodOf(start, end time.Time) *apienvelope.WarningPeriod {
	return &apienvelope.WarningPeriod{
		Kind:  "billing_period",
		Start: start.UTC().Format(time.RFC3339),
		End:   end.UTC().Format(time.RFC3339),
	}
}

// listUsageHandler builds the GET /v1/organizations/{org_id}/usage handler.
// It reads the current usage counters of the organization named by the
// {org_id} path parameter, joined with the effective limit for each
// resource — resolved as "organization override if present, else plan
// default" — from the source-of-truth database through the UsageReader
// port, and renders them in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action limits.read before the handler
// runs — authorized through organizationIDResolver against the organization
// the path names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the tenant boundary: a
// cross-tenant {org_id} was rejected as a 403 by the policy engine, never
// reaching this code. A request that arrives here with no principal is
// therefore a wiring error and is reported as a typed internal error
// rather than reading for a zero principal. A reader-store outage surfaces
// as its own typed 5xx, and an {org_id} with no configured policies and
// no usage rows is a deterministic empty list — the usage read has no
// "not found" path of its own, mirroring every list endpoint.
func listUsageHandler(reader UsageReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoUsageReader))
			return
		}

		usage, err := reader.ListOrganizationUsage(r.Context(), r.PathValue("org_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		resources := make([]resourceUsage, 0, len(usage))
		var period *periodResource
		for _, u := range usage {
			if period == nil && u.PeriodStart != nil && u.PeriodEnd != nil {
				period = periodOf(*u.PeriodStart, *u.PeriodEnd)
			}
			resources = append(resources, resourceUsageOf(u))
		}

		apienvelope.WriteDataWithWarnings(w, http.StatusOK, requestID(r), listUsagePayload{
			Period:         period,
			Usage:          resources,
			TrendSummaries: []usageTrend{},
		}, usageEnvelopeWarnings(usage))
	}
}
