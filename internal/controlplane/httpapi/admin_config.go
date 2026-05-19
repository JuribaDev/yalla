package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/backoffice"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

var errNoAdminConfigDryRunner = errors.New("httpapi: no admin config dry-run validator configured")

// AdminConfigDryRunner validates candidate backoffice runtime configuration
// before publish. It is deliberately narrower than the concrete backoffice
// validator so the HTTP layer owns only request/response mapping.
type AdminConfigDryRunner interface {
	Validate(ctx context.Context, in backoffice.DryRunInput) (backoffice.DryRunResult, error)
}

type adminConfigDryRunRequestBody struct {
	ConfigSetID             string                  `json:"config_set_id,omitempty"`
	Domain                  store.AdminConfigDomain `json:"domain"`
	Payload                 map[string]any          `json:"payload"`
	SimulateOrganizationIDs []string                `json:"simulate_organization_ids,omitempty"`
}

func dryRunAdminConfigHandler(runner AdminConfigDryRunner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if runner == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAdminConfigDryRunner))
			return
		}
		var body adminConfigDryRunRequestBody
		if err := validate.DecodeJSON(r.Body, &body, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		payload, err := marshalAdminConfigPayload(body.Payload)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		result, err := runner.Validate(r.Context(), backoffice.DryRunInput{
			ConfigSetID:             body.ConfigSetID,
			Domain:                  body.Domain,
			Payload:                 payload,
			SimulateOrganizationIDs: body.SimulateOrganizationIDs,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if result.Warnings == nil {
			result.Warnings = []backoffice.Issue{}
		}
		if result.BlockingErrors == nil {
			result.BlockingErrors = []backoffice.Issue{}
		}
		if result.SimulatedOrganizations == nil {
			result.SimulatedOrganizations = []backoffice.OrganizationImpact{}
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), result)
	}
}

func marshalAdminConfigPayload(payload map[string]any) ([]byte, error) {
	if payload == nil {
		return []byte(`{}`), nil
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, apierr.InvalidInput(apierr.FieldViolation{Field: "payload", Reason: "must be valid JSON"})
	}
	return out, nil
}
