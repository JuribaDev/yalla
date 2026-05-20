package main

import (
	"context"
	"errors"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

type policyStoreAuthorizer struct {
	engine *policy.Engine
}

func (a policyStoreAuthorizer) Authorize(ctx context.Context, _ store.Querier, action, organizationID string) error {
	if a.engine == nil {
		return apierr.Internal(errors.New("policy store authorizer requires policy engine"))
	}
	action = strings.TrimSpace(action)
	orgID := strings.TrimSpace(organizationID)
	return a.engine.AuthorizeCtx(ctx, policy.Action(action), policy.Resource{
		Kind: resourceKindForAction(action),
		Scope: policy.Scope{
			OrganizationID: orgID,
		},
	})
}

func resourceKindForAction(action string) domain.Kind {
	switch {
	case strings.HasPrefix(action, "project."):
		return domain.KindProject
	case strings.HasPrefix(action, "environment."):
		return domain.KindEnvironment
	case strings.HasPrefix(action, "service."):
		return domain.KindService
	default:
		return domain.KindOrganization
	}
}
