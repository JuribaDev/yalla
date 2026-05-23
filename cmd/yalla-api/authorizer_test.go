package main

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/policy"
)

func TestPolicyStoreAuthorizerAllowsOwnerProjectCreate(t *testing.T) {
	t.Parallel()

	authz := policyStoreAuthorizer{engine: policy.NewEngine()}
	ctx := policy.WithPrincipal(context.Background(), policy.Principal{
		ID:             "usr_owner",
		OrganizationID: "org_1",
		Role:           policy.RoleOwner,
	})
	if err := authz.Authorize(ctx, nil, "project.create", "org_1"); err != nil {
		t.Fatalf("Authorize returned error: %v", err)
	}
}

func TestPolicyStoreAuthorizerDeniesViewerProjectCreate(t *testing.T) {
	t.Parallel()

	authz := policyStoreAuthorizer{engine: policy.NewEngine()}
	ctx := policy.WithPrincipal(context.Background(), policy.Principal{
		ID:             "usr_viewer",
		OrganizationID: "org_1",
		Role:           policy.RoleViewer,
	})
	if err := authz.Authorize(ctx, nil, "project.create", "org_1"); err == nil {
		t.Fatal("Authorize succeeded for viewer project.create, want denial")
	}
}

func TestPolicyStoreAuthorizerDeniesCrossTenantWrite(t *testing.T) {
	t.Parallel()

	authz := policyStoreAuthorizer{engine: policy.NewEngine()}
	ctx := policy.WithPrincipal(context.Background(), policy.Principal{
		ID:             "usr_owner",
		OrganizationID: "org_1",
		Role:           policy.RoleOwner,
	})
	if err := authz.Authorize(ctx, nil, "service.create", "org_2"); err == nil {
		t.Fatal("Authorize succeeded for cross-tenant service.create, want denial")
	}
}
