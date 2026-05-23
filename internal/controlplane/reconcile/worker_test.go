package reconcile_test

import (
	"context"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/reconcile"
)

// BE-0320: Verify worker drift reconciliation.
//
// Worker services are role-scoped service subtypes. They may be implemented
// as application or compose services, but a drift from worker to web/cron
// changes runtime semantics and must be reviewed before ordinary safe repairs
// are considered.
func TestWorkerReconcileQuarantinesRoleDriftBeforeSafeRepairs(t *testing.T) {
	t.Parallel()
	const desiredBranch = "private-worker-main"
	const actualBranch = "private-worker-stale"

	state := simpleDesired()
	state.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceApplication
	state.Projects[0].Environments[0].Services[0].Role = dokploy.RoleWorker
	state.Projects[0].Environments[0].Services[0].Build = dokploy.BuildSettings{
		Builder:   dokploy.BuilderNixpacks,
		GitBranch: desiredBranch,
		GitCommit: "feedfacecafebeef",
	}

	actualState := simpleActual()
	actualState.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceApplication
	actualState.Projects[0].Environments[0].Services[0].Role = dokploy.RoleCron
	actualState.Projects[0].Environments[0].Services[0].Build = dokploy.BuildSettings{
		Builder:   dokploy.BuilderNixpacks,
		GitBranch: actualBranch,
		GitCommit: "stalecommitcafebabe",
	}

	repairer := &fakeRepairer{}
	reviewer := &fakeReviewer{}
	unmanaged := &fakeUnmanaged{}
	rec := newReconciler(t, &reconcile.Config{
		Desired:   &fakeDesiredReader{state: state},
		Actual:    &fakeActualReader{state: actualState},
		Repairer:  repairer,
		Reviewer:  reviewer,
		Unmanaged: unmanaged,
	})

	res, err := rec.Reconcile(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	if res.Repaired != 0 || res.Reviewed != 1 || res.Quarantined != 0 || len(res.Failures) != 0 {
		t.Fatalf("result = %+v; want exactly one dangerous review", res)
	}
	if len(repairer.buildCalls) != 0 || len(repairer.envCalls) != 0 || len(repairer.domainCalls) != 0 {
		t.Fatalf("repairer was called for role drift: build=%+v env=%+v domain=%+v",
			repairer.buildCalls, repairer.envCalls, repairer.domainCalls)
	}
	if unmanaged.calls != 0 {
		t.Errorf("unmanaged recorder was called for managed worker role drift")
	}

	plan, err := rec.Plan(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("plan.Actions = %+v; want one role-review action", plan.Actions)
	}
	action := plan.Actions[0]
	if action.Kind != reconcile.DriftDangerous ||
		action.Type != reconcile.ActionReviewServiceRoleChange ||
		action.Reason != reconcile.ReasonServiceRoleChanged {
		t.Fatalf("classification = %q/%q/%q; want dangerous/review_service_role_change/service_role_changed",
			action.Kind, action.Type, action.Reason)
	}
	classification := strings.Join([]string{
		string(action.Kind),
		string(action.Type),
		string(action.Reason),
		action.EnvVarKey,
		string(action.Service.ServiceID),
	}, "|")
	for _, leaked := range []string{desiredBranch, actualBranch, "feedfacecafebeef"} {
		if strings.Contains(classification, leaked) {
			t.Fatalf("classification leaked worker build value %q in %q", leaked, classification)
		}
	}
}

func TestWorkerReconcileDriftClassificationMatrix(t *testing.T) {
	t.Parallel()
	workerBuild := dokploy.BuildSettings{
		Builder:   dokploy.BuilderNixpacks,
		GitBranch: "main",
		GitCommit: "feedfacecafebeef",
	}
	cases := []struct {
		name       string
		mutate     func(desired *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization)
		repaired   int
		reviewed   int
		quarantine int
		wantKind   reconcile.DriftKind
		wantType   reconcile.ActionType
		wantReason reconcile.DriftReason
	}{
		{
			name: "deleted upstream resource is dangerous review",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services = filterActual(
					actual.Projects[0].Environments[0].Services,
					func(s reconcile.ActualService) bool { return s.DokployID != "dokploy-svc-app" },
				)
			},
			reviewed:   1,
			wantKind:   reconcile.DriftDangerous,
			wantType:   reconcile.ActionReviewMissingService,
			wantReason: reconcile.ReasonServiceMissing,
		},
		{
			name: "changed upstream worker config is safe repair",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services[0].Build.GitBranch = "staging"
			},
			repaired:   1,
			wantKind:   reconcile.DriftSafe,
			wantType:   reconcile.ActionUpdateBuildConfig,
			wantReason: reconcile.ReasonBuildConfigChanged,
		},
		{
			name: "role drift is dangerous review only",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services[0].Role = dokploy.RoleCron
				actual.Projects[0].Environments[0].Services[0].Build.GitBranch = "staging"
			},
			reviewed:   1,
			wantKind:   reconcile.DriftDangerous,
			wantType:   reconcile.ActionReviewServiceRoleChange,
			wantReason: reconcile.ReasonServiceRoleChanged,
		},
		{
			name: "unmanaged extra resource is quarantined",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services = append(
					actual.Projects[0].Environments[0].Services,
					reconcile.ActualService{
						DokployID: "dokploy-svc-rogue-worker",
						Name:      "rogue-worker",
						Type:      dokploy.ServiceApplication,
						Role:      dokploy.RoleWorker,
						Build:     workerBuild,
					},
				)
			},
			quarantine: 1,
			wantKind:   reconcile.DriftUnmanaged,
			wantType:   reconcile.ActionMarkUnmanaged,
			wantReason: reconcile.ReasonResourceUnmanaged,
		},
		{
			name: "changed service type is dangerous review only",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceDatabase
				actual.Projects[0].Environments[0].Services[0].Engine = "postgres"
				actual.Projects[0].Environments[0].Services[0].Build.GitBranch = "staging"
			},
			reviewed:   1,
			wantKind:   reconcile.DriftDangerous,
			wantType:   reconcile.ActionReviewServiceTypeChange,
			wantReason: reconcile.ReasonServiceTypeChanged,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			desiredState := simpleDesired()
			desiredState.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceApplication
			desiredState.Projects[0].Environments[0].Services[0].Role = dokploy.RoleWorker
			desiredState.Projects[0].Environments[0].Services[0].Build = workerBuild
			actualState := simpleActual()
			actualState.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceApplication
			actualState.Projects[0].Environments[0].Services[0].Role = dokploy.RoleWorker
			actualState.Projects[0].Environments[0].Services[0].Build = workerBuild
			tc.mutate(&desiredState, &actualState)

			repairer := &fakeRepairer{}
			reviewer := &fakeReviewer{}
			unmanaged := &fakeUnmanaged{}
			rec := newReconciler(t, &reconcile.Config{
				Desired:   &fakeDesiredReader{state: desiredState},
				Actual:    &fakeActualReader{state: actualState},
				Repairer:  repairer,
				Reviewer:  reviewer,
				Unmanaged: unmanaged,
			})
			res, err := rec.Reconcile(context.Background(), validOrgID)
			if err != nil {
				t.Fatalf("Reconcile error: %v", err)
			}
			if res.Repaired != tc.repaired || res.Reviewed != tc.reviewed ||
				res.Quarantined != tc.quarantine || len(res.Failures) != 0 {
				t.Fatalf("result = %+v; want repaired=%d reviewed=%d quarantined=%d",
					res, tc.repaired, tc.reviewed, tc.quarantine)
			}

			plan, err := rec.Plan(context.Background(), validOrgID)
			if err != nil {
				t.Fatalf("Plan error: %v", err)
			}
			if len(plan.Actions) != 1 {
				t.Fatalf("plan.Actions = %+v; want one action", plan.Actions)
			}
			action := plan.Actions[0]
			if action.Kind != tc.wantKind || action.Type != tc.wantType || action.Reason != tc.wantReason {
				t.Fatalf("classification = %q/%q/%q; want %q/%q/%q",
					action.Kind, action.Type, action.Reason,
					tc.wantKind, tc.wantType, tc.wantReason)
			}
		})
	}
}

func TestWorkerReconcileDoesNotBindMissingDomain(t *testing.T) {
	t.Parallel()
	state := simpleDesired()
	state.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceApplication
	state.Projects[0].Environments[0].Services[0].Role = dokploy.RoleWorker
	state.Projects[0].Environments[0].Services[0].Build = dokploy.BuildSettings{
		Builder:   dokploy.BuilderNixpacks,
		GitBranch: "main",
		GitCommit: "feedfacecafebeef",
	}
	state.Projects[0].Environments[0].Services[0].Domains = []reconcile.DesiredDomain{{
		ID:        domain.MustNewID(domain.KindService),
		Host:      "worker-should-not-bind.example.test",
		HTTPS:     true,
		DokployID: "dokploy-dom-worker",
	}}

	actualState := simpleActual()
	actualState.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceApplication
	actualState.Projects[0].Environments[0].Services[0].Role = dokploy.RoleWorker
	actualState.Projects[0].Environments[0].Services[0].Build = state.Projects[0].Environments[0].Services[0].Build
	actualState.Projects[0].Environments[0].Services[0].Domains = nil

	rec := newReconciler(t, &reconcile.Config{
		Desired:   &fakeDesiredReader{state: state},
		Actual:    &fakeActualReader{state: actualState},
		Repairer:  &fakeRepairer{},
		Reviewer:  &fakeReviewer{},
		Unmanaged: &fakeUnmanaged{},
	})

	plan, err := rec.Plan(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if !plan.IsEmpty() {
		t.Fatalf("worker missing-domain plan = %+v; want empty because worker domains are web-only", plan.Actions)
	}
}
