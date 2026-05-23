package reconcile_test

import (
	"context"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/reconcile"
)

// BE-0302: Verify application-git drift reconciliation.
//
// This pins the application-git-specific safe drift that generic service
// tests cannot see: Dokploy build settings drifting away from Yalla's git
// source of truth. Branches and commits can identify private repos or deploy
// cadence, so classification remains value-free while the desired build spec
// is routed only to the Repairer port.
func TestApplicationGitReconcileRepairsChangedBuildConfig(t *testing.T) {
	t.Parallel()
	const desiredCommit = "deadbeefcafebabe"
	const actualCommit = "stalecommitcafebabe"

	state := simpleDesired()
	state.Projects[0].Environments[0].Services[0].Build = dokploy.BuildSettings{
		Builder:        dokploy.BuilderDockerfile,
		DockerfilePath: "deploy/Dockerfile",
		GitBranch:      "main",
		GitCommit:      desiredCommit,
	}
	desired := &fakeDesiredReader{state: state}

	actualState := simpleActual()
	actualState.Projects[0].Environments[0].Services[0].Build = dokploy.BuildSettings{
		Builder:        dokploy.BuilderDockerfile,
		DockerfilePath: "Dockerfile",
		GitBranch:      "staging",
		GitCommit:      actualCommit,
	}
	actual := &fakeActualReader{state: actualState}

	repairer := &fakeRepairer{}
	reviewer := &fakeReviewer{}
	unmanaged := &fakeUnmanaged{}
	rec := newReconciler(t, &reconcile.Config{
		Desired: desired, Actual: actual,
		Repairer: repairer, Reviewer: reviewer, Unmanaged: unmanaged,
	})

	res, err := rec.Reconcile(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	if res.Repaired != 1 || res.Reviewed != 0 || res.Quarantined != 0 || len(res.Failures) != 0 {
		t.Fatalf("result = %+v; want exactly one repair", res)
	}
	if len(repairer.buildCalls) != 1 {
		t.Fatalf("repairer.buildCalls = %+v; want one build config repair", repairer.buildCalls)
	}
	call := repairer.buildCalls[0]
	if call.Build.Builder != dokploy.BuilderDockerfile ||
		call.Build.DockerfilePath != "deploy/Dockerfile" ||
		call.Build.GitBranch != "main" ||
		call.Build.GitCommit != desiredCommit {
		t.Errorf("build repair = %+v; want desired application-git build settings", call.Build)
	}
	if call.Ref.DokployServiceID != "dokploy-svc-app" {
		t.Errorf("repair target = %q; want dokploy-svc-app", call.Ref.DokployServiceID)
	}
	if reviewer.calls != 0 {
		t.Errorf("reviewer was called for safe application-git build drift")
	}
	if unmanaged.calls != 0 {
		t.Errorf("unmanaged recorder was called for managed application-git drift")
	}

	plan, err := rec.Plan(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("plan.Actions = %+v; want one action", plan.Actions)
	}
	action := plan.Actions[0]
	if action.Kind != reconcile.DriftSafe ||
		action.Type != reconcile.ActionUpdateBuildConfig ||
		action.Reason != reconcile.ReasonBuildConfigChanged {
		t.Fatalf("classification = %q/%q/%q; want safe/update_build_config/build_config_changed",
			action.Kind, action.Type, action.Reason)
	}
	classification := strings.Join([]string{
		string(action.Kind),
		string(action.Type),
		string(action.Reason),
		action.EnvVarKey,
		string(action.Service.ServiceID),
	}, "|")
	for _, leaked := range []string{desiredCommit, actualCommit, "staging", "deploy/Dockerfile"} {
		if strings.Contains(classification, leaked) {
			t.Fatalf("classification leaked build config value %q in %q", leaked, classification)
		}
	}
}

func TestApplicationGitReconcileDriftClassificationMatrix(t *testing.T) {
	t.Parallel()
	appGitBuild := dokploy.BuildSettings{
		Builder:        dokploy.BuilderDockerfile,
		DockerfilePath: "deploy/Dockerfile",
		GitBranch:      "main",
		GitCommit:      "deadbeefcafebabe",
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
			name: "changed upstream build config is safe repair",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services[0].Build.GitBranch = "staging"
			},
			repaired:   1,
			wantKind:   reconcile.DriftSafe,
			wantType:   reconcile.ActionUpdateBuildConfig,
			wantReason: reconcile.ReasonBuildConfigChanged,
		},
		{
			name: "missing managed domain is safe ensure",
			mutate: func(desired *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				desired.Projects[0].Environments[0].Services[0].Domains = []reconcile.DesiredDomain{{
					ID:        domain.MustNewID(domain.KindService),
					Host:      "app.example.test",
					HTTPS:     true,
					DokployID: "dokploy-dom-app",
				}}
				actual.Projects[0].Environments[0].Services[0].Domains = nil
			},
			repaired:   1,
			wantKind:   reconcile.DriftSafe,
			wantType:   reconcile.ActionEnsureDomain,
			wantReason: reconcile.ReasonDomainMissing,
		},
		{
			name: "unmanaged extra resource is quarantined",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services = append(
					actual.Projects[0].Environments[0].Services,
					reconcile.ActualService{
						DokployID: "dokploy-svc-rogue",
						Name:      "rogue",
						Type:      dokploy.ServiceApplication,
						Build:     appGitBuild,
					},
				)
			},
			quarantine: 1,
			wantKind:   reconcile.DriftUnmanaged,
			wantType:   reconcile.ActionMarkUnmanaged,
			wantReason: reconcile.ReasonResourceUnmanaged,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			desiredState := simpleDesired()
			desiredState.Projects[0].Environments[0].Services[0].Build = appGitBuild
			actualState := simpleActual()
			actualState.Projects[0].Environments[0].Services[0].Build = appGitBuild
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
