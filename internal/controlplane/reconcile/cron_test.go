package reconcile_test

import (
	"context"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/reconcile"
)

// BE-0322: Verify cron drift reconciliation.
//
// Cron services are role-scoped service subtypes. They run application or
// compose services on a schedule and must never receive web-domain repairs.
// Schedule drift is safe and idempotent to repair, while role/type drift is
// dangerous because it changes runtime semantics.
func TestCronReconcileRepairsScheduleDriftWithoutLeakingScheduleValues(t *testing.T) {
	t.Parallel()
	const desiredSchedule = "0 2 * * *"
	const actualSchedule = "15 3 * * *"

	state := simpleDesired()
	state.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceApplication
	state.Projects[0].Environments[0].Services[0].Role = dokploy.RoleCron
	state.Projects[0].Environments[0].Services[0].CronSchedule = desiredSchedule
	state.Projects[0].Environments[0].Services[0].Build = dokploy.BuildSettings{
		Builder:   dokploy.BuilderNixpacks,
		GitBranch: "main",
		GitCommit: "feedfacecafebeef",
	}

	actualState := simpleActual()
	actualState.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceApplication
	actualState.Projects[0].Environments[0].Services[0].Role = dokploy.RoleCron
	actualState.Projects[0].Environments[0].Services[0].CronSchedule = actualSchedule
	actualState.Projects[0].Environments[0].Services[0].Build = state.Projects[0].Environments[0].Services[0].Build

	repairer := &fakeRepairer{}
	rec := newReconciler(t, &reconcile.Config{
		Desired:   &fakeDesiredReader{state: state},
		Actual:    &fakeActualReader{state: actualState},
		Repairer:  repairer,
		Reviewer:  &fakeReviewer{},
		Unmanaged: &fakeUnmanaged{},
	})

	res, err := rec.Reconcile(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Reconcile error: %v", err)
	}
	if res.Repaired != 1 || res.Reviewed != 0 || res.Quarantined != 0 || len(res.Failures) != 0 {
		t.Fatalf("result = %+v; want exactly one safe repair", res)
	}
	if len(repairer.cronCalls) != 1 {
		t.Fatalf("cron repair calls = %+v; want one call", repairer.cronCalls)
	}
	if repairer.cronCalls[0].Schedule != desiredSchedule {
		t.Fatalf("cron repair schedule = %q, want desired schedule %q", repairer.cronCalls[0].Schedule, desiredSchedule)
	}

	plan, err := rec.Plan(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("plan.Actions = %+v; want one cron-schedule repair", plan.Actions)
	}
	action := plan.Actions[0]
	if action.Kind != reconcile.DriftSafe ||
		action.Type != reconcile.ActionUpdateCronSchedule ||
		action.Reason != reconcile.ReasonCronScheduleChanged {
		t.Fatalf("classification = %q/%q/%q; want safe/update_cron_schedule/cron_schedule_changed",
			action.Kind, action.Type, action.Reason)
	}
	classification := strings.Join([]string{
		string(action.Kind),
		string(action.Type),
		string(action.Reason),
		action.EnvVarKey,
		string(action.Service.ServiceID),
	}, "|")
	for _, leaked := range []string{desiredSchedule, actualSchedule} {
		if strings.Contains(classification, leaked) {
			t.Fatalf("classification leaked cron schedule %q in %q", leaked, classification)
		}
	}
}

func TestCronReconcileDriftClassificationMatrix(t *testing.T) {
	t.Parallel()
	cronBuild := dokploy.BuildSettings{
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
			name: "changed upstream cron schedule is safe repair",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services[0].CronSchedule = "15 3 * * *"
			},
			repaired:   1,
			wantKind:   reconcile.DriftSafe,
			wantType:   reconcile.ActionUpdateCronSchedule,
			wantReason: reconcile.ReasonCronScheduleChanged,
		},
		{
			name: "role drift is dangerous review only",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services[0].Role = dokploy.RoleWorker
				actual.Projects[0].Environments[0].Services[0].CronSchedule = "15 3 * * *"
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
						DokployID:    "dokploy-svc-rogue-cron",
						Name:         "rogue-cron",
						Type:         dokploy.ServiceApplication,
						Role:         dokploy.RoleCron,
						CronSchedule: "0 4 * * *",
						Build:        cronBuild,
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
				actual.Projects[0].Environments[0].Services[0].CronSchedule = "15 3 * * *"
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
			desiredState.Projects[0].Environments[0].Services[0].Role = dokploy.RoleCron
			desiredState.Projects[0].Environments[0].Services[0].CronSchedule = "0 2 * * *"
			desiredState.Projects[0].Environments[0].Services[0].Build = cronBuild
			actualState := simpleActual()
			actualState.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceApplication
			actualState.Projects[0].Environments[0].Services[0].Role = dokploy.RoleCron
			actualState.Projects[0].Environments[0].Services[0].CronSchedule = "0 2 * * *"
			actualState.Projects[0].Environments[0].Services[0].Build = cronBuild
			tc.mutate(&desiredState, &actualState)

			repairer := &fakeRepairer{}
			rec := newReconciler(t, &reconcile.Config{
				Desired:   &fakeDesiredReader{state: desiredState},
				Actual:    &fakeActualReader{state: actualState},
				Repairer:  repairer,
				Reviewer:  &fakeReviewer{},
				Unmanaged: &fakeUnmanaged{},
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

func TestCronReconcileDoesNotBindMissingDomain(t *testing.T) {
	t.Parallel()
	state := simpleDesired()
	state.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceApplication
	state.Projects[0].Environments[0].Services[0].Role = dokploy.RoleCron
	state.Projects[0].Environments[0].Services[0].CronSchedule = "0 2 * * *"
	state.Projects[0].Environments[0].Services[0].Build = dokploy.BuildSettings{
		Builder:   dokploy.BuilderNixpacks,
		GitBranch: "main",
		GitCommit: "feedfacecafebeef",
	}
	state.Projects[0].Environments[0].Services[0].Domains = []reconcile.DesiredDomain{{
		ID:        domain.MustNewID(domain.KindService),
		Host:      "cron-should-not-bind.example.test",
		HTTPS:     true,
		DokployID: "dokploy-dom-cron",
	}}

	actualState := simpleActual()
	actualState.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceApplication
	actualState.Projects[0].Environments[0].Services[0].Role = dokploy.RoleCron
	actualState.Projects[0].Environments[0].Services[0].CronSchedule = state.Projects[0].Environments[0].Services[0].CronSchedule
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
		t.Fatalf("cron missing-domain plan = %+v; want empty because cron domains are web-only", plan.Actions)
	}
}
