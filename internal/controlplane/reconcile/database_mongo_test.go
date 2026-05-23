package reconcile_test

import (
	"context"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/reconcile"
)

// BE-0316: Verify mongo drift reconciliation.
//
// Mongo is a database subtype: both desired and actual carry Type=database,
// and the engine value is the destructive subtype boundary. Engine drift is
// therefore dangerous review-only drift, not a safe repair.
func TestMongoReconcileRecordsEngineDriftForReview(t *testing.T) {
	t.Parallel()
	desiredState := simpleDesired()
	desiredState.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceDatabase
	desiredState.Projects[0].Environments[0].Services[0].Engine = dokploy.EngineMongo
	desiredState.Projects[0].Environments[0].Services[0].EnvVars = []reconcile.DesiredEnvVar{{
		Key:    "DATABASE_URL",
		Value:  "mongo://user:secret-password@db.internal/yalla",
		Secret: true,
	}}

	actualState := simpleActual()
	actualState.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceDatabase
	actualState.Projects[0].Environments[0].Services[0].Engine = dokploy.EngineMysql
	actualState.Projects[0].Environments[0].Services[0].EnvVars = []reconcile.ActualEnvVar{{
		Key:   "DATABASE_URL",
		Value: "mysql://user:other-secret@db.internal/yalla",
	}}

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
	if res.Repaired != 0 || res.Reviewed != 1 || res.Quarantined != 0 || len(res.Failures) != 0 {
		t.Fatalf("result = %+v; want one dangerous review and no repair", res)
	}
	if len(repairer.envCalls) != 0 || len(repairer.removeCalls) != 0 ||
		len(repairer.buildCalls) != 0 || len(repairer.domainCalls) != 0 {
		t.Fatalf("repairer was called for mongo engine drift: env=%+v remove=%+v build=%+v domain=%+v",
			repairer.envCalls, repairer.removeCalls, repairer.buildCalls, repairer.domainCalls)
	}
	if reviewer.calls != 1 || len(reviewer.events) != 1 {
		t.Fatalf("reviewer calls/events = %d/%d; want one review event", reviewer.calls, len(reviewer.events))
	}
	if unmanaged.calls != 0 {
		t.Errorf("unmanaged recorder was called for managed mongo drift")
	}

	plan, err := rec.Plan(context.Background(), validOrgID)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("plan.Actions = %+v; want one action", plan.Actions)
	}
	action := plan.Actions[0]
	if action.Kind != reconcile.DriftDangerous ||
		action.Type != reconcile.ActionReviewServiceTypeChange ||
		action.Reason != reconcile.ReasonServiceTypeChanged {
		t.Fatalf("classification = %q/%q/%q; want dangerous/review_service_type_change/service_type_changed",
			action.Kind, action.Type, action.Reason)
	}
	classification := strings.Join([]string{
		string(action.Kind),
		string(action.Type),
		string(action.Reason),
		action.EnvVarKey,
		string(action.Service.ServiceID),
	}, "|")
	for _, leaked := range []string{"mongo://", "mysql://", "secret-password", "other-secret"} {
		if strings.Contains(classification, leaked) {
			t.Fatalf("classification leaked database value %q in %q", leaked, classification)
		}
	}
}

func TestMongoReconcileDriftClassificationMatrix(t *testing.T) {
	t.Parallel()
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
			name: "deleted upstream resource is dangerous database review",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services = filterActual(
					actual.Projects[0].Environments[0].Services,
					func(s reconcile.ActualService) bool { return s.DokployID != "dokploy-svc-app" },
				)
			},
			reviewed:   1,
			wantKind:   reconcile.DriftDangerous,
			wantType:   reconcile.ActionReviewMissingDatabase,
			wantReason: reconcile.ReasonDatabaseMissing,
		},
		{
			name: "changed upstream engine is dangerous review",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services[0].Engine = dokploy.EnginePostgres
			},
			reviewed:   1,
			wantKind:   reconcile.DriftDangerous,
			wantType:   reconcile.ActionReviewServiceTypeChange,
			wantReason: reconcile.ReasonServiceTypeChanged,
		},
		{
			name: "missing managed domain is safe ensure",
			mutate: func(desired *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				desired.Projects[0].Environments[0].Services[0].Domains = []reconcile.DesiredDomain{{
					ID:        domain.MustNewID(domain.KindService),
					Host:      "mongo.example.test",
					HTTPS:     true,
					DokployID: "dokploy-dom-mongo",
				}}
				actual.Projects[0].Environments[0].Services[0].Domains = nil
			},
			repaired:   1,
			wantKind:   reconcile.DriftSafe,
			wantType:   reconcile.ActionEnsureDomain,
			wantReason: reconcile.ReasonDomainMissing,
		},
		{
			name: "unmanaged extra database is quarantined",
			mutate: func(_ *reconcile.DesiredOrganization, actual *reconcile.ActualOrganization) {
				actual.Projects[0].Environments[0].Services = append(
					actual.Projects[0].Environments[0].Services,
					reconcile.ActualService{
						DokployID: "dokploy-svc-rogue-mongo",
						Name:      "rogue-mongo",
						Type:      dokploy.ServiceDatabase,
						Engine:    dokploy.EngineMongo,
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
			desiredState.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceDatabase
			desiredState.Projects[0].Environments[0].Services[0].Engine = dokploy.EngineMongo
			actualState := simpleActual()
			actualState.Projects[0].Environments[0].Services[0].Type = dokploy.ServiceDatabase
			actualState.Projects[0].Environments[0].Services[0].Engine = dokploy.EngineMongo
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
