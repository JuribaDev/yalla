package jobs

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestCheckQueueReadyPassesWhenProvisioningJobsTableExists(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)

	if err := CheckQueueReady(context.Background(), db.Pool); err != nil {
		t.Fatalf("CheckQueueReady(migrated database): %v", err)
	}
}

func TestCheckQueueReadyReportsUnavailableWhenProvisioningJobsTableIsMissing(t *testing.T) {
	t.Parallel()

	db := testutil.RequireDB(t)

	err := CheckQueueReady(context.Background(), db.Pool)
	if err == nil {
		t.Fatal("CheckQueueReady(empty database): expected error")
	}
	if got, want := yerr.From(err).Code, yerr.CodeUnavailable; got != want {
		t.Fatalf("CheckQueueReady error code = %s, want %s", got, want)
	}
}
