package worker_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/JuribaDev/yalla/internal/controlplane/worker"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for the Postgres-backed worker queue (StoreClaimer +
// storeLease). They prove a job runs to a recorded outcome, that transient and
// terminal failures are classified differently, that the retry budget is
// honoured, and — the headline guarantee — that two workers polling the same
// queue run every job exactly once. They run against an isolated, freshly
// migrated Postgres database and skip when YALLA_TEST_DATABASE_URL is unset.

// newQueueStore builds a Store over the test database's pool.
func newQueueStore(t *testing.T, db *testutil.DB) *store.Store {
	t.Helper()
	s, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return s
}

// seedQueueOrg inserts an organization row and returns it.
func seedQueueOrg(t *testing.T, db *testutil.DB, f *testutil.Factory, label string) testutil.Organization {
	t.Helper()
	org := f.Organization(label)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		org.ID, org.Slug, org.Name); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	return org
}

// enqueueJob inserts a queued provisioning job and returns the stored row.
func enqueueJob(ctx context.Context, t *testing.T, s *store.Store, repo *store.JobRepository, j store.ProvisioningJob) store.ProvisioningJob {
	t.Helper()
	var stored store.ProvisioningJob
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Insert(ctx, tx, j)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("enqueue provisioning job: %v", err)
	}
	return stored
}

// getJob reads a job back through a read-only transaction.
func getJob(ctx context.Context, t *testing.T, s *store.Store, repo *store.JobRepository, orgID, jobID string) store.ProvisioningJob {
	t.Helper()
	var job store.ProvisioningJob
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		job, rErr = repo.Get(ctx, q, orgID, jobID)
		return rErr
	}); err != nil {
		t.Fatalf("get provisioning job: %v", err)
	}
	return job
}

// queueJobFixture builds a valid, minimal queued job for orgID.
func queueJobFixture(orgID, key string) store.ProvisioningJob {
	return store.ProvisioningJob{
		OrganizationID: orgID,
		JobType:        "ensure_project",
		IdempotencyKey: key,
		DesiredVersion: 1,
		RequestID:      "req-" + key,
		CorrelationID:  "corr-" + key,
	}
}

// TestNewStoreClaimerValidation proves the constructor rejects a misconfigured
// claimer with a typed InvalidInput error rather than panicking later.
func TestNewStoreClaimerValidation(t *testing.T) {
	t.Parallel()

	runner := worker.RunnerFunc(func(context.Context, store.ProvisioningJob) error { return nil })
	cases := []struct {
		name string
		cfg  worker.StoreClaimerConfig
	}{
		{name: "missing store", cfg: worker.StoreClaimerConfig{Runner: runner, Owner: "worker-1"}},
		{name: "missing runner", cfg: worker.StoreClaimerConfig{Store: &store.Store{}, Owner: "worker-1"}},
		{name: "missing owner", cfg: worker.StoreClaimerConfig{Store: &store.Store{}, Runner: runner}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := worker.NewStoreClaimer(tc.cfg)
			if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
				t.Fatalf("NewStoreClaimer(%s) error code = %v, want %s", tc.name, err, yerr.CodeValidation)
			}
		})
	}

	// A fully specified config constructs cleanly.
	if _, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store: &store.Store{}, Runner: runner, Owner: "worker-1",
	}); err != nil {
		t.Fatalf("NewStoreClaimer(valid) returned %v, want nil", err)
	}
}

// TestStoreClaimerRunsJobToSuccess proves the happy path: a claimed job is
// handed to the runner and, on a nil return, recorded as succeeded with its
// lease released.
func TestStoreClaimerRunsJobToSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQueueStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedQueueOrg(t, db, f, "Acme")
	stored := enqueueJob(ctx, t, s, repo, queueJobFixture(org.ID, "idem-success"))

	var ran atomic.Int64
	var sawJobID string
	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store: s, Runner: worker.RunnerFunc(func(_ context.Context, job store.ProvisioningJob) error {
			ran.Add(1)
			sawJobID = job.ID
			return nil
		}),
		Owner: worker.NewOwnerID(),
	})
	if err != nil {
		t.Fatalf("NewStoreClaimer: %v", err)
	}

	lease, err := claimer.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if lease == nil {
		t.Fatal("Claim returned no lease for a queued job")
	}
	if err := lease.Run(ctx); err != nil {
		t.Fatalf("lease.Run: %v", err)
	}
	if ran.Load() != 1 || sawJobID != stored.ID {
		t.Fatalf("runner ran %d time(s) for job %q, want 1 for %q", ran.Load(), sawJobID, stored.ID)
	}

	final := getJob(ctx, t, s, repo, org.ID, stored.ID)
	if final.Status != store.JobStatusSucceeded {
		t.Errorf("status = %q, want succeeded", final.Status)
	}
	if final.FinishedAt.IsZero() {
		t.Error("a succeeded job must carry finished_at")
	}
	if final.LeaseOwner != "" || !final.LeaseDeadline.IsZero() {
		t.Error("a succeeded job must not still hold a lease")
	}

	// The queue is now empty: a second claim returns no lease.
	empty, err := claimer.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim(empty): %v", err)
	}
	if empty != nil {
		t.Error("Claim returned a lease from an empty queue")
	}
}

// TestStoreClaimerRetriesTransientFailure proves a plain (non-Terminal) runner
// error sends the job back to retrying with a backed-off next_run_at, its lease
// released, ready to be claimed again.
func TestStoreClaimerRetriesTransientFailure(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQueueStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedQueueOrg(t, db, f, "Acme")
	stored := enqueueJob(ctx, t, s, repo, queueJobFixture(org.ID, "idem-retry"))

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store: s, Owner: worker.NewOwnerID(),
		Backoff: worker.Backoff{Base: time.Minute, Max: time.Hour},
		Runner: worker.RunnerFunc(func(context.Context, store.ProvisioningJob) error {
			return errors.New("dokploy returned 503")
		}),
	})
	if err != nil {
		t.Fatalf("NewStoreClaimer: %v", err)
	}

	before := time.Now().UTC()
	lease, err := claimer.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	// A transient failure is a committed outcome, so Run returns nil — the loop
	// must not release the lease afterwards.
	if err := lease.Run(ctx); err != nil {
		t.Fatalf("lease.Run on a transient failure = %v, want nil (outcome committed)", err)
	}

	final := getJob(ctx, t, s, repo, org.ID, stored.ID)
	if final.Status != store.JobStatusRetrying {
		t.Fatalf("status = %q, want retrying", final.Status)
	}
	if final.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", final.Attempts)
	}
	if final.LeaseOwner != "" || !final.LeaseDeadline.IsZero() {
		t.Error("a retrying job must not still hold a lease")
	}
	if !final.NextRunAt.After(before.Add(30 * time.Second)) {
		t.Errorf("next_run_at = %v, want it pushed forward by the backoff", final.NextRunAt)
	}
	if !final.FinishedAt.IsZero() {
		t.Error("retrying is not terminal; finished_at must stay unset")
	}
}

// TestStoreClaimerFailsTerminalError proves a Terminal runner error fails the
// job immediately — no retry — even though the retry budget is untouched.
func TestStoreClaimerFailsTerminalError(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQueueStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedQueueOrg(t, db, f, "Acme")
	stored := enqueueJob(ctx, t, s, repo, queueJobFixture(org.ID, "idem-terminal"))

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store: s, Owner: worker.NewOwnerID(),
		Runner: worker.RunnerFunc(func(context.Context, store.ProvisioningJob) error {
			return worker.Terminal(errors.New("desired state is invalid"))
		}),
	})
	if err != nil {
		t.Fatalf("NewStoreClaimer: %v", err)
	}

	lease, err := claimer.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := lease.Run(ctx); err != nil {
		t.Fatalf("lease.Run on a terminal failure = %v, want nil (outcome committed)", err)
	}

	final := getJob(ctx, t, s, repo, org.ID, stored.ID)
	if final.Status != store.JobStatusFailed {
		t.Fatalf("status = %q, want failed (terminal error must not retry)", final.Status)
	}
	if final.FinishedAt.IsZero() {
		t.Error("a failed job must carry finished_at")
	}
}

// TestStoreClaimerDeadLettersAfterBudget proves a transient failure on the
// last permitted attempt is dead-lettered, and that a secret in the failure
// reason is redacted before it is persisted.
func TestStoreClaimerDeadLettersAfterBudget(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQueueStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedQueueOrg(t, db, f, "Acme")
	in := queueJobFixture(org.ID, "idem-deadletter")
	in.MaxAttempts = 1
	stored := enqueueJob(ctx, t, s, repo, in)

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store: s, Owner: worker.NewOwnerID(),
		Runner: worker.RunnerFunc(func(context.Context, store.ProvisioningJob) error {
			return errors.New("dokploy call failed; Authorization: Bearer sk-leaked-token")
		}),
	})
	if err != nil {
		t.Fatalf("NewStoreClaimer: %v", err)
	}

	lease, err := claimer.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := lease.Run(ctx); err != nil {
		t.Fatalf("lease.Run = %v, want nil (outcome committed)", err)
	}

	final := getJob(ctx, t, s, repo, org.ID, stored.ID)
	if final.Status != store.JobStatusDeadLetter {
		t.Fatalf("status = %q, want dead_letter (retry budget spent)", final.Status)
	}
	if strings.Contains(final.ErrorSummary, "sk-leaked-token") {
		t.Errorf("dead-letter error summary leaked a secret: %q", final.ErrorSummary)
	}
}

// TestStoreClaimerReleaseRequeuesJob proves Release returns an interrupted job
// to the queue, claimable immediately, with its lease cleared.
func TestStoreClaimerReleaseRequeuesJob(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQueueStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedQueueOrg(t, db, f, "Acme")
	stored := enqueueJob(ctx, t, s, repo, queueJobFixture(org.ID, "idem-release"))

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store: s, Owner: worker.NewOwnerID(),
		Runner: worker.RunnerFunc(func(context.Context, store.ProvisioningJob) error { return nil }),
	})
	if err != nil {
		t.Fatalf("NewStoreClaimer: %v", err)
	}

	lease, err := claimer.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := lease.Release(ctx); err != nil {
		t.Fatalf("lease.Release: %v", err)
	}

	final := getJob(ctx, t, s, repo, org.ID, stored.ID)
	if final.Status != store.JobStatusRetrying {
		t.Fatalf("status = %q, want retrying after Release", final.Status)
	}
	if final.LeaseOwner != "" || !final.LeaseDeadline.IsZero() {
		t.Error("Release did not clear the lease")
	}
	if final.NextRunAt.After(time.Now().UTC()) {
		t.Error("a released job must be claimable immediately, not scheduled into the future")
	}
}

func TestStoreClaimerStaleLeaseOutcomeReturnsJobNotClaimed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQueueStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedQueueOrg(t, db, f, "Acme")
	stored := enqueueJob(ctx, t, s, repo, queueJobFixture(org.ID, "idem-stale-lease"))
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

	first, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store: s, Owner: "worker-stale-a",
		Runner:        worker.RunnerFunc(func(context.Context, store.ProvisioningJob) error { return nil }),
		LeaseDuration: time.Second,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewStoreClaimer(first): %v", err)
	}
	firstLease, err := first.Claim(ctx)
	if err != nil {
		t.Fatalf("first Claim: %v", err)
	}
	if firstLease == nil {
		t.Fatal("first Claim returned nil lease")
	}

	now = now.Add(2 * time.Second)
	second, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store: s, Owner: "worker-stale-b",
		Runner:        worker.RunnerFunc(func(context.Context, store.ProvisioningJob) error { return nil }),
		LeaseDuration: time.Minute,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewStoreClaimer(second): %v", err)
	}
	secondLease, err := second.Claim(ctx)
	if err != nil {
		t.Fatalf("second Claim: %v", err)
	}
	if secondLease == nil {
		t.Fatal("second Claim did not reclaim the expired lease")
	}

	err = firstLease.Run(ctx)
	var typed *yerr.Error
	if !errors.As(err, &typed) || typed.Code != yerr.CodeJobNotClaimed {
		t.Fatalf("stale lease Run error = %v, want %s", err, yerr.CodeJobNotClaimed)
	}

	if err := secondLease.Run(ctx); err != nil {
		t.Fatalf("second lease Run: %v", err)
	}
	final := getJob(ctx, t, s, repo, org.ID, stored.ID)
	if final.Status != store.JobStatusSucceeded {
		t.Fatalf("final status = %q, want succeeded", final.Status)
	}
}

func TestStoreClaimerCancelledLeaseOutcomeReturnsJobCancelled(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQueueStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedQueueOrg(t, db, f, "Acme")
	stored := enqueueJob(ctx, t, s, repo, queueJobFixture(org.ID, "idem-cancelled-lease"))

	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store: s, Owner: "worker-cancelled",
		Runner: worker.RunnerFunc(func(context.Context, store.ProvisioningJob) error {
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("NewStoreClaimer: %v", err)
	}
	lease, err := claimer.Claim(ctx)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if lease == nil {
		t.Fatal("Claim returned nil lease")
	}

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, tErr := repo.Transition(ctx, tx, org.ID, stored.ID, store.JobStatusCancelled, store.JobTransition{
			ErrorSummary: "operator cancelled token=secret",
			ActorID:      "usr_cancel",
			ActorKind:    "user",
			RequestID:    "req_cancelled",
		})
		return tErr
	}); err != nil {
		t.Fatalf("cancel job while leased: %v", err)
	}

	err = lease.Run(ctx)
	var typed *yerr.Error
	if !errors.As(err, &typed) || typed.Code != yerr.CodeJobCancelled {
		t.Fatalf("cancelled lease Run error = %v, want %s", err, yerr.CodeJobCancelled)
	}

	final := getJob(ctx, t, s, repo, org.ID, stored.ID)
	if final.Status != store.JobStatusCancelled {
		t.Fatalf("final status = %q, want cancelled", final.Status)
	}
	if strings.Contains(final.ErrorSummary, "token=secret") {
		t.Fatalf("cancelled error summary leaked secret: %q", final.ErrorSummary)
	}
}

// TestStoreClaimerTwoWorkersRunEachJobOnce is the headline guarantee: two
// workers polling the same queue concurrently run every job exactly once. Each
// worker has its own StoreClaimer and lease owner; SELECT ... FOR UPDATE SKIP
// LOCKED is what makes that safe.
func TestStoreClaimerTwoWorkersRunEachJobOnce(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQueueStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)

	org := seedQueueOrg(t, db, f, "Acme")
	const jobCount = 16
	jobIDs := make([]string, 0, jobCount)
	for i := 0; i < jobCount; i++ {
		stored := enqueueJob(context.Background(), t, s, repo, queueJobFixture(org.ID, fmt.Sprintf("idem-concurrent-%d", i)))
		jobIDs = append(jobIDs, stored.ID)
	}

	// A test-scoped deadline so a regression that drops a job cannot hang CI;
	// the runner cancels the moment every job has run.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var (
		mu    sync.Mutex
		runs  = make(map[string]int, jobCount)
		total atomic.Int64
	)
	runner := worker.RunnerFunc(func(_ context.Context, job store.ProvisioningJob) error {
		mu.Lock()
		runs[job.ID]++
		mu.Unlock()
		if total.Add(1) == int64(jobCount) {
			cancel()
		}
		return nil
	})

	newLoop := func(owner string) *worker.Loop {
		claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
			Store: s, Runner: runner, Owner: owner, LeaseDuration: 5 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewStoreClaimer(%s): %v", owner, err)
		}
		return &worker.Loop{Claimer: claimer, IdleDelay: time.Millisecond}
	}

	var wg sync.WaitGroup
	for _, owner := range []string{"worker-a", "worker-b"} {
		wg.Add(1)
		loop := newLoop(owner)
		go func() {
			defer wg.Done()
			if err := loop.Run(ctx); err != nil {
				t.Errorf("loop.Run: %v", err)
			}
		}()
	}
	wg.Wait()

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("workers did not finish every job within the deadline; ran %d of %d", total.Load(), jobCount)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(runs) != jobCount {
		t.Fatalf("ran %d distinct jobs, want %d", len(runs), jobCount)
	}
	for id, n := range runs {
		if n != 1 {
			t.Errorf("job %s ran %d times, want exactly 1 (duplicate execution)", id, n)
		}
	}
	// Every job must have reached the succeeded terminal state in the database.
	for _, id := range jobIDs {
		if got := getJob(context.Background(), t, s, repo, org.ID, id); got.Status != store.JobStatusSucceeded {
			t.Errorf("job %s final status = %q, want succeeded", id, got.Status)
		}
	}
}

// TestJobWorkerLeaseExclusivityNeverDoubleClaims is the first half of the
// canonical BE-0385 job worker lease pair. It encodes the
// FOR-UPDATE-SKIP-LOCKED contract: under contention against a single queued
// job, exactly one StoreClaimer wins the lease and the other sees (nil, nil) —
// never (lease, nil) for both. A regression that drops the SKIP LOCKED clause
// (or downgrades the row lock to a shared lock) would let two workers run the
// same job in parallel; this test trips that regression at the queue layer
// before any duplicate-execution side effect reaches Dokploy.
func TestJobWorkerLeaseExclusivityNeverDoubleClaims(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQueueStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedQueueOrg(t, db, f, "Acme")
	stored := enqueueJob(ctx, t, s, repo, queueJobFixture(org.ID, "idem-lease-exclusivity"))

	// Two claimers, distinct owners — anything else would mean a worker is
	// its own contention partner, which would mask the SKIP LOCKED contract.
	newClaimer := func(owner string) *worker.StoreClaimer {
		c, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
			Store: s, Owner: owner,
			Runner:        worker.RunnerFunc(func(context.Context, store.ProvisioningJob) error { return nil }),
			LeaseDuration: 5 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewStoreClaimer(%s): %v", owner, err)
		}
		return c
	}
	a := newClaimer("worker-lease-a")
	b := newClaimer("worker-lease-b")

	type result struct {
		owner string
		lease worker.Lease
		err   error
	}
	out := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(1)
	for _, c := range []struct {
		owner string
		cl    *worker.StoreClaimer
	}{{"worker-lease-a", a}, {"worker-lease-b", b}} {
		c := c
		go func() {
			start.Wait()
			l, err := c.cl.Claim(ctx)
			out <- result{owner: c.owner, lease: l, err: err}
		}()
	}
	start.Done()

	var holders int
	var winner result
	for i := 0; i < 2; i++ {
		r := <-out
		if r.err != nil {
			t.Fatalf("Claim(%s): %v", r.owner, r.err)
		}
		if r.lease != nil {
			holders++
			winner = r
		}
	}
	if holders != 1 {
		t.Fatalf("two concurrent claimers leased the same job %d times, want exactly 1 (FOR UPDATE SKIP LOCKED contract violated; the job could be run twice). job_id=%s organization_id=%s",
			holders, stored.ID, org.ID)
	}

	// The winner runs the job to success; the loser would still see nothing.
	if err := winner.lease.Run(ctx); err != nil {
		t.Fatalf("winner.lease.Run: %v", err)
	}
	final := getJob(ctx, t, s, repo, org.ID, stored.ID)
	if final.Status != store.JobStatusSucceeded {
		t.Errorf("final status = %q, want succeeded (job did not finish through the surviving lease). job_id=%s organization_id=%s",
			final.Status, stored.ID, org.ID)
	}
	if final.LeaseOwner != "" || !final.LeaseDeadline.IsZero() {
		t.Errorf("succeeded job still carries a lease — exclusivity was broken on the recording side. job_id=%s lease_owner=%q lease_deadline=%v",
			stored.ID, final.LeaseOwner, final.LeaseDeadline)
	}
}

// TestJobWorkerLeaseReleasedOnShutdownIsRetryable is the second half of the
// canonical BE-0385 job worker lease pair. It encodes the shutdown-safety
// contract: a worker interrupted while running a job MUST return the
// in-flight lease to the queue with the lease cleared and the job retryable
// immediately, so the job is not lost. A regression that orphans the lease
// on shutdown (skipped Release, lease left held by a dead worker, next_run_at
// scheduled into the future) would quarantine the job until the lease
// expires; this test trips that regression at the loop+queue boundary by
// driving a Loop past a runner that blocks until cancellation, cancelling
// the loop, and asserting the job is persisted as retrying with no
// stale lease and an immediate next_run_at.
func TestJobWorkerLeaseReleasedOnShutdownIsRetryable(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newQueueStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedQueueOrg(t, db, f, "Acme")
	stored := enqueueJob(ctx, t, s, repo, queueJobFixture(org.ID, "idem-lease-release"))

	started := make(chan struct{})
	runner := worker.RunnerFunc(func(runCtx context.Context, _ store.ProvisioningJob) error {
		close(started)
		<-runCtx.Done()
		return runCtx.Err()
	})
	owner := worker.NewOwnerID()
	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store: s, Owner: owner, Runner: runner, LeaseDuration: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewStoreClaimer: %v", err)
	}
	loop := &worker.Loop{Claimer: claimer, IdleDelay: time.Millisecond}

	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- loop.Run(loopCtx) }()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		cancel()
		<-done
		t.Fatalf("runner never started; the worker did not claim the queued job. job_id=%s organization_id=%s",
			stored.ID, org.ID)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop.Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("loop did not return after shutdown; the release path is hung. job_id=%s organization_id=%s",
			stored.ID, org.ID)
	}

	final := getJob(ctx, t, s, repo, org.ID, stored.ID)
	if final.Status != store.JobStatusRetrying {
		t.Fatalf("status = %q, want retrying after interrupted-lease release (the job would be lost). job_id=%s organization_id=%s",
			final.Status, stored.ID, org.ID)
	}
	if final.LeaseOwner != "" || !final.LeaseDeadline.IsZero() {
		t.Errorf("interrupted lease left a stale lease (owner=%q, deadline=%v); the row would be quarantined until the lease expires. job_id=%s organization_id=%s",
			final.LeaseOwner, final.LeaseDeadline, stored.ID, org.ID)
	}
	if final.NextRunAt.After(time.Now().UTC()) {
		t.Errorf("released job is scheduled into the future (%v); a released job must be claimable immediately. job_id=%s organization_id=%s",
			final.NextRunAt, stored.ID, org.ID)
	}
}
