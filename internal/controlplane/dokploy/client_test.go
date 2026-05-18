package dokploy_test

import (
	"context"
	stderrors "errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy/dokployfake"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// newTestClient returns a Client wired to fake with fast, deterministic retry
// timing so retry-policy tests do not sleep for real.
func newTestClient(t *testing.T, fake *dokployfake.Server, opts ...func(*dokploy.Config)) *dokploy.Client {
	t.Helper()
	cfg := dokploy.Config{
		BaseURL:        fake.URL(),
		Token:          fake.Token(),
		MaxRetries:     2,
		RetryBaseDelay: time.Millisecond,
		RetryMaxDelay:  2 * time.Millisecond,
		Timeout:        2 * time.Second,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	c, err := dokploy.New(cfg)
	if err != nil {
		t.Fatalf("dokploy.New: %v", err)
	}
	return c
}

// codeOf extracts the stable error code from a typed backend error.
func codeOf(t *testing.T, err error) yerr.Code {
	t.Helper()
	var ye *yerr.Error
	if !stderrors.As(err, &ye) {
		t.Fatalf("error is not a *yerr.Error: %v", err)
	}
	return ye.Code
}

// TestClientProvisioningChainSucceeds drives the whole intent surface against
// the fake: organization -> project -> environment -> service -> domain ->
// deploy -> read deployment -> read logs -> read status, and confirms IDs are
// deterministic and the deployment succeeds.
func TestClientProvisioningChainSucceeds(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)
	ctx := context.Background()

	org, err := c.EnsureOrganization(ctx, dokploy.EnsureOrganizationInput{Name: "acme"})
	if err != nil || org.ID != "org_1" {
		t.Fatalf("EnsureOrganization = %+v, %v", org, err)
	}
	proj, err := c.EnsureProject(ctx, dokploy.EnsureProjectInput{OrganizationID: org.ID, Name: "store"})
	if err != nil || proj.ID != "proj_1" || proj.OrganizationID != org.ID {
		t.Fatalf("EnsureProject = %+v, %v", proj, err)
	}
	env, err := c.EnsureEnvironment(ctx, dokploy.EnsureEnvironmentInput{ProjectID: proj.ID, Name: "production"})
	if err != nil || env.ID != "env_1" {
		t.Fatalf("EnsureEnvironment = %+v, %v", env, err)
	}
	svc, err := c.EnsureService(ctx, dokploy.EnsureServiceInput{
		EnvironmentID: env.ID, Name: "api", Type: dokploy.ServiceApplication,
	})
	if err != nil || svc.ID != "app_1" || svc.Type != string(dokploy.ServiceApplication) {
		t.Fatalf("EnsureService = %+v, %v", svc, err)
	}
	db, err := c.EnsureService(ctx, dokploy.EnsureServiceInput{
		EnvironmentID: env.ID, Name: "db", Type: dokploy.ServiceDatabase, Engine: "postgres",
	})
	if err != nil || db.Engine != "postgres" {
		t.Fatalf("EnsureService(database) = %+v, %v", db, err)
	}
	dom, err := c.EnsureDomain(ctx, dokploy.EnsureDomainInput{ServiceID: svc.ID, Host: "api.acme.test", HTTPS: true})
	if err != nil || dom.Host != "api.acme.test" || !dom.HTTPS {
		t.Fatalf("EnsureDomain = %+v, %v", dom, err)
	}

	dep, err := c.DeployService(ctx, dokploy.DeployServiceInput{ServiceID: svc.ID})
	if err != nil || !dep.Succeeded() {
		t.Fatalf("DeployService = %+v, %v", dep, err)
	}
	got, err := c.GetDeployment(ctx, dep.ID)
	if err != nil || got.ID != dep.ID {
		t.Fatalf("GetDeployment = %+v, %v", got, err)
	}
	logs, err := c.ReadDeploymentLogs(ctx, dep.ID)
	if err != nil || len(logs.Lines) == 0 {
		t.Fatalf("ReadDeploymentLogs = %+v, %v", logs, err)
	}
	status, err := c.GetServiceStatus(ctx, svc.ID)
	if err != nil || status.Status != dokployfake.StatusRunning {
		t.Fatalf("GetServiceStatus = %+v, %v", status, err)
	}
}

// TestClientEnsureWithExistingIDFetches proves the "ensure" intents are
// idempotent against Yalla's recorded state: a populated ExistingID fetches
// and verifies the resource rather than creating a duplicate.
func TestClientEnsureWithExistingIDFetches(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)
	ctx := context.Background()

	created, err := c.EnsureProject(ctx, dokploy.EnsureProjectInput{OrganizationID: mustOrg(t, c), Name: "store"})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	before := fake.RequestCount()

	fetched, err := c.EnsureProject(ctx, dokploy.EnsureProjectInput{ExistingID: created.ID})
	if err != nil {
		t.Fatalf("EnsureProject(ExistingID): %v", err)
	}
	if fetched.ID != created.ID || fetched.Name != "store" {
		t.Fatalf("fetched = %+v, want %+v", fetched, created)
	}
	// Exactly one GET, no create.
	if got := fake.RequestCount() - before; got != 1 {
		t.Fatalf("ensure-with-id made %d requests, want 1", got)
	}
}

func mustOrg(t *testing.T, c *dokploy.Client) string {
	t.Helper()
	org, err := c.EnsureOrganization(context.Background(), dokploy.EnsureOrganizationInput{Name: "acme"})
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	return org.ID
}

// TestClientValidationFailure proves obviously invalid intents are rejected
// locally as E_VALIDATION with structured field paths, never reaching
// Dokploy.
func TestClientValidationFailure(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)

	_, err := c.EnsureProject(context.Background(), dokploy.EnsureProjectInput{Name: ""})
	if err == nil {
		t.Fatal("EnsureProject with blank fields returned nil error")
	}
	if code := codeOf(t, err); code != yerr.CodeValidation {
		t.Fatalf("code = %s, want %s", code, yerr.CodeValidation)
	}
	violations, ok := apierr.ViolationsOf(err)
	if !ok || len(violations) != 2 {
		t.Fatalf("ViolationsOf = %v, %v; want 2 violations", violations, ok)
	}
	if fake.RequestCount() != 0 {
		t.Fatalf("validation failure reached Dokploy: %d requests", fake.RequestCount())
	}

	if _, err := c.EnsureService(context.Background(), dokploy.EnsureServiceInput{
		EnvironmentID: "env_1", Name: "x", Type: "bogus",
	}); codeOf(t, err) != yerr.CodeValidation {
		t.Fatalf("EnsureService with bad type: %v", err)
	}
}

// TestClientNotFound maps a Dokploy 404 onto E_DOKPLOY_NOT_FOUND.
func TestClientNotFound(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)

	_, err := c.EnsureProject(context.Background(), dokploy.EnsureProjectInput{ExistingID: "proj_does_not_exist"})
	if code := codeOf(t, err); code != yerr.CodeDokployNotFound {
		t.Fatalf("code = %s, want %s", code, yerr.CodeDokployNotFound)
	}
	if apierr.Retryable(err) {
		t.Fatal("a not-found error must not be retryable")
	}
}

// TestClientAuthorizationFailure maps a Dokploy credential rejection onto a
// non-retryable upstream-auth error: it is a Yalla misconfiguration, not
// something the customer or a retry can fix.
func TestClientAuthorizationFailure(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake, func(cfg *dokploy.Config) {
		cfg.Token = "dkp_wrongtoken_000000000000000000000000"
	})

	_, err := c.EnsureOrganization(context.Background(), dokploy.EnsureOrganizationInput{Name: "acme"})
	if code := codeOf(t, err); code != yerr.CodeDokployAuth {
		t.Fatalf("code = %s, want %s", code, yerr.CodeDokployAuth)
	}
	if apierr.Retryable(err) {
		t.Fatal("a credential-rejection error must not be retryable")
	}
}

// TestClientForbiddenFailure maps an upstream Dokploy 403 onto the dedicated
// non-retryable forbidden code, distinct from a 401 credential rejection.
func TestClientForbiddenFailure(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)
	fake.QueueFault(dokployfake.StatusFault(http.StatusForbidden))

	_, err := c.EnsureOrganization(context.Background(), dokploy.EnsureOrganizationInput{Name: "acme"})
	if code := codeOf(t, err); code != yerr.CodeDokployForbidden {
		t.Fatalf("code = %s, want %s", code, yerr.CodeDokployForbidden)
	}
	if apierr.Retryable(err) {
		t.Fatal("a Dokploy forbidden error must not be retryable")
	}
}

// TestClientConflict maps a Dokploy 409 onto E_DOKPLOY_CONFLICT.
func TestClientConflict(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)
	orgID := mustOrg(t, c)

	if _, err := c.EnsureProject(context.Background(), dokploy.EnsureProjectInput{OrganizationID: orgID, Name: "store"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := c.EnsureProject(context.Background(), dokploy.EnsureProjectInput{OrganizationID: orgID, Name: "store"})
	if code := codeOf(t, err); code != yerr.CodeDokployConflict {
		t.Fatalf("code = %s, want %s", code, yerr.CodeDokployConflict)
	}
	if apierr.Retryable(err) {
		t.Fatal("an upstream Dokploy conflict must not be retryable")
	}
}

// TestClientRetriesIdempotentRequests proves a GET that fails transiently is
// retried until it succeeds, while a POST is never retried.
func TestClientRetriesIdempotentRequests(t *testing.T) {
	t.Parallel()

	t.Run("GET retried then succeeds", func(t *testing.T) {
		t.Parallel()
		fake := dokployfake.New()
		defer fake.Close()
		c := newTestClient(t, fake)
		orgID := mustOrg(t, c)
		created, err := c.EnsureProject(context.Background(), dokploy.EnsureProjectInput{OrganizationID: orgID, Name: "store"})
		if err != nil {
			t.Fatalf("create project: %v", err)
		}
		before := fake.RequestCount()

		fake.QueueFault(
			dokployfake.StatusFault(http.StatusInternalServerError),
			dokployfake.StatusFault(http.StatusBadGateway),
		)
		got, err := c.EnsureProject(context.Background(), dokploy.EnsureProjectInput{ExistingID: created.ID})
		if err != nil {
			t.Fatalf("EnsureProject after transient faults: %v", err)
		}
		if got.ID != created.ID {
			t.Fatalf("got %+v, want id %s", got, created.ID)
		}
		if n := fake.RequestCount() - before; n != 3 {
			t.Fatalf("made %d attempts, want 3 (2 faults + 1 success)", n)
		}
	})

	t.Run("POST not retried", func(t *testing.T) {
		t.Parallel()
		fake := dokployfake.New()
		defer fake.Close()
		c := newTestClient(t, fake)
		fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))

		_, err := c.EnsureOrganization(context.Background(), dokploy.EnsureOrganizationInput{Name: "acme"})
		if err == nil {
			t.Fatal("EnsureOrganization returned nil despite injected 500")
		}
		if !apierr.Retryable(err) {
			t.Fatalf("a transient Dokploy 5xx must be retryable, got %v", err)
		}
		if fake.RequestCount() != 1 {
			t.Fatalf("POST was attempted %d times, want 1 (POST is never retried)", fake.RequestCount())
		}
	})

	t.Run("retries are bounded", func(t *testing.T) {
		t.Parallel()
		fake := dokployfake.New()
		defer fake.Close()
		c := newTestClient(t, fake) // MaxRetries: 2
		for i := 0; i < 5; i++ {
			fake.QueueFault(dokployfake.StatusFault(http.StatusServiceUnavailable))
		}
		_, err := c.GetDeployment(context.Background(), "dep_1")
		if err == nil {
			t.Fatal("GetDeployment returned nil despite a wall of faults")
		}
		// 1 initial attempt + 2 retries.
		if fake.RequestCount() != 3 {
			t.Fatalf("made %d attempts, want 3 (1 + MaxRetries)", fake.RequestCount())
		}
	})
}

// TestClientTimeout maps a slow upstream onto E_TIMEOUT against the Dokploy
// dependency.
func TestClientTimeout(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake, func(cfg *dokploy.Config) {
		cfg.Timeout = 20 * time.Millisecond
		cfg.MaxRetries = 1
	})
	fake.QueueFault(
		dokployfake.TimeoutFault(2*time.Second),
		dokployfake.TimeoutFault(2*time.Second),
	)

	_, err := c.GetDeployment(context.Background(), "dep_1")
	if code := codeOf(t, err); code != yerr.CodeTimeout {
		t.Fatalf("code = %s, want %s", code, yerr.CodeTimeout)
	}
	if dep, ok := apierr.DependencyOf(err); !ok || dep != apierr.DependencyDokploy {
		t.Fatalf("DependencyOf = %s, %v; want dokploy", dep, ok)
	}
}

// TestClientRemoveServiceIsIdempotent proves teardown succeeds whether or not
// the service still exists.
func TestClientRemoveServiceIsIdempotent(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)
	ctx := context.Background()

	orgID := mustOrg(t, c)
	proj, _ := c.EnsureProject(ctx, dokploy.EnsureProjectInput{OrganizationID: orgID, Name: "store"})
	env, _ := c.EnsureEnvironment(ctx, dokploy.EnsureEnvironmentInput{ProjectID: proj.ID, Name: "prod"})
	svc, err := c.EnsureService(ctx, dokploy.EnsureServiceInput{
		EnvironmentID: env.ID, Name: "api", Type: dokploy.ServiceApplication,
	})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}

	if err := c.RemoveService(ctx, dokploy.RemoveServiceInput{ServiceID: svc.ID}); err != nil {
		t.Fatalf("first RemoveService: %v", err)
	}
	// Second removal: the service is already gone, Dokploy answers 404, and the
	// client must still report success.
	if err := c.RemoveService(ctx, dokploy.RemoveServiceInput{ServiceID: svc.ID}); err != nil {
		t.Fatalf("second RemoveService must be idempotent, got: %v", err)
	}
	// The service is genuinely gone.
	if _, err := c.EnsureService(ctx, dokploy.EnsureServiceInput{
		ExistingID: svc.ID, Type: dokploy.ServiceApplication,
	}); codeOf(t, err) != yerr.CodeDokployNotFound {
		t.Fatalf("removed service still readable: %v", err)
	}
}

// TestClientRemoveEnvironmentIsIdempotent proves environment teardown succeeds
// whether or not the upstream environment still exists.
func TestClientRemoveEnvironmentIsIdempotent(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)
	ctx := context.Background()

	orgID := mustOrg(t, c)
	proj, _ := c.EnsureProject(ctx, dokploy.EnsureProjectInput{OrganizationID: orgID, Name: "store"})
	env, err := c.EnsureEnvironment(ctx, dokploy.EnsureEnvironmentInput{ProjectID: proj.ID, Name: "prod"})
	if err != nil {
		t.Fatalf("create environment: %v", err)
	}

	if err := c.RemoveEnvironment(ctx, dokploy.RemoveEnvironmentInput{EnvironmentID: env.ID}); err != nil {
		t.Fatalf("first RemoveEnvironment: %v", err)
	}
	if err := c.RemoveEnvironment(ctx, dokploy.RemoveEnvironmentInput{EnvironmentID: env.ID}); err != nil {
		t.Fatalf("second RemoveEnvironment must be idempotent, got: %v", err)
	}
	if _, err := c.EnsureEnvironment(ctx, dokploy.EnsureEnvironmentInput{ExistingID: env.ID}); codeOf(t, err) != yerr.CodeDokployNotFound {
		t.Fatalf("removed environment still readable: %v", err)
	}
}

func TestClientRestartService(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)
	ctx := context.Background()

	orgID := mustOrg(t, c)
	proj, _ := c.EnsureProject(ctx, dokploy.EnsureProjectInput{OrganizationID: orgID, Name: "store"})
	env, _ := c.EnsureEnvironment(ctx, dokploy.EnsureEnvironmentInput{ProjectID: proj.ID, Name: "prod"})
	svc, err := c.EnsureService(ctx, dokploy.EnsureServiceInput{
		EnvironmentID: env.ID, Name: "api", Type: dokploy.ServiceApplication,
	})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	if ok := fake.SetServiceStatus(svc.ID, "crashed"); !ok {
		t.Fatalf("SetServiceStatus(%q) returned false", svc.ID)
	}

	st, err := c.RestartService(ctx, dokploy.RestartServiceInput{ServiceID: svc.ID})
	if err != nil {
		t.Fatalf("RestartService: %v", err)
	}
	if st.ServiceID != svc.ID || st.Status != dokployfake.StatusRunning {
		t.Fatalf("RestartService status = %+v, want service %q running", st, svc.ID)
	}
	reqs := fake.Requests()
	last := reqs[len(reqs)-1]
	if last.Method != http.MethodPost || last.Path != "/api/services/"+svc.ID+"/restart" {
		t.Fatalf("last request = %+v, want POST restart", last)
	}
	if last.AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", last.AuthHeader)
	}
}

func TestClientRollbackService(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)
	ctx := context.Background()

	orgID := mustOrg(t, c)
	proj, _ := c.EnsureProject(ctx, dokploy.EnsureProjectInput{OrganizationID: orgID, Name: "store"})
	env, _ := c.EnsureEnvironment(ctx, dokploy.EnsureEnvironmentInput{ProjectID: proj.ID, Name: "prod"})
	svc, err := c.EnsureService(ctx, dokploy.EnsureServiceInput{
		EnvironmentID: env.ID, Name: "api", Type: dokploy.ServiceApplication,
	})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	if ok := fake.SetServiceStatus(svc.ID, "bad-release"); !ok {
		t.Fatalf("SetServiceStatus(%q) returned false", svc.ID)
	}

	st, err := c.RollbackService(ctx, dokploy.RollbackServiceInput{ServiceID: svc.ID})
	if err != nil {
		t.Fatalf("RollbackService: %v", err)
	}
	if st.ServiceID != svc.ID || st.Status != dokployfake.StatusRunning {
		t.Fatalf("RollbackService status = %+v, want service %q running", st, svc.ID)
	}
	reqs := fake.Requests()
	last := reqs[len(reqs)-1]
	if last.Method != http.MethodPost || last.Path != "/api/services/"+svc.ID+"/rollback" {
		t.Fatalf("last request = %+v, want POST rollback", last)
	}
	if last.AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", last.AuthHeader)
	}
}

func TestClientStartService(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)
	ctx := context.Background()

	orgID := mustOrg(t, c)
	proj, _ := c.EnsureProject(ctx, dokploy.EnsureProjectInput{OrganizationID: orgID, Name: "store"})
	env, _ := c.EnsureEnvironment(ctx, dokploy.EnsureEnvironmentInput{ProjectID: proj.ID, Name: "prod"})
	svc, err := c.EnsureService(ctx, dokploy.EnsureServiceInput{
		EnvironmentID: env.ID, Name: "api", Type: dokploy.ServiceApplication,
	})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	if _, err := c.StopService(ctx, dokploy.StopServiceInput{ServiceID: svc.ID}); err != nil {
		t.Fatalf("seed stopped service: %v", err)
	}

	st, err := c.StartService(ctx, dokploy.StartServiceInput{ServiceID: svc.ID})
	if err != nil {
		t.Fatalf("StartService: %v", err)
	}
	if st.ServiceID != svc.ID || st.Status != dokployfake.StatusRunning {
		t.Fatalf("StartService status = %+v, want service %q running", st, svc.ID)
	}
	reqs := fake.Requests()
	last := reqs[len(reqs)-1]
	if last.Method != http.MethodPost || last.Path != "/api/services/"+svc.ID+"/start" {
		t.Fatalf("last request = %+v, want POST start", last)
	}
	if last.AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", last.AuthHeader)
	}
}

func TestClientStopService(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)
	ctx := context.Background()

	orgID := mustOrg(t, c)
	proj, _ := c.EnsureProject(ctx, dokploy.EnsureProjectInput{OrganizationID: orgID, Name: "store"})
	env, _ := c.EnsureEnvironment(ctx, dokploy.EnsureEnvironmentInput{ProjectID: proj.ID, Name: "prod"})
	svc, err := c.EnsureService(ctx, dokploy.EnsureServiceInput{
		EnvironmentID: env.ID, Name: "api", Type: dokploy.ServiceApplication,
	})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}

	st, err := c.StopService(ctx, dokploy.StopServiceInput{ServiceID: svc.ID})
	if err != nil {
		t.Fatalf("StopService: %v", err)
	}
	if st.ServiceID != svc.ID || st.Status != dokployfake.StatusStopped {
		t.Fatalf("StopService status = %+v, want service %q stopped", st, svc.ID)
	}
	reqs := fake.Requests()
	last := reqs[len(reqs)-1]
	if last.Method != http.MethodPost || last.Path != "/api/services/"+svc.ID+"/stop" {
		t.Fatalf("last request = %+v, want POST stop", last)
	}
	if last.AuthHeader != output.Sentinel {
		t.Fatalf("auth header was not redacted: %q", last.AuthHeader)
	}
}

// TestClientRedactsSecrets proves the bearer token never reaches a recorded
// request fixture, an error message, or its wrapped cause.
func TestClientRedactsSecrets(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)

	// A 500 produces an error whose wrapped cause is built from response data.
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))
	_, err := c.GetDeployment(context.Background(), "dep_1")
	if err == nil {
		t.Fatal("expected an error from the injected 500")
	}

	// Walk the whole error chain: no level may contain the token.
	for e := err; e != nil; e = stderrors.Unwrap(e) {
		testutil.AssertRedacted(t, e.Error(), fake.Token())
	}

	// Every recorded request redacted its Authorization header and body.
	reqs := fake.Requests()
	if len(reqs) == 0 {
		t.Fatal("fake recorded no requests")
	}
	for _, rec := range reqs {
		if rec.AuthHeader != output.Sentinel {
			t.Fatalf("request %s %s leaked its Authorization header: %q", rec.Method, rec.Path, rec.AuthHeader)
		}
		testutil.AssertRedacted(t, rec.Body, fake.Token())
	}
}

// TestNewValidatesConfig proves construction rejects bad config with typed
// E_CONFIG errors that never echo the token.
func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()
	const secret = "dkp_supersecret_aaaaaaaaaaaaaaaaaaaaaaaa"

	cases := []struct {
		name string
		cfg  dokploy.Config
	}{
		{"missing base url", dokploy.Config{Token: secret}},
		{"non-absolute base url", dokploy.Config{BaseURL: "not-a-url", Token: secret}},
		{"bad scheme", dokploy.Config{BaseURL: "ftp://dokploy.test", Token: secret}},
		{"missing token", dokploy.Config{BaseURL: "https://dokploy.test"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := dokploy.New(tc.cfg)
			if err == nil {
				t.Fatal("New returned nil error for bad config")
			}
			if code := codeOf(t, err); code != yerr.CodeConfig {
				t.Fatalf("code = %s, want %s", code, yerr.CodeConfig)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("config error echoed the token: %q", err.Error())
			}
		})
	}
}

// TestClientPropagatesCorrelationIDs proves the request_id / correlation_id on
// the context are forwarded to Dokploy as headers.
func TestClientPropagatesCorrelationIDs(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)

	ctx := telemetry.WithCorrelation(context.Background(), telemetry.Correlation{
		RequestID:     "req_abc123",
		CorrelationID: "corr_xyz789",
	})
	if _, err := c.EnsureOrganization(ctx, dokploy.EnsureOrganizationInput{Name: "acme"}); err != nil {
		t.Fatalf("EnsureOrganization: %v", err)
	}

	reqs := fake.Requests()
	last := reqs[len(reqs)-1]
	if got := last.Headers.Get(telemetry.HeaderRequestID); got != "req_abc123" {
		t.Fatalf("X-Request-Id = %q, want req_abc123", got)
	}
	if got := last.Headers.Get(telemetry.HeaderCorrelationID); got != "corr_xyz789" {
		t.Fatalf("X-Correlation-Id = %q, want corr_xyz789", got)
	}
}

// TestClientLogValueRedactsToken proves logging a Client value does not leak
// the token.
func TestClientLogValueRedactsToken(t *testing.T) {
	t.Parallel()
	fake := dokployfake.New()
	defer fake.Close()
	c := newTestClient(t, fake)

	if strings.Contains(c.LogValue().String(), fake.Token()) {
		t.Fatalf("Client.LogValue leaked the token: %s", c.LogValue())
	}
}
