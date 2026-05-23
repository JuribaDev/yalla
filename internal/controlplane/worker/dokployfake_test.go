package worker_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/dokploy/dokployfake"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/JuribaDev/yalla/internal/controlplane/worker"
	"github.com/JuribaDev/yalla/internal/output"
)

// TestWorkerRunnerProvisionsThroughFakeDokploy is the worker's integration
// test against Dokploy: it drives a JobRunner through worker.Loop and proves
// the runner provisions an org -> project -> environment -> application ->
// deployment chain by talking to the in-memory fake — never a live Dokploy
// server — and that every request the worker made was recorded with its
// credentials redacted.
func TestWorkerRunnerProvisionsThroughFakeDokploy(t *testing.T) {
	t.Parallel()

	fake := dokployfake.New()
	defer fake.Close()

	runner := worker.RunnerFunc(func(ctx context.Context, _ store.ProvisioningJob) error {
		return provisionViaFakeDokploy(ctx, fake.URL(), fake.Token())
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var claims atomic.Int64
	var runErr error
	claimer := claimerFunc(func(context.Context) (worker.Lease, error) {
		if claims.Add(1) > 1 {
			return nil, nil // queue drained after the one provisioning job
		}
		return &fakeLease{run: func(runCtx context.Context) error {
			runErr = runner.Run(runCtx, store.ProvisioningJob{})
			cancel() // one job is enough; begin a clean shutdown
			return runErr
		}}, nil
	})

	loop := &worker.Loop{Claimer: claimer, IdleDelay: time.Millisecond}
	if err := loop.Run(ctx); err != nil {
		t.Fatalf("loop.Run returned %v, want nil", err)
	}
	if runErr != nil {
		t.Fatalf("provisioning runner failed against fake Dokploy: %v", runErr)
	}

	reqs := fake.Requests()
	if len(reqs) == 0 {
		t.Fatal("worker made no calls to the fake Dokploy server")
	}
	for _, rec := range reqs {
		if rec.AuthHeader != output.Sentinel {
			t.Fatalf("worker request to %s %s did not redact its Authorization header: %q",
				rec.Method, rec.Path, rec.AuthHeader)
		}
		// No recorded request body may contain the bearer token verbatim.
		testutil.AssertRedacted(t, rec.Body, fake.Token())
	}
}

// TestWorkerRunnerSurfacesFakeDokployFaults proves a worker test can exercise
// the failure path: an injected 500 from the fake propagates out of the runner
// as an error the worker's retry machinery would act on.
func TestWorkerRunnerSurfacesFakeDokployFaults(t *testing.T) {
	t.Parallel()

	fake := dokployfake.New()
	defer fake.Close()
	fake.QueueFault(dokployfake.StatusFault(http.StatusInternalServerError))

	runner := worker.RunnerFunc(func(ctx context.Context, _ store.ProvisioningJob) error {
		return provisionViaFakeDokploy(ctx, fake.URL(), fake.Token())
	})

	if err := runner.Run(context.Background(), store.ProvisioningJob{}); err == nil {
		t.Fatal("runner returned nil, want an error from the injected 500")
	}
}

// provisionViaFakeDokploy performs a minimal end-to-end provisioning chain
// against a Dokploy-shaped HTTP API: organization -> project -> environment ->
// application -> deployment, then confirms the deployment succeeded.
func provisionViaFakeDokploy(ctx context.Context, baseURL, token string) error {
	orgID, err := dokployCreate(ctx, baseURL, token, "/api/organizations",
		map[string]any{"name": "acme"})
	if err != nil {
		return fmt.Errorf("create organization: %w", err)
	}
	projID, err := dokployCreate(ctx, baseURL, token, "/api/projects",
		map[string]any{"organization_id": orgID, "name": "store"})
	if err != nil {
		return fmt.Errorf("create project: %w", err)
	}
	envID, err := dokployCreate(ctx, baseURL, token, "/api/environments",
		map[string]any{"project_id": projID, "name": "production"})
	if err != nil {
		return fmt.Errorf("create environment: %w", err)
	}
	svcID, err := dokployCreate(ctx, baseURL, token, "/api/applications",
		map[string]any{"environment_id": envID, "name": "api"})
	if err != nil {
		return fmt.Errorf("create application: %w", err)
	}

	depID, err := dokployCreate(ctx, baseURL, token, "/api/deployments",
		map[string]any{"service_id": svcID})
	if err != nil {
		return fmt.Errorf("trigger deployment: %w", err)
	}

	dep, err := dokployGet(ctx, baseURL, token, "/api/deployments/"+depID)
	if err != nil {
		return fmt.Errorf("read deployment: %w", err)
	}
	if dep["status"] != dokployfake.DeploymentSucceeded {
		return fmt.Errorf("deployment %s status = %v, want succeeded", depID, dep["status"])
	}
	return nil
}

// dokployCreate POSTs body to path and returns the created resource's ID.
func dokployCreate(ctx context.Context, baseURL, token, path string, body map[string]any) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, payload)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return "", err
	}
	id, _ := decoded["id"].(string)
	if id == "" {
		return "", fmt.Errorf("response missing id: %s", payload)
	}
	return id, nil
}

// dokployGet GETs path and returns the decoded JSON object.
func dokployGet(ctx context.Context, baseURL, token, path string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, payload)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}
