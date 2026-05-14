// Command yalla-api runs the Yalla Control Plane HTTP API.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/config"
	"github.com/JuribaDev/yalla/internal/controlplane/httpapi"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
)

var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func main() {
	// Resolve configuration before anything else so a misconfigured process
	// fails fast with a deterministic exit code instead of half-starting.
	cfg, err := config.LoadFromEnv()
	if err != nil {
		// The config loader guarantees CodeConfig errors never echo secret
		// values, so logging err.Error() here is safe.
		slog.Error("invalid backend configuration", "error", err.Error())
		os.Exit(1)
	}

	// Service processes log structured JSON to stdout so a container runtime
	// or log shipper captures one record per line. The service name is bound
	// once here so every record — including the per-request logs emitted by
	// telemetry.RequestLogging — carries it.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel})).
		With(slog.String("service", "yalla-api"))
	slog.SetDefault(logger)
	logger.Info("yalla control-plane api configuration loaded", slog.Any("config", cfg))

	build := runtime.BuildInfo{Version: Version, Commit: Commit, Date: Date}.Normalized()

	// Readiness gates the load balancer: /readyz reports 503 until every
	// startup dependency check passes, so traffic is only routed to a process
	// that can actually serve it. One gate per dependency the API needs —
	// database connectivity, migration state, and the job queue — plus the
	// Dokploy dependency when a Dokploy base URL is configured. The real
	// probes land with the persistence and provisioning stories; the gate
	// scaffolding is wired now so the readiness transition and the /readyz
	// per-check payload are exercised end to end.
	readinessGates := []string{"database", "migrations", "queue"}
	if cfg.DokployBaseURL != "" {
		readinessGates = append(readinessGates, "dokploy")
	}
	readiness := runtime.NewReadiness(readinessGates...)

	// Meta supplies the dynamic fields of /version. The applied migration
	// version is unknown until the persistence layer resolves it; the startup
	// goroutine populates it once the migration check lands.
	meta := runtime.NewMeta()

	server := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           httpapi.NewHandler(build, readiness, meta, logger),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// signal.NotifyContext cancels ctx on SIGINT/SIGTERM; every lifecycle
	// component below derives its shutdown from that single context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Run startup checks in the background so the server can answer probes
	// immediately; /readyz only flips to ready once the checks pass.
	go func() {
		if err := runStartupChecks(ctx); err != nil {
			logger.Error("startup dependency checks failed", "error", err)
			return
		}
		// Placeholder: the real database, migration, queue, and Dokploy
		// probes land with the persistence and provisioning stories, which
		// will also resolve the applied migration version onto meta. Marking
		// every gate ready here keeps the readiness transition wired end to
		// end so /readyz flips to 200 once startup completes.
		for _, gate := range readinessGates {
			readiness.MarkReady(gate)
		}
		logger.Info("startup dependency checks passed; api is ready to serve traffic")
	}()

	logger.Info("yalla control-plane api listening", "addr", cfg.APIAddr,
		"shutdown_timeout", cfg.ShutdownTimeout.String())
	if err := runtime.RunHTTPServer(ctx, server, cfg.ShutdownTimeout, logger); err != nil {
		logger.Error("api server lifecycle failed", "error", err)
		os.Exit(1)
	}
	logger.Info("yalla control-plane api stopped")
}

// runStartupChecks verifies the dependencies the API needs before it can
// serve customer traffic. It is a placeholder today: database connectivity
// and migration-state checks land with the persistence stories. Keeping the
// hook here means the readiness transition — unready until checks pass — is
// wired end to end now.
func runStartupChecks(ctx context.Context) error {
	return ctx.Err()
}
