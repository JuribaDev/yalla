// Command yalla-worker runs Yalla Control Plane background jobs.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/JuribaDev/yalla/internal/controlplane/config"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/worker"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func main() {
	// Resolve configuration before anything else so a misconfigured worker
	// fails fast with a deterministic exit code instead of half-starting.
	cfg, err := config.LoadFromEnv()
	if err != nil {
		slog.Error("invalid backend configuration", "error", err.Error())
		os.Exit(1)
	}

	// Service processes log structured JSON to stdout, one record per line.
	// The service name is bound once so every record carries it.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel})).
		With(slog.String("service", "yalla-worker"))
	slog.SetDefault(logger)

	build := runtime.BuildInfo{Version: Version, Commit: Commit, Date: Date}.Normalized()
	logger.Info("yalla control-plane worker starting",
		"version", build.Version, "commit", build.Commit, "date", build.Date,
		"shutdown_timeout", cfg.ShutdownTimeout.String(),
		slog.Any("config", cfg))

	// signal.NotifyContext cancels ctx on SIGINT/SIGTERM. The worker loop
	// derives its shutdown from this context: it stops claiming new jobs and
	// releases any in-flight lease so no work is lost.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.DatabaseURL == "" {
		logger.Error("invalid backend configuration",
			"error", "YALLA_DATABASE_URL is required to run the control-plane worker")
		os.Exit(1)
	}
	if cfg.DokployBaseURL == "" || cfg.DokployToken == "" {
		logger.Error("invalid backend configuration",
			"error", "YALLA_DOKPLOY_BASE_URL and YALLA_DOKPLOY_TOKEN are required to run the control-plane worker")
		os.Exit(1)
	}

	pool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		logger.Error("failed to initialize the database connection pool")
		os.Exit(1)
	}
	defer pool.Close()

	dataStore, err := store.New(pool, logger)
	if err != nil {
		logger.Error("failed to initialize the persistence layer", "error", err.Error())
		os.Exit(1)
	}
	dokployClient, err := dokploy.New(dokploy.Config{
		BaseURL: cfg.DokployBaseURL,
		Token:   cfg.DokployToken,
	})
	if err != nil {
		logger.Error("failed to initialize the Dokploy client", "error", err.Error())
		os.Exit(1)
	}
	provisioner, err := worker.NewProvisioner(worker.ProvisionerConfig{
		Store:  dataStore,
		Client: dokployClient,
		Mapper: dokploy.NewMapper(),
	})
	if err != nil {
		logger.Error("failed to initialize the provisioning runner", "error", err.Error())
		os.Exit(1)
	}
	claimer, err := worker.NewStoreClaimer(worker.StoreClaimerConfig{
		Store:  dataStore,
		Runner: provisioner,
		Owner:  worker.NewOwnerID(),
		Logger: logger,
	})
	if err != nil {
		logger.Error("failed to initialize the job claimer", "error", err.Error())
		os.Exit(1)
	}

	loop := &worker.Loop{
		Claimer:        claimer,
		Logger:         logger,
		ReleaseTimeout: cfg.ShutdownTimeout,
	}

	if err := loop.Run(ctx); err != nil {
		logger.Error("worker loop failed", "error", err)
		os.Exit(1)
	}

	logger.Info("yalla control-plane worker stopped")
}
