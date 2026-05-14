// Command yalla-worker runs Yalla Control Plane background jobs.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/JuribaDev/yalla/internal/controlplane/config"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/worker"
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

	loop := &worker.Loop{
		// NoopClaimer is the placeholder until the durable Postgres-backed
		// job store lands with the persistence stories. With it the worker
		// starts, idles, and shuts down cleanly through the real run loop.
		Claimer:        worker.NoopClaimer{},
		Logger:         logger,
		ReleaseTimeout: cfg.ShutdownTimeout,
	}

	if err := loop.Run(ctx); err != nil {
		logger.Error("worker loop failed", "error", err)
		os.Exit(1)
	}

	logger.Info("yalla control-plane worker stopped")
}
