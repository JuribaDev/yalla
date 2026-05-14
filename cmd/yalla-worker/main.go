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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	build := runtime.BuildInfo{Version: Version, Commit: Commit, Date: Date}.Normalized()
	logger.Info("yalla control-plane worker starting",
		"version", build.Version, "commit", build.Commit, "date", build.Date,
		slog.Any("config", cfg))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("yalla control-plane worker stopped")
}
