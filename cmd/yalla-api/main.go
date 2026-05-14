// Command yalla-api runs the Yalla Control Plane HTTP API.
package main

import (
	"context"
	"errors"
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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)
	logger.Info("yalla control-plane api configuration loaded", slog.Any("config", cfg))

	server := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           httpapi.NewHandler(runtime.BuildInfo{Version: Version, Commit: Commit, Date: Date}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("yalla control-plane api listening", "addr", cfg.APIAddr)
		errCh <- server.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("api shutdown failed", "error", err)
			os.Exit(1)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("api server failed", "error", err)
			os.Exit(1)
		}
	}
}
