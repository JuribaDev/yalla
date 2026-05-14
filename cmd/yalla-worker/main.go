// Command yalla-worker runs Yalla Control Plane background jobs.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
)

var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func main() {
	build := runtime.BuildInfo{Version: Version, Commit: Commit, Date: Date}.Normalized()
	slog.Info("yalla control-plane worker starting", "version", build.Version, "commit", build.Commit, "date", build.Date)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	slog.Info("yalla control-plane worker stopped")
}
