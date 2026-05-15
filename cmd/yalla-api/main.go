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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/config"
	"github.com/JuribaDev/yalla/internal/controlplane/httpapi"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
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

	// The control plane cannot authenticate a request — and therefore cannot
	// serve any customer-facing endpoint — without its source-of-truth
	// database. The strict profiles already require YALLA_DATABASE_URL; this
	// guard makes the same requirement explicit for every profile so the API
	// never starts in a state where /v1/me would have no credential store.
	if cfg.DatabaseURL == "" {
		slog.Error("invalid backend configuration",
			"error", "YALLA_DATABASE_URL is required to run the control-plane API")
		os.Exit(1)
	}

	// The connection pool outlives any single request, so it is created from a
	// background context and closed explicitly on shutdown. A pool-construction
	// failure can echo the connection string, so the raw error is deliberately
	// not logged here — only a fixed, secret-free message.
	pool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to initialize the database connection pool")
		os.Exit(1)
	}
	defer pool.Close()

	// The persistence layer, the credential adapter, and the authenticator are
	// resolved once at startup and shared across every request. The
	// authenticator resolves inbound bearer credentials into a principal; the
	// policy engine authorizes that principal against each route's action.
	dataStore, err := store.New(pool, logger)
	if err != nil {
		logger.Error("failed to initialize the persistence layer", "error", err.Error())
		os.Exit(1)
	}
	credentials, err := store.NewCredentialReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the credential reader", "error", err.Error())
		os.Exit(1)
	}
	organizations, err := store.NewOrganizationReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the organization reader", "error", err.Error())
		os.Exit(1)
	}
	orgRepo := store.NewOrganizationRepository()
	membershipRepo := store.NewMembershipRepository()
	auditRepo := store.NewAuditRepository()
	serviceAccountRepo := store.NewServiceAccountRepository()
	apiKeyRepo := store.NewAPIKeyRepository()
	organizationService, err := store.NewOrganizationService(dataStore, orgRepo, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the organization service", "error", err.Error())
		os.Exit(1)
	}
	members, err := store.NewMembershipReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the membership reader", "error", err.Error())
		os.Exit(1)
	}
	membershipService, err := store.NewMembershipService(dataStore, orgRepo, membershipRepo, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the membership service", "error", err.Error())
		os.Exit(1)
	}
	apiKeys, err := store.NewAPIKeyReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the api key reader", "error", err.Error())
		os.Exit(1)
	}
	apiKeyService, err := store.NewAPIKeyService(dataStore, orgRepo, serviceAccountRepo, apiKeyRepo, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the api key service", "error", err.Error())
		os.Exit(1)
	}
	authenticator, err := auth.NewAuthenticator(auth.AuthenticatorConfig{
		Store:       credentials,
		SigningKeys: cfg.SigningKeys,
	})
	if err != nil {
		logger.Error("failed to initialize the authenticator", "error", err.Error())
		os.Exit(1)
	}
	engine := policy.NewEngine()

	build := runtime.BuildInfo{Version: Version, Commit: Commit, Date: Date}.Normalized()

	// Readiness gates the load balancer: /readyz reports 503 until every
	// startup dependency check passes, so traffic is only routed to a process
	// that can actually serve it. One gate per dependency the API needs —
	// database connectivity, migration state, and the job queue — plus the
	// Dokploy dependency when a Dokploy base URL is configured. The database
	// gate is backed by a real connectivity probe below; the migration and
	// queue probes land with their own stories.
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
		Handler:           httpapi.NewHandler(build, readiness, meta, authenticator, engine, organizations, organizationService, organizationService, organizationService, members, membershipService, membershipService, membershipService, apiKeys, apiKeyService, apiKeyService, logger),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// signal.NotifyContext cancels ctx on SIGINT/SIGTERM; every lifecycle
	// component below derives its shutdown from that single context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Run startup checks in the background so the server can answer probes
	// immediately; /readyz only flips to ready once the checks pass.
	go func() {
		if err := runStartupChecks(ctx, pool); err != nil {
			logger.Error("startup dependency checks failed", "error", err.Error())
			return
		}
		// The database gate is now backed by a real connectivity probe. The
		// remaining gates stay placeholder marks: the migration-state and queue
		// probes land with the persistence and worker stories.
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

// runStartupChecks verifies the dependencies the API needs before it can serve
// customer traffic. It probes database connectivity through the shared pool;
// migration-state and queue checks land with the persistence and worker
// stories. A pool ping error is a connection-level failure and does not echo
// the connection string, so it is safe for the caller to log.
func runStartupChecks(ctx context.Context, pool *pgxpool.Pool) error {
	if err := pool.Ping(ctx); err != nil {
		return err
	}
	return nil
}
