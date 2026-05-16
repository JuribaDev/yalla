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
	"github.com/JuribaDev/yalla/internal/controlplane/backup"
	"github.com/JuribaDev/yalla/internal/controlplane/config"
	"github.com/JuribaDev/yalla/internal/controlplane/httpapi"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/ratelimit"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
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
	// Defense-in-depth ports for the add-member unit of work. The HTTP
	// RequireAuth middleware authorizes action members.manage before the
	// handler is reached; the in-transaction QuotaReserver is the
	// dimension-level guard whose real adapter is quota.Checker — it lands
	// with the cross-cutting members quota plan-resolver story. Until then
	// this placeholder never rejects, mirroring the api_keys / project /
	// environment / service wiring so a misconfigured limit cannot block
	// production traffic before the real plan resolver is wired.
	membersQuota := noopQuotaReserver{}
	membershipService, err := store.NewMembershipService(dataStore, orgRepo, membershipRepo, membersQuota, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the membership service", "error", err.Error())
		os.Exit(1)
	}
	limits, err := store.NewLimitsReader(dataStore, nil)
	if err != nil {
		logger.Error("failed to initialize the limits reader", "error", err.Error())
		os.Exit(1)
	}
	quotaRepo := store.NewQuotaRepository()
	limitsService, err := store.NewLimitsService(dataStore, orgRepo, quotaRepo, auditRepo, nil)
	if err != nil {
		logger.Error("failed to initialize the limits service", "error", err.Error())
		os.Exit(1)
	}
	usage, err := store.NewUsageReader(dataStore, nil)
	if err != nil {
		logger.Error("failed to initialize the usage reader", "error", err.Error())
		os.Exit(1)
	}
	auditEvents, err := store.NewAuditEventReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the audit event reader", "error", err.Error())
		os.Exit(1)
	}
	orgVariables, err := store.NewOrganizationVariableReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the organization variable reader", "error", err.Error())
		os.Exit(1)
	}
	orgVariableRepo := store.NewOrganizationVariableRepository()
	secretsProvider, err := buildSecretsProvider(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize the secrets provider", "error", err.Error())
		os.Exit(1)
	}
	orgVariableService, err := store.NewOrganizationVariableService(dataStore, orgRepo, orgVariableRepo, auditRepo, secretsProvider)
	if err != nil {
		logger.Error("failed to initialize the organization variable service", "error", err.Error())
		os.Exit(1)
	}
	apiKeys, err := store.NewAPIKeyReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the api key reader", "error", err.Error())
		os.Exit(1)
	}
	// Defense-in-depth quota port for the api-key mint unit of work. The
	// real adapter is quota.Checker; it lands with the cross-cutting
	// api_keys quota plan-resolver story. Until then this placeholder
	// never rejects, mirroring the project/environment/service wiring
	// above so a misconfigured limit cannot block production traffic
	// before the real plan resolver is wired.
	apiKeysQuota := noopQuotaReserver{}
	apiKeyService, err := store.NewAPIKeyService(dataStore, orgRepo, serviceAccountRepo, apiKeyRepo, apiKeysQuota, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the api key service", "error", err.Error())
		os.Exit(1)
	}
	projects, err := store.NewProjectReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the project reader", "error", err.Error())
		os.Exit(1)
	}
	// Defense-in-depth ports for the project creation unit of work. The HTTP
	// RequireAuth middleware is the authoritative gate for action
	// project.create; the in-transaction Authorizer is a redundant check whose
	// real adapter (a policy.Engine-driven port that reads grant rows from
	// the same *Tx as the desired-state write) lands with the quota and jobs
	// adapters in later stories. Until those land, the placeholder always
	// allows — the policy boundary at the HTTP layer is what protects the
	// tenant boundary — and the quota and jobs ports record no-ops. A nil
	// dependency at the store-service construction site is rejected by
	// store.NewProjectService, so the placeholders also guard the contract
	// that ProjectService never runs with an unwired dependency.
	projectAuthz := alwaysAllowAuthorizer{}
	projectQuota := noopQuotaReserver{}
	projectJobs := noopJobEnqueuer{}
	projectService, err := store.NewProjectService(dataStore, store.NewProjectRepository(), projectAuthz, projectQuota, projectJobs, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the project service", "error", err.Error())
		os.Exit(1)
	}
	projectGrants, err := store.NewProjectGrantReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the project grant reader", "error", err.Error())
		os.Exit(1)
	}
	projectGrantService, err := store.NewProjectGrantService(dataStore, store.NewProjectRepository(), store.NewProjectGrantRepository(), auditRepo)
	if err != nil {
		logger.Error("failed to initialize the project grant service", "error", err.Error())
		os.Exit(1)
	}
	projectVariables, err := store.NewProjectVariableReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the project variable reader", "error", err.Error())
		os.Exit(1)
	}
	projectVariableService, err := store.NewProjectVariableService(dataStore, store.NewProjectRepository(), store.NewProjectVariableRepository(), auditRepo, secretsProvider)
	if err != nil {
		logger.Error("failed to initialize the project variable service", "error", err.Error())
		os.Exit(1)
	}
	projectEnvironments, err := store.NewEnvironmentReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the environment reader", "error", err.Error())
		os.Exit(1)
	}
	// Defense-in-depth ports for the environment creation unit of work. The
	// HTTP RequireAuth middleware is the authoritative gate for action
	// environment.create; the in-transaction Authorizer is a redundant check
	// whose real adapter (a policy.Engine-driven port that reads grant rows
	// from the same *Tx as the desired-state write) lands with the quota and
	// jobs adapters in later stories. Until those land, the placeholder always
	// allows — the policy boundary at the HTTP layer is what protects the
	// tenant boundary — and the quota and jobs ports record no-ops. A nil
	// dependency at the store-service construction site is rejected by
	// store.NewEnvironmentService, so the placeholders also guard the
	// contract that EnvironmentService never runs with an unwired dependency.
	environmentAuthz := alwaysAllowAuthorizer{}
	environmentQuota := noopQuotaReserver{}
	environmentJobs := noopJobEnqueuer{}
	environmentService, err := store.NewEnvironmentService(dataStore, store.NewProjectRepository(), store.NewEnvironmentRepository(), environmentAuthz, environmentQuota, environmentJobs, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the environment service", "error", err.Error())
		os.Exit(1)
	}
	environmentGrants, err := store.NewEnvironmentGrantReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the environment grant reader", "error", err.Error())
		os.Exit(1)
	}
	environmentGrantService, err := store.NewEnvironmentGrantService(dataStore, store.NewEnvironmentRepository(), store.NewEnvironmentGrantRepository(), auditRepo)
	if err != nil {
		logger.Error("failed to initialize the environment grant service", "error", err.Error())
		os.Exit(1)
	}
	environmentVariables, err := store.NewEnvironmentVariableReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the environment variable reader", "error", err.Error())
		os.Exit(1)
	}
	environmentVariableService, err := store.NewEnvironmentVariableService(dataStore, store.NewEnvironmentRepository(), store.NewEnvironmentVariableRepository(), auditRepo, secretsProvider)
	if err != nil {
		logger.Error("failed to initialize the environment variable service", "error", err.Error())
		os.Exit(1)
	}
	environmentServices, err := store.NewServiceReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the service reader", "error", err.Error())
		os.Exit(1)
	}
	// Defense-in-depth ports for the service creation unit of work.
	// As with environmentAuthz / environmentQuota / environmentJobs,
	// the HTTP RequireAuth middleware is the authoritative gate for
	// action service.create; the in-transaction Authorizer is a
	// redundant check whose real adapter (a policy.Engine-driven port
	// that reads grant rows from the same *Tx as the desired-state
	// write) lands with the quota and jobs adapters in later stories.
	// Until those land, the placeholder always allows — the policy
	// boundary at the HTTP layer is what protects the tenant boundary
	// — and the quota and jobs ports record no-ops. A nil dependency
	// at the store-service construction site is rejected by
	// store.NewServiceService, so the placeholders also guard the
	// contract that ServiceService never runs with an unwired
	// dependency.
	serviceAuthz := alwaysAllowAuthorizer{}
	serviceQuota := noopQuotaReserver{}
	serviceJobs := noopJobEnqueuer{}
	serviceService, err := store.NewServiceService(dataStore, store.NewProjectRepository(), store.NewEnvironmentRepository(), store.NewServiceRepository(), serviceAuthz, serviceQuota, serviceJobs, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the service service", "error", err.Error())
		os.Exit(1)
	}
	serviceLogReader, err := store.NewServiceLogReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the service log reader", "error", err.Error())
		os.Exit(1)
	}
	serviceMetricsReader, err := store.NewServiceMetricsReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the service metrics reader", "error", err.Error())
		os.Exit(1)
	}
	serviceDomainReader, err := store.NewServiceDomainReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the service domain reader", "error", err.Error())
		os.Exit(1)
	}
	serviceDomainService, err := store.NewServiceDomainService(dataStore, store.NewServiceRepository(), store.NewServiceDomainRepository(), serviceAuthz, serviceQuota, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the service domain service", "error", err.Error())
		os.Exit(1)
	}
	serviceBackupReader, err := store.NewServiceBackupReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the service backup reader", "error", err.Error())
		os.Exit(1)
	}
	serviceBackupService, err := store.NewServiceBackupService(dataStore, store.NewServiceRepository(), store.NewServiceBackupRepository(), serviceAuthz, serviceQuota, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the service backup service", "error", err.Error())
		os.Exit(1)
	}
	serviceVariables, err := store.NewServiceVariableReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the service variable reader", "error", err.Error())
		os.Exit(1)
	}
	serviceVariableService, err := store.NewServiceVariableService(dataStore, store.NewServiceRepository(), store.NewServiceVariableRepository(), auditRepo)
	if err != nil {
		logger.Error("failed to initialize the service variable service", "error", err.Error())
		os.Exit(1)
	}
	// DeploymentService composes the same placeholder authorizer / quota
	// reserver / job enqueuer triple ServiceService uses today. The HTTP
	// boundary is the authoritative authorization gate for
	// deployment.create; the in-tx Authorize is the defense-in-depth
	// re-check whose real adapter (a policy.Engine-driven port that
	// reads grant rows from the same *Tx as the desired-state write)
	// lands with the quota and jobs adapters in later stories.
	deploymentService, err := store.NewDeploymentService(dataStore, store.NewServiceRepository(), store.NewDeploymentRepository(), serviceAuthz, serviceQuota, serviceJobs, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the deployment service", "error", err.Error())
		os.Exit(1)
	}
	deploymentReader, err := store.NewDeploymentReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the deployment reader", "error", err.Error())
		os.Exit(1)
	}
	breakGlassService, err := store.NewBreakGlassService(dataStore, store.NewOrganizationRepository(), store.NewBreakGlassRepository(), auditRepo, nil)
	if err != nil {
		logger.Error("failed to initialize the break-glass service", "error", err.Error())
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

	// Backup health reporter drives /healthz/backup. When the operator wires
	// YALLA_BACKUP_STATUS_FILE, we read it on demand and surface the
	// timestamp; when it is empty (the default for local/test profiles and
	// for any operator who has not opted in) we install the Unconfigured
	// reporter so the probe still serves with configured=false. The reporter
	// never writes the file — the operator's backup pipeline owns that.
	var backupReporter backup.Reporter
	if cfg.BackupStatusFile != "" {
		fileReporter, err := backup.NewFileReporter(cfg.BackupStatusFile, cfg.BackupMaxAge, nil)
		if err != nil {
			// CodeConfig errors from the backup constructor name the field
			// but never echo a secret. Surface them at startup so a typo in
			// the env variable is loud and recoverable rather than silently
			// degrading the probe.
			logger.Error("failed to initialize the backup health reporter", "error", err.Error())
			os.Exit(1)
		}
		backupReporter = fileReporter
		logger.Info("backup health reporter wired",
			"path", cfg.BackupStatusFile,
			"max_age", cfg.BackupMaxAge.String())
	} else {
		backupReporter = backup.Unconfigured()
	}

	// The rate limiter is wired inside the HTTP authorization middleware
	// so the resolved principal (org id, API key id, auth method) is on
	// the request context when the gate decides. A disabled or zero
	// RateLimit config produces a nil limiter, which the httpapi
	// middleware treats as a passthrough — so an operator can turn the
	// limiter off without changing the wiring.
	var httpRateLimiter httpapi.RateLimiter
	if cfg.RateLimit.AnyEnabled() {
		built, err := ratelimit.New(rateLimitConfigFromAppConfig(cfg.RateLimit))
		if err != nil {
			logger.Error("failed to initialize the rate limiter", "error", err.Error())
			os.Exit(1)
		}
		httpRateLimiter = built
	}

	server := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           httpapi.NewHandler(build, readiness, meta, backupReporter, authenticator, engine, organizations, organizationService, organizationService, organizationService, members, membershipService, membershipService, membershipService, limits, limitsService, usage, auditEvents, orgVariables, orgVariableService, orgVariableService, orgVariableService, apiKeys, apiKeyService, apiKeyService, apiKeyService, apiKeyService, projects, projectService, projectService, projectService, projectService, projectGrants, projectGrantService, projectVariables, projectVariableService, projectEnvironments, environmentService, projectEnvironments, environmentService, environmentService, environmentService, environmentGrants, environmentGrantService, environmentVariables, environmentVariableService, environmentServices, serviceService, environmentServices, serviceService, serviceService, serviceService, serviceService, serviceService, serviceService, serviceLogReader, serviceMetricsReader, serviceDomainReader, serviceDomainService, serviceDomainService, serviceDomainService, serviceBackupReader, serviceBackupService, serviceBackupService, serviceBackupService, serviceBackupService, serviceVariables, serviceVariableService, deploymentService, deploymentReader, deploymentReader, deploymentService, deploymentService, breakGlassService, logger, httpRateLimiter),
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

// buildSecretsProvider chooses the at-rest secret-protection provider
// based on the resolved configuration profile.
//
//   - Strict profiles (staging, production) require YALLA_SECRET_KEYS to
//     be configured (config.Validate enforces presence). buildSecretsProvider
//     decodes the hex-encoded keys and returns an AES-256-GCM provider.
//     A configuration where SecretKeys is somehow empty in a strict
//     profile is rejected here as defence-in-depth (never reaches this
//     code path under Validate, but the failure mode is explicit if it
//     ever does).
//
//   - Permissive profiles (local, test) accept either a configured
//     SecretKeys list (so a developer can exercise the production
//     codepath locally) or no SecretKeys (the Plaintext passthrough
//     provider is returned with a warning log so the operator notices
//     they have no at-rest encryption). The Plaintext provider is NEVER
//     returned from a strict profile.
//
// The returned provider is logged through its slog.LogValuer so the
// startup record carries only the provider id and key id — the key
// material never appears in any log.
func buildSecretsProvider(cfg *config.Config, logger *slog.Logger) (secrets.Provider, error) {
	keys, err := cfg.DecodedSecretKeys()
	if err != nil {
		return nil, err
	}
	if len(keys) > 0 {
		provider, err := secrets.NewAESGCM(keys)
		if err != nil {
			return nil, err
		}
		logger.Info("secrets provider configured", "provider", provider)
		return provider, nil
	}
	if cfg.Profile.IsStrict() {
		return nil, errStrictProfileMissingSecretKeys
	}
	provider := secrets.NewPlaintext()
	logger.Warn("secrets provider falling back to plaintext (no YALLA_SECRET_KEYS configured)", "provider", provider, "profile", cfg.Profile)
	return provider, nil
}

// errStrictProfileMissingSecretKeys is the sentinel for the
// defence-in-depth check inside buildSecretsProvider. config.Validate
// should reject a strict profile without YALLA_SECRET_KEYS before
// buildSecretsProvider is ever called; this sentinel is the explicit
// failure if that invariant is somehow violated.
var errStrictProfileMissingSecretKeys = errStrictProfileMissingSecretKeysFn()

func errStrictProfileMissingSecretKeysFn() error {
	return missingSecretKeysErr{}
}

type missingSecretKeysErr struct{}

func (missingSecretKeysErr) Error() string {
	return "YALLA_SECRET_KEYS is required in strict profiles"
}

// alwaysAllowAuthorizer is a placeholder store.Authorizer for the project
// creation unit of work. The authoritative authorization for POST
// /v1/projects is the HTTP RequireAuth middleware, which authorizes action
// project.create against the principal's home organization before the
// handler runs; the in-transaction Authorizer step is defense-in-depth that
// will become a real policy.Engine-driven adapter when its story lands.
// Until then, this placeholder always allows — never overriding the HTTP
// gate, but never running an extra check either.
type alwaysAllowAuthorizer struct{}

func (alwaysAllowAuthorizer) Authorize(context.Context, store.Querier, string, string) error {
	return nil
}

// noopQuotaReserver is a placeholder store.QuotaReserver for the project
// creation unit of work. The real adapter is quota.Checker; it lands with
// the project-quota plan-resolver story. Until then, this placeholder never
// rejects — a misconfigured limit cannot block production traffic before
// the real plan resolver is wired.
type noopQuotaReserver struct{}

func (noopQuotaReserver) Reserve(context.Context, *store.Tx, string, string) error { return nil }

func (noopQuotaReserver) ReserveAmount(context.Context, *store.Tx, string, string, int64) error {
	return nil
}

// noopJobEnqueuer is a placeholder store.JobEnqueuer for the project
// creation unit of work. The real adapter mints a durable provisioning job
// row through store.JobRepository.Insert with a per-request idempotency key
// and lands with the project provisioning worker story. Until then, this
// placeholder records nothing — the desired-state row still commits, and
// the provisioning side will be reconciled when the worker lands.
type noopJobEnqueuer struct{}

func (noopJobEnqueuer) Enqueue(context.Context, *store.Tx, string, string, string) error { return nil }

// rateLimitConfigFromAppConfig adapts the resolved config.RateLimit
// struct onto the ratelimit.Config the limiter consumes. The translation
// is purely structural — Specs.Read/Write maps to the read- and write-
// side fields on the application config — so the wire-level env vars
// stay the single source of truth for operator-visible knobs.
func rateLimitConfigFromAppConfig(r config.RateLimit) ratelimit.Config {
	return ratelimit.Config{
		Org: ratelimit.Specs{
			Read:  ratelimit.Spec{Rate: r.OrgReadRPS, Burst: r.OrgReadBurst},
			Write: ratelimit.Spec{Rate: r.OrgWriteRPS, Burst: r.OrgWriteBurst},
		},
		Key: ratelimit.Specs{
			Read:  ratelimit.Spec{Rate: r.KeyReadRPS, Burst: r.KeyReadBurst},
			Write: ratelimit.Spec{Rate: r.KeyWriteRPS, Burst: r.KeyWriteBurst},
		},
		IP: ratelimit.Specs{
			Read:  ratelimit.Spec{Rate: r.IPReadRPS, Burst: r.IPReadBurst},
			Write: ratelimit.Spec{Rate: r.IPWriteRPS, Burst: r.IPWriteBurst},
		},
		IdleTTL: r.IdleTTL,
	}
}
