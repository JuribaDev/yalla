// Command yalla-api runs the Yalla Control Plane HTTP API.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	redis "github.com/redis/go-redis/v9"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/backoffice"
	"github.com/JuribaDev/yalla/internal/controlplane/backup"
	"github.com/JuribaDev/yalla/internal/controlplane/config"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/entitlements"
	"github.com/JuribaDev/yalla/internal/controlplane/httpapi"
	"github.com/JuribaDev/yalla/internal/controlplane/jobs"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/quota"
	"github.com/JuribaDev/yalla/internal/controlplane/ratelimit"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/store/migrate"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func main() {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		slog.Error("invalid yalla-api command line", "error", err.Error())
		os.Exit(2)
	}
	if opts.version {
		printVersion("yalla-api")
		return
	}

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

	// signal.NotifyContext cancels ctx on SIGINT/SIGTERM; every lifecycle
	// component below derives its shutdown from that single context. The
	// migration-only command uses the same cancellation semantics as the HTTP
	// server path so operators can interrupt a blocked database operation
	// cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if opts.migrateOnly {
		if err := runMigrationCommand(ctx, pool, logger); err != nil {
			logger.Error("migration command failed", "error", err.Error())
			os.Exit(1)
		}
		logger.Info("migration command completed")
		return
	}
	if opts.seedAdmin {
		dataStore, err := store.New(pool, logger)
		if err != nil {
			logger.Error("failed to initialize the persistence layer", "error", err.Error())
			os.Exit(1)
		}
		if err := runSeedAdminCommand(ctx, dataStore, logger, opts); err != nil {
			logger.Error("seed admin command failed", "error", err.Error())
			os.Exit(1)
		}
		logger.Info("seed admin command completed")
		return
	}

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
	subscriptionRepo := store.NewSubscriptionRepository()
	entitlementResolver, err := entitlements.NewResolver(dataStore, subscriptionRepo)
	if err != nil {
		logger.Error("failed to initialize the entitlement resolver", "error", err.Error())
		os.Exit(1)
	}
	planLookup := store.PlanLookup(subscriptionRepo.PlanLookup)
	quotaChecker, err := quota.NewChecker(
		store.NewQuotaRepository(),
		quota.PlanResolverFunc(subscriptionRepo.PlanLookup),
		quota.WithEntitlementResolver(entitlementResolver),
		quota.WithMetrics(telemetry.DefaultQuotaUsageMetrics),
	)
	if err != nil {
		logger.Error("failed to initialize the quota checker", "error", err.Error())
		os.Exit(1)
	}
	jobEnqueuer := jobs.NewEnqueuer()
	engine := policy.NewEngine()
	storeAuthz := policyStoreAuthorizer{engine: engine}
	organizationService, err := store.NewOrganizationService(dataStore, orgRepo, jobEnqueuer, auditRepo)
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
	// handler is reached; quotaChecker is the in-transaction entitlement-aware
	// dimension-level guard.
	membersQuota := quotaChecker
	membershipService, err := store.NewMembershipService(dataStore, orgRepo, membershipRepo, membersQuota, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the membership service", "error", err.Error())
		os.Exit(1)
	}
	limits, err := store.NewLimitsReader(dataStore, planLookup)
	if err != nil {
		logger.Error("failed to initialize the limits reader", "error", err.Error())
		os.Exit(1)
	}
	quotaRepo := store.NewQuotaRepository()
	limitsService, err := store.NewLimitsService(dataStore, orgRepo, quotaRepo, auditRepo, planLookup)
	if err != nil {
		logger.Error("failed to initialize the limits service", "error", err.Error())
		os.Exit(1)
	}
	usage, err := store.NewUsageReader(dataStore, planLookup)
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
	// Defense-in-depth quota port for the api-key mint unit of work.
	apiKeysQuota := quotaChecker
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
	// Defense-in-depth ports for the project unit of work. The HTTP RequireAuth
	// middleware is the authoritative request-boundary gate; the in-transaction
	// Authorizer re-checks the same policy engine before desired-state writes.
	projectAuthz := storeAuthz
	projectQuota := quotaChecker
	projectJobs := jobEnqueuer
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
	// Defense-in-depth ports for the environment unit of work. Policy, quota,
	// and jobs all run before the desired-state transaction commits.
	environmentAuthz := storeAuthz
	environmentQuota := quotaChecker
	environmentJobs := jobEnqueuer
	environmentService, err := store.NewEnvironmentService(dataStore, store.NewProjectRepository(), store.NewEnvironmentRepository(), environmentAuthz, environmentQuota, environmentJobs, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the environment service", "error", err.Error())
		os.Exit(1)
	}
	previewService, err := store.NewPreviewEnvironmentService(dataStore, store.NewProjectRepository(), store.NewEnvironmentRepository(), store.NewPreviewEnvironmentRepository(), environmentAuthz, environmentQuota, environmentJobs, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the preview environment service", "error", err.Error())
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
	// Defense-in-depth ports for service-scoped units of work. The store
	// authorizer reuses the same policy engine as the HTTP boundary.
	serviceAuthz := storeAuthz
	serviceQuota := quotaChecker
	serviceJobs := jobEnqueuer
	serviceService, err := store.NewServiceService(dataStore, store.NewProjectRepository(), store.NewEnvironmentRepository(), store.NewServiceRepository(), serviceAuthz, serviceQuota, serviceJobs, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the service service", "error", err.Error())
		os.Exit(1)
	}
	serviceBuildConfigService, err := store.NewServiceBuildConfigService(dataStore, store.NewServiceRepository(), store.NewServiceBuildConfigRepository(), serviceJobs, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the service build config service", "error", err.Error())
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
	serviceDomainService, err := store.NewServiceDomainService(dataStore, store.NewServiceRepository(), store.NewServiceDomainRepository(), serviceAuthz, serviceQuota, serviceJobs, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the service domain service", "error", err.Error())
		os.Exit(1)
	}
	serviceBackupReader, err := store.NewServiceBackupReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the service backup reader", "error", err.Error())
		os.Exit(1)
	}
	serviceBackupService, err := store.NewServiceBackupService(dataStore, store.NewServiceRepository(), store.NewServiceBackupRepository(), serviceAuthz, serviceQuota, serviceJobs, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the service backup service", "error", err.Error())
		os.Exit(1)
	}
	serviceVariables, err := store.NewServiceVariableReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the service variable reader", "error", err.Error())
		os.Exit(1)
	}
	serviceVariableService, err := store.NewServiceVariableService(dataStore, store.NewServiceRepository(), store.NewServiceVariableRepository(), serviceJobs, auditRepo, secretsProvider)
	if err != nil {
		logger.Error("failed to initialize the service variable service", "error", err.Error())
		os.Exit(1)
	}
	// DeploymentService composes the same authorizer / quota reserver / job
	// enqueuer triple ServiceService uses today. The HTTP
	// boundary is the authoritative authorization gate for
	// deployment.create; the in-tx Authorize is the defense-in-depth
	// re-check whose real adapter (a policy.Engine-driven port that
	// reads grant rows from the same *Tx as the desired-state write)
	// lands in a later story.
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
	jobReader, err := store.NewJobReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the job reader", "error", err.Error())
		os.Exit(1)
	}
	driftFindingReader, err := store.NewDriftFindingReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the drift finding reader", "error", err.Error())
		os.Exit(1)
	}
	dokployRefReader, err := store.NewDokployRefReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the dokploy ref reader", "error", err.Error())
		os.Exit(1)
	}
	adminImportService, err := store.NewAdminImportService(dataStore, orgRepo, store.NewJobRepository(), auditRepo)
	if err != nil {
		logger.Error("failed to initialize the admin import service", "error", err.Error())
		os.Exit(1)
	}
	adminConfigImpact, err := backoffice.NewStoreImpactReader(dataStore)
	if err != nil {
		logger.Error("failed to initialize the admin config impact reader", "error", err.Error())
		os.Exit(1)
	}
	adminConfigValidator := backoffice.NewValidator(backoffice.WithImpactReader(adminConfigImpact))
	adminConfigService, err := store.NewAdminConfigService(dataStore, orgRepo, store.NewAdminConfigRepository(), auditRepo)
	if err != nil {
		logger.Error("failed to initialize the admin config promotion service", "error", err.Error())
		os.Exit(1)
	}
	adminPlanService, err := store.NewAdminPlanService(dataStore, orgRepo, store.NewPricingPlanRepository(), auditRepo)
	if err != nil {
		logger.Error("failed to initialize the admin plan service", "error", err.Error())
		os.Exit(1)
	}
	adminSubscriptionService, err := store.NewAdminSubscriptionService(dataStore, orgRepo, store.NewPricingPlanRepository(), subscriptionRepo, auditRepo)
	if err != nil {
		logger.Error("failed to initialize the admin subscription service", "error", err.Error())
		os.Exit(1)
	}
	adminMeteringSourceService, err := store.NewAdminMeteringSourceService(dataStore, orgRepo, store.NewMeteringSourceRepository(), auditRepo, secretsProvider)
	if err != nil {
		logger.Error("failed to initialize the admin metering source service", "error", err.Error())
		os.Exit(1)
	}
	adminMetricDefinitionService, err := store.NewAdminMetricDefinitionService(dataStore, orgRepo, store.NewMetricDefinitionRepository(), auditRepo)
	if err != nil {
		logger.Error("failed to initialize the admin metric definition service", "error", err.Error())
		os.Exit(1)
	}
	adminAttributionRuleService, err := store.NewAdminAttributionRuleService(dataStore, orgRepo, store.NewAttributionRuleRepository(), auditRepo)
	if err != nil {
		logger.Error("failed to initialize the admin attribution rule service", "error", err.Error())
		os.Exit(1)
	}
	adminUsageAggregationScheduleService, err := store.NewAdminUsageAggregationScheduleService(dataStore, orgRepo, store.NewUsageAggregationScheduleRepository(), auditRepo)
	if err != nil {
		logger.Error("failed to initialize the admin usage aggregation schedule service", "error", err.Error())
		os.Exit(1)
	}
	adminBillingProviderService, err := store.NewAdminBillingProviderService(dataStore, orgRepo, store.NewBillingProviderConfigRepository(), auditRepo, secretsProvider)
	if err != nil {
		logger.Error("failed to initialize the admin billing provider service", "error", err.Error())
		os.Exit(1)
	}
	adminOveragePolicyService, err := store.NewAdminOveragePolicyService(dataStore, orgRepo, store.NewPricingPlanRepository(), store.NewOveragePolicyRepository(), auditRepo)
	if err != nil {
		logger.Error("failed to initialize the admin overage policy service", "error", err.Error())
		os.Exit(1)
	}
	adminFeatureFlagService, err := store.NewAdminFeatureFlagService(dataStore, orgRepo, store.NewFeatureFlagRepository(), auditRepo)
	if err != nil {
		logger.Error("failed to initialize the admin feature flag service", "error", err.Error())
		os.Exit(1)
	}
	breakGlassService, err := store.NewBreakGlassService(dataStore, store.NewOrganizationRepository(), store.NewBreakGlassRepository(), auditRepo, nil)
	if err != nil {
		logger.Error("failed to initialize the break-glass service", "error", err.Error())
		os.Exit(1)
	}
	authenticator, err := auth.NewAuthenticator(auth.AuthenticatorConfig{
		Store:               credentials,
		SigningKeys:         cfg.SigningKeys,
		InternalWorkerToken: cfg.InternalWorkerToken,
	})
	if err != nil {
		logger.Error("failed to initialize the authenticator", "error", err.Error())
		os.Exit(1)
	}
	build := runtime.BuildInfo{Version: Version, Commit: Commit, Date: Date}.Normalized()

	// Readiness gates the load balancer: /readyz reports 503 until every
	// startup dependency check passes, so traffic is only routed to a process
	// that can actually serve it. One gate per dependency the API needs:
	// database connectivity, migration state, the job queue, and the Dokploy
	// dependency when a Dokploy base URL is configured.
	readinessGates := []string{"database", "migrations", "queue"}
	var dokployChecker func(context.Context) error
	if cfg.DokployBaseURL != "" {
		readinessGates = append(readinessGates, "dokploy")
		dokployHealthClient, err := dokploy.New(dokploy.Config{
			BaseURL: cfg.DokployBaseURL,
			Token:   cfg.DokployToken,
			Logger:  logger,
		})
		if err != nil {
			logger.Error("failed to initialize the Dokploy health client", "error", err.Error())
			os.Exit(1)
		}
		dokployChecker = func(ctx context.Context) error {
			_, err := dokployHealthClient.GetUserServerMetrics(ctx)
			return err
		}
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
		rlCfg := rateLimitConfigFromAppConfig(cfg.RateLimit)
		switch cfg.RateLimit.Backend {
		case config.RateLimitBackendRedis:
			opt, err := redis.ParseURL(cfg.RateLimit.RedisURL)
			if err != nil {
				logger.Error("invalid Redis rate-limit configuration", "error", config.EnvRateLimitRedisURL+" is invalid")
				os.Exit(1)
			}
			opt.DialTimeout = cfg.RateLimit.RedisTimeout
			opt.ReadTimeout = cfg.RateLimit.RedisTimeout
			opt.WriteTimeout = cfg.RateLimit.RedisTimeout
			client := redis.NewClient(opt)
			if err := client.Ping(ctx).Err(); err != nil {
				_ = client.Close()
				logger.Error("failed to connect to Redis rate-limit backend")
				os.Exit(1)
			}
			built, err := ratelimit.NewRedisLimiter(client, rlCfg, cfg.RateLimit.RedisPrefix)
			if err != nil {
				_ = client.Close()
				logger.Error("failed to initialize the Redis rate limiter", "error", err.Error())
				os.Exit(1)
			}
			defer func() { _ = built.Close() }()
			httpRateLimiter = built
		case config.RateLimitBackendMemory:
			built, err := ratelimit.New(rlCfg)
			if err != nil {
				logger.Error("failed to initialize the rate limiter", "error", err.Error())
				os.Exit(1)
			}
			defer func() { _ = built.Close() }()
			httpRateLimiter = built
		default:
			logger.Error("invalid rate-limit backend", "backend", cfg.RateLimit.Backend)
			os.Exit(1)
		}
	}
	clientIPResolver := httpapi.NewTrustedProxyClientIPResolver(cfg.TrustedProxyCIDRs)

	server := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           httpapi.NewHandler(build, readiness, meta, backupReporter, authenticator, engine, organizations, organizationService, organizationService, organizationService, members, membershipService, membershipService, membershipService, limits, limitsService, usage, auditEvents, orgVariables, orgVariableService, orgVariableService, orgVariableService, apiKeys, apiKeyService, apiKeyService, apiKeyService, apiKeyService, projects, projectService, projectService, projectService, projectService, projectGrants, projectGrantService, projectVariables, projectVariableService, projectEnvironments, environmentService, projectEnvironments, environmentService, environmentService, environmentService, environmentGrants, environmentGrantService, environmentVariables, environmentVariableService, environmentServices, serviceService, environmentServices, serviceService, serviceService, serviceService, serviceService, serviceService, serviceService, serviceLogReader, serviceMetricsReader, serviceDomainReader, serviceDomainService, serviceDomainService, serviceDomainService, serviceBackupReader, serviceBackupService, serviceBackupService, serviceBackupService, serviceBackupService, serviceVariables, serviceVariableService, deploymentService, deploymentReader, deploymentReader, deploymentService, deploymentService, breakGlassService, logger, httpRateLimiter, previewService, jobReader, driftFindingReader, dokployRefReader, adminImportService, adminConfigValidator, adminConfigService, adminPlanService, adminSubscriptionService, adminMeteringSourceService, adminMetricDefinitionService, adminAttributionRuleService, adminUsageAggregationScheduleService, adminBillingProviderService, adminOveragePolicyService, adminFeatureFlagService, serviceBuildConfigService, clientIPResolver),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
	}

	// Run startup checks in the background so the server can answer probes
	// immediately; /readyz only flips to ready once the checks pass.
	go func() {
		results := runStartupChecks(ctx, pool, meta, dokployChecker)
		markStartupReadiness(readiness, readinessGates, results)
		if pending := readiness.PendingGates(); len(pending) > 0 {
			logger.Error("startup dependency checks failed", "pending_gates", pending)
			return
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

type cliOptions struct {
	version                bool
	migrateOnly            bool
	seedAdmin              bool
	seedAdminEmail         string
	seedAdminOrganization  string
	seedAdminRole          string
	seedAdminRequestID     string
	seedAdminCorrelationID string
}

func parseOptions(args []string) (cliOptions, error) {
	var opts cliOptions
	fs := flag.NewFlagSet("yalla-api", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.BoolVar(&opts.version, "version", false, "print build version and exit without loading configuration")
	fs.BoolVar(&opts.migrateOnly, "migrate-only", false, "apply embedded database migrations and exit without starting the HTTP API")
	fs.BoolVar(&opts.seedAdmin, "seed-admin", false, "seed an initial operator user and membership, then exit without starting the HTTP API")
	fs.StringVar(&opts.seedAdminEmail, "seed-admin-email", "", "email address for the initial operator user")
	fs.StringVar(&opts.seedAdminOrganization, "seed-admin-organization", "", "organization name or slug for the initial operator tenant")
	fs.StringVar(&opts.seedAdminRole, "seed-admin-role", "owner", "organization role for the seeded operator user: owner, admin, or member")
	fs.StringVar(&opts.seedAdminRequestID, "seed-admin-request-id", "req_seed_admin", "stable request id to record on the seed audit event")
	fs.StringVar(&opts.seedAdminCorrelationID, "seed-admin-correlation-id", "corr_seed_admin", "stable correlation id to record on the seed audit event")
	if err := fs.Parse(args); err != nil {
		return cliOptions{}, err
	}
	if opts.version && (opts.migrateOnly || opts.seedAdmin) {
		return cliOptions{}, fmt.Errorf("version cannot be combined with maintenance modes")
	}
	if opts.migrateOnly && opts.seedAdmin {
		return cliOptions{}, fmt.Errorf("only one maintenance mode may be selected")
	}
	return opts, nil
}

func printVersion(name string) {
	build := runtime.BuildInfo{Version: Version, Commit: Commit, Date: Date}.Normalized()
	fmt.Fprintf(os.Stdout, "%s version=%s commit=%s date=%s\n", name, build.Version, build.Commit, build.Date)
}

func runMigrationCommand(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	migrator, err := migrate.New(pool, logger)
	if err != nil {
		return err
	}
	status, err := migrator.Status(ctx)
	if err != nil {
		return err
	}
	logger.Info("migration command starting",
		"current_version", status.Current,
		"pending_count", len(status.Pending),
		"dirty", status.Dirty)
	if err := migrator.Up(ctx); err != nil {
		return err
	}
	status, err = migrator.Status(ctx)
	if err != nil {
		return err
	}
	logger.Info("migration command applied embedded migrations",
		"current_version", status.Current,
		"pending_count", len(status.Pending),
		"dirty", status.Dirty)
	return nil
}

func runSeedAdminCommand(ctx context.Context, dataStore *store.Store, logger *slog.Logger, opts cliOptions) error {
	email := strings.TrimSpace(strings.ToLower(opts.seedAdminEmail))
	if email == "" || !strings.Contains(email, "@") {
		return fmt.Errorf("seed admin email must be a non-empty email address")
	}
	orgName := strings.TrimSpace(opts.seedAdminOrganization)
	if orgName == "" {
		return fmt.Errorf("seed admin organization must not be blank")
	}
	role := strings.TrimSpace(strings.ToLower(opts.seedAdminRole))
	switch role {
	case "owner", "admin", "member":
	default:
		return fmt.Errorf("seed admin role must be one of owner, admin, or member")
	}
	slug, err := domain.NormalizeSlug(orgName)
	if err != nil {
		return fmt.Errorf("seed admin organization slug: %w", err)
	}
	orgID, err := domain.NewID(domain.KindOrganization)
	if err != nil {
		return err
	}
	userID, err := domain.NewID(domain.KindUser)
	if err != nil {
		return err
	}

	var seededOrgID, seededUserID string
	auditRepo := store.NewAuditRepository()
	err = dataStore.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO organizations (id, slug, display_name)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (slug) DO UPDATE SET slug = EXCLUDED.slug
			 RETURNING id`,
			orgID.String(), slug.String(), orgName).Scan(&seededOrgID); err != nil {
			return err
		}
		displayName := seedAdminDisplayName(email)
		if err := tx.QueryRow(ctx,
			`INSERT INTO users (id, email, display_name)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
			 RETURNING id`,
			userID.String(), email, displayName).Scan(&seededUserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO memberships (organization_id, user_id, role)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (organization_id, user_id)
			 DO UPDATE SET role = EXCLUDED.role`,
			seededOrgID, seededUserID, role); err != nil {
			return err
		}
		_, err := auditRepo.Append(ctx, tx, store.AuditEvent{
			OrganizationID: seededOrgID,
			ActorKind:      "system",
			Action:         "admin.seed",
			ResourceKind:   string(domain.KindUser),
			ResourceID:     seededUserID,
			Decision:       store.AuditDecisionAllowed,
			Reason:         "operator seed admin command",
			RequestID:      strings.TrimSpace(opts.seedAdminRequestID),
			CorrelationID:  strings.TrimSpace(opts.seedAdminCorrelationID),
			Metadata: map[string]string{
				"organization_slug": slug.String(),
				"role":              role,
			},
		})
		return err
	})
	if err != nil {
		return err
	}

	logger.Info("seed admin command wrote source-of-truth rows",
		"organization_id", seededOrgID,
		"user_id", seededUserID,
		"role", role)
	return nil
}

func seedAdminDisplayName(email string) string {
	local, _, ok := strings.Cut(email, "@")
	if !ok || strings.TrimSpace(local) == "" {
		return "Seed Admin"
	}
	return local
}

// runStartupChecks verifies the dependencies the API needs before it can serve
// customer traffic. It reports one result per readiness gate: missing map keys
// mean that gate passed. A pool ping error is a connection-level failure and
// does not echo the connection string, so it is safe for the caller to log.
func runStartupChecks(ctx context.Context, pool *pgxpool.Pool, meta *runtime.Meta, dokployChecker func(context.Context) error) map[string]error {
	results := make(map[string]error)
	if err := pool.Ping(ctx); err != nil {
		results["database"] = err
	}
	migrator, err := migrate.New(pool, slog.Default())
	if err != nil {
		results["migrations"] = err
	} else if st, err := migrator.Status(ctx); err != nil {
		results["migrations"] = err
	} else {
		if meta != nil {
			meta.SetMigrationVersion(fmt.Sprintf("%04d", st.Current))
		}
		if st.Dirty || len(st.Pending) > 0 {
			results["migrations"] = apierr.MigrationRequired(fmt.Errorf(
				"migration current=%d pending=%d dirty=%v", st.Current, len(st.Pending), st.Dirty))
		}
	}
	if err := jobs.CheckQueueReady(ctx, pool); err != nil {
		results["queue"] = err
	}
	if dokployChecker != nil {
		if err := dokployChecker(ctx); err != nil {
			results["dokploy"] = err
		}
	}
	return results
}

func markStartupReadiness(readiness *runtime.Readiness, gates []string, results map[string]error) {
	if readiness == nil {
		return
	}
	for _, gate := range gates {
		readiness.Set(gate, results[gate] == nil)
	}
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
