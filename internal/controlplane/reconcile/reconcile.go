package reconcile

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// DesiredStateReader returns the source-of-truth view of an organization.
// Adapters typically wrap a *store.Store; the reconcile package itself has no
// Postgres dependency.
type DesiredStateReader interface {
	Read(ctx context.Context, orgID domain.ID) (DesiredOrganization, error)
}

// ActualStateReader returns the live Dokploy view of the same organization,
// scoped to the tenant's Dokploy organization. Adapters typically wrap a
// *dokploy.Client.
type ActualStateReader interface {
	Read(ctx context.Context, dokployOrganizationID string) (ActualOrganization, error)
}

// Repairer applies safe drift repairs. Each method is a single, idempotent
// operation; the engine routes one method call per Plan action and treats
// per-action failures as best-effort (the rest of the plan still runs).
type Repairer interface {
	// UpdateEnvVar writes value under key on the Dokploy service named by
	// ref. secret reports whether the value is sensitive; adapters that
	// route secrets to a secret store consult this flag, but neither value
	// nor secret are ever logged.
	UpdateEnvVar(ctx context.Context, ref ServiceRef, key, value string, secret bool) error
	// RemoveEnvVar removes key from the Dokploy service named by ref.
	RemoveEnvVar(ctx context.Context, ref ServiceRef, key string) error
	// UpdateBuildConfig converges the service's build settings to the
	// desired source-of-truth spec.
	UpdateBuildConfig(ctx context.Context, ref ServiceRef, build dokploy.BuildSettings) error
	// EnsureDomain re-binds the desired domain on the Dokploy service named
	// by ref.
	EnsureDomain(ctx context.Context, ref ServiceRef, d DesiredDomain) error
}

// ReviewRecorder records dangerous drift the engine refuses to auto-repair.
// Adapters persist the event so a human operator can triage it.
type ReviewRecorder interface {
	Record(ctx context.Context, event ReviewEvent) error
}

// UnmanagedRecorder records Dokploy resources without a Yalla counterpart.
// Adapters persist them in a quarantine table; unmanaged resources are never
// auto-deleted and never exposed to customers by default.
type UnmanagedRecorder interface {
	Mark(ctx context.Context, resource UnmanagedResource) error
}

// Config bundles the dependencies a Reconciler needs. Every field is required
// except Logger, Now, and Redactor (each has a sensible default).
type Config struct {
	Desired   DesiredStateReader
	Actual    ActualStateReader
	Repairer  Repairer
	Reviewer  ReviewRecorder
	Unmanaged UnmanagedRecorder
	Logger    *slog.Logger
	// Now is an injectable clock; tests set it for determinism. A nil value
	// defaults to time.Now().UTC.
	Now func() time.Time
	// Redactor scrubs Dokploy/Yalla error strings before they reach logs.
	// A nil value defaults to a fresh output.NewRedactor() with no literal
	// secrets registered, which still scrubs Authorization-style headers
	// and token-bearing query parameters from upstream error dumps.
	Redactor *output.Redactor
}

// Reconciler detects and resolves drift between desired and actual state. It
// is safe for concurrent use across multiple worker ticks.
type Reconciler struct {
	desired   DesiredStateReader
	actual    ActualStateReader
	repairer  Repairer
	reviewer  ReviewRecorder
	unmanaged UnmanagedRecorder
	logger    *slog.Logger
	now       func() time.Time
	redactor  *output.Redactor
}

// New validates cfg and returns a ready Reconciler. Construction failures are
// typed apierr.Internal errors: a misconfigured reconciler is a Yalla
// deployment bug, not a customer-facing input failure.
func New(cfg Config) (*Reconciler, error) {
	if cfg.Desired == nil {
		return nil, apierr.Internal(stderrors.New("reconcile: Config.Desired is required"))
	}
	if cfg.Actual == nil {
		return nil, apierr.Internal(stderrors.New("reconcile: Config.Actual is required"))
	}
	if cfg.Repairer == nil {
		return nil, apierr.Internal(stderrors.New("reconcile: Config.Repairer is required"))
	}
	if cfg.Reviewer == nil {
		return nil, apierr.Internal(stderrors.New("reconcile: Config.Reviewer is required"))
	}
	if cfg.Unmanaged == nil {
		return nil, apierr.Internal(stderrors.New("reconcile: Config.Unmanaged is required"))
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := cfg.Now
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	redactor := cfg.Redactor
	if redactor == nil {
		redactor = output.NewRedactor()
	}
	return &Reconciler{
		desired:   cfg.Desired,
		actual:    cfg.Actual,
		repairer:  cfg.Repairer,
		reviewer:  cfg.Reviewer,
		unmanaged: cfg.Unmanaged,
		logger:    logger,
		now:       clock,
		redactor:  redactor,
	}, nil
}

// Result is the outcome of one Apply. It records counts for telemetry and the
// list of per-action failures (each carrying a redacted error string) so a
// caller can decide whether to retry the tick.
type Result struct {
	Repaired    int
	Reviewed    int
	Quarantined int
	Failures    []Failure
}

// Failure is one per-action failure. The error is preserved for logging and
// retry decisions; its message has already been scrubbed by the engine's
// Redactor before being placed here.
type Failure struct {
	Action Action
	Err    error
}

// Plan reads desired and actual state and returns the diff. The returned
// Plan is the sole input to Apply; tests that exercise pure classification
// call this method (or the Diff function directly) and never reach Apply.
func (r *Reconciler) Plan(ctx context.Context, orgID domain.ID) (Plan, error) {
	if err := validateOrgID(orgID); err != nil {
		return Plan{}, err
	}
	desired, err := r.desired.Read(ctx, trimmedID(orgID))
	if err != nil {
		return Plan{}, wrapDesiredErr(r.redactor, err)
	}
	if strings.TrimSpace(string(desired.ID)) == "" {
		// A reader that returns an empty desired struct without an error is
		// a programming bug in that adapter, not a customer-facing failure.
		return Plan{}, apierr.Internal(fmt.Errorf(
			"reconcile: DesiredStateReader returned no organization ID for %s",
			redact(r.redactor, string(orgID))))
	}
	if desired.DokployID == "" {
		// The organization has never been provisioned: nothing to reconcile.
		return Plan{OrganizationID: trimmedID(desired.ID)}, nil
	}
	actual, err := r.actual.Read(ctx, desired.DokployID)
	if err != nil {
		return Plan{}, wrapActualErr(r.redactor, err)
	}
	return Diff(desired, actual), nil
}

// Apply executes the plan. It is best-effort: every action is attempted and
// per-action failures are collected in Result.Failures so the caller can
// emit one structured log line per failure and decide on retry. Apply
// returns a non-nil error only when ctx itself is cancelled before the loop
// completes.
func (r *Reconciler) Apply(ctx context.Context, plan Plan) (Result, error) {
	res := Result{}
	for _, action := range plan.Actions {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		switch action.Kind {
		case DriftSafe:
			if err := r.applySafe(ctx, action); err != nil {
				r.logFailure(ctx, "repair", action, err)
				res.Failures = append(res.Failures, Failure{Action: action, Err: scrub(r.redactor, err)})
				continue
			}
			res.Repaired++
		case DriftDangerous:
			if err := r.reviewer.Record(ctx, reviewEventFor(action)); err != nil {
				r.logFailure(ctx, "review", action, err)
				res.Failures = append(res.Failures, Failure{Action: action, Err: scrub(r.redactor, err)})
				continue
			}
			res.Reviewed++
		case DriftUnmanaged:
			if action.Unmanaged == nil {
				err := apierr.Internal(stderrors.New("reconcile: unmanaged action with no payload"))
				r.logFailure(ctx, "unmanaged", action, err)
				res.Failures = append(res.Failures, Failure{Action: action, Err: err})
				continue
			}
			if err := r.unmanaged.Mark(ctx, *action.Unmanaged); err != nil {
				r.logFailure(ctx, "unmanaged", action, err)
				res.Failures = append(res.Failures, Failure{Action: action, Err: scrub(r.redactor, err)})
				continue
			}
			res.Quarantined++
		default:
			// A drift kind we do not recognise is a Yalla bug; record it as
			// a failure rather than panicking so the rest of the plan
			// still runs.
			err := apierr.Internal(fmt.Errorf("reconcile: unrecognised drift kind %q", action.Kind))
			r.logFailure(ctx, "unknown-kind", action, err)
			res.Failures = append(res.Failures, Failure{Action: action, Err: err})
		}
	}
	return res, nil
}

// Reconcile is the convenience wrapper: Plan then Apply, with one log record
// for the tick outcome.
func (r *Reconciler) Reconcile(ctx context.Context, orgID domain.ID) (Result, error) {
	plan, err := r.Plan(ctx, orgID)
	if err != nil {
		r.logger.ErrorContext(ctx, "reconcile plan failed",
			append(telemetry.LogAttrs(ctx),
				slog.String("organization_id", redact(r.redactor, string(orgID))),
				slog.String("error", scrubMessage(r.redactor, err)),
			)...)
		return Result{}, err
	}
	res, err := r.Apply(ctx, plan)
	r.logger.InfoContext(ctx, "reconcile tick complete",
		append(telemetry.LogAttrs(ctx),
			slog.String("organization_id", redact(r.redactor, string(orgID))),
			slog.Int("actions", len(plan.Actions)),
			slog.Int("repaired", res.Repaired),
			slog.Int("reviewed", res.Reviewed),
			slog.Int("quarantined", res.Quarantined),
			slog.Int("failures", len(res.Failures)),
		)...)
	return res, err
}

func (r *Reconciler) applySafe(ctx context.Context, action Action) error {
	switch action.Type {
	case ActionUpdateEnvVar:
		return r.repairer.UpdateEnvVar(ctx, action.Service, action.EnvVarKey, action.DesiredValue, action.DesiredSecret)
	case ActionRemoveExtraEnvVar:
		return r.repairer.RemoveEnvVar(ctx, action.Service, action.EnvVarKey)
	case ActionUpdateBuildConfig:
		return r.repairer.UpdateBuildConfig(ctx, action.Service, action.DesiredBuild)
	case ActionEnsureDomain:
		if action.DesiredDomain == nil {
			return apierr.Internal(stderrors.New("reconcile: ensure_domain action with no payload"))
		}
		return r.repairer.EnsureDomain(ctx, action.Service, *action.DesiredDomain)
	default:
		return apierr.Internal(fmt.Errorf("reconcile: unrecognised safe action type %q", action.Type))
	}
}

func reviewEventFor(action Action) ReviewEvent {
	event := ReviewEvent{
		OrganizationID: action.Service.OrganizationID,
		Reason:         action.Reason,
		Service:        action.Service,
	}
	switch action.Type {
	case ActionReviewMissingService, ActionReviewMissingDatabase, ActionReviewServiceTypeChange:
		event.Level = LevelService
	case ActionReviewRenamedDomain:
		event.Level = LevelDomain
		event.Domain = action.Domain
	default:
		event.Level = LevelService
	}
	return event
}

func validateOrgID(id domain.ID) error {
	trimmed := strings.TrimSpace(string(id))
	if trimmed == "" {
		return apierr.InvalidInput(apierr.FieldViolation{
			Field: "organization_id", Reason: "required",
		})
	}
	parsed, err := domain.ParseID(trimmed)
	if err != nil {
		return apierr.InvalidInput(apierr.FieldViolation{
			Field: "organization_id", Reason: "must be a valid resource id",
		})
	}
	if parsed.Kind() != domain.KindOrganization {
		return apierr.InvalidInput(apierr.FieldViolation{
			Field: "organization_id", Reason: "must be an organization id",
		})
	}
	return nil
}

// wrapDesiredErr coerces a DesiredStateReader failure into the apierr taxonomy.
// A typed apierr from the adapter is preserved untouched; anything else is
// upgraded to apierr.StoreUnavailable so callers always see a catalogued code.
func wrapDesiredErr(redactor *output.Redactor, err error) error {
	if err == nil {
		return nil
	}
	if isCatalogued(err) {
		return err
	}
	return apierr.StoreUnavailable(scrub(redactor, err))
}

// wrapActualErr coerces an ActualStateReader failure into the apierr taxonomy.
// A typed apierr is preserved; anything else is upgraded to
// apierr.DokployUnavailable so a transport-level failure is correctly
// retryable.
func wrapActualErr(redactor *output.Redactor, err error) error {
	if err == nil {
		return nil
	}
	if isCatalogued(err) {
		return err
	}
	return apierr.DokployUnavailable(scrub(redactor, err))
}

func isCatalogued(err error) bool {
	var ye *yerr.Error
	return stderrors.As(err, &ye)
}

// logFailure emits one structured failure record per per-action failure. The
// action context (kind, reason, service IDs) is stable and value-free; the
// error string is scrubbed before logging.
func (r *Reconciler) logFailure(ctx context.Context, phase string, action Action, err error) {
	r.logger.WarnContext(ctx, "reconcile action failed",
		append(telemetry.LogAttrs(ctx),
			slog.String("phase", phase),
			slog.String("action_type", string(action.Type)),
			slog.String("drift_kind", string(action.Kind)),
			slog.String("reason", string(action.Reason)),
			slog.String("organization_id", string(action.Service.OrganizationID)),
			slog.String("service_id", string(action.Service.ServiceID)),
			slog.String("error", scrubMessage(r.redactor, err)),
		)...)
}

// scrub returns a typed Internal error carrying the redacted message of err.
// Used to ensure no caller of the engine accidentally re-exposes an unredacted
// Dokploy or store error from a Failure.Err.
func scrub(redactor *output.Redactor, err error) error {
	if err == nil {
		return nil
	}
	if isCatalogued(err) {
		return err
	}
	return apierr.Internal(stderrors.New(scrubMessage(redactor, err)))
}

func scrubMessage(redactor *output.Redactor, err error) string {
	if err == nil {
		return ""
	}
	if redactor == nil {
		return err.Error()
	}
	return redactor.Redact(err.Error())
}

func redact(redactor *output.Redactor, s string) string {
	if redactor == nil {
		return s
	}
	return redactor.Redact(s)
}
