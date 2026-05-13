package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/config"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

type databaseEngine string

const (
	databasePostgres databaseEngine = "postgres"
	databaseMySQL    databaseEngine = "mysql"
	databaseMariaDB  databaseEngine = "mariadb"
	databaseMongo    databaseEngine = "mongo"
	databaseRedis    databaseEngine = "redis"
)

type databaseCreateOptions struct {
	Engine           databaseEngine
	Name             string
	AppName          string
	EnvironmentID    string
	DatabaseName     string
	DatabaseUser     string
	DatabasePassword string
	RootPassword     string
	Description      string
	ServerID         string
	Image            string
	ReplicaSets      bool
	Deploy           bool
}

type databaseDeployOptions struct {
	Engine databaseEngine
	ID     string
}

type databaseUpdateOptions struct {
	Engine               databaseEngine
	ID                   string
	MemoryReservation    string
	MemoryReservationSet bool
	MemoryLimit          string
	MemoryLimitSet       bool
	CPUReservation       string
	CPUReservationSet    bool
	CPULimit             string
	CPULimitSet          bool
	Replicas             int
	ReplicasSet          bool
}

type databaseBackupCreateOptions struct {
	Engine        databaseEngine
	DatabaseID    string
	DestinationID string
	Database      string
	Prefix        string
	Schedule      string
	KeepLatest    int
	KeepLatestSet bool
	Disabled      bool
}

type databaseBackupUpdateOptions struct {
	Engine           databaseEngine
	BackupID         string
	Schedule         string
	ScheduleSet      bool
	Prefix           string
	PrefixSet        bool
	DestinationID    string
	DestinationIDSet bool
	Database         string
	DatabaseSet      bool
	KeepLatest       int
	KeepLatestSet    bool
	ServiceName      string
	ServiceNameSet   bool
	Enabled          bool
	EnabledSet       bool
	Disabled         bool
	DisabledSet      bool
}

type databaseBackupActionOptions struct {
	Engine   databaseEngine
	BackupID string
}

type databaseBackupGetOptions struct {
	BackupID string
}

type databaseBackupListFilesOptions struct {
	DestinationID string
	Prefix        string
	ServerID      string
}

type databaseCreateDoc struct {
	Engine        string `json:"engine"`
	Name          string `json:"name"`
	EnvironmentID string `json:"environment_id"`
	ID            string `json:"id,omitempty"`
	AppName       string `json:"app_name,omitempty"`
	Deployed      bool   `json:"deployed"`
	Warning       string `json:"warning,omitempty"`
}

type databaseDeployDoc struct {
	Engine string `json:"engine"`
	ID     string `json:"id"`
}

type databaseUpdateDoc struct {
	Engine            string `json:"engine"`
	ID                string `json:"id"`
	MemoryReservation string `json:"memory_reservation,omitempty"`
	MemoryLimit       string `json:"memory_limit,omitempty"`
	CPUReservation    string `json:"cpu_reservation,omitempty"`
	CPULimit          string `json:"cpu_limit,omitempty"`
	Replicas          int    `json:"replicas,omitempty"`
	ReplicasSet       bool   `json:"replicas_set,omitempty"`
}

type databaseBackupCreateDoc struct {
	Engine        string `json:"engine"`
	DatabaseID    string `json:"database_id"`
	BackupID      string `json:"backup_id,omitempty"`
	DestinationID string `json:"destination_id"`
	Database      string `json:"database"`
	Prefix        string `json:"prefix"`
	Schedule      string `json:"schedule"`
	Enabled       bool   `json:"enabled"`
	KeepLatest    int    `json:"keep_latest,omitempty"`
	KeepLatestSet bool   `json:"keep_latest_set,omitempty"`
}

type databaseBackupUpdateDoc struct {
	Engine        string `json:"engine"`
	BackupID      string `json:"backup_id"`
	DestinationID string `json:"destination_id,omitempty"`
	Database      string `json:"database,omitempty"`
	Prefix        string `json:"prefix,omitempty"`
	Schedule      string `json:"schedule,omitempty"`
	Enabled       bool   `json:"enabled"`
	KeepLatest    int    `json:"keep_latest,omitempty"`
	KeepLatestSet bool   `json:"keep_latest_set,omitempty"`
}

type databaseBackupActionDoc struct {
	Operation string `json:"operation"`
	Engine    string `json:"engine,omitempty"`
	BackupID  string `json:"backup_id"`
}

type databaseBackupGetDoc struct {
	BackupID     string         `json:"backup_id"`
	DatabaseType string         `json:"database_type,omitempty"`
	Prefix       string         `json:"prefix,omitempty"`
	Backup       map[string]any `json:"backup"`
}

type databaseBackupListFilesDoc struct {
	DestinationID string   `json:"destination_id"`
	Prefix        string   `json:"prefix"`
	ServerID      string   `json:"server_id,omitempty"`
	Files         []string `json:"files"`
	Raw           any      `json:"raw,omitempty"`
}

type databaseService struct {
	ctx    context.Context
	reg    *api.Registry
	client *api.Client
}

func newDatabaseService(ctx context.Context, cfg *config.Config, build BuildInfo) (*databaseService, error) {
	if cfg.BaseURL == "" {
		return nil, yerr.New(yerr.CodeConfig, "no Dokploy base URL configured").
			WithHint("run `yalla auth login`, set YALLA_BASE_URL, or pass --base-url")
	}
	if cfg.Token == "" {
		return nil, yerr.New(yerr.CodeAuth, "database commands require authentication; no Dokploy API token configured").
			WithHint("run `yalla auth login`, set YALLA_TOKEN, or pass --token")
	}
	client, err := apiCallClientFactory(apiCallClientArgs{
		Config: cfg,
		Build:  build,
	})
	if err != nil {
		return nil, errAsTyped(err, yerr.CodeConfig)
	}
	return &databaseService{ctx: ctx, reg: api.Default(), client: client}, nil
}

func parseDatabaseEngine(raw string) (databaseEngine, error) {
	switch databaseEngine(strings.ToLower(strings.TrimSpace(raw))) {
	case databasePostgres:
		return databasePostgres, nil
	case databaseMySQL:
		return databaseMySQL, nil
	case databaseMariaDB:
		return databaseMariaDB, nil
	case databaseMongo:
		return databaseMongo, nil
	case databaseRedis:
		return databaseRedis, nil
	case "libsql":
		return "", yerr.New(yerr.CodeUnsupported, `unsupported database engine "libsql"`).
			WithHint("this yalla build has no libsql OpenAPI operations; use postgres, mysql, mariadb, mongo, or redis")
	default:
		return "", yerr.Newf(yerr.CodeInvalidInput, "unsupported database engine %q", raw).
			WithHint("supported engines: postgres, mysql, mariadb, mongo, redis")
	}
}

func validateDatabaseCreate(o databaseCreateOptions) error {
	if strings.TrimSpace(o.Name) == "" {
		return yerr.New(yerr.CodeInvalidInput, "database name is required").WithHint("pass --name")
	}
	if strings.TrimSpace(o.EnvironmentID) == "" {
		return yerr.New(yerr.CodeInvalidInput, "environment ID is required").WithHint("pass --environment-id")
	}
	if strings.TrimSpace(o.DatabasePassword) == "" {
		return yerr.New(yerr.CodeInvalidInput, "database password is required").WithHint("pass --database-password")
	}
	switch o.Engine {
	case databasePostgres, databaseMySQL, databaseMariaDB:
		if o.ReplicaSets {
			return yerr.New(yerr.CodeInvalidInput, "--replica-sets is not valid for "+string(o.Engine))
		}
		if strings.TrimSpace(o.DatabaseName) == "" {
			return yerr.New(yerr.CodeInvalidInput, "database name inside the server is required").WithHint("pass --database-name")
		}
		if strings.TrimSpace(o.DatabaseUser) == "" {
			return yerr.New(yerr.CodeInvalidInput, "database user is required").WithHint("pass --database-user")
		}
	case databaseMongo:
		if strings.TrimSpace(o.DatabaseName) != "" {
			return yerr.New(yerr.CodeInvalidInput, "--database-name is not valid for mongo")
		}
		if strings.TrimSpace(o.DatabaseUser) == "" {
			return yerr.New(yerr.CodeInvalidInput, "database user is required").WithHint("pass --database-user")
		}
	case databaseRedis:
		if strings.TrimSpace(o.DatabaseName) != "" {
			return yerr.New(yerr.CodeInvalidInput, "--database-name is not valid for redis")
		}
		if strings.TrimSpace(o.DatabaseUser) != "" {
			return yerr.New(yerr.CodeInvalidInput, "--database-user is not valid for redis")
		}
		if o.ReplicaSets {
			return yerr.New(yerr.CodeInvalidInput, "--replica-sets is not valid for redis")
		}
	}
	return nil
}

func validateDatabaseDeploy(o databaseDeployOptions) error {
	if strings.TrimSpace(o.ID) == "" {
		return yerr.New(yerr.CodeInvalidInput, "database ID is required").WithHint("pass --id")
	}
	return nil
}

func validateDatabaseUpdate(o databaseUpdateOptions) error {
	if strings.TrimSpace(o.ID) == "" {
		return yerr.New(yerr.CodeInvalidInput, "database ID is required").WithHint("pass --id")
	}
	if !o.MemoryReservationSet && !o.MemoryLimitSet && !o.CPUReservationSet && !o.CPULimitSet && !o.ReplicasSet {
		return yerr.New(yerr.CodeInvalidInput, "at least one update flag is required").
			WithHint("pass --memory-reservation, --memory-limit, --cpu-reservation, --cpu-limit, or --replicas")
	}
	if err := validateNonEmptyChanged("memory-reservation", o.MemoryReservation, o.MemoryReservationSet); err != nil {
		return err
	}
	if err := validateNonEmptyChanged("memory-limit", o.MemoryLimit, o.MemoryLimitSet); err != nil {
		return err
	}
	if err := validatePositiveDecimal("cpu-reservation", o.CPUReservation, o.CPUReservationSet); err != nil {
		return err
	}
	if err := validatePositiveDecimal("cpu-limit", o.CPULimit, o.CPULimitSet); err != nil {
		return err
	}
	if o.ReplicasSet && o.Replicas <= 0 {
		return yerr.New(yerr.CodeInvalidInput, "--replicas must be greater than zero")
	}
	return nil
}

func validateDatabaseBackupCreate(o databaseBackupCreateOptions) error {
	if err := validateDatabaseBackupEngine(o.Engine); err != nil {
		return err
	}
	if strings.TrimSpace(o.DatabaseID) == "" {
		return yerr.New(yerr.CodeInvalidInput, "database ID is required").WithHint("pass --id")
	}
	if strings.TrimSpace(o.DestinationID) == "" {
		return yerr.New(yerr.CodeInvalidInput, "backup destination ID is required").WithHint("pass --destination-id")
	}
	if strings.TrimSpace(o.Database) == "" {
		return yerr.New(yerr.CodeInvalidInput, "database name is required").WithHint("pass --database")
	}
	if strings.TrimSpace(o.Prefix) == "" {
		return yerr.New(yerr.CodeInvalidInput, "backup prefix is required").WithHint("pass --prefix")
	}
	if strings.TrimSpace(o.Schedule) == "" {
		return yerr.New(yerr.CodeInvalidInput, "backup schedule is required").WithHint("pass --schedule")
	}
	if o.KeepLatestSet && o.KeepLatest < 0 {
		return yerr.New(yerr.CodeInvalidInput, "--keep-latest must be zero or greater")
	}
	return nil
}

func validateDatabaseBackupUpdate(o databaseBackupUpdateOptions) error {
	if err := validateDatabaseBackupEngine(o.Engine); err != nil {
		return err
	}
	if strings.TrimSpace(o.BackupID) == "" {
		return yerr.New(yerr.CodeInvalidInput, "backup ID is required").WithHint("pass --backup-id")
	}
	if !o.ScheduleSet && !o.PrefixSet && !o.DestinationIDSet && !o.DatabaseSet && !o.KeepLatestSet && !o.ServiceNameSet && !o.EnabledSet && !o.DisabledSet {
		return yerr.New(yerr.CodeInvalidInput, "at least one backup update flag is required").
			WithHint("pass --schedule, --prefix, --destination-id, --database, --keep-latest, --enabled, or --disabled")
	}
	if o.EnabledSet && o.DisabledSet {
		return yerr.New(yerr.CodeInvalidInput, "--enabled and --disabled cannot be used together")
	}
	if err := validateNonEmptyChanged("schedule", o.Schedule, o.ScheduleSet); err != nil {
		return err
	}
	if err := validateNonEmptyChanged("prefix", o.Prefix, o.PrefixSet); err != nil {
		return err
	}
	if err := validateNonEmptyChanged("destination-id", o.DestinationID, o.DestinationIDSet); err != nil {
		return err
	}
	if err := validateNonEmptyChanged("database", o.Database, o.DatabaseSet); err != nil {
		return err
	}
	if o.KeepLatestSet && o.KeepLatest < 0 {
		return yerr.New(yerr.CodeInvalidInput, "--keep-latest must be zero or greater")
	}
	return nil
}

func validateDatabaseBackupAction(o databaseBackupActionOptions) error {
	if o.Engine != "" {
		if err := validateDatabaseBackupEngine(o.Engine); err != nil {
			return err
		}
	}
	if strings.TrimSpace(o.BackupID) == "" {
		return yerr.New(yerr.CodeInvalidInput, "backup ID is required").WithHint("pass --backup-id")
	}
	return nil
}

func validateDatabaseBackupGet(o databaseBackupGetOptions) error {
	if strings.TrimSpace(o.BackupID) == "" {
		return yerr.New(yerr.CodeInvalidInput, "backup ID is required").WithHint("pass --backup-id")
	}
	return nil
}

func validateDatabaseBackupListFiles(o databaseBackupListFilesOptions) error {
	if strings.TrimSpace(o.DestinationID) == "" {
		return yerr.New(yerr.CodeInvalidInput, "backup destination ID is required").WithHint("pass --destination-id")
	}
	if strings.TrimSpace(o.Prefix) == "" {
		return yerr.New(yerr.CodeInvalidInput, "backup prefix is required").WithHint("pass --prefix")
	}
	return nil
}

func validateDatabaseBackupEngine(engine databaseEngine) error {
	switch engine {
	case databasePostgres, databaseMySQL, databaseMariaDB, databaseMongo:
		return nil
	case databaseRedis:
		return yerr.New(yerr.CodeUnsupported, "database backups are not supported for redis").
			WithHint("Dokploy's backup API supports postgres, mysql, mariadb, and mongo database backups")
	default:
		return yerr.Newf(yerr.CodeInvalidInput, "unsupported database backup engine %q", engine).
			WithHint("supported backup engines: postgres, mysql, mariadb, mongo")
	}
}

func validateNonEmptyChanged(name, value string, changed bool) error {
	if changed && strings.TrimSpace(value) == "" {
		return yerr.Newf(yerr.CodeInvalidInput, "--%s cannot be empty", name)
	}
	return nil
}

func validatePositiveDecimal(name, value string, changed bool) error {
	if !changed {
		return nil
	}
	if strings.TrimSpace(value) == "" {
		return yerr.Newf(yerr.CodeInvalidInput, "--%s cannot be empty", name)
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 {
		return yerr.Newf(yerr.CodeInvalidInput, "--%s must be a positive decimal number", name)
	}
	return nil
}

func (e databaseEngine) createOperationID() string { return string(e) + "-create" }
func (e databaseEngine) deployOperationID() string { return string(e) + "-deploy" }
func (e databaseEngine) searchOperationID() string { return string(e) + "-search" }
func (e databaseEngine) oneOperationID() string    { return string(e) + "-one" }
func (e databaseEngine) updateOperationID() string { return string(e) + "-update" }

func (e databaseEngine) manualBackupOperationID() string {
	switch e {
	case databasePostgres:
		return "backup-manualBackupPostgres"
	case databaseMySQL:
		return "backup-manualBackupMySql"
	case databaseMariaDB:
		return "backup-manualBackupMariadb"
	case databaseMongo:
		return "backup-manualBackupMongo"
	default:
		return ""
	}
}

func (e databaseEngine) defaultImage() string {
	switch e {
	case databasePostgres:
		return "postgres:18"
	case databaseMySQL:
		return "mysql:8"
	case databaseMariaDB:
		return "mariadb:11.4"
	case databaseMongo:
		return "mongo:8"
	case databaseRedis:
		return "redis:8"
	default:
		return ""
	}
}

func (e databaseEngine) idField() string {
	switch e {
	case databasePostgres:
		return "postgresId"
	case databaseMySQL:
		return "mysqlId"
	case databaseMariaDB:
		return "mariadbId"
	case databaseMongo:
		return "mongoId"
	case databaseRedis:
		return "redisId"
	default:
		return ""
	}
}

func (s *databaseService) Create(o databaseCreateOptions) (databaseCreateDoc, error) {
	doc := databaseCreateDoc{
		Engine:        string(o.Engine),
		Name:          o.Name,
		EnvironmentID: o.EnvironmentID,
	}
	if err := s.callBody(o.Engine.createOperationID(), databaseCreateBody(o)); err != nil {
		return doc, err
	}

	ref, err := s.findCreated(o.Engine, o.Name, o.EnvironmentID)
	if err != nil {
		doc.Warning = err.Error()
	}
	doc.ID = ref.ID
	doc.AppName = ref.AppName

	if o.Deploy {
		if doc.ID == "" {
			return doc, yerr.Newf(yerr.CodeNotFound, "created %s database %q but could not recover its ID for deploy", o.Engine, o.Name).
				WithHintf("run `yalla api call %s --input ...` or search by name in the Dokploy portal", o.Engine.searchOperationID())
		}
		if err := s.deploy(o.Engine, doc.ID); err != nil {
			return doc, err
		}
		doc.Deployed = true
	}
	return doc, nil
}

func (s *databaseService) Deploy(o databaseDeployOptions) (databaseDeployDoc, error) {
	if err := s.deploy(o.Engine, o.ID); err != nil {
		return databaseDeployDoc{}, err
	}
	return databaseDeployDoc{Engine: string(o.Engine), ID: o.ID}, nil
}

func (s *databaseService) Update(o databaseUpdateOptions) (databaseUpdateDoc, error) {
	current, err := s.fetchOne(o.Engine, o.ID)
	if err != nil {
		return databaseUpdateDoc{}, err
	}
	current = filterDatabaseUpdateBody(current, o.Engine)
	idField := o.Engine.idField()
	current[idField] = o.ID
	if o.MemoryReservationSet {
		current["memoryReservation"] = o.MemoryReservation
	}
	if o.MemoryLimitSet {
		current["memoryLimit"] = o.MemoryLimit
	}
	if o.CPUReservationSet {
		current["cpuReservation"] = o.CPUReservation
	}
	if o.CPULimitSet {
		current["cpuLimit"] = o.CPULimit
	}
	if o.ReplicasSet {
		current["replicas"] = o.Replicas
	}
	if err := s.callBody(o.Engine.updateOperationID(), current); err != nil {
		return databaseUpdateDoc{}, err
	}
	return databaseUpdateDoc{
		Engine:            string(o.Engine),
		ID:                o.ID,
		MemoryReservation: valueWhenSet(o.MemoryReservation, o.MemoryReservationSet),
		MemoryLimit:       valueWhenSet(o.MemoryLimit, o.MemoryLimitSet),
		CPUReservation:    valueWhenSet(o.CPUReservation, o.CPUReservationSet),
		CPULimit:          valueWhenSet(o.CPULimit, o.CPULimitSet),
		Replicas:          o.Replicas,
		ReplicasSet:       o.ReplicasSet,
	}, nil
}

func (s *databaseService) CreateBackup(o databaseBackupCreateOptions) (databaseBackupCreateDoc, error) {
	body := databaseBackupCreateBody(o)
	resBody, err := s.callBodyResponse("backup-create", body)
	if err != nil {
		return databaseBackupCreateDoc{}, err
	}
	backupID := extractIDFromBody(resBody, "backupId")
	if backupID == "" {
		ref, err := s.findCreatedBackup(o)
		if err != nil {
			return databaseBackupCreateDoc{}, err
		}
		backupID = ref
	}
	return databaseBackupCreateDoc{
		Engine:        string(o.Engine),
		DatabaseID:    o.DatabaseID,
		BackupID:      backupID,
		DestinationID: o.DestinationID,
		Database:      o.Database,
		Prefix:        o.Prefix,
		Schedule:      o.Schedule,
		Enabled:       !o.Disabled,
		KeepLatest:    o.KeepLatest,
		KeepLatestSet: o.KeepLatestSet,
	}, nil
}

func (s *databaseService) findCreatedBackup(o databaseBackupCreateOptions) (string, error) {
	db, err := s.fetchOne(o.Engine, o.DatabaseID)
	if err != nil {
		return "", err
	}
	items, err := extractDatabaseBackups(db)
	if err != nil {
		return "", err
	}
	if id := findBackupID(items, o); id != "" {
		return id, nil
	}

	body, err := s.callQuery("user-getBackups", nil)
	if err != nil {
		return "", err
	}
	items, err = extractUserBackups(body)
	if err != nil {
		return "", err
	}
	if id := findBackupID(items, o); id != "" {
		return id, nil
	}
	return "", yerr.Newf(yerr.CodeNotFound, "created %s backup for %s but could not recover its ID", o.Engine, o.DatabaseID).
		WithHint("inspect backups in the Dokploy portal or run `yalla api call " + o.Engine.oneOperationID() + " --input '{\"query\":{\"" + o.Engine.idField() + "\":[\"" + o.DatabaseID + "\"]}}'`")
}

func findBackupID(items []map[string]any, o databaseBackupCreateOptions) string {
	for _, item := range items {
		if stringField(item, "databaseType") != string(o.Engine) {
			continue
		}
		if stringField(item, o.Engine.idField()) != o.DatabaseID {
			continue
		}
		if stringField(item, "destinationId") != o.DestinationID {
			continue
		}
		if stringField(item, "database") != o.Database {
			continue
		}
		if stringField(item, "prefix") != o.Prefix {
			continue
		}
		if stringField(item, "schedule") != o.Schedule {
			continue
		}
		if id := firstNonEmpty(stringField(item, "backupId"), stringField(item, "id")); id != "" {
			return id
		}
	}
	return ""
}

func (s *databaseService) RunBackup(o databaseBackupActionOptions) (databaseBackupActionDoc, error) {
	op := o.Engine.manualBackupOperationID()
	if op == "" {
		return databaseBackupActionDoc{}, yerr.New(yerr.CodeUnsupported, "manual backup is not supported for "+string(o.Engine))
	}
	if err := s.validateBackupEngine(o.BackupID, o.Engine); err != nil {
		return databaseBackupActionDoc{}, err
	}
	if err := s.callBody(op, map[string]any{"backupId": o.BackupID}); err != nil {
		return databaseBackupActionDoc{}, err
	}
	return databaseBackupActionDoc{Operation: "run", Engine: string(o.Engine), BackupID: o.BackupID}, nil
}

func (s *databaseService) UpdateBackup(o databaseBackupUpdateOptions) (databaseBackupUpdateDoc, error) {
	current, err := s.fetchBackup(o.BackupID)
	if err != nil {
		return databaseBackupUpdateDoc{}, err
	}
	if err := validateBackupEngineRecord(o.BackupID, current, o.Engine); err != nil {
		return databaseBackupUpdateDoc{}, err
	}
	body := filterBackupUpdateBody(current)
	body["backupId"] = o.BackupID
	body["databaseType"] = string(o.Engine)
	if o.ScheduleSet {
		body["schedule"] = o.Schedule
	}
	if o.PrefixSet {
		body["prefix"] = o.Prefix
	}
	if o.DestinationIDSet {
		body["destinationId"] = o.DestinationID
	}
	if o.DatabaseSet {
		body["database"] = o.Database
	}
	if o.KeepLatestSet {
		body["keepLatestCount"] = o.KeepLatest
	}
	if o.ServiceNameSet {
		body["serviceName"] = o.ServiceName
	}
	if o.EnabledSet {
		body["enabled"] = o.Enabled
	}
	if o.DisabledSet {
		body["enabled"] = !o.Disabled
	}
	if err := validateBackupUpdateBody(o.BackupID, body); err != nil {
		return databaseBackupUpdateDoc{}, err
	}
	if err := s.callBody("backup-update", body); err != nil {
		return databaseBackupUpdateDoc{}, err
	}
	return databaseBackupUpdateDoc{
		Engine:        string(o.Engine),
		BackupID:      o.BackupID,
		DestinationID: stringField(body, "destinationId"),
		Database:      stringField(body, "database"),
		Prefix:        stringField(body, "prefix"),
		Schedule:      stringField(body, "schedule"),
		Enabled:       boolField(body, "enabled"),
		KeepLatest:    intField(body, "keepLatestCount"),
		KeepLatestSet: o.KeepLatestSet || body["keepLatestCount"] != nil,
	}, nil
}

func (s *databaseService) GetBackup(o databaseBackupGetOptions) (databaseBackupGetDoc, error) {
	backup, err := s.fetchBackup(o.BackupID)
	if err != nil {
		return databaseBackupGetDoc{}, err
	}
	return databaseBackupGetDoc{
		BackupID:     firstNonEmpty(stringField(backup, "backupId"), o.BackupID),
		DatabaseType: stringField(backup, "databaseType"),
		Prefix:       stringField(backup, "prefix"),
		Backup:       backup,
	}, nil
}

func (s *databaseService) DeleteBackup(o databaseBackupActionOptions) (databaseBackupActionDoc, error) {
	if err := s.callBody("backup-remove", map[string]any{"backupId": o.BackupID}); err != nil {
		return databaseBackupActionDoc{}, err
	}
	return databaseBackupActionDoc{Operation: "delete", BackupID: o.BackupID}, nil
}

func (s *databaseService) ListBackupFiles(o databaseBackupListFilesOptions) (databaseBackupListFilesDoc, error) {
	query := url.Values{
		"destinationId": []string{o.DestinationID},
		"search":        []string{o.Prefix},
	}
	if o.ServerID != "" {
		query.Set("serverId", o.ServerID)
	}
	body, err := s.callQuery("backup-listBackupFiles", query)
	if err != nil {
		return databaseBackupListFilesDoc{}, err
	}
	files, raw, err := extractBackupFiles(body)
	if err != nil {
		return databaseBackupListFilesDoc{}, err
	}
	return databaseBackupListFilesDoc{
		DestinationID: o.DestinationID,
		Prefix:        o.Prefix,
		ServerID:      o.ServerID,
		Files:         files,
		Raw:           raw,
	}, nil
}

func valueWhenSet(value string, set bool) string {
	if !set {
		return ""
	}
	return value
}

func databaseBackupCreateBody(o databaseBackupCreateOptions) map[string]any {
	body := map[string]any{
		"schedule":         o.Schedule,
		"enabled":          !o.Disabled,
		"prefix":           o.Prefix,
		"destinationId":    o.DestinationID,
		"database":         o.Database,
		"databaseType":     string(o.Engine),
		"backupType":       "database",
		o.Engine.idField(): o.DatabaseID,
	}
	if o.KeepLatestSet {
		body["keepLatestCount"] = o.KeepLatest
	}
	return body
}

func filterBackupUpdateBody(current map[string]any) map[string]any {
	allowed := []string{
		"schedule",
		"enabled",
		"prefix",
		"backupId",
		"destinationId",
		"database",
		"keepLatestCount",
		"serviceName",
		"metadata",
		"databaseType",
	}
	out := make(map[string]any, len(allowed))
	for _, key := range allowed {
		if value, ok := current[key]; ok {
			out[key] = value
		}
	}
	for _, key := range []string{"enabled", "keepLatestCount", "serviceName", "metadata"} {
		if _, ok := out[key]; !ok {
			out[key] = nil
		}
	}
	return out
}

func databaseCreateBody(o databaseCreateOptions) map[string]any {
	body := map[string]any{
		"name":             o.Name,
		"environmentId":    o.EnvironmentID,
		"databasePassword": o.DatabasePassword,
	}
	if o.AppName != "" {
		body["appName"] = o.AppName
	}
	if o.Description != "" {
		body["description"] = o.Description
	}
	if o.ServerID != "" {
		body["serverId"] = o.ServerID
	}
	if image := strings.TrimSpace(o.Image); image != "" {
		body["dockerImage"] = image
	} else if image := o.Engine.defaultImage(); image != "" {
		body["dockerImage"] = image
	}
	switch o.Engine {
	case databasePostgres, databaseMySQL, databaseMariaDB:
		body["databaseName"] = o.DatabaseName
		body["databaseUser"] = o.DatabaseUser
		if o.RootPassword != "" && (o.Engine == databaseMySQL || o.Engine == databaseMariaDB) {
			body["databaseRootPassword"] = o.RootPassword
		}
	case databaseMongo:
		body["databaseUser"] = o.DatabaseUser
		if o.ReplicaSets {
			body["replicaSets"] = true
		}
	case databaseRedis:
		// Redis only needs the shared fields above.
	}
	return body
}

func filterDatabaseUpdateBody(current map[string]any, engine databaseEngine) map[string]any {
	allowed := map[string]struct{}{
		engine.idField():       {},
		"name":                 {},
		"appName":              {},
		"description":          {},
		"databaseName":         {},
		"databaseUser":         {},
		"databasePassword":     {},
		"databaseRootPassword": {},
		"dockerImage":          {},
		"command":              {},
		"args":                 {},
		"env":                  {},
		"memoryReservation":    {},
		"memoryLimit":          {},
		"cpuReservation":       {},
		"cpuLimit":             {},
		"externalPort":         {},
		"applicationStatus":    {},
		"healthCheckSwarm":     {},
		"restartPolicySwarm":   {},
		"placementSwarm":       {},
		"updateConfigSwarm":    {},
		"rollbackConfigSwarm":  {},
		"modeSwarm":            {},
		"labelsSwarm":          {},
		"networkSwarm":         {},
		"stopGracePeriodSwarm": {},
		"endpointSpecSwarm":    {},
		"ulimitsSwarm":         {},
		"replicas":             {},
		"createdAt":            {},
		"environmentId":        {},
		"replicaSets":          {},
	}
	out := make(map[string]any, len(current))
	for key, value := range current {
		if _, ok := allowed[key]; ok {
			out[key] = value
		}
	}
	return out
}

func (s *databaseService) fetchBackup(backupID string) (map[string]any, error) {
	body, err := s.callQuery("backup-one", url.Values{"backupId": []string{backupID}})
	if err != nil {
		return nil, err
	}
	obj, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func (s *databaseService) validateBackupEngine(backupID string, engine databaseEngine) error {
	backup, err := s.fetchBackup(backupID)
	if err != nil {
		return err
	}
	return validateBackupEngineRecord(backupID, backup, engine)
}

func validateBackupEngineRecord(backupID string, backup map[string]any, engine databaseEngine) error {
	if currentType := stringField(backup, "databaseType"); currentType != "" && currentType != string(engine) {
		return yerr.Newf(yerr.CodeInvalidInput, "backup %s is for %s, not %s", backupID, currentType, engine).
			WithHint("use the engine that matches the backup schedule, or inspect it with `yalla database backup get --backup-id " + backupID + "`")
	}
	return nil
}

func validateBackupUpdateBody(backupID string, body map[string]any) error {
	for _, field := range []string{"schedule", "prefix", "backupId", "destinationId", "database", "databaseType"} {
		if strings.TrimSpace(stringField(body, field)) == "" {
			return yerr.Newf(yerr.CodeInvalidInput, "backup %s is missing required field %s", backupID, field).
				WithHint("provide the missing value as a flag, or inspect the schedule with `yalla database backup get --backup-id " + backupID + "`")
		}
	}
	return nil
}

func (s *databaseService) deploy(engine databaseEngine, id string) error {
	return s.callBody(engine.deployOperationID(), map[string]any{engine.idField(): id})
}

func (s *databaseService) fetchOne(engine databaseEngine, id string) (map[string]any, error) {
	body, err := s.callQuery(engine.oneOperationID(), url.Values{engine.idField(): []string{id}})
	if err != nil {
		return nil, err
	}
	obj, err := decodeJSONObject(body)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

type databaseRef struct {
	ID      string
	AppName string
}

func (s *databaseService) findCreated(engine databaseEngine, name, environmentID string) (databaseRef, error) {
	body, err := s.callQuery(engine.searchOperationID(), url.Values{
		"name":          []string{name},
		"environmentId": []string{environmentID},
		"limit":         []string{"20"},
		"offset":        []string{"0"},
	})
	if err != nil {
		return databaseRef{}, err
	}
	items, err := extractSearchItems(body)
	if err != nil {
		return databaseRef{}, err
	}
	for _, item := range items {
		if stringField(item, "name") != name {
			continue
		}
		if env := stringField(item, "environmentId"); env != "" && env != environmentID {
			continue
		}
		id := stringField(item, engine.idField())
		if id == "" {
			id = stringField(item, "id")
		}
		return databaseRef{ID: id, AppName: stringField(item, "appName")}, nil
	}
	return databaseRef{}, yerr.Newf(yerr.CodeNotFound, "database %q was not found in %s search results", name, engine)
}

func (s *databaseService) callBody(operationID string, body map[string]any) error {
	_, err := s.callBodyResponse(operationID, body)
	return err
}

func (s *databaseService) callBodyResponse(operationID string, body map[string]any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, yerr.Newf(yerr.CodeInvalidInput, "encode %s request body: %v", operationID, err)
	}
	return s.call(operationID, nil, payload)
}

func (s *databaseService) callQuery(operationID string, query url.Values) ([]byte, error) {
	return s.call(operationID, query, nil)
}

func (s *databaseService) call(operationID string, query url.Values, body []byte) ([]byte, error) {
	op, ok := s.reg.Get(operationID)
	if !ok {
		return nil, yerr.Newf(yerr.CodeNotFound, "unknown operation %q", operationID)
	}
	req := &api.Request{
		Method:      op.Method,
		Path:        op.Path,
		Query:       query,
		Body:        body,
		ContentType: api.ContentTypeJSON,
		Idempotent:  strings.EqualFold(op.Method, http.MethodGet),
	}
	res, err := s.client.Do(s.ctx, req)
	if err != nil {
		return nil, errAsTyped(err, yerr.CodeNetwork)
	}
	if !res.Success() {
		return nil, res.AsError()
	}
	return res.Body, nil
}

func decodeJSONObject(body []byte) (map[string]any, error) {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, yerr.Newf(yerr.CodeInvalidInput, "parse Dokploy JSON response: %v", err)
	}
	return obj, nil
}

func extractSearchItems(body []byte) ([]map[string]any, error) {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, yerr.Newf(yerr.CodeInvalidInput, "parse database search response: %v", err)
	}
	switch v := raw.(type) {
	case []any:
		return mapsFromAnySlice(v), nil
	case map[string]any:
		for _, key := range []string{"items", "databases", "data"} {
			if arr, ok := v[key].([]any); ok {
				return mapsFromAnySlice(arr), nil
			}
		}
		return []map[string]any{v}, nil
	default:
		return nil, yerr.Newf(yerr.CodeInvalidInput, "database search response had unexpected shape %T", raw)
	}
}

func extractUserBackups(body []byte) ([]map[string]any, error) {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, yerr.Newf(yerr.CodeInvalidInput, "parse backups response: %v", err)
	}
	switch v := raw.(type) {
	case []any:
		return mapsFromAnySlice(v), nil
	case map[string]any:
		for _, key := range []string{"backups", "items", "data"} {
			if arr, ok := v[key].([]any); ok {
				return mapsFromAnySlice(arr), nil
			}
		}
		return nil, yerr.New(yerr.CodeInvalidInput, "backups response did not include a backups array")
	default:
		return nil, yerr.Newf(yerr.CodeInvalidInput, "backups response had unexpected shape %T", raw)
	}
}

func extractDatabaseBackups(db map[string]any) ([]map[string]any, error) {
	raw, ok := db["backups"]
	if !ok || raw == nil {
		return nil, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, yerr.Newf(yerr.CodeInvalidInput, "database backups response had unexpected shape %T", raw)
	}
	return mapsFromAnySlice(items), nil
}

func extractBackupFiles(body []byte) ([]string, any, error) {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, yerr.Newf(yerr.CodeInvalidInput, "parse backup files response: %v", err)
	}
	var source any = raw
	if obj, ok := raw.(map[string]any); ok {
		for _, key := range []string{"items", "files", "data"} {
			if value, exists := obj[key]; exists {
				source = value
				break
			}
		}
	}
	items, ok := source.([]any)
	if !ok {
		return nil, raw, nil
	}
	files := make([]string, 0, len(items))
	for _, item := range items {
		switch v := item.(type) {
		case string:
			files = append(files, v)
		case map[string]any:
			if name := firstNonEmpty(stringField(v, "name"), stringField(v, "key"), stringField(v, "path")); name != "" {
				files = append(files, name)
			}
		}
	}
	return files, raw, nil
}

func extractIDFromBody(body []byte, keys ...string) string {
	if len(body) == 0 {
		return ""
	}
	obj, err := decodeJSONObject(body)
	if err != nil {
		return ""
	}
	for _, key := range keys {
		if value := stringField(obj, key); value != "" {
			return value
		}
	}
	return stringField(obj, "id")
}

func mapsFromAnySlice(items []any) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if obj, ok := item.(map[string]any); ok {
			out = append(out, obj)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func boolField(obj map[string]any, key string) bool {
	v, ok := obj[key]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	default:
		return false
	}
}

func intField(obj map[string]any, key string) int {
	v, ok := obj[key]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case json.Number:
		i, _ := t.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(t)
		return i
	default:
		return 0
	}
}

func stringField(obj map[string]any, key string) string {
	v, ok := obj[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}
