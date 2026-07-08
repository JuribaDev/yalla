package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/output"
)

func TestDatabaseCommand_IsRegistered(t *testing.T) {
	cmd := NewRootCommand(IOStreams{}, BuildInfo{Version: "test"})
	found := false
	for _, child := range cmd.Commands() {
		if child.Name() == "database" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("root command missing database command")
	}
}

func TestDatabaseCreate_ValidatesRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"postgres missing password", []string{"database", "create", "postgres", "--environment-id", "env_1", "--name", "db", "--database-name", "app", "--database-user", "app"}, "database password is required"},
		{"redis rejects database name", []string{"database", "create", "redis", "--environment-id", "env_1", "--name", "cache", "--database-name", "app", "--database-password", "secret"}, "--database-name is not valid for redis"},
		{"mongo rejects database name", []string{"database", "create", "mongo", "--environment-id", "env_1", "--name", "mongo", "--database-name", "app", "--database-user", "app", "--database-password", "secret"}, "--database-name is not valid for mongo"},
		{"redis rejects replica sets", []string{"database", "create", "redis", "--environment-id", "env_1", "--name", "cache", "--database-password", "secret", "--replica-sets"}, "--replica-sets is not valid for redis"},
		{"libsql unsupported", []string{"database", "create", "libsql", "--environment-id", "env_1", "--name", "db"}, "unsupported database engine"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, err := runRootArgs(t, tc.args...)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr = %q, want %q", stderr, tc.want)
			}
		})
	}
}

func TestDatabaseCreateBody_UsesSafeDefaultImages(t *testing.T) {
	cases := []struct {
		engine databaseEngine
		want   string
	}{
		{databasePostgres, "postgres:18"},
		{databaseMySQL, "mysql:8"},
		{databaseMariaDB, "mariadb:11.4"},
		{databaseMongo, "mongo:8"},
		{databaseRedis, "redis:8"},
	}
	for _, tc := range cases {
		t.Run(string(tc.engine), func(t *testing.T) {
			body := databaseCreateBody(databaseCreateOptions{
				Engine:           tc.engine,
				Name:             "db",
				EnvironmentID:    "env_1",
				DatabaseName:     "app",
				DatabaseUser:     "app",
				DatabasePassword: "secret",
			})
			if body["dockerImage"] != tc.want {
				t.Fatalf("dockerImage = %v, want %q", body["dockerImage"], tc.want)
			}
		})
	}
}

func TestDatabaseCreateBody_ImageOverrideWins(t *testing.T) {
	body := databaseCreateBody(databaseCreateOptions{
		Engine:           databaseMariaDB,
		Name:             "db",
		EnvironmentID:    "env_1",
		DatabaseName:     "app",
		DatabaseUser:     "app",
		DatabasePassword: "secret",
		Image:            "mariadb:12",
	})
	if body["dockerImage"] != "mariadb:12" {
		t.Fatalf("dockerImage = %v, want override", body["dockerImage"])
	}
}

func TestDatabaseCreate_PostgresWithDeploy_JSON(t *testing.T) {
	var calls []string
	var createBody map[string]any
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case coverageWirePath("/postgres.create"):
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatalf("decode create body: %v", err)
			}
			_, _ = w.Write([]byte(`{}`))
		case coverageWirePath("/postgres.search"):
			if got := r.URL.Query().Get("name"); got != "eduai-postgres" {
				t.Errorf("search name = %q", got)
			}
			_, _ = w.Write([]byte(`{"items":[{"name":"eduai-postgres","environmentId":"env_1","postgresId":"pg_1","appName":"eduai-postgres-abc"}],"total":1}`))
		case coverageWirePath("/postgres.deploy"):
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode deploy body: %v", err)
			}
			if body["postgresId"] != "pg_1" {
				t.Errorf("deploy postgresId = %q", body["postgresId"])
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	stdout, stderr, err := runRootArgs(t, "--json", "database", "create", "postgres",
		"--environment-id", "env_1",
		"--name", "eduai-postgres",
		"--database-name", "eduai",
		"--database-user", "eduai",
		"--database-password", "secret-db-password",
		"--image", "postgres:18",
		"--deploy")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
	wantCalls := []string{
		coverageWirePath("/postgres.create"),
		coverageWirePath("/postgres.search"),
		coverageWirePath("/postgres.deploy"),
	}
	if strings.Join(calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
	if createBody["databasePassword"] != "secret-db-password" {
		t.Errorf("databasePassword not forwarded in request body: %v", createBody)
	}
	if createBody["dockerImage"] != "postgres:18" {
		t.Errorf("dockerImage = %v", createBody["dockerImage"])
	}
	if strings.Contains(stdout, "secret-db-password") {
		t.Fatalf("password leaked in stdout: %q", stdout)
	}

	var env struct {
		SchemaVersion string            `json:"schema_version"`
		Data          databaseCreateDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode stdout: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("schema_version = %q", env.SchemaVersion)
	}
	if env.Data.ID != "pg_1" || !env.Data.Deployed || env.Data.AppName != "eduai-postgres-abc" {
		t.Errorf("unexpected create doc: %+v", env.Data)
	}
}

func TestDatabaseCreate_MongoReplicaSets(t *testing.T) {
	var createBody map[string]any
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case coverageWirePath("/mongo.create"):
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatalf("decode create body: %v", err)
			}
			_, _ = w.Write([]byte(`{}`))
		case coverageWirePath("/mongo.search"):
			_, _ = w.Write([]byte(`{"items":[{"name":"eduai-mongo","environmentId":"env_1","mongoId":"mongo_1"}],"total":1}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})
	_, stderr, err := runRootArgs(t, "--json", "database", "create", "mongo",
		"--environment-id", "env_1",
		"--name", "eduai-mongo",
		"--database-user", "eduai",
		"--database-password", "mongo-secret",
		"--replica-sets")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if createBody["replicaSets"] != true {
		t.Errorf("replicaSets = %v, want true", createBody["replicaSets"])
	}
	if _, ok := createBody["databaseName"]; ok {
		t.Errorf("mongo create body should not include databaseName: %v", createBody)
	}
}

func TestDatabaseDeploy_Redis_JSON(t *testing.T) {
	var deployBody map[string]string
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != coverageWirePath("/redis.deploy") {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&deployBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	stdout, stderr, err := runRootArgs(t, "--json", "database", "deploy", "redis", "--id", "redis_1")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if deployBody["redisId"] != "redis_1" {
		t.Errorf("redisId = %q", deployBody["redisId"])
	}
	var env struct {
		Data databaseDeployDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Data.Engine != "redis" || env.Data.ID != "redis_1" {
		t.Errorf("unexpected doc: %+v", env.Data)
	}
}

func TestDatabaseUpdate_ScalesPostgres(t *testing.T) {
	var calls []string
	var updateBody map[string]any
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case coverageWirePath("/postgres.one"):
			if got := r.URL.Query().Get("postgresId"); got != "pg_1" {
				t.Errorf("postgresId query = %q", got)
			}
			_, _ = w.Write([]byte(`{"postgresId":"pg_1","name":"eduai-postgres","memoryLimit":"256M","replicas":1}`))
		case coverageWirePath("/postgres.update"):
			if err := json.NewDecoder(r.Body).Decode(&updateBody); err != nil {
				t.Fatalf("decode update body: %v", err)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})
	stdout, stderr, err := runRootArgs(t, "--json", "database", "update", "postgres",
		"--id", "pg_1",
		"--memory-reservation", "512M",
		"--memory-limit", "1G",
		"--cpu-reservation", "0.25",
		"--cpu-limit", "1",
		"--replicas", "2")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	wantCalls := []string{coverageWirePath("/postgres.one"), coverageWirePath("/postgres.update")}
	if strings.Join(calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
	if updateBody["postgresId"] != "pg_1" || updateBody["memoryReservation"] != "512M" || updateBody["memoryLimit"] != "1G" {
		t.Errorf("update body missing memory fields: %v", updateBody)
	}
	replicas, ok := updateBody["replicas"].(float64)
	if !ok || updateBody["cpuReservation"] != "0.25" || updateBody["cpuLimit"] != "1" || replicas != 2 {
		t.Errorf("update body missing cpu/replica fields: %v", updateBody)
	}
	if updateBody["name"] != "eduai-postgres" {
		t.Errorf("current fields were not preserved: %v", updateBody)
	}
	var env struct {
		Data databaseUpdateDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.Replicas != 2 || !env.Data.ReplicasSet {
		t.Errorf("unexpected update doc: %+v", env.Data)
	}
}

func TestDatabaseUpdate_ValidatesFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"missing id", []string{"database", "update", "postgres", "--memory-limit", "1G"}, "database ID is required"},
		{"no fields", []string{"database", "update", "postgres", "--id", "pg_1"}, "at least one update flag is required"},
		{"bad cpu", []string{"database", "update", "postgres", "--id", "pg_1", "--cpu-limit", "nope"}, "--cpu-limit must be a positive decimal number"},
		{"zero replicas", []string{"database", "update", "postgres", "--id", "pg_1", "--replicas", "0"}, "--replicas must be greater than zero"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, err := runRootArgs(t, tc.args...)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr = %q, want %q", stderr, tc.want)
			}
		})
	}
}

func TestDatabaseBackupCreate_Postgres_JSON(t *testing.T) {
	var calls []string
	var createBody map[string]any
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case coverageWirePath("/backup.create"):
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatalf("decode create body: %v", err)
			}
			_, _ = w.Write([]byte(`{}`))
		case coverageWirePath("/postgres.one"):
			_, _ = w.Write([]byte(`{"postgresId":"pg_1","backups":[{"backupId":"backup_1","databaseType":"postgres","postgresId":"pg_1","destinationId":"dst_1","database":"app","prefix":"backups/app/","schedule":"0 2 * * *"}]}`))
		case coverageWirePath("/user.getBackups"):
			_, _ = w.Write([]byte(`{"backups":[]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	stdout, stderr, err := runRootArgs(t, "--json", "database", "backup", "create", "postgres",
		"--id", "pg_1",
		"--destination-id", "dst_1",
		"--database", "app",
		"--prefix", "backups/app/",
		"--schedule", "0 2 * * *",
		"--keep-latest", "7",
		"--disabled")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	wantCalls := []string{coverageWirePath("/backup.create"), coverageWirePath("/postgres.one")}
	if strings.Join(calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
	if createBody["postgresId"] != "pg_1" || createBody["databaseType"] != "postgres" || createBody["backupType"] != "database" {
		t.Errorf("create body missing postgres backup fields: %v", createBody)
	}
	if createBody["destinationId"] != "dst_1" || createBody["database"] != "app" || createBody["prefix"] != "backups/app/" || createBody["schedule"] != "0 2 * * *" {
		t.Errorf("create body missing schedule fields: %v", createBody)
	}
	keepLatest, ok := createBody["keepLatestCount"].(float64)
	if !ok || createBody["enabled"] != false || keepLatest != 7 {
		t.Errorf("create body missing optional fields: %v", createBody)
	}

	var env struct {
		Data databaseBackupCreateDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.BackupID != "backup_1" || env.Data.Engine != "postgres" || env.Data.Enabled {
		t.Errorf("unexpected create doc: %+v", env.Data)
	}
}

func TestDatabaseBackupCreate_RejectsRedis(t *testing.T) {
	_, stderr, err := runRootArgs(t, "database", "backup", "create", "redis",
		"--id", "redis_1",
		"--destination-id", "dst_1",
		"--database", "cache",
		"--prefix", "backups/cache/",
		"--schedule", "0 2 * * *")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(stderr, "database backups are not supported for redis") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestDatabaseBackupRun_MySQL_JSON(t *testing.T) {
	var calls []string
	var runBody map[string]string
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case coverageWirePath("/backup.one"):
			_, _ = w.Write([]byte(`{"backupId":"backup_1","databaseType":"mysql"}`))
		case coverageWirePath("/backup.manualBackupMySql"):
			if err := json.NewDecoder(r.Body).Decode(&runBody); err != nil {
				t.Fatalf("decode run body: %v", err)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	stdout, stderr, err := runRootArgs(t, "--json", "database", "backup", "run", "mysql", "--backup-id", "backup_1")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	wantCalls := []string{coverageWirePath("/backup.one"), coverageWirePath("/backup.manualBackupMySql")}
	if strings.Join(calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
	if runBody["backupId"] != "backup_1" {
		t.Errorf("backupId = %q", runBody["backupId"])
	}
	var env struct {
		Data databaseBackupActionDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Data.Operation != "run" || env.Data.Engine != "mysql" || env.Data.BackupID != "backup_1" {
		t.Errorf("unexpected run doc: %+v", env.Data)
	}
}

func TestDatabaseBackupRun_RejectsEngineMismatch(t *testing.T) {
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != coverageWirePath("/backup.one") {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"backupId":"backup_1","databaseType":"mongo"}`))
	})

	_, stderr, err := runRootArgs(t, "database", "backup", "run", "postgres", "--backup-id", "backup_1")
	if err == nil {
		t.Fatal("expected engine mismatch error")
	}
	if !strings.Contains(stderr, "backup backup_1 is for mongo, not postgres") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestDatabaseBackupUpdate_PreservesCurrentFields(t *testing.T) {
	var calls []string
	var updateBody map[string]any
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case coverageWirePath("/backup.one"):
			if got := r.URL.Query().Get("backupId"); got != "backup_1" {
				t.Errorf("backupId query = %q", got)
			}
			_, _ = w.Write([]byte(`{"backupId":"backup_1","schedule":"0 1 * * *","enabled":true,"prefix":"old/","destinationId":"dst_1","database":"app","keepLatestCount":5,"serviceName":null,"metadata":null,"databaseType":"postgres"}`))
		case coverageWirePath("/backup.update"):
			if err := json.NewDecoder(r.Body).Decode(&updateBody); err != nil {
				t.Fatalf("decode update body: %v", err)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	stdout, stderr, err := runRootArgs(t, "--json", "database", "backup", "update", "postgres",
		"--backup-id", "backup_1",
		"--schedule", "0 3 * * *",
		"--prefix", "new/",
		"--disabled")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	wantCalls := []string{coverageWirePath("/backup.one"), coverageWirePath("/backup.update")}
	if strings.Join(calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
	if updateBody["backupId"] != "backup_1" || updateBody["destinationId"] != "dst_1" || updateBody["database"] != "app" {
		t.Errorf("current fields were not preserved: %v", updateBody)
	}
	if updateBody["schedule"] != "0 3 * * *" || updateBody["prefix"] != "new/" || updateBody["enabled"] != false {
		t.Errorf("changed fields were not applied: %v", updateBody)
	}
	var env struct {
		Data databaseBackupUpdateDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	if env.Data.BackupID != "backup_1" || env.Data.Enabled != false || env.Data.Schedule != "0 3 * * *" {
		t.Errorf("unexpected update doc: %+v", env.Data)
	}
}

func TestDatabaseBackupUpdate_RejectsEngineMismatch(t *testing.T) {
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != coverageWirePath("/backup.one") {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"backupId":"backup_1","schedule":"0 1 * * *","enabled":true,"prefix":"mongo/","destinationId":"dst_1","database":"app","keepLatestCount":5,"serviceName":null,"metadata":null,"databaseType":"mongo"}`))
	})

	_, stderr, err := runRootArgs(t, "database", "backup", "update", "postgres",
		"--backup-id", "backup_1",
		"--schedule", "0 3 * * *")
	if err == nil {
		t.Fatal("expected engine mismatch error")
	}
	if !strings.Contains(stderr, "backup backup_1 is for mongo, not postgres") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestDatabaseBackupUpdate_RejectsMissingRequiredCurrentField(t *testing.T) {
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != coverageWirePath("/backup.one") {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"backupId":"backup_1","schedule":"0 1 * * *","enabled":true,"prefix":"pg/","destinationId":"dst_1","keepLatestCount":5,"serviceName":null,"metadata":null,"databaseType":"postgres"}`))
	})

	_, stderr, err := runRootArgs(t, "database", "backup", "update", "postgres",
		"--backup-id", "backup_1",
		"--schedule", "0 3 * * *")
	if err == nil {
		t.Fatal("expected missing current field error")
	}
	if !strings.Contains(stderr, "backup backup_1 is missing required field database") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestDatabaseBackupGetDeleteAndListFiles(t *testing.T) {
	var removeBody map[string]string
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case coverageWirePath("/backup.one"):
			_, _ = w.Write([]byte(`{"backupId":"backup_1","databaseType":"mongo","prefix":"mongo/"}`))
		case coverageWirePath("/backup.remove"):
			if err := json.NewDecoder(r.Body).Decode(&removeBody); err != nil {
				t.Fatalf("decode remove body: %v", err)
			}
			_, _ = w.Write([]byte(`{}`))
		case coverageWirePath("/backup.listBackupFiles"):
			if r.URL.Query().Get("destinationId") != "dst_1" || r.URL.Query().Get("search") != "mongo/" || r.URL.Query().Get("serverId") != "srv_1" {
				t.Errorf("unexpected query: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"items":["mongo/file.sql.gz"]}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	if _, stderr, err := runRootArgs(t, "--json", "database", "backup", "get", "--backup-id", "backup_1"); err != nil {
		t.Fatalf("get Execute: %v (stderr=%q)", err, stderr)
	}
	if _, stderr, err := runRootArgs(t, "--json", "database", "backup", "delete", "--backup-id", "backup_1"); err != nil {
		t.Fatalf("delete Execute: %v (stderr=%q)", err, stderr)
	}
	if removeBody["backupId"] != "backup_1" {
		t.Errorf("remove backupId = %q", removeBody["backupId"])
	}
	if _, stderr, err := runRootArgs(t, "--json", "database", "backup", "list-files", "--destination-id", "dst_1", "--prefix", "mongo/", "--server-id", "srv_1"); err != nil {
		t.Fatalf("list-files Execute: %v (stderr=%q)", err, stderr)
	}
}

func TestDatabaseBackupNoArgCommandsRejectUnexpectedArgs(t *testing.T) {
	cases := [][]string{
		{"database", "backup", "get", "extra", "--backup-id", "backup_1"},
		{"database", "backup", "delete", "extra", "--backup-id", "backup_1"},
		{"database", "backup", "list-files", "extra", "--destination-id", "dst_1", "--prefix", "mongo/"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args[:3], " "), func(t *testing.T) {
			_, stderr, err := runRootArgs(t, args...)
			if err == nil {
				t.Fatal("expected unexpected arg error")
			}
			if !strings.Contains(stderr, "unknown command") && !strings.Contains(stderr, "accepts 0 arg") {
				t.Fatalf("stderr = %q", stderr)
			}
		})
	}
}

func TestDatabaseCreate_ErrorRedactsPassword(t *testing.T) {
	const secret = "super-secret-db-password"
	setupAPICallServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"bad password super-secret-db-password"}`))
	})
	stdout, stderr, err := runRootArgs(t, "--json", "database", "create", "redis",
		"--environment-id", "env_1",
		"--name", "cache",
		"--database-password", secret)
	if err == nil {
		t.Fatal("expected upstream error")
	}
	combined := stdout + stderr
	if strings.Contains(combined, secret) {
		t.Fatalf("password leaked: %q", combined)
	}
	if !strings.Contains(combined, output.Sentinel) {
		t.Fatalf("expected redaction sentinel; got %q", combined)
	}
}
