package httpapi

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

type fakeServiceBackupRunRestorer struct {
	backup    store.ServiceBackup
	err       error
	gotInput  *store.RestoreServiceBackupInput
	callCount *int
}

func (f fakeServiceBackupRunRestorer) Run(context.Context, store.RunServiceBackupInput) (store.ServiceBackup, error) {
	return store.ServiceBackup{}, apierr.Internal(stderrors.New("run not expected"))
}

func (f fakeServiceBackupRunRestorer) Restore(_ context.Context, in store.RestoreServiceBackupInput) (store.ServiceBackup, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.backup, f.err
}

type restoreServiceBackupSuccessEnvelope struct {
	SchemaVersion string                      `json:"schema_version"`
	OK            bool                        `json:"ok"`
	RequestID     string                      `json:"request_id"`
	Data          restoreServiceBackupPayload `json:"data"`
}

func postRestoreServiceBackup(handler http.Handler, serviceID, backupID, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost,
		"/v1/services/"+serviceID+"/backups/"+backupID+"/restore", strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestRestoreServiceBackupHappyPath(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_nightly"
	)
	created := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	var gotIn store.RestoreServiceBackupInput
	callCount := 0
	restorer := fakeServiceBackupRunRestorer{
		backup: seedServiceBackupWire(
			bkpID, org, svcID, "nightly", "0 2 * * *", 14, true,
			store.ServiceBackupStatusSucceeded, 7, created, updated,
		),
		gotInput:  &gotIn,
		callCount: &callCount,
	}
	handler := runServiceBackupHandlerFor(
		principalForRunBackup("usr_dev", org), nil, restorer)

	rec := postRestoreServiceBackup(handler, svcID, bkpID, "", "token")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Fatalf("Restore call count = %d, want 1", callCount)
	}
	if gotIn.OrganizationID != org || gotIn.ServiceID != svcID || gotIn.BackupID != bkpID {
		t.Fatalf("restore input = %+v", gotIn)
	}
	if gotIn.ActorID != "usr_dev" || gotIn.ActorOrgID != org || gotIn.ActorKind == "" {
		t.Fatalf("actor audit fields = %+v", gotIn)
	}

	var env restoreServiceBackupSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode success envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID == "" {
		t.Fatalf("bad envelope: %+v", env)
	}
	if env.Data.Backup.ID != bkpID || env.Data.Backup.Status != store.ServiceBackupStatusSucceeded {
		t.Fatalf("backup payload = %+v", env.Data.Backup)
	}
}

func TestRestoreServiceBackupStoreErrorsAreTyped(t *testing.T) {
	t.Parallel()

	const (
		org   = "org_acme"
		svcID = "svc_api"
		bkpID = "sbkp_nightly"
	)
	callCount := 0
	restorer := fakeServiceBackupRunRestorer{
		err:       apierr.Conflict("backup has no successful run to restore"),
		callCount: &callCount,
	}
	handler := runServiceBackupHandlerFor(
		principalForRunBackup("usr_dev", org), nil, restorer)

	rec := postRestoreServiceBackup(handler, svcID, bkpID, "", "token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Fatalf("Restore call count = %d, want 1", callCount)
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.Error.Code != string(yerr.CodeConflict) {
		t.Fatalf("error code = %q, want %q", env.Error.Code, yerr.CodeConflict)
	}
}
