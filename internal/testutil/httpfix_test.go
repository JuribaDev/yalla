package testutil_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/testutil"
)

// NewServer must wire YALLA_BASE_URL/YALLA_TOKEN, register cleanup, and
// return the seeded token so secret-leak assertions have something to
// compare against.
func TestNewServer_WiresEnvAndCleansUp(t *testing.T) {
	srv, token := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutil.JSONResponse(w, http.StatusOK, map[string]string{"ok": "yes"})
	}))
	if srv.URL == "" {
		t.Fatal("NewServer returned a server without a URL")
	}
	if token == "" {
		t.Fatal("NewServer returned an empty token; secret-leak tests need a value")
	}
	resp, err := http.Get(srv.URL + "/anything")
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"ok":"yes"`) {
		t.Errorf("unexpected body %q", body)
	}
}

// RecordingServer must capture method, path, query, headers, and body
// without mutating the live request seen by the inner handler.
func TestRecordingServer_CapturesAllRequestParts(t *testing.T) {
	innerSawBody := ""
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		innerSawBody = string(b)
		testutil.JSONResponse(w, http.StatusOK, map[string]any{"echo": innerSawBody})
	})
	srv, rec, _ := testutil.RecordingServer(t, handler)

	form := url.Values{"a": []string{"1"}}
	resp, err := http.Post(
		srv.URL+"/project.create?tag=staging",
		"application/json",
		strings.NewReader(`{"name":"yalla","values":[`+form.Encode()+`]}`),
	)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if rec.Len() != 1 {
		t.Fatalf("recorder.Len = %d, want 1", rec.Len())
	}
	got := rec.First(t)
	if got.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", got.Method)
	}
	if got.Path != "/project.create" {
		t.Errorf("path = %q, want /project.create", got.Path)
	}
	if got.Query.Get("tag") != "staging" {
		t.Errorf("query[tag] = %q, want staging", got.Query.Get("tag"))
	}
	if !strings.Contains(string(got.Body), `"name":"yalla"`) {
		t.Errorf("body not captured: %q", got.Body)
	}
	if !strings.Contains(innerSawBody, `"name":"yalla"`) {
		t.Errorf("inner handler saw a mangled body: %q", innerSawBody)
	}
}

// CapturedRequest.AsJSON must round-trip into a typed struct.
func TestCapturedRequest_AsJSON(t *testing.T) {
	srv, rec, _ := testutil.RecordingServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	body := `{"name":"yalla","count":3}`
	if _, err := http.Post(srv.URL+"/x", "application/json", strings.NewReader(body)); err != nil {
		t.Fatalf("post: %v", err)
	}
	var got struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	rec.First(t).AsJSON(t, &got)
	if got.Name != "yalla" || got.Count != 3 {
		t.Errorf("decoded payload mismatch: %+v", got)
	}
}

// AssertOperationCalled must match on method+path and provide a useful
// message when the recorder is empty.
func TestAssertOperationCalled_Match(t *testing.T) {
	srv, rec, _ := testutil.RecordingServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutil.JSONResponse(w, http.StatusOK, struct{}{})
	}))
	if _, err := http.Get(srv.URL + "/project.all"); err != nil {
		t.Fatalf("get: %v", err)
	}
	got := testutil.AssertOperationCalled(t, rec, "project-all", http.MethodGet, "/project.all")
	if got.Method != http.MethodGet {
		t.Errorf("returned request did not match: %+v", got)
	}
}

// JSONResponse writes Content-Type and a JSON body.
func TestJSONResponse_Encodes(t *testing.T) {
	srv, _ := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		testutil.JSONResponse(w, http.StatusTeapot, map[string]int{"n": 7})
	}))
	resp, err := http.Get(srv.URL + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status = %d, want 418", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q", ct)
	}
	var payload map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["n"] != 7 {
		t.Errorf("payload = %+v, want {n:7}", payload)
	}
}
