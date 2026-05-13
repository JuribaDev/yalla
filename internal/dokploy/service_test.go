package dokploy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
)

func TestHTTPRunnerCallBuildsRequest(t *testing.T) {
	var seenPath, seenBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.String()
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		seenBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"p1","name":"smoke"}`))
	}))
	t.Cleanup(srv.Close)

	cli, err := api.NewClient(api.ClientConfig{BaseURL: srv.URL, Token: "t", AuthScheme: api.AuthSchemeAPIKeyHeader, BasePathPrefix: api.Default().ServerPath})
	if err != nil {
		t.Fatal(err)
	}
	runner := NewHTTPRunner(api.Default(), cli)
	res, err := runner.Call(context.Background(), "project-create", Input{Body: json.RawMessage(`{"name":"smoke"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusOK || !strings.Contains(string(res.Body), `"p1"`) {
		t.Fatalf("result = %+v body=%s", res, string(res.Body))
	}
	if seenPath != "/api/project.create" {
		t.Fatalf("path = %q", seenPath)
	}
	if seenBody != `{"name":"smoke"}` {
		t.Fatalf("body = %q", seenBody)
	}
}

func TestKnownIssuesWrapsComposeStopENOENT(t *testing.T) {
	err := MatchKnownIssue("compose-stop", 500, []byte(`{"message":"spawn /bin/sh ENOENT"}`))
	if err == nil || string(err.Code) != "E_UPSTREAM_BUG" {
		t.Fatalf("known issue = %#v, want E_UPSTREAM_BUG", err)
	}
}
