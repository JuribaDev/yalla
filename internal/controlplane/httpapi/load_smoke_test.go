package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// Verification suite — load smoke tests (BE-0392).
//
// The canonical pair below is the load-bearing test pair that the PRD's
// `go test -run TestLoadSmoke ./...` filter binds to. Together they pin
// two complementary load-smoke invariants:
//
//   - TestLoadSmokeContractCoversCoreEndpoints pins the closed-set
//     harness-coverage invariant. The endpoint table the burst harness
//     iterates MUST stay non-empty, free of duplicates, scoped to the
//     bootstrap surface (paths that need no fake dependencies, no
//     Postgres, no quota counters, and no Dokploy fixtures), and the
//     HTTP method on every entry MUST be a valid request method. This
//     member is deterministic — it walks an in-memory fixture table and
//     trips on every developer machine.
//
//   - TestLoadSmokeContractRunsBurstWithStableEnvelopes pins the
//     runtime burst invariant. Spinning the public HTTP handler up
//     in-process and firing `loadSmokeWorkers * loadSmokeIterationsPerWorker`
//     concurrent requests per endpoint MUST yield only responses that
//     (a) return the canonical status, (b) carry a stable
//     yalla.output.v1 envelope with ok=true, (c) carry a SafeID-clean
//     request_id, (d) carry a request_id unique across the whole
//     burst, and (e) contain no secret-shaped substring in body or
//     header. Failures surface with the offending endpoint AND the
//     observed request_id so an operator can correlate.
//
// Both members are deterministic by design: the bootstrap surface is
// the one part of the API that needs no backing infrastructure, so the
// load smoke gate stays green on every machine without Postgres or a
// live Dokploy server. The static verification suite under
// `internal/release/verification_suite_load_smoke_static_test.go` pins
// every collateral surface (CI step, verify.sh entry, CONTRIBUTING
// entry, SECURITY row+section, PRD command, and this canonical pair's
// existence) so that a rename or deletion trips ONE test, not six.

// loadSmokeEndpoint is one entry in the closed set of bootstrap
// endpoints the burst harness MUST exercise. Each entry is intentionally
// scoped to the deterministic-by-default surface (no Postgres, no fake
// Dokploy fixtures, no quota counters mutated, no scope-resolution
// chain). Adding an endpoint that mutates state, or that requires fake
// dependencies the closed-set member is not aware of, would defeat the
// deterministic-by-default contract documented under
// `## Load Smoke Tests` in SECURITY.md.
type loadSmokeEndpoint struct {
	method     string
	path       string
	wantStatus int
}

// loadSmokeEndpoints is the closed set. Keep it small, deterministic,
// and limited to the bootstrap surface. The TestLoadSmokeContract*
// pair MUST stay green on every developer machine without any
// infrastructure dependency.
var loadSmokeEndpoints = []loadSmokeEndpoint{
	{http.MethodGet, "/healthz", http.StatusOK},
	{http.MethodGet, "/readyz", http.StatusOK},
	{http.MethodGet, "/version", http.StatusOK},
}

// loadSmokeSecretMarkers is the closed set of substrings the harness
// MUST never observe in any response body or header. Each marker
// represents one redaction contract the bootstrap surface MUST keep
// even under concurrent burst load: API key prefix, bearer scheme,
// cookie header, raw Postgres connection string, and the literal
// Dokploy token env var name. The list is intentionally short so a
// new redaction contract can be added in one edit.
var loadSmokeSecretMarkers = []string{
	"yka_",
	"Bearer ",
	"Set-Cookie",
	"postgres://",
	"DOKPLOY_TOKEN",
}

// loadSmokeWorkers and loadSmokeIterationsPerWorker bound the burst
// the harness fires. The product (workers * iterations * endpoints)
// MUST stay small enough that the test completes in well under one
// second on a developer laptop and on every CI runner, otherwise the
// gate becomes flaky.
const (
	loadSmokeWorkers              = 16
	loadSmokeIterationsPerWorker  = 32
	loadSmokeMaxAllowedDuplicates = 0
)

// validHTTPMethods is the closed set of HTTP methods the harness will
// accept for an endpoint entry. The harness is bootstrap-only so only
// GET is meaningful today; the wider list is here so an unintentional
// typo (e.g. `Method: "Get"`) trips the closed-set member before the
// burst member runs.
var validHTTPMethods = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodHead:    {},
	http.MethodOptions: {},
}

// TestLoadSmokeContractCoversCoreEndpoints pins the closed-set
// harness-coverage invariant for the load smoke gate. The endpoint
// table the burst harness iterates MUST stay non-empty, free of
// duplicate (method,path) tuples, scoped to the bootstrap surface
// (paths that begin with `/` and never `/v1/`), and the HTTP method
// on every entry MUST be a valid request method. Runs without any
// infrastructure dependency so the gate trips on every developer
// machine.
func TestLoadSmokeContractCoversCoreEndpoints(t *testing.T) {
	t.Parallel()

	if len(loadSmokeEndpoints) == 0 {
		t.Fatal("loadSmokeEndpoints is empty; the burst harness MUST exercise at least one bootstrap endpoint or the load smoke gate is a no-op")
	}

	seen := map[string]struct{}{}
	for _, ep := range loadSmokeEndpoints {
		if _, ok := validHTTPMethods[ep.method]; !ok {
			t.Errorf("loadSmokeEndpoints: method %q for path %q is not a recognised bootstrap HTTP method; the closed-set member MUST trip on a typo before the burst member runs",
				ep.method, ep.path)
		}
		if !strings.HasPrefix(ep.path, "/") {
			t.Errorf("loadSmokeEndpoints: path %q does not begin with `/`; every entry MUST be an absolute path so the burst harness can target it deterministically",
				ep.path)
		}
		if strings.HasPrefix(ep.path, "/v1/") {
			t.Errorf("loadSmokeEndpoints: path %q is under `/v1/` and would require authenticated, scope-resolved fixtures that defeat the deterministic-by-default contract; keep load smoke on the bootstrap surface (`/healthz`, `/readyz`, `/version`, `/openapi`)",
				ep.path)
		}
		if ep.wantStatus < 100 || ep.wantStatus > 599 {
			t.Errorf("loadSmokeEndpoints: wantStatus %d for %s %s is outside the valid HTTP status range",
				ep.wantStatus, ep.method, ep.path)
		}
		key := ep.method + " " + ep.path
		if _, dup := seen[key]; dup {
			t.Errorf("loadSmokeEndpoints: duplicate entry %q; the harness MUST hit each endpoint exactly once per burst iteration so duplicate request-id observations are real regressions, not table-driven repeats",
				key)
		}
		seen[key] = struct{}{}
	}

	for _, marker := range loadSmokeSecretMarkers {
		if strings.TrimSpace(marker) == "" {
			t.Errorf("loadSmokeSecretMarkers contains an empty entry; an empty substring would match every response and silently de-gate the redaction contract")
		}
	}
}

// TestLoadSmokeContractRunsBurstWithStableEnvelopes pins the runtime
// burst invariant. The in-process public HTTP handler MUST handle
// `loadSmokeWorkers * loadSmokeIterationsPerWorker` concurrent
// requests per endpoint without returning a 5xx, without dropping the
// yalla.output.v1 envelope, without producing a request_id collision,
// and without echoing any secret-shaped substring. The test is
// deterministic — no Postgres, no fake Dokploy fixtures, no
// scope-resolution chain — so the gate trips on every developer
// machine.
//
// Failures surface with the offending endpoint AND the observed
// request_id (or "<missing>" when the response carried none) so an
// operator can correlate the gate failure with a specific in-flight
// request without re-running the suite locally.
func TestLoadSmokeContractRunsBurstWithStableEnvelopes(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(runtime.BuildInfo{
		Version: "1.2.3",
		Commit:  "abc123",
		Date:    "2026-05-14T00:00:00Z",
	}, nil, nil, nil)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	type observation struct {
		endpoint  string
		status    int
		schema    string
		requestID string
		ok        bool
		bodyBad   string
		headerBad string
	}

	totalPerEndpoint := loadSmokeWorkers * loadSmokeIterationsPerWorker
	results := make(chan observation, len(loadSmokeEndpoints)*totalPerEndpoint)

	var wg sync.WaitGroup
	for _, ep := range loadSmokeEndpoints {
		ep := ep
		for w := 0; w < loadSmokeWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				client := server.Client()
				for i := 0; i < loadSmokeIterationsPerWorker; i++ {
					req, err := http.NewRequest(ep.method, server.URL+ep.path, nil)
					if err != nil {
						results <- observation{
							endpoint:  ep.method + " " + ep.path,
							requestID: "<request-construction-failed:" + err.Error() + ">",
						}
						continue
					}
					resp, err := client.Do(req)
					if err != nil {
						results <- observation{
							endpoint:  ep.method + " " + ep.path,
							requestID: "<request-do-failed:" + err.Error() + ">",
						}
						continue
					}
					obs := observation{
						endpoint: ep.method + " " + ep.path,
						status:   resp.StatusCode,
					}
					obs.requestID = resp.Header.Get(telemetry.HeaderRequestID)

					for _, marker := range loadSmokeSecretMarkers {
						for name, values := range resp.Header {
							if strings.Contains(name, marker) {
								obs.headerBad = marker
							}
							for _, v := range values {
								if strings.Contains(v, marker) {
									obs.headerBad = marker
								}
							}
						}
					}

					var env struct {
						SchemaVersion string          `json:"schema_version"`
						OK            bool            `json:"ok"`
						RequestID     string          `json:"request_id"`
						Data          json.RawMessage `json:"data"`
						Error         json.RawMessage `json:"error"`
					}
					body := make([]byte, 0, 1024)
					buf := make([]byte, 512)
					for {
						n, rerr := resp.Body.Read(buf)
						if n > 0 {
							body = append(body, buf[:n]...)
						}
						if rerr != nil {
							break
						}
					}
					_ = resp.Body.Close()

					if jerr := json.Unmarshal(body, &env); jerr == nil {
						obs.schema = env.SchemaVersion
						obs.ok = env.OK
						if env.RequestID != "" {
							obs.requestID = env.RequestID
						}
					}
					bodyStr := string(body)
					for _, marker := range loadSmokeSecretMarkers {
						if strings.Contains(bodyStr, marker) {
							obs.bodyBad = marker
							break
						}
					}
					results <- obs
				}
			}()
		}
	}
	wg.Wait()
	close(results)

	requestIDs := map[string][]string{}
	var observations []observation
	for obs := range results {
		observations = append(observations, obs)
		if obs.requestID != "" {
			requestIDs[obs.requestID] = append(requestIDs[obs.requestID], obs.endpoint)
		}
	}

	wantPerEndpoint := totalPerEndpoint
	got := map[string]int{}
	for _, obs := range observations {
		got[obs.endpoint]++
	}
	for _, ep := range loadSmokeEndpoints {
		key := ep.method + " " + ep.path
		if got[key] != wantPerEndpoint {
			t.Errorf("burst harness fired %d requests against %s, want %d; a missing observation hides a panic or a silently dropped request",
				got[key], key, wantPerEndpoint)
		}
	}

	for _, obs := range observations {
		if obs.status == 0 {
			t.Errorf("burst harness recorded a zero-status observation for %s with request_id=%q; the underlying request failed to round-trip",
				obs.endpoint, obs.requestID)
			continue
		}
		// Find the wantStatus for this endpoint.
		var wantStatus int
		for _, ep := range loadSmokeEndpoints {
			if ep.method+" "+ep.path == obs.endpoint {
				wantStatus = ep.wantStatus
				break
			}
		}
		if obs.status != wantStatus {
			t.Errorf("burst harness response for %s returned status=%d, want %d; request_id=%q",
				obs.endpoint, obs.status, wantStatus, obs.requestID)
		}
		if obs.schema != "yalla.output.v1" {
			t.Errorf("burst harness response for %s carried schema_version=%q, want %q; request_id=%q",
				obs.endpoint, obs.schema, "yalla.output.v1", obs.requestID)
		}
		if !obs.ok {
			t.Errorf("burst harness response for %s carried ok=false; request_id=%q",
				obs.endpoint, obs.requestID)
		}
		if obs.requestID == "" {
			t.Errorf("burst harness response for %s carried no request_id; every response MUST carry one for operator correlation",
				obs.endpoint)
		} else if !telemetry.SafeID(obs.requestID) {
			t.Errorf("burst harness response for %s carried request_id=%q which is not a SafeID; an unsafe id is a header-injection vector",
				obs.endpoint, obs.requestID)
		}
		if obs.bodyBad != "" {
			t.Errorf("burst harness response for %s leaked secret-shaped substring %q in body; request_id=%q",
				obs.endpoint, obs.bodyBad, obs.requestID)
		}
		if obs.headerBad != "" {
			t.Errorf("burst harness response for %s leaked secret-shaped substring %q in headers; request_id=%q",
				obs.endpoint, obs.headerBad, obs.requestID)
		}
	}

	duplicates := 0
	var sampleDuplicates []string
	type dup struct {
		id        string
		endpoints []string
	}
	var dups []dup
	for id, eps := range requestIDs {
		if len(eps) > 1 {
			duplicates += len(eps) - 1
			dups = append(dups, dup{id: id, endpoints: eps})
		}
	}
	sort.Slice(dups, func(i, j int) bool { return dups[i].id < dups[j].id })
	for i, d := range dups {
		if i >= 3 {
			break
		}
		sampleDuplicates = append(sampleDuplicates, d.id+" -> "+strings.Join(d.endpoints, ","))
	}
	if duplicates > loadSmokeMaxAllowedDuplicates {
		t.Errorf("burst harness observed %d duplicate request_id(s) across endpoints (sample: %v); request_id MUST be unique per-request so operators can correlate exactly one observation per id",
			duplicates, sampleDuplicates)
	}
}
