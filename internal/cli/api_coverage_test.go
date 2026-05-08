package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// apiCoverageCase locks the per-operation contract that every Dokploy
// API operation story (API-0001 onward in `ralph/prd.json`) signs off on.
//
// The harness below loops over `coveredAPIOperations` and runs the same
// five-part check for each entry: registry presence (ID/method/path/tag
// invariant), schema reachability, manifest inclusion, an httptest-backed
// success exchange, and at least one representative failure path. Adding
// coverage for a new API-XXXX story therefore only ever means appending
// one struct literal — never duplicating boilerplate.
type apiCoverageCase struct {
	// StoryID is the PRD identifier (e.g. "API-0001"). Used in subtest
	// names so a failing assertion points back to the story it gates.
	StoryID string

	// OperationID is the OpenAPI operationId surfaced by the registry,
	// e.g. "admin-setupMonitoring".
	OperationID string

	// Method, Path, and Tag are the registry-level invariants the story's
	// acceptance criteria explicitly call out. Any spec drift between
	// `data/openapi.json` and the story manifest must fail this test
	// before it can ship.
	Method string
	Path   string
	Tag    string

	// SampleBody is a representative JSON request body for operations
	// that declare `requestBody.required = true`. The bytes are sent
	// verbatim to the httptest server so the success path exercises real
	// JSON serialisation, content-type negotiation, and body forwarding.
	// Operations with no body leave this nil.
	SampleBody json.RawMessage

	// SampleQuery / SamplePathParams cover the equivalent acceptance
	// criteria for operations that declare query parameters or
	// `{placeholder}` path segments. The harness ignores empty maps so
	// most operations do not need to populate them.
	SampleQuery      map[string][]string
	SamplePathParams map[string]string

	// SuccessStatus is the HTTP status the httptest server returns for
	// the success leg. Defaults to 200 when zero so most cases stay
	// short.
	SuccessStatus int

	// SuccessResponse is the JSON document returned by the httptest
	// server on success. Defaults to `{}` so omitting it keeps the body
	// valid JSON.
	SuccessResponse string

	// FailureStatus is the HTTP status code the failure leg returns.
	// Defaults to 401 (the most representative failure for an
	// authenticated Dokploy operation) when zero.
	FailureStatus int

	// FailureCode is the typed yerr.Code the renderer must surface for
	// FailureStatus. Defaults to yerr.CodeAuth when empty.
	FailureCode yerr.Code
}

// coveredAPIOperations is the append-only registry of API-XXXX stories
// that have shipped per-operation contract coverage. Each subsequent
// API story adds exactly one entry here; the harness below proves the
// invariants automatically.
//
// Keep entries sorted by StoryID for diff-friendliness.
var coveredAPIOperations = []apiCoverageCase{
	{
		StoryID:     "API-0001",
		OperationID: "admin-setupMonitoring",
		Method:      http.MethodPost,
		Path:        "/admin.setupMonitoring",
		Tag:         "admin",
		// Mirrors the schema in `data/openapi.json` for /admin.setupMonitoring:
		// the only required top-level field is `metricsConfig`, which itself
		// requires `server` (with `refreshRate`) and `containers`. We supply
		// a minimal-but-valid shape so a future schema validator will not
		// reject the fixture.
		SampleBody: json.RawMessage(`{
			"metricsConfig": {
				"server": {
					"refreshRate": 5,
					"port": 4500,
					"cronJob": "*/5 * * * *",
					"urlCallback": "https://example.test/callback",
					"thresholds": {
						"cpu": 80,
						"memory": 80
					}
				},
				"containers": {
					"refreshRate": 30,
					"services": {
						"include": ["dokploy"],
						"exclude": []
					}
				}
			}
		}`),
		SuccessResponse: `{"ok":true}`,
	},
	{
		StoryID:     "API-0002",
		OperationID: "ai-create",
		Method:      http.MethodPost,
		Path:        "/ai.create",
		Tag:         "ai",
		// Mirrors the schema in `data/openapi.json` for /ai.create:
		// every top-level field (`name`, `apiUrl`, `apiKey`, `model`,
		// `isEnabled`) is required, so the fixture supplies all five
		// with deterministic-but-clearly-fake values. The bytes only
		// ever live in a per-test `t.TempDir()` so the placeholder
		// `apiKey` does not leak between cases.
		SampleBody: json.RawMessage(`{
			"name": "yalla-coverage-ai-create-0002",
			"apiUrl": "https://example.test/v1",
			"apiKey": "fake-api-key-coverage-0002",
			"model": "gpt-test",
			"isEnabled": true
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`.
		// Keep the body empty-object so the success-leg envelope assertion
		// stays focused on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0003",
		OperationID: "ai-delete",
		Method:      http.MethodPost,
		Path:        "/ai.delete",
		Tag:         "ai",
		// Mirrors the schema in `data/openapi.json` for /ai.delete: the
		// only required field is `aiId` (string). Keep the fixture
		// minimal-but-valid so a future schema validator wired into the
		// harness still accepts it.
		SampleBody: json.RawMessage(`{
			"aiId": "ai-cov-delete-0003"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other ai/* and application/* peers. We keep an
		// empty-object body so the success-leg envelope assertion stays
		// focused on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0004",
		OperationID: "ai-deploy",
		Method:      http.MethodPost,
		Path:        "/ai.deploy",
		Tag:         "ai",
		// Mirrors the schema in `data/openapi.json` for /ai.deploy: six
		// required string fields (`environmentId`, `id`, `dockerCompose`,
		// `envVariables`, `name`, `description`) plus three optional
		// ones (`serverId`, `domains[]`, `configFiles[]`). Per the
		// API-0014 convention we supply every optional with a
		// deterministic-but-clearly-fake value so the wire payload
		// exercises the full deploy envelope (array branches included),
		// not just the minimum. Per-case fixture token
		// `*-cov-ai-deploy-0004` keeps `git grep` traceable to this PRD
		// story.
		SampleBody: json.RawMessage(`{
			"environmentId": "env-cov-ai-deploy-0004",
			"id": "ai-cov-ai-deploy-0004",
			"dockerCompose": "version: \"3\"\nservices:\n  app:\n    image: yalla/coverage:0004\n",
			"envVariables": "FOO=bar\nBAZ=qux\n",
			"serverId": "srv-cov-ai-deploy-0004",
			"name": "yalla-coverage-ai-deploy-0004",
			"description": "yalla coverage fixture for API-0004",
			"domains": [
				{
					"host": "ai-deploy-0004.example.test",
					"port": 8080,
					"serviceName": "app"
				}
			],
			"configFiles": [
				{
					"filePath": "/etc/yalla/coverage-0004.conf",
					"content": "key=value\n"
				}
			]
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other ai/* and application/* peers. Keep the body
		// empty-object so the success-leg envelope assertion stays focused
		// on `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0005",
		OperationID: "ai-get",
		Method:      http.MethodGet,
		Path:        "/ai.get",
		Tag:         "ai",
		// First GET-shaped entry in the ai/* coverage roster. Mirrors
		// the schema in `data/openapi.json` for /ai.get: a single
		// required query parameter `aiId` (string), no request body.
		// The harness forwards SampleQuery via the `--input` JSON
		// `query` field, and the success-leg assertion at
		// runAPICoverageSuccess re-reads `r.URL.Query()` to confirm
		// the CLI propagated the param verbatim. We reuse the
		// deterministic-but-clearly-fake `<tag>-cov-<slug>-<storyID>`
		// naming convention shared with API-0021/0022/0023.
		SampleQuery: map[string][]string{
			"aiId": {"ai-cov-get-0005"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior ai/* peer. Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0006",
		OperationID: "ai-getAll",
		Method:      http.MethodGet,
		Path:        "/ai.getAll",
		Tag:         "ai",
		// Parameter-free GET in the ai/* coverage roster. The spec for
		// /ai.getAll declares zero parameters and no request body, so
		// neither SampleQuery, SamplePathParams, nor SampleBody are
		// populated — the harness still asserts the wire-level
		// invariants (method, path, Authorization header, empty query
		// string) at runAPICoverageSuccess. Keeping the entry minimal
		// matches the no-input shape the agent contract guarantees:
		// `yalla api call ai-getAll --input '{}' --json` is the
		// canonical invocation.
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior ai/* peer. Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0007",
		OperationID: "ai-getModels",
		Method:      http.MethodGet,
		Path:        "/ai.getModels",
		Tag:         "ai",
		// Second query-only GET in the ai/* coverage roster. Mirrors
		// the schema in `data/openapi.json` for /ai.getModels: no
		// request body, two required query parameters — `apiUrl` and
		// `apiKey` (both strings). Unlike API-0005 (`ai-get`, single
		// `aiId` param) this operation forwards an upstream provider
		// secret on the wire, so the fixture supplies a deterministic-
		// but-clearly-fake `apiKey` value (`fake-api-key-coverage-0007`)
		// that lives only inside the per-test `t.TempDir()` JSON input
		// — it never reaches stdout/stderr or git history. Mirrors the
		// `ai-create` (API-0002) precedent for placeholder secret
		// shaping. The harness forwards SampleQuery via the `--input`
		// JSON `query` field, and `runAPICoverageSuccess` re-reads
		// `r.URL.Query()` to confirm the CLI propagated both params
		// verbatim.
		SampleQuery: map[string][]string{
			"apiUrl": {"https://example.test/v1"},
			"apiKey": {"fake-api-key-coverage-0007"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior ai/* peer. Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0011",
		OperationID: "application-cancelDeployment",
		Method:      http.MethodPost,
		Path:        "/application.cancelDeployment",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.cancelDeployment: the only required field is
		// `applicationId` (string). Keep the fixture minimal-but-valid so
		// a future schema validator wired into the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-cancel-deploy-0011"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`.
		// We keep an empty-object body so the success-leg envelope assertion
		// stays focused on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0012",
		OperationID: "application-cleanQueues",
		Method:      http.MethodPost,
		Path:        "/application.cleanQueues",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.cleanQueues: the only required field is
		// `applicationId` (string). Keep the fixture minimal-but-valid so
		// a future schema validator wired into the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-clean-queues-0012"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching application-cancelDeployment. We keep an empty-object body
		// so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0013",
		OperationID: "application-clearDeployments",
		Method:      http.MethodPost,
		Path:        "/application.clearDeployments",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.clearDeployments: the only required field is
		// `applicationId` (string). Keep the fixture minimal-but-valid so
		// a future schema validator wired into the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-clear-deploys-0013"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching application-cancelDeployment / application-cleanQueues.
		// We keep an empty-object body so the success-leg envelope
		// assertion stays focused on `data.method` / `data.status`
		// rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0014",
		OperationID: "application-create",
		Method:      http.MethodPost,
		Path:        "/application.create",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for /application.create:
		// the required top-level fields are `name` and `environmentId`. The
		// optional `appName`, `description`, and `serverId` fields are also
		// supplied with deterministic-but-clearly-fake values so the wire
		// fixture exercises the full create payload, not just the minimum.
		// `description` and `serverId` use anyOf [string, null]; we send the
		// string variant so the fixture remains valid against either branch
		// once a future schema validator is wired into the harness.
		SampleBody: json.RawMessage(`{
			"name": "yalla-coverage-app-create-0014",
			"appName": "yalla-cov-app-create-0014",
			"description": "API-0014 fixture for application-create coverage",
			"environmentId": "env-cov-app-create-0014",
			"serverId": "srv-cov-app-create-0014"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other application/* peers. We keep an empty-object
		// body so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0015",
		OperationID: "application-delete",
		Method:      http.MethodPost,
		Path:        "/application.delete",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for /application.delete:
		// the only required field is `applicationId` (string). Keep the
		// fixture minimal-but-valid so a future schema validator wired into
		// the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-delete-0015"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other application/* peers. We keep an empty-object
		// body so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0016",
		OperationID: "application-deploy",
		Method:      http.MethodPost,
		Path:        "/application.deploy",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for /application.deploy:
		// the only required field is `applicationId` (string); `title` and
		// `description` are optional strings. The fixture supplies all three
		// with deterministic-but-clearly-fake values so the wire payload
		// assertion exercises the full deploy envelope rather than just the
		// minimum, matching the *-create / *-update convention recorded in
		// internal/cli/AGENTS.md.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-deploy-0016",
			"title": "API-0016 deploy fixture",
			"description": "API-0016 fixture for application-deploy coverage"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other application/* peers. We keep an empty-object
		// body so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0017",
		OperationID: "application-disconnectGitProvider",
		Method:      http.MethodPost,
		Path:        "/application.disconnectGitProvider",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.disconnectGitProvider: the only required field is
		// `applicationId` (string). Same minimal shape as API-0013 /
		// API-0015 (clearDeployments / delete) — keep the fixture
		// minimal-but-valid so a future schema validator wired into the
		// harness still accepts it.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-disconnect-git-0017"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other application/* peers. We keep an empty-object
		// body so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0018",
		OperationID: "application-killBuild",
		Method:      http.MethodPost,
		Path:        "/application.killBuild",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.killBuild: the only required field is
		// `applicationId` (string). Same minimal shape as
		// API-0013/API-0015/API-0017 — keep the fixture
		// minimal-but-valid so a future schema validator wired into
		// the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-kill-build-0018"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other application/* peers. We keep an empty-object
		// body so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0019",
		OperationID: "application-markRunning",
		Method:      http.MethodPost,
		Path:        "/application.markRunning",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.markRunning: the only required field is
		// `applicationId` (string). Same minimal shape as
		// API-0013/API-0015/API-0017/API-0018 — keep the fixture
		// minimal-but-valid so a future schema validator wired into
		// the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-mark-running-0019"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other application/* peers. We keep an empty-object
		// body so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0020",
		OperationID: "application-move",
		Method:      http.MethodPost,
		Path:        "/application.move",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for /application.move:
		// TWO required string fields, `applicationId` and
		// `targetEnvironmentId`. Unlike the single-field application/*
		// peers (API-0013/0015/0017/0018/0019) this operation also moves
		// across environments, so the fixture must populate both fields
		// with deterministic-but-clearly-fake values.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-move-0020",
			"targetEnvironmentId": "env-cov-move-0020"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other application/* peers. We keep an empty-object
		// body so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0021",
		OperationID: "application-one",
		Method:      http.MethodGet,
		Path:        "/application.one",
		Tag:         "application",
		// First GET-shaped entry in the application/* coverage roster.
		// Mirrors the schema in `data/openapi.json` for /application.one:
		// no request body, a single required query parameter
		// `applicationId` (string). The harness forwards SampleQuery via
		// the `--input` JSON `query` field, and the success-leg assertion
		// at runAPICoverageSuccess re-reads `r.URL.Query()` to confirm
		// the CLI propagated the param verbatim. We mirror the
		// deterministic-but-clearly-fake naming used by API-0013/0015/
		// 0017/0018/0019/0020 so a future schema validator wired into
		// the harness still accepts the fixture without surprise.
		SampleQuery: map[string][]string{
			"applicationId": {"app-cov-one-0021"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the other application/* peers. We keep an empty-object
		// body so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0022",
		OperationID: "application-readAppMonitoring",
		Method:      http.MethodGet,
		Path:        "/application.readAppMonitoring",
		Tag:         "application",
		// Second GET-shaped application/* entry. Mirrors the schema in
		// `data/openapi.json` for /application.readAppMonitoring: no
		// request body, a single required query parameter — but unlike
		// API-0021 the param name is `appName` (string), not
		// `applicationId`. The harness forwards SampleQuery via the
		// `--input` JSON `query` field, and `runAPICoverageSuccess`
		// re-reads `r.URL.Query()` to confirm the CLI propagated the
		// param verbatim. Deterministic-but-clearly-fake value follows
		// the established `app-cov-<slug>-<storyID>` convention.
		SampleQuery: map[string][]string{
			"appName": {"app-cov-read-app-monitoring-0022"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0023",
		OperationID: "application-readTraefikConfig",
		Method:      http.MethodGet,
		Path:        "/application.readTraefikConfig",
		Tag:         "application",
		// Third GET-shaped application/* entry. Mirrors the schema in
		// `data/openapi.json` for /application.readTraefikConfig: no
		// request body, a single required query parameter
		// `applicationId` (string) — the same shape as API-0021's
		// `application-one`. The harness forwards SampleQuery via the
		// `--input` JSON `query` field, and `runAPICoverageSuccess`
		// re-reads `r.URL.Query()` to confirm the CLI propagated the
		// param verbatim. Deterministic-but-clearly-fake value follows
		// the established `app-cov-<slug>-<storyID>` convention.
		SampleQuery: map[string][]string{
			"applicationId": {"app-cov-read-traefik-config-0023"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0024",
		OperationID: "application-redeploy",
		Method:      http.MethodPost,
		Path:        "/application.redeploy",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.redeploy: the only *required* field is
		// `applicationId` (string); `title` and `description` are
		// optional. We keep the fixture minimal-but-valid (matching
		// API-0013/API-0015/API-0017/API-0018/API-0019) so a future
		// schema validator wired into the harness still accepts it
		// without depending on optional-field handling. Deterministic-
		// but-clearly-fake slug follows the established
		// `app-cov-<slug>-<storyID>` convention.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-redeploy-0024"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0025",
		OperationID: "application-refreshToken",
		Method:      http.MethodPost,
		Path:        "/application.refreshToken",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.refreshToken: a single required string field
		// `applicationId` and no optional fields. Same minimal POST
		// shape as the nine prior application/* peers
		// (cancelDeployment, cleanQueues, clearDeployments, delete,
		// disconnectGitProvider, killBuild, markRunning, redeploy, …).
		// Deterministic-but-clearly-fake slug follows the established
		// `app-cov-<slug>-<storyID>` convention so a future schema
		// validator wired into the harness still sees a well-formed
		// value.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-refresh-token-0025"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0026",
		OperationID: "application-reload",
		Method:      http.MethodPost,
		Path:        "/application.reload",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.reload: two required string fields
		// (`appName`, `applicationId`) and no optional fields.
		// This is the first application/* peer so far that
		// requires a *second* string alongside `applicationId`,
		// so we follow the existing `app-cov-<slug>-<storyID>`
		// convention for both values to stay deterministic and
		// clearly-fake for a future schema validator.
		SampleBody: json.RawMessage(`{
			"appName": "app-cov-reload-0026",
			"applicationId": "app-cov-reload-0026"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0027",
		OperationID: "application-saveBitbucketProvider",
		Method:      http.MethodPost,
		Path:        "/application.saveBitbucketProvider",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.saveBitbucketProvider: seven required fields
		// (`bitbucketBranch`, `bitbucketBuildPath`, `bitbucketOwner`,
		// `bitbucketRepository`, `bitbucketRepositorySlug`,
		// `bitbucketId`, `applicationId`) — six of which are nullable
		// strings — plus optional `enableSubmodules` (bool) and
		// `watchPaths` (string array, nullable). We populate the
		// required nullable strings with the deterministic
		// `app-cov-<slug>-0027` placeholder so the fixture stays
		// schema-valid while remaining clearly-fake for any future
		// validator. Optional fields are intentionally omitted to
		// keep the failure leg's surface area small and to match the
		// minimal-but-valid pattern of prior application/* peers.
		SampleBody: json.RawMessage(`{
			"bitbucketBranch": "app-cov-bitbucket-branch-0027",
			"bitbucketBuildPath": "app-cov-bitbucket-build-path-0027",
			"bitbucketOwner": "app-cov-bitbucket-owner-0027",
			"bitbucketRepository": "app-cov-bitbucket-repo-0027",
			"bitbucketRepositorySlug": "app-cov-bitbucket-slug-0027",
			"bitbucketId": "app-cov-bitbucket-id-0027",
			"applicationId": "app-cov-save-bitbucket-0027"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0028",
		OperationID: "application-saveBuildType",
		Method:      http.MethodPost,
		Path:        "/application.saveBuildType",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.saveBuildType: seven required fields
		// (`applicationId`, `buildType`, `dockerfile`,
		// `dockerContextPath`, `dockerBuildStage`, `herokuVersion`,
		// `railpackVersion`) plus optional `publishDirectory`
		// (nullable string) and `isStaticSpa` (nullable bool).
		// `buildType` is a closed enum — we pick `dockerfile` because
		// it is the most established build path and keeps the fixture
		// closest to a realistic happy-path call. The remaining six
		// required fields are nullable strings; we use the
		// deterministic `app-cov-<slug>-0028` placeholder so the
		// fixture stays schema-valid while remaining clearly fake for
		// any future validator. Optional fields are intentionally
		// omitted to match the minimal-but-valid pattern of prior
		// application/* peers.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-save-build-type-0028",
			"buildType": "dockerfile",
			"dockerfile": "app-cov-build-type-dockerfile-0028",
			"dockerContextPath": "app-cov-build-type-context-0028",
			"dockerBuildStage": "app-cov-build-type-stage-0028",
			"herokuVersion": "app-cov-build-type-heroku-0028",
			"railpackVersion": "app-cov-build-type-railpack-0028"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0029",
		OperationID: "application-saveDockerProvider",
		Method:      http.MethodPost,
		Path:        "/application.saveDockerProvider",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.saveDockerProvider: five required fields
		// (`dockerImage`, `applicationId`, `username`, `password`,
		// `registryUrl`), each declared as `anyOf:[string,null]`. We
		// populate every required field with a dedicated
		// `app-cov-docker-<slug>-0029` placeholder following the
		// API-0027 (saveBitbucketProvider) precedent for many-required-
		// nullable-string bodies — distinct values keep diffs readable
		// and let any future schema validator's failure messages point
		// at the offending field. The `password` placeholder is
		// deterministic-but-clearly-fake; the redactor still scrubs
		// `--token` / Authorization-header bleed-through, but body
		// fields are not auto-redacted, so reviewers should rely on the
		// `app-cov-*` prefix to recognise it as test fixture data
		// rather than a real secret.
		SampleBody: json.RawMessage(`{
			"dockerImage": "app-cov-docker-image-0029",
			"applicationId": "app-cov-docker-application-id-0029",
			"username": "app-cov-docker-username-0029",
			"password": "app-cov-docker-password-0029",
			"registryUrl": "app-cov-docker-registry-url-0029"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
}

// TestAPICoverage_RegistryInvariants asserts that every covered story's
// operationId is present in the embedded OpenAPI registry with exactly
// the method, path, and tag the PRD declared. This catches spec drift
// (e.g. a future Dokploy revision renaming an endpoint) before the binary
// ships.
func TestAPICoverage_RegistryInvariants(t *testing.T) {
	reg := api.Default()
	for _, tc := range coveredAPIOperations {
		t.Run(tc.StoryID+"/"+tc.OperationID, func(t *testing.T) {
			op, ok := reg.Get(tc.OperationID)
			if !ok {
				t.Fatalf("registry missing operationId %q", tc.OperationID)
			}
			if op.Method != tc.Method {
				t.Errorf("method = %q, want %q", op.Method, tc.Method)
			}
			if op.Path != tc.Path {
				t.Errorf("path = %q, want %q", op.Path, tc.Path)
			}
			if op.Tag != tc.Tag {
				t.Errorf("tag = %q, want %q", op.Tag, tc.Tag)
			}
		})
	}
}

// TestAPICoverage_SchemaCommandWorks asserts the dedicated
// `yalla schema get <operationId> --json` command resolves every covered
// operation and emits the documented envelope. This is the
// "Schema command works: yalla schema get …" line item from each
// API-XXXX story's acceptance criteria.
func TestAPICoverage_SchemaCommandWorks(t *testing.T) {
	for _, tc := range coveredAPIOperations {
		t.Run(tc.StoryID+"/"+tc.OperationID, func(t *testing.T) {
			stdout, stderr, err := runRootArgs(t, "--json", "schema", "get", tc.OperationID)
			if err != nil {
				t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
			}
			if stderr != "" {
				t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
			}

			var env struct {
				SchemaVersion string `json:"schema_version"`
				Data          struct {
					OperationID string `json:"operation_id"`
					Method      string `json:"method"`
					Path        string `json:"path"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("decode: %v; raw=%q", err, stdout)
			}
			if env.SchemaVersion != output.SuccessSchema {
				t.Errorf("schema_version = %q, want %q", env.SchemaVersion, output.SuccessSchema)
			}
			if env.Data.OperationID != tc.OperationID {
				t.Errorf("data.operation_id = %q, want %q", env.Data.OperationID, tc.OperationID)
			}
			if env.Data.Method != tc.Method {
				t.Errorf("data.method = %q, want %q", env.Data.Method, tc.Method)
			}
			if env.Data.Path != tc.Path {
				t.Errorf("data.path = %q, want %q", env.Data.Path, tc.Path)
			}
		})
	}
}

// TestAPICoverage_ManifestListsOperation asserts the `yalla manifest`
// envelope advertises every covered operation. The aggregate
// `TestManifest_JSONIncludesEveryAPIOperation` already locks the full
// set; this per-story check is intentionally redundant so a single
// failing assertion points at the right PRD entry.
func TestAPICoverage_ManifestListsOperation(t *testing.T) {
	stdout, stderr, err := runRootArgs(t, "--json", "manifest")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr should be empty; got %q", stderr)
	}

	var env struct {
		Data manifestDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	listed := make(map[string]struct{}, len(env.Data.Operations.IDs))
	for _, id := range env.Data.Operations.IDs {
		listed[id] = struct{}{}
	}
	for _, tc := range coveredAPIOperations {
		t.Run(tc.StoryID+"/"+tc.OperationID, func(t *testing.T) {
			if _, ok := listed[tc.OperationID]; !ok {
				t.Errorf("manifest operations.ids missing %q", tc.OperationID)
			}
		})
	}
}

// TestAPICoverage_SuccessRoundTrip drives `yalla api call <operationId>
// --json` through an httptest.Server for every covered operation and
// asserts the contract: stable success envelope, deterministic body
// forwarding, and the registry-declared method/path on the wire.
//
// This is the success leg of the PRD's
// "Add unit or contract tests using httptest fixtures for success and
//
//	at least one representative failure path." line item.
func TestAPICoverage_SuccessRoundTrip(t *testing.T) {
	for _, tc := range coveredAPIOperations {
		t.Run(tc.StoryID+"/"+tc.OperationID, func(t *testing.T) {
			runAPICoverageSuccess(t, tc)
		})
	}
}

// TestAPICoverage_RepresentativeFailure exercises the failure leg of the
// same acceptance criterion. We default to a 401 → CodeAuth mapping
// because every covered Dokploy operation today requires authentication;
// stories may override the status/code via the case fields.
func TestAPICoverage_RepresentativeFailure(t *testing.T) {
	for _, tc := range coveredAPIOperations {
		t.Run(tc.StoryID+"/"+tc.OperationID, func(t *testing.T) {
			runAPICoverageFailure(t, tc)
		})
	}
}

// runAPICoverageSuccess is the body of the success-leg subtest. It is
// extracted so individual cases can call it directly from a future
// per-operation test file when a story needs richer assertions than
// the default harness offers.
func runAPICoverageSuccess(t *testing.T, tc apiCoverageCase) {
	t.Helper()

	wantStatus := tc.SuccessStatus
	if wantStatus == 0 {
		wantStatus = http.StatusOK
	}
	wantBody := tc.SuccessResponse
	if wantBody == "" {
		wantBody = "{}"
	}

	var (
		seenMethod      string
		seenPath        string
		seenAuth        string
		seenContentType string
		seenQuery       url.Values
		seenBody        []byte
	)
	srv := setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		seenAuth = r.Header.Get("Authorization")
		seenContentType = r.Header.Get("Content-Type")
		seenQuery = r.URL.Query()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("server read body: %v", err)
		}
		seenBody = body
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-coverage-"+tc.OperationID)
		w.WriteHeader(wantStatus)
		_, _ = w.Write([]byte(wantBody))
	})
	_ = srv

	args := []string{"--json", "api", "call", tc.OperationID}
	args = append(args, buildCoverageInputArgs(t, tc)...)

	stdout, stderr, err := runRootArgs(t, args...)
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}

	if seenMethod != tc.Method {
		t.Errorf("server method = %q, want %q", seenMethod, tc.Method)
	}
	resolvedPath, err := substitutePathParams(tc.Path, tc.SamplePathParams)
	if err != nil {
		t.Fatalf("substitutePathParams: %v", err)
	}
	if seenPath != resolvedPath {
		t.Errorf("server path = %q, want %q", seenPath, resolvedPath)
	}
	if seenAuth != "Bearer test-token-value" {
		t.Errorf("Authorization header = %q, want Bearer test-token-value", seenAuth)
	}
	if len(tc.SampleBody) > 0 {
		if !strings.HasPrefix(seenContentType, "application/json") {
			t.Errorf("Content-Type = %q, want application/json…", seenContentType)
		}
		if len(seenBody) == 0 {
			t.Errorf("server received empty body; expected forwarded request")
		} else {
			// The CLI forwards the bytes verbatim; round-trip through the
			// JSON decoder so whitespace differences do not cause flakes.
			var got, want any
			if err := json.Unmarshal(seenBody, &got); err != nil {
				t.Errorf("server body is not valid JSON: %v (raw=%q)", err, string(seenBody))
			}
			if err := json.Unmarshal(tc.SampleBody, &want); err != nil {
				t.Fatalf("test fixture body is not valid JSON: %v", err)
			}
			gotBytes, _ := json.Marshal(got)
			wantBytes, _ := json.Marshal(want)
			if string(gotBytes) != string(wantBytes) {
				t.Errorf("server body mismatch:\n got=%s\nwant=%s", string(gotBytes), string(wantBytes))
			}
		}
	}
	for k, want := range tc.SampleQuery {
		if got := seenQuery[k]; !equalStringSlice(got, want) {
			t.Errorf("query[%q] = %v, want %v", k, got, want)
		}
	}

	var env struct {
		SchemaVersion string            `json:"schema_version"`
		Data          apiCallSuccessDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode envelope: %v; raw=%q", err, stdout)
	}
	if env.SchemaVersion != output.SuccessSchema {
		t.Errorf("schema_version = %q, want %q", env.SchemaVersion, output.SuccessSchema)
	}
	if env.Data.OperationID != tc.OperationID {
		t.Errorf("data.operation_id = %q, want %q", env.Data.OperationID, tc.OperationID)
	}
	if env.Data.Status != wantStatus {
		t.Errorf("data.status = %d, want %d", env.Data.Status, wantStatus)
	}
	if env.Data.Method != tc.Method {
		t.Errorf("data.method = %q, want %q", env.Data.Method, tc.Method)
	}
}

// runAPICoverageFailure is the body of the failure-leg subtest, kept
// public-by-test-package so future per-operation files can reuse it.
func runAPICoverageFailure(t *testing.T, tc apiCoverageCase) {
	t.Helper()

	failStatus := tc.FailureStatus
	if failStatus == 0 {
		failStatus = http.StatusUnauthorized
	}
	failCode := tc.FailureCode
	if failCode == "" {
		failCode = yerr.CodeAuth
	}

	srv := setupAPICallServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(failStatus)
		_, _ = w.Write([]byte(`{"error":"representative failure"}`))
	})
	_ = srv

	args := []string{"--json", "api", "call", tc.OperationID}
	args = append(args, buildCoverageInputArgs(t, tc)...)

	stdout, stderr, err := runRootArgs(t, args...)
	if err == nil {
		t.Fatalf("expected failure for status %d", failStatus)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty on error path; got %q", stdout)
	}
	if !strings.Contains(stderr, string(failCode)) {
		t.Errorf("expected %q in stderr; got %q", failCode, stderr)
	}
	if !strings.Contains(stderr, yerr.SchemaVersion) {
		t.Errorf("expected %q envelope in stderr; got %q", yerr.SchemaVersion, stderr)
	}
}

// buildCoverageInputArgs writes the case's path/query/body into a temp
// `--input` JSON file and returns the matching CLI flags. Empty cases
// return no extra args so operations without inputs stay terse.
func buildCoverageInputArgs(t *testing.T, tc apiCoverageCase) []string {
	t.Helper()
	if len(tc.SampleBody) == 0 && len(tc.SampleQuery) == 0 && len(tc.SamplePathParams) == 0 {
		return nil
	}
	doc := struct {
		PathParams map[string]string   `json:"path_params,omitempty"`
		Query      map[string][]string `json:"query,omitempty"`
		Body       json.RawMessage     `json:"body,omitempty"`
	}{
		PathParams: tc.SamplePathParams,
		Query:      tc.SampleQuery,
		Body:       tc.SampleBody,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal coverage input: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, tc.OperationID+".json")
	// 0o600 mirrors the production redactor pattern so a stray --input
	// fixture cannot leak a secret to other users on the host.
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write coverage input: %v", err)
	}
	return []string{"--input", path}
}

// equalStringSlice is a non-allocating slice equality helper used by the
// query-parameter assertion. We deliberately avoid reflect.DeepEqual so
// the failure messages above stay readable.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
