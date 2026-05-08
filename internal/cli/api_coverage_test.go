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
		StoryID:     "API-0008",
		OperationID: "ai-one",
		Method:      http.MethodGet,
		Path:        "/ai.one",
		Tag:         "ai",
		// Third query-only GET in the ai/* coverage roster, structurally
		// identical to API-0005 (`ai-get`): a single required query
		// parameter `aiId` (string), no request body. The harness
		// forwards SampleQuery via the `--input` JSON `query` field,
		// and `runAPICoverageSuccess` re-reads `r.URL.Query()` to
		// confirm the CLI propagated the param verbatim. We reuse the
		// deterministic-but-clearly-fake `<tag>-cov-<slug>-<storyID>`
		// naming convention shared with API-0005/0021/0022/0023.
		SampleQuery: map[string][]string{
			"aiId": {"ai-cov-one-0008"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior ai/* peer. Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0009",
		OperationID: "ai-suggest",
		Method:      http.MethodPost,
		Path:        "/ai.suggest",
		Tag:         "ai",
		// Mirrors the schema in `data/openapi.json` for /ai.suggest:
		// two required string fields (`aiId`, `input`) plus one optional
		// (`serverId`). Per the API-0004/API-0014 convention we supply
		// the optional with a deterministic-but-clearly-fake value so
		// the wire payload exercises the full suggest envelope, not just
		// the minimum-required pair. Per-case fixture token
		// `*-cov-suggest-0009` keeps `git grep` traceable to this PRD
		// story.
		SampleBody: json.RawMessage(`{
			"aiId": "ai-cov-suggest-0009",
			"input": "yalla coverage prompt for API-0009",
			"serverId": "srv-cov-suggest-0009"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior ai/* peer. Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0010",
		OperationID: "ai-update",
		Method:      http.MethodPost,
		Path:        "/ai.update",
		Tag:         "ai",
		// Mirrors the schema in `data/openapi.json` for /ai.update:
		// the only required field is `aiId` (string); every other
		// field (`name`, `apiUrl`, `apiKey`, `model`, `isEnabled`,
		// `createdAt`) is optional. Per the API-0002/API-0009
		// convention we supply the full optional surface with
		// deterministic-but-clearly-fake values so the wire payload
		// exercises the entire update envelope, not just the
		// minimum-required pair. The placeholder `apiKey` only ever
		// lives inside a per-test `t.TempDir()`, mirroring ai-create.
		// Per-case fixture token `*-cov-update-0010` keeps `git grep`
		// traceable to this PRD story.
		SampleBody: json.RawMessage(`{
			"aiId": "ai-cov-update-0010",
			"name": "yalla-coverage-ai-update-0010",
			"apiUrl": "https://example.test/v1",
			"apiKey": "fake-api-key-coverage-0010",
			"model": "gpt-test-update",
			"isEnabled": true,
			"createdAt": "2026-01-01T00:00:00.000Z"
		}`),
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
	{
		StoryID:     "API-0030",
		OperationID: "application-saveEnvironment",
		Method:      http.MethodPost,
		Path:        "/application.saveEnvironment",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.saveEnvironment: five required fields —
		// `applicationId` (plain string), `env` / `buildArgs` /
		// `buildSecrets` (each `anyOf:[string,null]`), and
		// `createEnvFile` (boolean). This is the FIRST application/*
		// coverage entry whose required set mixes string, nullable-
		// string, AND boolean shapes; we populate every required field
		// rather than relying on null defaults so the harness exercises
		// the full happy-path body shape on the wire. Distinct
		// `app-cov-env-<slug>-0030` placeholders keep diffs readable and
		// let any future schema validator's failure messages identify
		// which field tripped the check. `createEnvFile` is set to
		// `true` to keep the fixture closest to a realistic call where
		// the user wants Dokploy to materialise the env file alongside
		// the build; the boolean is otherwise contract-orthogonal.
		// As with API-0027 / API-0029, `buildSecrets` is a body-field
		// secret that is NOT auto-redacted — the `app-cov-*` prefix is
		// the convention reviewers should rely on to recognise it as
		// fixture data rather than a real credential.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-env-application-id-0030",
			"env": "app-cov-env-vars-0030",
			"buildArgs": "app-cov-env-build-args-0030",
			"buildSecrets": "app-cov-env-build-secrets-0030",
			"createEnvFile": true
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0031",
		OperationID: "application-saveGiteaProvider",
		Method:      http.MethodPost,
		Path:        "/application.saveGiteaProvider",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.saveGiteaProvider: six required fields —
		// `applicationId` (plain string) plus `giteaBranch`,
		// `giteaBuildPath`, `giteaOwner`, `giteaRepository`, and
		// `giteaId` (each `anyOf:[string,null]`). Optional
		// `enableSubmodules` (boolean) and `watchPaths`
		// (`anyOf:[array<string>,null]`) are intentionally omitted to
		// keep the fixture minimal-but-valid, matching the
		// API-0027 (saveBitbucketProvider) precedent for
		// many-required-nullable-string `save*Provider` bodies. We
		// populate every required field with a dedicated
		// `app-cov-gitea-<slug>-0031` placeholder so distinct values
		// keep diffs readable and let any future schema validator's
		// failure messages point at the offending field. This is the
		// first of the four remaining `save*Provider` family entries
		// (API-0031..0034); subsequent gitea/github/gitlab/git stories
		// should pattern-match against this literal rather than against
		// API-0029 (whose body is uniform across five fields with no
		// non-nullable `applicationId` peer).
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-gitea-application-id-0031",
			"giteaBranch": "app-cov-gitea-branch-0031",
			"giteaBuildPath": "app-cov-gitea-build-path-0031",
			"giteaOwner": "app-cov-gitea-owner-0031",
			"giteaRepository": "app-cov-gitea-repository-0031",
			"giteaId": "app-cov-gitea-id-0031"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0032",
		OperationID: "application-saveGithubProvider",
		Method:      http.MethodPost,
		Path:        "/application.saveGithubProvider",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.saveGithubProvider. The required set is the
		// same six-field shape as API-0031 (saveGiteaProvider) —
		// `applicationId` (plain string) plus `repository`, `branch`,
		// `owner`, `buildPath`, and `githubId` (each
		// `anyOf:[string,null]`) — PLUS one extra required field
		// unique to the github vendor: `triggerType`, a closed enum
		// (`"push"` / `"tag"`) with a `default: "push"`. This is the
		// FIRST application/* coverage entry to exercise a
		// closed-enum required field, so we populate it with the
		// default value `"push"` to keep the fixture inside the
		// permitted value set even if a future schema validator is
		// wired into the harness. Optional `enableSubmodules`
		// (boolean) and `watchPaths` (`anyOf:[array<string>,null]`)
		// are intentionally omitted to keep the fixture minimal-but-
		// valid, matching the API-0031 precedent for
		// many-required-nullable-string `save*Provider` bodies.
		// Distinct `app-cov-github-<slug>-0032` placeholders keep
		// diffs readable and let any future schema validator's
		// failure messages point at the offending field. The
		// successor stories API-0033 (gitlab) / API-0034 (custom git)
		// should pattern-match against THIS literal rather than
		// API-0031 because both also extend the gitea shape with
		// vendor-specific fields (gitlab adds two nullable
		// `gitlabProjectId` / `gitlabPathNamespace`; custom-git
		// promotes `watchPaths` from optional to required).
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-github-application-id-0032",
			"repository": "app-cov-github-repository-0032",
			"branch": "app-cov-github-branch-0032",
			"owner": "app-cov-github-owner-0032",
			"buildPath": "app-cov-github-build-path-0032",
			"githubId": "app-cov-github-id-0032",
			"triggerType": "push"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0033",
		OperationID: "application-saveGitlabProvider",
		Method:      http.MethodPost,
		Path:        "/application.saveGitlabProvider",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.saveGitlabProvider. The required set extends the
		// gitea/github six-field shape with TWO extra vendor fields:
		// `gitlabProjectId` (`anyOf:[number,null]`) and
		// `gitlabPathNamespace` (`anyOf:[string,null]`). This makes
		// API-0033 the FIRST application/* coverage entry whose required
		// surface includes a non-string, non-boolean primitive
		// (`gitlabProjectId` is numeric), so we populate it with a JSON
		// numeric literal rather than the usual `app-cov-*` string
		// placeholder. The trailing-`1033` digit convention echoes the
		// story id and keeps the value distinct from any other fixture
		// in the file. Required fields are: `applicationId` (plain
		// string), `gitlabBranch` / `gitlabBuildPath` / `gitlabOwner` /
		// `gitlabRepository` / `gitlabId` / `gitlabPathNamespace` (each
		// `anyOf:[string,null]`), and `gitlabProjectId`
		// (`anyOf:[number,null]`). Optional `enableSubmodules`
		// (boolean) and `watchPaths` (`anyOf:[array<string>,null]`) are
		// intentionally omitted to keep the fixture minimal-but-valid,
		// matching the API-0031 / API-0032 precedent for
		// many-required-nullable-string `save*Provider` bodies.
		// Distinct `app-cov-gitlab-<slug>-0033` placeholders keep diffs
		// readable and let any future schema validator's failure
		// messages point at the offending field. The successor story
		// API-0034 (custom git) is the family outlier — it promotes
		// `watchPaths` from optional to required — and should
		// pattern-match against THIS literal only for the shared
		// `applicationId` / nullable-string spine, not the
		// numeric-required `gitlabProjectId`.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-gitlab-application-id-0033",
			"gitlabBranch": "app-cov-gitlab-branch-0033",
			"gitlabBuildPath": "app-cov-gitlab-build-path-0033",
			"gitlabOwner": "app-cov-gitlab-owner-0033",
			"gitlabRepository": "app-cov-gitlab-repository-0033",
			"gitlabId": "app-cov-gitlab-id-0033",
			"gitlabProjectId": 1033,
			"gitlabPathNamespace": "app-cov-gitlab-path-namespace-0033"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0034",
		OperationID: "application-saveGitProvider",
		Method:      http.MethodPost,
		Path:        "/application.saveGitProvider",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.saveGitProvider. This is the FAMILY OUTLIER among
		// the application/save*Provider entries (API-0031 gitea / API-0032
		// github / API-0033 gitlab): instead of a `*Id` vendor field, the
		// custom-git provider promotes `watchPaths`
		// (`anyOf:[array<string>,null]`) from optional to required. That
		// makes API-0034 the FIRST application/* coverage entry whose
		// required surface includes a non-string, non-boolean, non-numeric
		// primitive — namely a JSON array of strings. Required fields per
		// the spec are: `applicationId` (plain string), `customGitBranch`
		// / `customGitBuildPath` / `customGitUrl` (each
		// `anyOf:[string,null]`), and `watchPaths`
		// (`anyOf:[array<string>,null]`). Optional `customGitSSHKeyId`
		// (`anyOf:[string,null]`) is intentionally omitted to keep the
		// fixture minimal-but-valid, mirroring the API-0031/0032/0033
		// precedent of leaving optional fields off the SampleBody so the
		// success-leg comparator stays decoupled from optional-field
		// behavior the spec may evolve. Distinct `app-cov-customgit-<slug>-0034`
		// placeholders keep diffs readable and let any future
		// schema-validator failure messages point at the offending field.
		// `watchPaths` is populated with a single-element array (rather
		// than an empty array) so the success-leg JSON round-trip
		// non-trivially verifies that array-typed required fields survive
		// the api/call body forwarding intact.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-customgit-application-id-0034",
			"customGitBranch": "app-cov-customgit-branch-0034",
			"customGitBuildPath": "app-cov-customgit-build-path-0034",
			"customGitUrl": "app-cov-customgit-url-0034",
			"watchPaths": ["app-cov-customgit-watch-path-0034"]
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0035",
		OperationID: "application-search",
		Method:      http.MethodGet,
		Path:        "/application.search",
		Tag:         "application",
		// Fourth GET-shaped application/* entry, and a STRUCTURAL FIRST
		// for the application/* roster: every query parameter on
		// /application.search is OPTIONAL (`required: false`). Prior
		// application/* GETs (API-0021 / API-0022 / API-0023) all gated
		// on at least one required string param, so this is the first
		// case where a fully-empty query is wire-valid. The fixture
		// nevertheless populates a representative subset so
		// `runAPICoverageSuccess` can re-read `r.URL.Query()` and prove
		// the CLI propagated every param verbatim — including the two
		// numeric-typed params (`limit` / `offset`, both `number` per
		// the spec) which travel through the `--input` JSON `query`
		// field as strings (HTTP query strings are untyped on the
		// wire). The PRD declares 11 parameters total: free-text `q`,
		// the seven name/identity filters (`name`, `appName`,
		// `description`, `repository`, `owner`, `dockerImage`),
		// scoped-resource filters (`projectId`, `environmentId`), and
		// the pagination pair (`limit`, `offset`). We exercise three
		// representative slices so the harness covers (a) free-text
		// search, (b) a scoped filter, and (c) numeric pagination —
		// without bloating the fixture into a noisy 11-key map. Same
		// `app-cov-<slug>-<storyID>` naming convention as API-0021/
		// 0022/0023; deterministic-but-clearly-fake values keep diffs
		// readable. Numeric values use the canonical decimal grammar
		// (`"5"` / `"0"`) so a future schema validator that
		// re-coerces query strings to numbers still accepts them.
		SampleQuery: map[string][]string{
			"q":      {"app-cov-search-q-0035"},
			"owner":  {"app-cov-search-owner-0035"},
			"limit":  {"5"},
			"offset": {"0"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0036",
		OperationID: "application-start",
		Method:      http.MethodPost,
		Path:        "/application.start",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for /application.start:
		// the only required field is `applicationId` (string), with no
		// optional siblings — `properties` is the single key. This
		// pattern-matches the minimal-applicationId POST family already
		// covered by API-0011 (cancelDeployment), API-0012 (cleanQueues),
		// API-0013 (clearDeployments), API-0015 (delete), and API-0024
		// (redeploy). Keep the fixture minimal-but-valid so a future
		// schema validator wired into the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-start-0036"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0037",
		OperationID: "application-stop",
		Method:      http.MethodPost,
		Path:        "/application.stop",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for /application.stop:
		// `{applicationId: string}` required, no optional siblings. Identical
		// shape to API-0036 (start) and the broader minimal-applicationId
		// POST family — API-0011 (cancelDeployment), API-0012 (cleanQueues),
		// API-0013 (clearDeployments), API-0015 (delete), API-0024 (redeploy),
		// API-0036 (start). Keeping the fixture minimal-but-valid stays
		// future-proof against a schema validator being wired into the harness.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-stop-0037"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every prior application/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0038",
		OperationID: "application-update",
		Method:      http.MethodPost,
		Path:        "/application.update",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for /application.update:
		// the only required top-level field is `applicationId` (string); every
		// other property (name, env, buildType, swarm config, git provider IDs,
		// resource limits, …) is optional with anyOf-null semantics so the
		// minimal-but-valid fixture is a single-field document. The harness
		// forwards these bytes verbatim to the httptest server, so the success
		// leg still exercises real JSON serialisation, the application/json
		// content-type negotiation, and the body forwarding through
		// `yalla api call`.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-update-0038"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// consistent with every other application/* mutation peer (start, stop,
		// reload, redeploy, delete, deploy, cancelDeployment, …). Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0039",
		OperationID: "application-updateTraefikConfig",
		Method:      http.MethodPost,
		Path:        "/application.updateTraefikConfig",
		Tag:         "application",
		// Mirrors the schema in `data/openapi.json` for
		// /application.updateTraefikConfig: the request body declares two
		// required string fields — `applicationId` and `traefikConfig` —
		// with no optional siblings. Unlike the broader minimal-applicationId
		// POST family (start/stop/update/…), this operation requires the
		// raw Traefik router YAML alongside the id, so the minimal-but-valid
		// fixture carries both fields. The harness forwards these bytes
		// verbatim to the httptest server, exercising real JSON serialisation
		// of an embedded YAML payload (newline + colon-bearing string),
		// application/json content-type negotiation, and body forwarding
		// through `yalla api call`.
		SampleBody: json.RawMessage(`{
			"applicationId": "app-cov-traefik-0039",
			"traefikConfig": "http:\n  routers:\n    app: {}\n"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching every other application/* mutation peer (start, stop,
		// update, reload, redeploy, delete, deploy, cancelDeployment, …).
		// Empty-object body keeps the success-leg envelope assertion focused
		// on `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0040",
		OperationID: "backup-create",
		Method:      http.MethodPost,
		Path:        "/backup.create",
		Tag:         "backup",
		// Mirrors the schema in `data/openapi.json` for /backup.create:
		// the required top-level fields are `schedule`, `prefix`,
		// `destinationId`, `database`, and `databaseType` (enum:
		// postgres|mariadb|mysql|mongo|web-server). Optional siblings
		// — `enabled` (anyOf [boolean, null]), `keepLatestCount` (anyOf
		// [number, null]), `mariadbId`/`mysqlId`/`postgresId`/`mongoId`/
		// `userId`/`composeId`/`serviceName` (anyOf [string, null]),
		// `backupType` (enum: database|compose), and `metadata` (anyOf
		// [object, null]) — are populated with deterministic-but-clearly-
		// fake values so the wire fixture exercises the full create
		// payload, not just the minimum, matching the *-create
		// convention from API-0014 (application-create) and API-0069
		// (compose-create) recorded in internal/cli/AGENTS.md. Per the
		// AGENTS.md "anyOf [string, null] → send string branch" rule we
		// supply strings for every nullable string field; the same logic
		// generalises to the boolean/number/object anyOfs (we send the
		// non-null branch) so a future schema validator confirms
		// forwarding for the populated branch in one fixture. Picking
		// `databaseType: "postgres"` alongside a populated `postgresId`
		// keeps the fixture internally consistent (the postgres branch
		// of Dokploy's polymorphic backup record), and `backupType:
		// "database"` matches the chosen database-mode shape. This is
		// the FIRST backup/* coverage entry, so it also seeds the
		// `backup-cov-<slug>-<storyID>` slug convention for every
		// backup/* peer that follows.
		SampleBody: json.RawMessage(`{
			"schedule": "0 3 * * *",
			"enabled": true,
			"prefix": "yalla-cov-backup-create-0040/",
			"destinationId": "dst-cov-backup-create-0040",
			"keepLatestCount": 7,
			"database": "yalla-cov-backup-db-0040",
			"mariadbId": "mariadb-cov-backup-create-0040",
			"mysqlId": "mysql-cov-backup-create-0040",
			"postgresId": "postgres-cov-backup-create-0040",
			"mongoId": "mongo-cov-backup-create-0040",
			"databaseType": "postgres",
			"userId": "user-cov-backup-create-0040",
			"backupType": "database",
			"composeId": "compose-cov-backup-create-0040",
			"serviceName": "service-cov-backup-create-0040",
			"metadata": {"yallaStoryId": "API-0040"}
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// *-create peer (API-0014, API-0069). Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0041",
		OperationID: "backup-listBackupFiles",
		Method:      http.MethodGet,
		Path:        "/backup.listBackupFiles",
		Tag:         "backup",
		// Second backup/* coverage entry, sibling of API-0040
		// (backup-create), and the FIRST backup/* GET — so it seeds the
		// query-only fixture shape that future backup/* GETs (API-0048
		// `backup-one`, API-0041's listFiles peers) will mirror. The
		// spec at `data/openapi.json > /backup.listBackupFiles > get`
		// declares no request body and three query parameters:
		// `destinationId` (string, REQUIRED — the backup destination
		// whose object store should be enumerated), `search` (string,
		// REQUIRED — a server-side filter prefix/glob the listing
		// applies before returning), and `serverId` (string, OPTIONAL
		// — scopes the lookup to a specific Dokploy worker server when
		// the destination is replicated). The closest precedent in the
		// roster for a "REQUIRED + REQUIRED + OPTIONAL" GET fixture is
		// API-0082 (compose-loadServices, REQUIRED + OPTIONAL enum) and
		// API-0081 (compose-loadMountsByService, REQUIRED + REQUIRED).
		// We populate all three params — including the OPTIONAL
		// `serverId` — so the success-leg `r.URL.Query()` re-read at
		// runAPICoverageSuccess exercises end-to-end forwarding for
		// every declared parameter in one fixture; the harness does not
		// gate on `required`-ness, it forwards whatever SampleQuery
		// carries (per the API-0077 `compose-getTags` precedent which
		// also populated an OPTIONAL `baseUrl`). The slug convention
		// `backup-cov-<slug>-<storyID>` follows the seed laid by
		// API-0040 so cross-story grep continues to find every backup/*
		// fixture.
		SampleQuery: map[string][]string{
			"destinationId": {"dst-cov-backup-list-backup-files-0041"},
			"search":        {"yalla-cov-backup-list-backup-files-0041/"},
			"serverId":      {"server-cov-backup-list-backup-files-0041"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// backup/* (API-0040), application/*, and compose/* peer.
		// Empty-object body keeps the success-leg envelope assertion
		// focused on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0042",
		OperationID: "backup-manualBackupCompose",
		Method:      http.MethodPost,
		Path:        "/backup.manualBackupCompose",
		Tag:         "backup",
		// Third backup/* coverage entry and the FIRST member of the
		// `backup-manualBackup*` family (six siblings: API-0042 compose,
		// API-0043 mariadb, API-0044 mongo, API-0045 mySql, API-0046
		// postgres, API-0047 webServer). The spec at
		// `data/openapi.json > /backup.manualBackupCompose > post` is
		// the canonical "single id-only POST" shape: the only required
		// field is `backupId` (string), no optional siblings, no path
		// or query parameters. Schema is byte-identical across all six
		// `manualBackup*` peers, so this fixture seeds the
		// `backup-cov-manual-<slug>-<storyID>` slug convention every
		// sibling will mirror — keeping cross-story grep useful and
		// each manualBackup story's diff a single contiguous insert.
		// Closest precedents are the compose/* minimal-id POST family
		// (API-0066 cancelDeployment, API-0067 cleanQueues, API-0068
		// clearDeployments) and the application/* twins
		// (API-0011/0012/0013/0015/0024/0036/0037). Keep the fixture
		// minimal-but-valid so a future schema validator wired into
		// the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"backupId": "backup-cov-manual-compose-0042"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// backup/* (API-0040 backup-create, API-0041 backup-listBackupFiles),
		// application/*, and compose/* peer. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method`
		// / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0066",
		OperationID: "compose-cancelDeployment",
		Method:      http.MethodPost,
		Path:        "/compose.cancelDeployment",
		Tag:         "compose",
		// Mirrors the schema in `data/openapi.json` for
		// /compose.cancelDeployment: the only required field is `composeId`
		// (string), with no optional siblings. This is the compose/* twin of
		// the minimal-applicationId POST family already covered by API-0011
		// (application-cancelDeployment), API-0012 (application-cleanQueues),
		// API-0013 (application-clearDeployments), API-0015 (application-delete),
		// API-0024 (application-redeploy), API-0036 (application-start), and
		// API-0037 (application-stop). Keep the fixture minimal-but-valid so a
		// future schema validator wired into the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-cancel-deploy-0066"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// application/* mutation peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` / `data.status` rather
		// than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0067",
		OperationID: "compose-cleanQueues",
		Method:      http.MethodPost,
		Path:        "/compose.cleanQueues",
		Tag:         "compose",
		// Mirrors the schema in `data/openapi.json` for
		// /compose.cleanQueues: the only required field is `composeId`
		// (string), with no optional siblings. Second compose/* member of
		// the minimal-id-only POST family — same shape as API-0066
		// (compose-cancelDeployment) and the application/* twins
		// (API-0011/0012/0013/0015/0024/0036/0037). Keep the fixture
		// minimal-but-valid so a future schema validator wired into the
		// harness still accepts it.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-clean-queues-0067"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// application/* and compose/* mutation peer. Empty-object body
		// keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0068",
		OperationID: "compose-clearDeployments",
		Method:      http.MethodPost,
		Path:        "/compose.clearDeployments",
		Tag:         "compose",
		// Mirrors the schema in `data/openapi.json` for
		// /compose.clearDeployments: the only required field is
		// `composeId` (string), with no optional siblings. Third
		// compose/* member of the minimal-id-only POST family — same
		// shape as API-0066 (compose-cancelDeployment), API-0067
		// (compose-cleanQueues), and the application/* twins
		// (API-0011/0012/0013/0015/0024/0036/0037), plus the direct
		// application-clearDeployments precedent at API-0013. Keep the
		// fixture minimal-but-valid so a future schema validator wired
		// into the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-clear-deployments-0068"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// application/* and compose/* mutation peer. Empty-object body
		// keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0069",
		OperationID: "compose-create",
		Method:      http.MethodPost,
		Path:        "/compose.create",
		Tag:         "compose",
		// Mirrors the schema in `data/openapi.json` for /compose.create:
		// the required top-level fields are `name` and `environmentId`.
		// Optional fields `appName`, `composeFile`, `composeType` (enum:
		// docker-compose|stack), `description`, and `serverId` are also
		// supplied with deterministic-but-clearly-fake values so the wire
		// fixture exercises the full create payload, not just the minimum.
		// `description` and `serverId` use anyOf [string, null]; we send
		// the string variant so the fixture remains valid against either
		// branch once a future schema validator is wired into the harness.
		// Direct precedent: API-0014 (application-create) — same
		// "create" shape, swapped tag namespace.
		SampleBody: json.RawMessage(`{
			"name": "yalla-coverage-compose-create-0069",
			"appName": "yalla-cov-compose-create-0069",
			"composeFile": "version: \"3\"\nservices:\n  web:\n    image: nginx",
			"composeType": "docker-compose",
			"description": "API-0069 fixture for compose-create coverage",
			"environmentId": "env-cov-compose-create-0069",
			"serverId": "srv-cov-compose-create-0069"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// application/* and compose/* mutation peer. Empty-object body
		// keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0070",
		OperationID: "compose-delete",
		Method:      http.MethodPost,
		Path:        "/compose.delete",
		Tag:         "compose",
		// Mirrors the schema in `data/openapi.json` for /compose.delete:
		// `composeId` (string) and `deleteVolumes` (boolean) are BOTH
		// required — this is NOT a minimal-id-only POST despite living
		// next to API-0066/0067/0068. The compose/* twin of
		// application-delete (API-0015) is *not* a direct shape copy:
		// application-delete only requires `applicationId`, while
		// compose-delete adds the `deleteVolumes` flag. We send
		// `deleteVolumes: false` so the wire fixture stays a non-mutating
		// shape against any future side-effect-aware test double, while
		// still satisfying the `required` invariant. Keep the fixture
		// minimal-but-valid so a future schema validator wired into the
		// harness still accepts it.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-delete-0070",
			"deleteVolumes": false
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// application/* and compose/* mutation peer. Empty-object body
		// keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0071",
		OperationID: "compose-deploy",
		Method:      http.MethodPost,
		Path:        "/compose.deploy",
		Tag:         "compose",
		// Mirrors the schema in `data/openapi.json` for /compose.deploy:
		// the only required field is `composeId` (string); `title` and
		// `description` are optional strings. Direct shape twin of
		// API-0016 (application-deploy) — same `*-deploy` envelope, just
		// the compose/* tag namespace. The fixture supplies all three
		// with deterministic-but-clearly-fake values so the wire payload
		// assertion exercises the full deploy envelope rather than just
		// the minimum, matching the *-create / *-update convention
		// recorded in internal/cli/AGENTS.md.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-deploy-0071",
			"title": "API-0071 deploy fixture",
			"description": "API-0071 fixture for compose-deploy coverage"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// application/* and compose/* mutation peer. Empty-object body
		// keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0072",
		OperationID: "compose-deployTemplate",
		Method:      http.MethodPost,
		Path:        "/compose.deployTemplate",
		Tag:         "compose",
		// Mirrors the schema in `data/openapi.json` for
		// /compose.deployTemplate: required string fields are
		// `environmentId` and `id`; `serverId` and `baseUrl` are
		// optional strings. Unlike the sibling `compose-deploy`
		// operation this one provisions from a template registry
		// entry, so `id` references the template catalog rather than
		// an existing composeId — the fixture spells that out so a
		// future contributor doesn't accidentally swap in a composeId
		// shape. All four fields are populated with deterministic-
		// but-clearly-fake values to exercise the full envelope on
		// the wire-payload assertion.
		SampleBody: json.RawMessage(`{
			"environmentId": "env-cov-deployTemplate-0072",
			"id": "template-cov-deployTemplate-0072",
			"serverId": "server-cov-deployTemplate-0072",
			"baseUrl": "https://example.invalid/templates/0072"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// application/* and compose/* mutation peer. Empty-object body
		// keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0073",
		OperationID: "compose-disconnectGitProvider",
		Method:      http.MethodPost,
		Path:        "/compose.disconnectGitProvider",
		Tag:         "compose",
		// Mirrors the schema in `data/openapi.json` for
		// /compose.disconnectGitProvider: the only required field is
		// `composeId` (string), with no optional siblings. Fifth
		// compose/* member of the minimal-composeId-only POST family —
		// same shape as API-0066 (compose-cancelDeployment), API-0067
		// (compose-cleanQueues), and API-0068 (compose-clearDeployments).
		// Unlike API-0070 (compose-delete) this operation does NOT carry
		// a `deleteVolumes` boolean — disconnecting a git provider is a
		// pure unlink and the spec does not expose any cleanup flags.
		// Keep the fixture minimal-but-valid so a future schema validator
		// wired into the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-disconnect-git-0073"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// application/* and compose/* mutation peer. Empty-object body
		// keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0074",
		OperationID: "compose-fetchSourceType",
		Method:      http.MethodPost,
		Path:        "/compose.fetchSourceType",
		Tag:         "compose",
		// Mirrors the schema in `data/openapi.json` for
		// /compose.fetchSourceType: the only required field is
		// `composeId` (string), with no optional siblings. Sixth
		// compose/* member of the minimal-composeId-only POST family —
		// same shape as API-0066 (compose-cancelDeployment), API-0067
		// (compose-cleanQueues), API-0068 (compose-clearDeployments),
		// and API-0073 (compose-disconnectGitProvider). Despite the
		// `fetch*` verb this is a POST in the Dokploy spec because the
		// operation derives the source type for the referenced compose
		// record (a side-effect-free read modeled as a mutation in the
		// upstream tRPC bridge); we honour the wire shape verbatim and
		// keep the fixture minimal-but-valid so a future schema
		// validator wired into the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-fetch-source-type-0074"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// application/* and compose/* peer. Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0075",
		OperationID: "compose-getConvertedCompose",
		Method:      http.MethodGet,
		Path:        "/compose.getConvertedCompose",
		Tag:         "compose",
		// First GET-shaped entry in the compose/* coverage roster — every
		// prior compose/* story (API-0066..API-0074) was a POST, so this
		// is a STRUCTURAL FIRST for the tag. Mirrors the schema in
		// `data/openapi.json` for /compose.getConvertedCompose: no
		// request body, a single required query parameter `composeId`
		// (string). The application/* roster's analogous "single
		// composeId/applicationId GET" precedents are API-0021
		// (application-one) and API-0023 (application-readTraefikConfig);
		// we follow their fixture shape verbatim, just swapping the
		// `app-cov-<slug>-<storyID>` slug for the `compose-cov-<slug>-
		// <storyID>` convention every prior compose/* POST has used
		// (API-0066/0067/0068/0070/0073/0074). The harness forwards
		// SampleQuery via the `--input` JSON `query` field, and the
		// success-leg assertion at runAPICoverageSuccess re-reads
		// `r.URL.Query()` to confirm the CLI propagated the param
		// verbatim.
		SampleQuery: map[string][]string{
			"composeId": {"compose-cov-get-converted-compose-0075"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// application/* and compose/* peer. Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0076",
		OperationID: "compose-getDefaultCommand",
		Method:      http.MethodGet,
		Path:        "/compose.getDefaultCommand",
		Tag:         "compose",
		// Second GET-shaped entry in the compose/* coverage roster, sibling
		// of API-0075 (compose-getConvertedCompose). The spec at
		// `data/openapi.json > /compose.getDefaultCommand > get` declares no
		// request body, a single required query parameter `composeId`
		// (string), and a 200 body of `{}` with `additionalProperties:
		// false` — i.e. structurally identical to API-0075. We mirror that
		// fixture verbatim, only swapping the slug to keep the
		// `compose-cov-<slug>-<storyID>` convention every prior compose/*
		// case has used (API-0066/0067/0068/0070/0073/0074/0075). The
		// harness forwards SampleQuery via the `--input` JSON `query` field,
		// and runAPICoverageSuccess re-reads `r.URL.Query()` to confirm the
		// CLI propagated the param verbatim.
		SampleQuery: map[string][]string{
			"composeId": {"compose-cov-get-default-command-0076"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// application/* and compose/* peer. Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0077",
		OperationID: "compose-getTags",
		Method:      http.MethodGet,
		Path:        "/compose.getTags",
		Tag:         "compose",
		// Third GET-shaped entry in the compose/* coverage roster, after
		// API-0075 (compose-getConvertedCompose) and API-0076
		// (compose-getDefaultCommand). The spec at
		// `data/openapi.json > /compose.getTags > get` declares no request
		// body and a SINGLE OPTIONAL query parameter `baseUrl` (string, no
		// `required: true`) — distinguishing this entry from its
		// API-0075/0076 siblings which both carry a required `composeId`.
		// The 200 body is `{}` with `additionalProperties: false`, matching
		// the empty-success convention. We still populate SampleQuery so
		// the harness exercises end-to-end query propagation; the harness
		// does not gate on `required`-ness, it simply forwards what we hand
		// it via the `--input` JSON `query` field, and
		// `runAPICoverageSuccess` re-reads `r.URL.Query()` to confirm the
		// CLI propagated the param verbatim.
		SampleQuery: map[string][]string{
			"baseUrl": {"https://compose-cov-get-tags-0077.example"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0078",
		OperationID: "compose-import",
		Method:      http.MethodPost,
		Path:        "/compose.import",
		Tag:         "compose",
		// First POST-with-non-trivial-body entry in the compose/* roster
		// after the GET trio API-0075/0076/0077 (getConvertedCompose,
		// getDefaultCommand, getTags). Mirrors the schema in
		// `data/openapi.json` for /compose.import: the request body is
		// REQUIRED and declares two required string fields — `base64`
		// (the encoded docker-compose payload to import) and `composeId`
		// (the target record). This breaks the minimal-composeId-only
		// shape shared by API-0066/0067/0068/0073/0074 because `base64`
		// is a non-empty payload-bearing field; we still keep the
		// fixture deterministic-but-valid (decodes to `version: "3"\n`)
		// so a future schema validator wired into the harness still
		// accepts it. The harness forwards SampleBody via the `--input`
		// JSON `body` field, and `runAPICoverageSuccess` re-reads the
		// request body to confirm the CLI propagated the payload
		// verbatim.
		SampleBody: json.RawMessage(`{
			"base64": "dmVyc2lvbjogIjMiCg==",
			"composeId": "compose-cov-import-0078"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0079",
		OperationID: "compose-isolatedDeployment",
		Method:      http.MethodPost,
		Path:        "/compose.isolatedDeployment",
		Tag:         "compose",
		// Mirrors the schema in `data/openapi.json` for
		// /compose.isolatedDeployment: the request body is REQUIRED and
		// declares one required string field — `composeId` (the target
		// record) — plus a single OPTIONAL sibling, `suffix` (string,
		// appended to the isolated deployment's resource names so the
		// caller can run multiple isolated copies side-by-side without
		// collision). This is structurally a near-twin of the
		// minimal-composeId-only POST family (API-0066/0067/0068/0073/
		// 0074) with one extra optional field; the API-0078 (compose-
		// import) entry is the closest analogue with two required fields
		// (`base64`, `composeId`) but does not exercise the
		// required+optional split. We populate `suffix` deterministically
		// so the harness round-trips both fields verbatim and a future
		// schema validator wired into the harness still accepts the
		// fixture (`suffix` is well-typed and the only required field is
		// satisfied). The harness forwards SampleBody via the `--input`
		// JSON `body` field, and `runAPICoverageSuccess` re-reads the
		// request body to confirm the CLI propagated the payload
		// verbatim.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-isolated-deployment-0079",
			"suffix": "cov-0079"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0080",
		OperationID: "compose-killBuild",
		Method:      http.MethodPost,
		Path:        "/compose.killBuild",
		Tag:         "compose",
		// Seventh compose/* member of the minimal-composeId-only POST
		// family — same shape as API-0066 (compose-cancelDeployment),
		// API-0067 (compose-cleanQueues), API-0068 (compose-clearDeployments),
		// API-0073 (compose-disconnectGitProvider), and API-0074
		// (compose-fetchSourceType). The spec at `data/openapi.json >
		// /compose.killBuild > post` declares the request body is REQUIRED
		// with one required string field `composeId` (the target record
		// whose in-flight build should be killed) and no optional siblings,
		// so this entry is a near-verbatim copy of the prior
		// minimal-composeId-only fixtures with the slug rotated. Distinct
		// from API-0078 (compose-import, two required fields) and API-0079
		// (compose-isolatedDeployment, required+optional split). Keep the
		// fixture minimal-but-valid so a future schema validator wired into
		// the harness still accepts it.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-kill-build-0080"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0081",
		OperationID: "compose-loadMountsByService",
		Method:      http.MethodGet,
		Path:        "/compose.loadMountsByService",
		Tag:         "compose",
		// Fourth GET-shaped entry in the compose/* coverage roster after
		// API-0075 (getConvertedCompose), API-0076 (getDefaultCommand), and
		// API-0077 (getTags). The spec at `data/openapi.json >
		// /compose.loadMountsByService > get` declares no request body and
		// TWO REQUIRED query parameters — `composeId` (string, the target
		// compose record) and `serviceName` (string, the service inside that
		// compose whose mount entries should be enumerated). This is the
		// first compose/* GET that exercises the multi-required-query-param
		// path; the closest structural analogue is API-0078 (compose-import)
		// which carries two required fields but as a POST body. The harness
		// forwards SampleQuery via the `--input` JSON `query` field, and
		// `runAPICoverageSuccess` re-reads `r.URL.Query()` to confirm the
		// CLI propagated both params verbatim. We keep the slug convention
		// `compose-cov-<slug>-<storyID>` consistent with every prior
		// compose/* GET (API-0075/0076/0077) so cross-story grep continues
		// to find every fixture.
		SampleQuery: map[string][]string{
			"composeId":   {"compose-cov-load-mounts-by-service-0081"},
			"serviceName": {"compose-cov-load-mounts-by-service-0081-svc"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0082",
		OperationID: "compose-loadServices",
		Method:      http.MethodGet,
		Path:        "/compose.loadServices",
		Tag:         "compose",
		// Fifth GET-shaped entry in the compose/* coverage roster after
		// API-0075 (getConvertedCompose), API-0076 (getDefaultCommand),
		// API-0077 (getTags), and API-0081 (loadMountsByService). The spec
		// at `data/openapi.json > /compose.loadServices > get` declares no
		// request body and TWO query parameters — `composeId` (string,
		// REQUIRED) and `type` (string enum {"fetch", "cache"}, OPTIONAL,
		// default "cache"). This is the first compose/* GET that mixes a
		// REQUIRED query param with an OPTIONAL enum-restricted one; the
		// closest precedent in the compose/* roster is API-0071
		// (compose-deploy) which carries `composeId` REQUIRED plus optional
		// title/description, but as a POST body rather than query string.
		// We populate BOTH params so the success leg exercises the full
		// envelope rather than relying on Dokploy's server-side default —
		// this mirrors the API-0071 "exercise the optional path" pattern
		// recorded in earlier compose/* learnings. Picking `fetch` (the
		// non-default enum value) distinguishes the wire-level transmission
		// from the default-applied behavior so a future schema validator
		// wired into the harness can confirm the value is forwarded
		// verbatim. Slug convention `compose-cov-<slug>-<storyID>` continues
		// the cross-story grep contract from API-0075/0076/0077/0081.
		SampleQuery: map[string][]string{
			"composeId": {"compose-cov-load-services-0082"},
			"type":      {"fetch"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0083",
		OperationID: "compose-move",
		Method:      http.MethodPost,
		Path:        "/compose.move",
		Tag:         "compose",
		// Second POST-with-two-required-body-fields entry in the compose/*
		// roster after API-0078 (compose-import). The spec at
		// `data/openapi.json > /compose.move > post` declares the request
		// body is REQUIRED and carries two required string fields —
		// `composeId` (the source record being moved) and
		// `targetEnvironmentId` (the destination environment). No optional
		// siblings, no enum restrictions, no nested objects — making this a
		// near-verbatim structural twin of API-0078, but with a domain-
		// specific second field (an environment FK rather than the base64
		// payload). Distinct from the minimal-composeId-only POST family
		// (API-0066/0067/0068/0073/0074/0080) which carries a single
		// required field, and from API-0079 (compose-isolatedDeployment)
		// which uses a required+optional split. Slug convention
		// `compose-cov-<slug>-<storyID>` continues the cross-story grep
		// contract from API-0075/0076/0077/0078/0080/0081/0082 — both FK
		// values use deterministic placeholders so a future schema
		// validator wired into the harness can still accept the fixture
		// while the success leg confirms the CLI propagates BOTH required
		// fields verbatim through the `--input` JSON `body` envelope.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-move-0083",
			"targetEnvironmentId": "env-cov-move-0083"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0084",
		OperationID: "compose-one",
		Method:      http.MethodGet,
		Path:        "/compose.one",
		Tag:         "compose",
		// Sixth GET-shaped entry in the compose/* coverage roster after
		// API-0075 (getConvertedCompose), API-0076 (getDefaultCommand),
		// API-0077 (getTags), API-0081 (loadMountsByService), and API-0082
		// (loadServices). The spec at `data/openapi.json > /compose.one >
		// get` declares no request body and a SINGLE REQUIRED query
		// parameter `composeId` (string) — structurally identical to
		// API-0075 (compose-getConvertedCompose) and API-0076
		// (compose-getDefaultCommand). Distinct from API-0077 which carries
		// a single OPTIONAL query, from API-0081 which carries two
		// REQUIRED queries, and from API-0082 which mixes one REQUIRED
		// with one OPTIONAL enum query. We mirror the API-0075/0076
		// fixture verbatim, only swapping the slug to keep the
		// `compose-cov-<slug>-<storyID>` convention every prior compose/*
		// case has used. The harness forwards SampleQuery via the
		// `--input` JSON `query` field, and `runAPICoverageSuccess`
		// re-reads `r.URL.Query()` to confirm the CLI propagated the
		// param verbatim.
		SampleQuery: map[string][]string{
			"composeId": {"compose-cov-one-0084"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0085",
		OperationID: "compose-processTemplate",
		Method:      http.MethodPost,
		Path:        "/compose.processTemplate",
		Tag:         "compose",
		// Third POST-with-two-required-body-fields entry in the compose/*
		// roster after API-0078 (compose-import) and API-0083 (compose-move).
		// The spec at `data/openapi.json > /compose.processTemplate > post`
		// declares the request body is REQUIRED and carries two required
		// string fields — `base64` (the encoded template payload) and
		// `composeId` (the target compose record). No optional siblings, no
		// enum restrictions, no nested objects — making this a near-verbatim
		// structural twin of API-0078 (which also pairs a `base64` field
		// with `composeId`) rather than API-0083 which swaps the second
		// field for an environment FK. Distinct from the minimal-composeId-
		// only POST family (API-0066/0067/0068/0073/0074/0080) which carries
		// a single required field, and from API-0079 (compose-
		// isolatedDeployment) which uses a required+optional split. Slug
		// convention `compose-cov-<slug>-<storyID>` continues the cross-
		// story grep contract from every prior compose/* case — the
		// `base64` value is a deterministic placeholder rather than a
		// genuine base64 string so a future schema validator wired into
		// the harness can still accept the fixture while the success leg
		// confirms the CLI propagates BOTH required fields verbatim
		// through the `--input` JSON `body` envelope.
		SampleBody: json.RawMessage(`{
			"base64": "compose-cov-process-template-0085-payload",
			"composeId": "compose-cov-process-template-0085"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0086",
		OperationID: "compose-randomizeCompose",
		Method:      http.MethodPost,
		Path:        "/compose.randomizeCompose",
		Tag:         "compose",
		// Second compose/* entry exercising the required+optional split
		// shape after API-0079 (compose-isolatedDeployment). The spec at
		// `data/openapi.json > /compose.randomizeCompose > post` declares
		// the request body is REQUIRED with one required string field
		// `composeId` (the target record) plus a single OPTIONAL sibling
		// `suffix` (string, appended to the randomized service names so
		// the caller can run the randomization in distinguishable
		// scopes). That schema is byte-for-byte identical to API-0079 —
		// same property names, same `required` projection — so this
		// entry is a near-verbatim slug-rotated twin of the
		// compose-isolatedDeployment fixture rather than a brand new
		// shape. Distinct from the minimal-composeId-only POST family
		// (API-0066/0067/0068/0073/0074/0080) which omits the optional
		// sibling, from the two-required-body-fields family
		// (API-0078/0083/0085) which makes the second field required,
		// and from API-0071 (compose-deployTemplate) whose optional
		// siblings are `title`+`description` rather than `suffix`. We
		// populate `suffix` deterministically so the harness round-trips
		// both fields verbatim and a future schema validator wired into
		// the harness still accepts the fixture (`suffix` is well-typed
		// and the only required field is satisfied). The harness
		// forwards SampleBody via the `--input` JSON `body` field, and
		// `runAPICoverageSuccess` re-reads the request body to confirm
		// the CLI propagated the payload verbatim. Slug convention
		// `compose-cov-<slug>-<storyID>` continues the cross-story grep
		// contract from every prior compose/* case.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-randomize-compose-0086",
			"suffix": "cov-0086"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0087",
		OperationID: "compose-redeploy",
		Method:      http.MethodPost,
		Path:        "/compose.redeploy",
		Tag:         "compose",
		// Mirrors the schema in `data/openapi.json` for /compose.redeploy:
		// the request body is REQUIRED, the only required string field is
		// `composeId`, and `title`+`description` are optional string
		// siblings. That schema is byte-for-byte identical to API-0071
		// (compose-deploy) — same property names, same `required`
		// projection — so this entry is the slug-rotated twin of the
		// compose-deploy fixture, exercising the redeploy variant of the
		// same envelope. Distinct from the minimal-composeId-only POST
		// family (API-0066/0067/0068/0073/0074/0080) which omits the
		// optional siblings entirely, from the two-required-body-fields
		// family (API-0078/0083/0085) which makes the second field
		// required, from the `composeId`+`suffix` shape (API-0079/0086)
		// whose optional sibling is a single `suffix`, and from API-0072
		// (compose-deployTemplate) whose required pair is
		// `environmentId`+`id` rather than `composeId`. All three fields
		// are populated with deterministic-but-clearly-fake values so the
		// wire-payload assertion exercises the full redeploy envelope
		// rather than just the minimum, matching the *-create / *-deploy
		// convention recorded in internal/cli/AGENTS.md. The harness
		// forwards SampleBody via the `--input` JSON `body` field, and
		// `runAPICoverageSuccess` re-reads the request body to confirm
		// the CLI propagated the payload verbatim. Slug convention
		// `compose-cov-<slug>-<storyID>` continues the cross-story grep
		// contract from every prior compose/* case.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-redeploy-0087",
			"title": "API-0087 redeploy fixture",
			"description": "API-0087 fixture for compose-redeploy coverage"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0088",
		OperationID: "compose-refreshToken",
		Method:      http.MethodPost,
		Path:        "/compose.refreshToken",
		Tag:         "compose",
		// Eighth compose/* member of the minimal-composeId-only POST
		// family — same shape as API-0066 (compose-cancelDeployment),
		// API-0067 (compose-cleanQueues), API-0068 (compose-clearDeployments),
		// API-0073 (compose-disconnectGitProvider), API-0074
		// (compose-fetchSourceType), and API-0080 (compose-killBuild).
		// The spec at `data/openapi.json > /compose.refreshToken > post`
		// declares the request body is REQUIRED with one required string
		// field `composeId` (the target compose record whose deploy webhook
		// token should be rotated) and no optional siblings, so this entry
		// is a near-verbatim slug-rotated twin of the prior
		// minimal-composeId-only fixtures. Distinct from API-0078/0083/0085
		// (two required fields), API-0079/0086 (required+optional with
		// `suffix`), and API-0071/0087 (required+optional with
		// `title`+`description`). Keep the fixture minimal-but-valid so a
		// future schema validator wired into the harness still accepts it,
		// and so the success leg confirms the CLI propagated the single
		// required field verbatim through the `--input` JSON `body`
		// envelope. Slug convention `compose-cov-<slug>-<storyID>`
		// continues the cross-story grep contract from every prior
		// compose/* case.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-refresh-token-0088"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0089",
		OperationID: "compose-search",
		Method:      http.MethodGet,
		Path:        "/compose.search",
		Tag:         "compose",
		// Tenth GET-shaped compose/* coverage entry, after API-0075
		// (compose-getConvertedCompose), API-0076 (compose-getDefaultCommand),
		// API-0077 (compose-getTags), API-0081 (compose-loadMountsByService),
		// API-0082 (compose-loadServices), and API-0084 (compose-one).
		// STRUCTURAL FIRST for the compose/* roster: every query parameter
		// on /compose.search is OPTIONAL (`required: false`) — every prior
		// compose/* GET gated on at least one required string param
		// (typically `composeId`), so this is the first compose/* case
		// where a fully-empty query is wire-valid. The closest precedent in
		// the entire roster is API-0035 (application-search) which mirrors
		// the same all-optional fan-out — free-text `q`, identity/name
		// filters, scoped-resource filters, and a numeric pagination pair —
		// just on the application/* surface. The spec at
		// `data/openapi.json > /compose.search > get` declares no request
		// body and 8 OPTIONAL parameters: free-text `q`, the three
		// name/identity filters (`name`, `appName`, `description`),
		// scoped-resource filters (`projectId`, `environmentId`), and the
		// numeric pagination pair (`limit`, `offset`, both `number` per the
		// spec). HTTP query strings are untyped on the wire, so the numeric
		// pair travels through the `--input` JSON `query` field as strings;
		// canonical decimal grammar (`"10"` / `"0"`) keeps a future schema
		// validator that re-coerces query strings to numbers happy. We
		// exercise three representative slices so the harness covers
		// (a) free-text search, (b) a scoped filter, and (c) numeric
		// pagination — without bloating the fixture into a noisy 8-key map,
		// matching the API-0035 precedent verbatim. Slug convention
		// `compose-cov-<slug>-<storyID>` continues the cross-story grep
		// contract from every prior compose/* case.
		SampleQuery: map[string][]string{
			"q":             {"compose-cov-search-q-0089"},
			"projectId":     {"compose-cov-search-project-0089"},
			"environmentId": {"compose-cov-search-environment-0089"},
			"limit":         {"10"},
			"offset":        {"0"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0090",
		OperationID: "compose-start",
		Method:      http.MethodPost,
		Path:        "/compose.start",
		Tag:         "compose",
		// Ninth compose/* member of the minimal-composeId-only POST
		// family — same shape as API-0066 (compose-cancelDeployment),
		// API-0067 (compose-cleanQueues), API-0068 (compose-clearDeployments),
		// API-0073 (compose-disconnectGitProvider), API-0074
		// (compose-fetchSourceType), API-0080 (compose-killBuild), and
		// API-0088 (compose-refreshToken). The spec at
		// `data/openapi.json > /compose.start > post` declares the
		// request body is REQUIRED with one required string field
		// `composeId` (the target compose record whose containers
		// should be started) and no optional siblings, so this entry
		// is a near-verbatim slug-rotated twin of the prior
		// minimal-composeId-only fixtures. Distinct from API-0078/0083/0085
		// (two required fields), API-0079/0086 (required+optional with
		// `suffix`), and API-0071/0087 (required+optional with
		// `title`+`description`). Keep the fixture minimal-but-valid so
		// a future schema validator wired into the harness still
		// accepts it, and so the success leg confirms the CLI
		// propagated the single required field verbatim through the
		// `--input` JSON `body` envelope. Slug convention
		// `compose-cov-<slug>-<storyID>` continues the cross-story grep
		// contract from every prior compose/* case.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-start-0090"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0091",
		OperationID: "compose-stop",
		Method:      http.MethodPost,
		Path:        "/compose.stop",
		Tag:         "compose",
		// Tenth compose/* member of the minimal-composeId-only POST
		// family — same shape as API-0066 (compose-cancelDeployment),
		// API-0067 (compose-cleanQueues), API-0068 (compose-clearDeployments),
		// API-0073 (compose-disconnectGitProvider), API-0074
		// (compose-fetchSourceType), API-0080 (compose-killBuild),
		// API-0088 (compose-refreshToken), and API-0090 (compose-start).
		// The spec at `data/openapi.json > /compose.stop > post` declares
		// the request body is REQUIRED with one required string field
		// `composeId` (the target compose record whose containers should
		// be stopped) and no optional siblings, so this entry is a
		// near-verbatim slug-rotated twin of API-0090 (compose-start),
		// its lifecycle counterpart. Distinct from API-0078/0083/0085
		// (two required fields), API-0079/0086 (required+optional with
		// `suffix`), and API-0071/0087 (required+optional with
		// `title`+`description`). Keep the fixture minimal-but-valid so
		// a future schema validator wired into the harness still
		// accepts it, and so the success leg confirms the CLI
		// propagated the single required field verbatim through the
		// `--input` JSON `body` envelope. Slug convention
		// `compose-cov-<slug>-<storyID>` continues the cross-story grep
		// contract from every prior compose/* case.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-stop-0091"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0092",
		OperationID: "compose-templates",
		Method:      http.MethodGet,
		Path:        "/compose.templates",
		Tag:         "compose",
		// Fourth GET-shaped entry in the compose/* coverage roster, after
		// API-0075 (compose-getConvertedCompose), API-0076
		// (compose-getDefaultCommand), API-0077 (compose-getTags),
		// API-0081 (compose-loadMountsByService), API-0082
		// (compose-loadServices), API-0084 (compose-publicLoadServices),
		// and API-0089 (compose-search). The spec at
		// `data/openapi.json > /compose.templates > get` declares no
		// request body and a SINGLE OPTIONAL query parameter `baseUrl`
		// (string, no `required: true`). This is byte-for-byte identical
		// to API-0077 (compose-getTags) — same single-optional-baseUrl
		// shape, same empty `{}` 200 body — making this entry a near-
		// verbatim slug-rotated twin of API-0077 inside the compose/*
		// roster. Distinct from API-0089 (compose-search) which carries
		// 8 optional params, and from API-0075/0076/0081/0082/0084 which
		// all carry at least one REQUIRED query param. We populate
		// SampleQuery so the harness exercises end-to-end query
		// propagation; the harness does not gate on `required`-ness, it
		// simply forwards what we hand it via the `--input` JSON `query`
		// field, and `runAPICoverageSuccess` re-reads `r.URL.Query()` to
		// confirm the CLI propagated the param verbatim. Slug convention
		// `compose-cov-<slug>-<storyID>` continues the cross-story grep
		// contract from every prior compose/* case.
		SampleQuery: map[string][]string{
			"baseUrl": {"https://compose-cov-templates-0092.example"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer. Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status` rather than
		// payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0093",
		OperationID: "compose-update",
		Method:      http.MethodPost,
		Path:        "/compose.update",
		Tag:         "compose",
		// Final compose/* roster member. The spec at
		// `data/openapi.json > /compose.update > post` declares the
		// LARGEST request body in the compose/* tag — a single
		// REQUIRED string `composeId` plus 40+ optional siblings
		// covering every git provider knob (`repository`/`owner`/
		// `branch` for the native git/github/gitlab/bitbucket/gitea
		// surfaces), build-time settings (`composeFile`,
		// `composeType` enum, `composePath`, `command`,
		// `enableSubmodules`), runtime metadata (`name`, `appName`,
		// `description`, `env`, `suffix`, `randomize`,
		// `isolatedDeployment*`, `triggerType` enum,
		// `composeStatus` enum, `environmentId`, `createdAt`,
		// `watchPaths` array, `*Id` provider-record refs) and an
		// optional `refreshToken` rotate field. Only `composeId` is
		// required, mirroring the cross-tag precedent set by
		// API-0038 (application-update) — the sole prior `*-update`
		// entry in the roster — which also ships only the required
		// id even though its OpenAPI body declares 30+ optional
		// siblings. Per the AGENTS.md "Per-operation API coverage"
		// rule the SampleBody must mirror the required-field shape;
		// the bytes go on the wire verbatim and the success leg's
		// body-equality check enforces deterministic forwarding, so
		// a single-field document is the minimal-but-valid fixture.
		// Distinct from the minimal-composeId-only POST family
		// (API-0066/0067/0068/0073/0074/0080/0088/0090/0091)
		// because the request body's optional surface is incomparably
		// richer — naming this entry as the dedicated `*-update`
		// twin keeps cross-story grep clean. Slug convention
		// `compose-cov-<slug>-<storyID>` continues the cross-story
		// grep contract from every prior compose/* case.
		SampleBody: json.RawMessage(`{
			"composeId": "compose-cov-update-0093"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// compose/* peer (start, stop, redeploy, deploy, …) and by the
		// cross-tag `*-update` precedent API-0038 (application-update).
		// Empty-object body keeps the success-leg envelope assertion
		// focused on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0094",
		OperationID: "deployment-all",
		Method:      http.MethodGet,
		Path:        "/deployment.all",
		Tag:         "deployment",
		// First deployment/* roster member. The spec at
		// `data/openapi.json > /deployment.all > get` declares no
		// request body and a SINGLE REQUIRED query parameter
		// `applicationId` (string, `required: true`). This is the
		// minimal-shape GET-with-required-query precedent for the
		// deployment/* tag — every subsequent `deployment.allBy*`
		// peer (API-0095/0096/0097/0098) follows the same one-required-
		// query-id shape, just rotating the discriminator field name
		// (`composeId`/`serverId`/`type`). We populate SampleQuery so
		// the harness exercises end-to-end query propagation; the
		// harness simply forwards what we hand it via the `--input`
		// JSON `query` field, and `runAPICoverageSuccess` re-reads
		// `r.URL.Query()` to confirm the CLI propagated the param
		// verbatim. Slug convention `deployment-cov-<slug>-<storyID>`
		// opens the deployment/* cross-story grep contract.
		SampleQuery: map[string][]string{
			"applicationId": {"deployment-cov-all-0094"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the empty-success
		// convention shared by the cross-tag GET-list precedent
		// API-0033 (application-readTraefikConfig) and the bulk of
		// the compose/* roster. Empty-object body keeps the success-
		// leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0095",
		OperationID: "deployment-allByCompose",
		Method:      http.MethodGet,
		Path:        "/deployment.allByCompose",
		Tag:         "deployment",
		// Second deployment/* roster member and a byte-for-byte twin of
		// the API-0094 (`deployment-all`) precedent: no request body, a
		// SINGLE REQUIRED query parameter, and an empty-object 200. The
		// only delta versus API-0094 is the discriminator field name —
		// `composeId` here, mirroring the compose/* tag's id grammar
		// (see API-0090/0091/0092/0093 for the matching compose-side
		// usage). Spec source: `data/openapi.json >
		// /deployment.allByCompose > get` declares
		// `parameters[0]` as `{ in: "query", name: "composeId",
		// required: true, schema: { type: "string" } }`. SampleQuery
		// drives the same end-to-end query-propagation assertion the
		// harness exercises via `runAPICoverageSuccess` (`r.URL.Query()`
		// re-read inside the httptest handler). Slug continues the
		// `deployment-cov-<slug>-<storyID>` convention opened by
		// API-0094 so cross-story greps stay cohesive.
		SampleQuery: map[string][]string{
			"composeId": {"deployment-cov-allbycompose-0095"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, identical to API-0094 and the
		// cross-tag GET-list precedent API-0033
		// (application-readTraefikConfig). Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0096",
		OperationID: "deployment-allByServer",
		Method:      http.MethodGet,
		Path:        "/deployment.allByServer",
		Tag:         "deployment",
		// Third deployment/* roster member and a byte-for-byte twin of
		// the API-0094 (`deployment-all`) / API-0095
		// (`deployment-allByCompose`) precedents: no request body, a
		// SINGLE REQUIRED query parameter, and an empty-object 200. The
		// only delta versus API-0094/0095 is the discriminator field
		// name — `serverId` here, mirroring the server-scoped lookup
		// grammar shared with future deployment/* peers (see API-0097
		// `*-allByType` and API-0098 `*-allCentralized` for the
		// remaining shape variants in this sub-family). Spec source:
		// `data/openapi.json > /deployment.allByServer > get` declares
		// `parameters[0]` as `{ in: "query", name: "serverId",
		// required: true, schema: { type: "string" } }`. SampleQuery
		// drives the same end-to-end query-propagation assertion the
		// harness exercises via `runAPICoverageSuccess` (`r.URL.Query()`
		// re-read inside the httptest handler). Slug continues the
		// `deployment-cov-<slug>-<storyID>` convention opened by
		// API-0094 so cross-story greps stay cohesive.
		SampleQuery: map[string][]string{
			"serverId": {"deployment-cov-allbyserver-0096"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, identical to API-0094/0095 and
		// the cross-tag GET-list precedent API-0033
		// (application-readTraefikConfig). Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0097",
		OperationID: "deployment-allByType",
		Method:      http.MethodGet,
		Path:        "/deployment.allByType",
		Tag:         "deployment",
		// Fourth deployment/* roster member and the first shape variant
		// in the sub-family that declares TWO required query
		// parameters instead of one. API-0094..0096 each carry a single
		// discriminator (`applicationId` / `composeId` / `serverId`);
		// here the spec pairs a polymorphic `id` with a `type`
		// discriminator whose enum lists the seven owner kinds Dokploy
		// recognises (`application`, `compose`, `server`, `schedule`,
		// `previewDeployment`, `backup`, `volumeBackup`). Spec source:
		// `data/openapi.json > /deployment.allByType > get` declares
		// `parameters[0]` as `{ in: "query", name: "id", required:
		// true, schema: { type: "string" } }` and `parameters[1]` as
		// `{ in: "query", name: "type", required: true, schema: {
		// type: "string", enum: [...] } }`. Sending both keys exercises
		// the harness's multi-key URL-query forwarding leg (the same
		// `r.URL.Query()` re-read used by API-0094..0096) and proves
		// the enum value survives `--input` JSON marshalling end-to-end.
		// `application` is chosen as the canonical enum member because
		// it matches the predominant tag in the broader registry and
		// keeps grep cohesion with the application/* peers. Slug
		// continues the `deployment-cov-<slug>-<storyID>` convention
		// opened by API-0094.
		SampleQuery: map[string][]string{
			"id":   {"deployment-cov-allbytype-0097"},
			"type": {"application"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, identical to API-0094..0096
		// and the cross-tag GET-list precedent API-0033
		// (application-readTraefikConfig). Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0098",
		OperationID: "deployment-allCentralized",
		Method:      http.MethodGet,
		Path:        "/deployment.allCentralized",
		Tag:         "deployment",
		// Fifth deployment/* roster member and the family outlier — the
		// only `deployment.all*` peer that takes ZERO parameters. The
		// API-0094..0097 cohort each rotates a required query
		// discriminator (`applicationId` / `composeId` / `serverId` /
		// `id`+`type`); `allCentralized` instead returns the
		// caller's centralised deployment view scoped purely by the
		// bearer token. Spec source: `data/openapi.json >
		// /deployment.allCentralized > get` declares
		// `parameters: null` and no request body, matching the
		// cross-tag parameter-free GET precedent set by API-0006
		// (`ai-getAll`). Leaving SampleQuery/SamplePathParams/SampleBody
		// unset is therefore intentional — the harness still asserts
		// the wire-level invariants (method, path, Authorization
		// header, empty query string) at runAPICoverageSuccess, and the
		// canonical agent invocation is
		// `yalla api call deployment-allCentralized --input '{}' --json`.
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, identical to API-0094..0097
		// and the cross-tag GET-list precedent API-0033
		// (application-readTraefikConfig). Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0099",
		OperationID: "deployment-killProcess",
		Method:      http.MethodPost,
		Path:        "/deployment.killProcess",
		Tag:         "deployment",
		// First POST in the deployment/* coverage roster after the five
		// GET-shaped entries API-0094..0098 (`deployment-all`,
		// `*-allByCompose`, `*-allByServer`, `*-allByType`,
		// `*-allCentralized`). Spec source: `data/openapi.json >
		// /deployment.killProcess > post` declares no parameters and a
		// REQUIRED request body with exactly one required string field
		// `deploymentId` (the target in-flight deployment whose worker
		// process should be terminated). This is byte-for-byte identical
		// in shape to the minimal-required-id POST family established
		// by the compose/* roster — API-0066 (compose-cancelDeployment),
		// API-0067 (compose-cleanQueues), API-0068 (compose-clearDeployments),
		// API-0073 (compose-disconnectGitProvider), API-0074
		// (compose-fetchSourceType), API-0080 (compose-killBuild),
		// API-0088 (compose-refreshToken), API-0090 (compose-start),
		// and API-0091 (compose-stop) — only the discriminator field name
		// rotates from `composeId` to `deploymentId`, mirroring the
		// deployment/* tag's id grammar (the same `deploymentId` field
		// the registry will use for future deployment lifecycle peers
		// such as `removeDeployment` covered by API-0101). The fixture is
		// deliberately minimal-but-valid: only the required field is
		// populated so a future schema validator wired into the harness
		// still accepts it, and the success leg's body-equality check
		// inside `runAPICoverageSuccess` confirms the CLI propagated the
		// single required field verbatim through the `--input` JSON
		// `body` envelope. Slug convention `deployment-cov-<slug>-<storyID>`
		// continues the cross-story grep contract opened by API-0094.
		SampleBody: json.RawMessage(`{
			"deploymentId": "deployment-cov-killprocess-0099"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// identical to API-0094..0098 and the wider empty-success
		// convention shared by every minimal-id POST family member.
		// Empty-object body keeps the success-leg envelope assertion
		// focused on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0100",
		OperationID: "deployment-queueList",
		Method:      http.MethodGet,
		Path:        "/deployment.queueList",
		Tag:         "deployment",
		// Seventh deployment/* coverage entry and the second parameter-free
		// GET in the tag (alongside API-0098 `deployment-allCentralized`).
		// Spec source: `data/openapi.json > /deployment.queueList > get`
		// declares `parameters: null` and no request body — the endpoint
		// returns the entire queued-deployment view scoped purely by the
		// bearer token, mirroring the cross-tag parameter-free GET
		// precedent set by API-0006 (`ai-getAll`) and re-used by API-0098.
		// Leaving SampleQuery/SamplePathParams/SampleBody unset is therefore
		// intentional — the harness still asserts the wire-level invariants
		// (method, path, Authorization header, empty query string) at
		// runAPICoverageSuccess, and the canonical agent invocation is
		// `yalla api call deployment-queueList --input '{}' --json`.
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// identical to API-0094..0099 and the cross-tag GET-list precedent
		// API-0033 (application-readTraefikConfig). Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0101",
		OperationID: "deployment-removeDeployment",
		Method:      http.MethodPost,
		Path:        "/deployment.removeDeployment",
		Tag:         "deployment",
		// Eighth deployment/* coverage entry and the second POST in the
		// tag (twin of API-0099 `deployment-killProcess`). Spec source:
		// `data/openapi.json > /deployment.removeDeployment > post`
		// declares no parameters and a REQUIRED request body whose schema
		// is byte-for-byte identical to `deployment.killProcess` — a
		// single required string field `deploymentId` identifying the
		// deployment record to delete from the registry. The forward
		// reference embedded in the API-0099 comment block ("the same
		// `deploymentId` field the registry will use for future
		// deployment lifecycle peers such as `removeDeployment` covered
		// by API-0101") materialises here. Identical response shape too:
		// 200 returns `{}` with `additionalProperties: false`, plus the
		// 400/401/403/500 error envelopes.
		//
		// `removeDeployment` and `killProcess` differ only in semantics
		// (terminate worker vs. delete record) and in the lifecycle stage
		// they target — they do NOT differ on the wire. Keeping the
		// fixture shape aligned with API-0099 therefore preserves the
		// minimal-required-id POST family precedent established by
		// API-0066/0067/0068/0073/0074/0080/0088/0090/0091 in the
		// compose/* roster and now mirrored across deployment/* by
		// API-0099 + API-0101. Future deployment lifecycle peers should
		// grep these two entries first. The fixture is deliberately
		// minimal-but-valid: only the required field is populated so a
		// future schema validator wired into the harness still accepts
		// it, and the success leg's body-equality check inside
		// `runAPICoverageSuccess` confirms the CLI propagated the single
		// required field verbatim through the `--input` JSON `body`
		// envelope. Slug convention `deployment-cov-<slug>-<storyID>`
		// continues the cross-story grep contract opened by API-0094.
		SampleBody: json.RawMessage(`{
			"deploymentId": "deployment-cov-removedeployment-0101"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// identical to API-0094..0100 and the wider empty-success
		// convention shared by every minimal-id POST family member.
		// Empty-object body keeps the success-leg envelope assertion
		// focused on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0246",
		OperationID: "organization-active",
		Method:      http.MethodGet,
		Path:        "/organization.active",
		Tag:         "organization",
		// First entry in the organization/* roster and the kickoff for the
		// tag's parameter-free GET cohort. Spec source:
		// `data/openapi.json > /organization.active > get` declares
		// `parameters: []` and no request body — the endpoint resolves the
		// caller's currently-active organization purely from the bearer
		// token, mirroring the cross-tag parameter-free GET precedent set
		// by API-0006 (`ai-getAll`), API-0098 (`deployment-allCentralized`),
		// and API-0100 (`deployment-queueList`). The 404 response code in
		// the spec reflects "no active organization for this principal";
		// the harness's representative-failure leg still defaults to
		// 401→CodeAuth because authentication is the universal failure
		// mode shared across every Dokploy operation, and 404→CodeNotFound
		// would shadow the auth invariant we want each per-tag opener to
		// re-prove.
		//
		// Leaving SampleQuery/SamplePathParams/SampleBody unset is
		// intentional — the harness still asserts the wire-level
		// invariants (method, path, Authorization header, empty query
		// string) at runAPICoverageSuccess, and the canonical agent
		// invocation is `yalla api call organization-active --input '{}'
		// --json`. The 200 response in the spec is `{}` with
		// `additionalProperties: false`, identical to API-0094..0101 and
		// the cross-tag GET-list precedent API-0033
		// (application-readTraefikConfig). Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection. Future
		// organization/* peers (API-0247 `*-all`, API-0248
		// `*-allInvitations`, API-0251 `*-one`) should grep this entry
		// first when extending the parameter-free GET cohort.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0247",
		OperationID: "organization-all",
		Method:      http.MethodGet,
		Path:        "/organization.all",
		Tag:         "organization",
		// Second entry in the organization/* roster, completing the
		// forward reference embedded in the API-0246 comment block
		// ("Future organization/* peers (API-0247 `*-all`, …) should
		// grep this entry first"). Spec source `data/openapi.json >
		// /organization.all > get` is byte-for-byte the same wire
		// shape as `/organization.active`: `parameters: []`, no
		// request body, responses 200/400/401/403/404/500 where the
		// 200 schema is `{}` with `additionalProperties: false`. The
		// only semantic difference is scope — `organization-all`
		// returns *every* organization the bearer principal can see
		// (membership-scoped list), while `organization-active`
		// returns the single currently-selected one. From the
		// harness's perspective both are parameter-free GETs whose
		// canonical agent invocation is `yalla api call <id>
		// --input '{}' --json`, so SampleQuery / SamplePathParams /
		// SampleBody stay unset and the representative-failure leg
		// keeps the harness default of 401→CodeAuth (auth is the
		// universal failure mode every organization/* peer must
		// re-prove; 404 in the spec exists for filter-shaped peers
		// like `*-one` rather than this list endpoint).
		//
		// This is also the canonical *intra-tag* twin GET precedent
		// for the organization/* roster: `*-active` (singular,
		// principal-scoped) vs. `*-all` (plural, membership-scoped)
		// — analogous to deployment-allCentralized (API-0098) /
		// deployment-queueList (API-0100) but inside one tag rather
		// than across two operations of the same tag. Future
		// organization/* peers that introduce a third
		// parameter-free GET (e.g. API-0248 `*-allInvitations`)
		// should grep API-0246 → API-0247 first to inherit the
		// empty-fixture invariant; peers that introduce a path or
		// query parameter (none expected in the organization/*
		// roster) should fall back to the cross-tag list precedent
		// API-0033 (application-readTraefikConfig).
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0248",
		OperationID: "organization-allInvitations",
		Method:      http.MethodGet,
		Path:        "/organization.allInvitations",
		Tag:         "organization",
		// Third entry in the organization/* roster, completing the
		// trio of parameter-free GETs forecast by the API-0246 comment
		// block ("Future organization/* peers (API-0247 `*-all`,
		// API-0248 `*-allInvitations`, API-0251 `*-one`) should grep
		// this entry first when extending the parameter-free GET
		// cohort"). Spec source `data/openapi.json >
		// /organization.allInvitations > get` is byte-for-byte the
		// same wire shape as `/organization.active` and
		// `/organization.all`: no `parameters` array (the spec omits
		// it entirely rather than declaring `[]` — the registry
		// normalises both forms to "no query/path params"), no
		// request body, responses 200/400/401/403/404/500 where the
		// 200 schema is `{}` with `additionalProperties: false`.
		//
		// The semantic difference vs. API-0246/API-0247 is the
		// resource being listed: this endpoint returns every
		// outstanding invitation across organizations the bearer
		// principal can administer, rather than the principal's own
		// organization memberships. From the coverage harness's
		// perspective it is identical to API-0247 — the canonical
		// agent invocation is `yalla api call organization-allInvitations
		// --input '{}' --json`, SampleQuery / SamplePathParams /
		// SampleBody stay unset, and the representative-failure leg
		// keeps the harness default of 401→CodeAuth (auth is the
		// universal failure mode every organization/* peer must
		// re-prove; 404 in the spec exists for filter-shaped peers
		// like `*-one` rather than this list endpoint, and 403
		// applies to admin-scope checks the success leg already
		// short-circuits).
		//
		// This entry also closes out the *list-shaped* sub-cohort of
		// the organization/* roster — the next failing story
		// (API-0249 `organization-create`) introduces a required
		// request body and shifts the cohort into POST mutation
		// territory, where API-0249 → API-0250 → API-0252 → API-0253
		// → API-0254 → API-0255 will follow the
		// minimal-required-body precedent set by ai-create
		// (API-0003) / certificates-create rather than the empty
		// `{}` fixture this trio uses. Future contributors picking
		// up the organization/* mutation arc should grep API-0249
		// (once landed) first instead of this entry.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0249",
		OperationID: "organization-create",
		Method:      http.MethodPost,
		Path:        "/organization.create",
		Tag:         "organization",
		// First mutation in the organization/* roster and the first
		// required-body POST after the API-0246/0247/0248 trio of
		// parameter-free GETs. Spec source `data/openapi.json >
		// /organization.create > post` declares zero parameters and a
		// required `application/json` request body whose schema has two
		// top-level string fields — `name` (required) and `logo`
		// (optional). Per the API-0010 / API-0014 convention adopted
		// across the ai/* and application/* mutation rosters, we supply
		// every optional field with a deterministic-but-clearly-fake
		// value so the wire payload exercises the entire envelope (not
		// just the minimum-required pair) and the success-leg JSON
		// forwarding assertion exercises array-free-but-non-trivial
		// shape projection. Per-case fixture token
		// `*-cov-org-create-0249` keeps `git grep` traceable to this
		// PRD story.
		//
		// Responses 200/400/401/403/500 mirror the rest of the
		// organization/* tag — the 200 schema is `{}` with
		// `additionalProperties: false`, identical to API-0246/0247/
		// 0248 above and to every ai/* and application/* mutation
		// peer; the success-leg envelope assertion therefore stays
		// focused on `data.method` / `data.status` rather than payload
		// projection. The representative-failure leg keeps the harness
		// default (401 → CodeAuth) because auth is the universal
		// failure mode every organization/* peer must re-prove —
		// 400 (validation) is exercised once at the package level by
		// the API-0001 entry rather than re-asserted on every
		// minimum-required-body POST in the roster.
		//
		// Future contributors picking up the next mutation in the
		// arc (API-0250 `organization-delete`, an `organizationId`
		// scalar, then API-0252 `*-removeInvitation`, API-0253
		// `*-setDefault`, API-0254 `*-update`, API-0255
		// `*-updateMemberRole`) should grep this entry first when
		// shaping their `SampleBody` — every successor is a single
		// or two-field POST that can copy the closed-shape
		// `{name, logo}` literal pattern verbatim with the field
		// names swapped, and the comment header above keeps the
		// design rationale (every-optional-populated, per-case
		// fixture token, default 401 failure leg) discoverable
		// without re-deriving it from API-0010 / API-0014.
		SampleBody: json.RawMessage(`{
			"name": "yalla-coverage-org-create-0249",
			"logo": "https://example.test/logos/yalla-cov-org-create-0249.png"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior organization/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0250",
		OperationID: "organization-delete",
		Method:      http.MethodPost,
		Path:        "/organization.delete",
		Tag:         "organization",
		// Second mutation in the organization/* roster, immediately
		// after API-0249 `organization-create`. Spec source
		// `data/openapi.json > /organization.delete > post` declares
		// zero parameters and a required `application/json` request
		// body whose schema is the closed-shape single-string-scalar
		// `{organizationId}` (required, no optionals) — the exact
		// "single or two-field POST that can copy the closed-shape
		// `{name, logo}` literal pattern verbatim with the field
		// names swapped" forecast called out in the API-0249 future-
		// contributors comment block above. Per the API-0010 / API-
		// 0014 convention adopted across the ai/* and application/*
		// mutation rosters and re-affirmed by API-0249, we still
		// supply a deterministic-but-clearly-fake value for the lone
		// required scalar so the wire payload exercises the full
		// envelope; per-case fixture token `*-cov-org-delete-0250`
		// keeps `git grep` traceable to this PRD story.
		//
		// Responses 200/400/401/403/500 mirror the rest of the
		// organization/* tag — the 200 schema is `{}` with
		// `additionalProperties: false`, identical to API-0246/0247/
		// 0248/0249 above and to every ai/* and application/*
		// mutation peer; the success-leg envelope assertion therefore
		// stays focused on `data.method` / `data.status` rather than
		// payload projection. The representative-failure leg keeps
		// the harness default (401 → CodeAuth) because auth is the
		// universal failure mode every organization/* peer must re-
		// prove — 400 (validation) is exercised once at the package
		// level by the API-0001 entry rather than re-asserted on
		// every minimum-required-body POST in the roster.
		//
		// Future contributors picking up the next mutation in the
		// arc (API-0252 `*-removeInvitation`, API-0253 `*-setDefault`,
		// API-0254 `*-update`, API-0255 `*-updateMemberRole`) should
		// grep API-0249 first for the design-rationale header and
		// this entry second for the `{single-required-scalar}`
		// fixture pattern — every successor remains a single or two-
		// field POST that can copy the closed-shape literal verbatim
		// with the field names swapped, and the API-0249 comment
		// header keeps the every-optional-populated / per-case
		// fixture token / default 401 failure leg invariants
		// discoverable without re-deriving them from API-0010 /
		// API-0014.
		SampleBody: json.RawMessage(`{
			"organizationId": "yalla-coverage-org-delete-0250"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior organization/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0251",
		OperationID: "organization-one",
		Method:      http.MethodGet,
		Path:        "/organization.one",
		Tag:         "organization",
		// First single-query-param GET in the organization/* roster,
		// breaking the parameter-free streak established by API-0246
		// `organization-active`, API-0247 `organization-all`, and
		// API-0248 `organization-allInvitations`. Spec source
		// `data/openapi.json > /organization.one > get` declares no
		// request body and exactly one required query parameter
		// `organizationId` (string) — the canonical "fetch a single
		// resource by ID" GET shape that mirrors API-0008 (`ai-one`)
		// and API-0021 (`application-one`) byte-for-byte at the wire
		// level. The API-0246 forecast block flagged this entry as a
		// future organization/* peer; the parameter-free framing in
		// that block was intentionally aspirational — `organization-
		// one`'s spec ships with a required `organizationId` scalar
		// because the principal can be a member of more than one org
		// and must disambiguate, whereas `organization-active`
		// resolves implicitly from the bearer token.
		//
		// The harness forwards SampleQuery via the `--input` JSON
		// `query` field, and `runAPICoverageSuccess` re-reads
		// `r.URL.Query()` to confirm the CLI propagated the param
		// verbatim — exactly the assertion path exercised by the
		// API-0008 / API-0021 / API-0022 single-required-query-param
		// peers. Per the established `<tag>-cov-<slug>-<storyID>`
		// deterministic-but-clearly-fake naming convention shared
		// across the ai/* and application/* GET rosters, the fixture
		// token `org-cov-one-0251` keeps `git grep` traceable to this
		// PRD story without colliding with the API-0250 mutation
		// fixture (`yalla-coverage-org-delete-0250`).
		//
		// Responses 200/400/401/403/404/500 mirror every other
		// organization/* peer — the 200 schema is `{}` with
		// `additionalProperties: false`, identical to API-0246/0247/
		// 0248/0249/0250 above. The representative-failure leg keeps
		// the harness default (401 → CodeAuth) because auth is the
		// universal failure mode every organization/* peer must re-
		// prove; 404 (the `organizationId` resolves to no record) is
		// not asserted per-case here because the registry-driven
		// invariants test already covers the response-code surface.
		//
		// Future contributors picking up the next mutation in the
		// arc (API-0252 `*-removeInvitation`, API-0253 `*-setDefault`,
		// API-0254 `*-update`, API-0255 `*-updateMemberRole`) should
		// continue grepping API-0249 first for the design-rationale
		// header and API-0250 for the `{single-required-scalar}`
		// fixture pattern — those are POST mutations and inherit a
		// different code path from this single-query-param GET.
		SampleQuery: map[string][]string{
			"organizationId": {"org-cov-one-0251"},
		},
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior organization/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0252",
		OperationID: "organization-removeInvitation",
		Method:      http.MethodPost,
		Path:        "/organization.removeInvitation",
		Tag:         "organization",
		// Third mutation in the organization/* roster, immediately after
		// API-0249 `organization-create` (the design-rationale anchor)
		// and API-0250 `organization-delete` (the fixture-pattern anchor)
		// — and the first peer to pick up the
		// `{single-required-scalar}` body shape forecast in the API-0250
		// future-contributors comment block ("Future contributors
		// picking up the next mutation in the arc (API-0252
		// `*-removeInvitation`, API-0253 `*-setDefault`, API-0254
		// `*-update`, API-0255 `*-updateMemberRole`) should grep
		// API-0249 first for the design-rationale header and this entry
		// second for the `{single-required-scalar}` fixture pattern").
		// Spec source `data/openapi.json > /organization.removeInvitation
		// > post` declares zero parameters and a required
		// `application/json` request body whose schema is the
		// closed-shape single-string-scalar `{invitationId}` (required,
		// no optionals) — the exact same wire shape as API-0250
		// `organization-delete` with the field name swapped from
		// `organizationId` → `invitationId`. Per the established
		// `<tag>-cov-<slug>-<storyID>` deterministic-but-clearly-fake
		// naming convention, the fixture token
		// `yalla-coverage-org-removeInvitation-0252` keeps `git grep`
		// traceable to this PRD story without colliding with the
		// API-0249 (`yalla-coverage-org-create-0249`) or API-0250
		// (`yalla-coverage-org-delete-0250`) mutation fixtures.
		//
		// Responses 200/400/401/403/500 mirror every other
		// organization/* mutation peer — the 200 schema is `{}` with
		// `additionalProperties: false`, identical to API-0246/0247/
		// 0248/0249/0250/0251 above; notably the 404 response code that
		// `organization-one` (the lookup-shape GET) declares is absent
		// here because removeInvitation is a delete-by-id action whose
		// missing-target failure path collapses into 400 (validation)
		// rather than 404 (not found) per Dokploy's tRPC conventions.
		// The success-leg envelope assertion therefore stays focused on
		// `data.method` / `data.status` rather than payload projection,
		// and the representative-failure leg keeps the harness default
		// (401 → CodeAuth) because auth is the universal failure mode
		// every organization/* peer must re-prove — 400 (validation) is
		// exercised once at the package level by the API-0001 entry
		// rather than re-asserted on every minimum-required-body POST
		// in the roster.
		//
		// Future contributors picking up the remaining mutations in
		// the arc (API-0253 `*-setDefault`, API-0254 `*-update`,
		// API-0255 `*-updateMemberRole`) should continue grepping
		// API-0249 first for the design-rationale header and this
		// entry (or API-0250) second for the
		// `{single-required-scalar}` fixture pattern — every successor
		// remains a single or two-field POST that can copy the
		// closed-shape literal verbatim with the field names swapped.
		SampleBody: json.RawMessage(`{
			"invitationId": "yalla-coverage-org-removeInvitation-0252"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior organization/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0253",
		OperationID: "organization-setDefault",
		Method:      http.MethodPost,
		Path:        "/organization.setDefault",
		Tag:         "organization",
		// Fourth mutation in the organization/* roster, picking up the
		// `{single-required-scalar}` body-shape arc forecast in the
		// API-0250 / API-0252 future-contributors comment blocks. Per
		// that contract, this entry copies the API-0250
		// `organization-delete` literal verbatim — the spec source
		// `data/openapi.json > /organization.setDefault > post`
		// declares zero parameters and a required `application/json`
		// request body whose schema is the closed-shape single-string
		// `{organizationId}` (required, no optionals), the exact same
		// wire shape as `organization-delete`. Per the established
		// `<tag>-cov-<slug>-<storyID>` deterministic-but-clearly-fake
		// naming convention, the fixture token
		// `yalla-coverage-org-setDefault-0253` keeps `git grep`
		// traceable to this PRD story without colliding with the
		// API-0249 (`yalla-coverage-org-create-0249`), API-0250
		// (`yalla-coverage-org-delete-0250`), or API-0252
		// (`yalla-coverage-org-removeInvitation-0252`) mutation
		// fixtures.
		//
		// Responses 200/400/401/403/500 mirror every other
		// organization/* mutation peer — the 200 schema is `{}` with
		// `additionalProperties: false`, identical to API-0246/0247/
		// 0248/0249/0250/0251/0252 above; like API-0252
		// `removeInvitation` (and unlike API-0251 `organization-one`,
		// the lookup-shape GET) the 404 response code is absent
		// because setDefault is a state-mutation action whose
		// missing-target failure path collapses into 400 (validation)
		// rather than 404 (not found) per Dokploy's tRPC conventions.
		// The success-leg envelope assertion therefore stays focused on
		// `data.method` / `data.status` rather than payload projection,
		// and the representative-failure leg keeps the harness default
		// (401 → CodeAuth) because auth is the universal failure mode
		// every organization/* peer must re-prove — 400 (validation) is
		// exercised once at the package level by the API-0001 entry
		// rather than re-asserted on every minimum-required-body POST
		// in the roster.
		//
		// Future contributors picking up the remaining mutations in
		// the arc (API-0254 `*-update`, API-0255 `*-updateMemberRole`)
		// should continue grepping API-0249 first for the
		// design-rationale header and either API-0250 / API-0252 /
		// this entry second for the `{single-required-scalar}`
		// fixture pattern — both successors remain single or
		// two-field POSTs that can copy the closed-shape literal
		// verbatim with the field names swapped.
		SampleBody: json.RawMessage(`{
			"organizationId": "yalla-coverage-org-setDefault-0253"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior organization/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0254",
		OperationID: "organization-update",
		Method:      http.MethodPost,
		Path:        "/organization.update",
		Tag:         "organization",
		// Fifth mutation in the organization/* roster and the first
		// entry to break out of the strict `{single-required-scalar}`
		// arc the API-0250 / API-0252 / API-0253 future-contributors
		// blocks forecast — `organization-update` is the natural
		// "two-required-plus-optional" peer the arc expected to land
		// next. Per the spec source `data/openapi.json >
		// /organization.update > post`, the request body declares zero
		// parameters and a required `application/json` payload with
		// `organizationId` and `name` both `required` plus an optional
		// `logo` string. The fixture intentionally omits the optional
		// `logo` field to keep the closed-shape contract focused on
		// the minimum-required body shape (the same reductionist
		// posture API-0249 `organization-create` took with its own
		// optional `logo`/`slug` fields), which keeps the success-leg
		// envelope assertion squarely on `data.method` / `data.status`
		// rather than encouraging payload projection drift.
		//
		// Per the established `<tag>-cov-<slug>-<storyID>`
		// deterministic-but-clearly-fake naming convention, both
		// fixture tokens (`yalla-coverage-org-update-0254-id` /
		// `yalla-coverage-org-update-0254-name`) keep `git grep`
		// traceable to this PRD story without colliding with the
		// API-0249 (`yalla-coverage-org-create-0249`), API-0250
		// (`yalla-coverage-org-delete-0250`), API-0252
		// (`yalla-coverage-org-removeInvitation-0252`), or API-0253
		// (`yalla-coverage-org-setDefault-0253`) mutation fixtures —
		// the `-id` / `-name` suffixes disambiguate the two required
		// scalars within this single body without losing the story-ID
		// trail.
		//
		// Responses 200/400/401/403/500 mirror every other
		// organization/* mutation peer — the 200 schema is `{}` with
		// `additionalProperties: false`, identical to API-0246/0247/
		// 0248/0249/0250/0251/0252/0253 above; like the other
		// state-mutation peers (and unlike API-0251 `organization-one`,
		// the lookup-shape GET) the 404 response code is absent
		// because `update` is a state-mutation action whose
		// missing-target failure path collapses into 400 (validation)
		// rather than 404 (not found) per Dokploy's tRPC conventions.
		// The representative-failure leg therefore keeps the harness
		// default (401 → CodeAuth) because auth is the universal
		// failure mode every organization/* peer must re-prove —
		// 400 (validation) is exercised once at the package level by
		// the API-0001 entry rather than re-asserted on every
		// minimum-required-body POST in the roster.
		//
		// Future contributors picking up the final mutation in the
		// arc (API-0255 `*-updateMemberRole`) should continue grepping
		// API-0249 first for the design-rationale header and either
		// this entry (for the `{required-scalar, required-scalar,
		// +optional}` shape) or API-0250 / API-0252 / API-0253 (for
		// the strict `{single-required-scalar}` shape) second
		// depending on whichever closed-shape literal lines up with
		// the spec — `updateMemberRole` is the last `*-update*` POST
		// in the organization/* roster and closes the tag.
		SampleBody: json.RawMessage(`{
			"organizationId": "yalla-coverage-org-update-0254-id",
			"name": "yalla-coverage-org-update-0254-name"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior organization/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0255",
		OperationID: "organization-updateMemberRole",
		Method:      http.MethodPost,
		Path:        "/organization.updateMemberRole",
		Tag:         "organization",
		// Sixth and final mutation in the organization/* roster, closing
		// the tag the API-0246 → API-0254 arc opened. Per the spec
		// source `data/openapi.json > /organization.updateMemberRole >
		// post`, the request body declares zero parameters and a
		// required `application/json` payload with two required string
		// fields and zero optionals: `memberId` (free-form string) and
		// `role` (enum-constrained to `"admin"` | `"member"`). That
		// shape lands squarely in the `{required-scalar,
		// required-scalar}` family the API-0254 future-contributors
		// block forecast — strictly closed, no optional drift to
		// project — and the literal below copies the API-0254
		// `organization-update` body verbatim with the field names
		// swapped, exactly as the arc design rationale (API-0249)
		// promised future contributors they could.
		//
		// The `role` value is pinned to `"admin"` so the wire payload
		// exercises the enum-constrained branch (rather than the
		// `"member"` peer) and a future schema-aware validator wired
		// into the harness still accepts the fixture without
		// per-case overrides. Per the established
		// `<tag>-cov-<slug>-<storyID>` deterministic-but-clearly-fake
		// naming convention, the `memberId` token
		// `yalla-coverage-org-updateMemberRole-0255-member` keeps
		// `git grep` traceable to this PRD story without colliding
		// with the API-0249 (`yalla-coverage-org-create-0249`),
		// API-0250 (`yalla-coverage-org-delete-0250`), API-0252
		// (`yalla-coverage-org-removeInvitation-0252`), API-0253
		// (`yalla-coverage-org-setDefault-0253`), or API-0254
		// (`yalla-coverage-org-update-0254-id` /
		// `yalla-coverage-org-update-0254-name`) mutation fixtures —
		// the `-member` suffix disambiguates this entry from its
		// sibling `role` enum scalar without losing the story-ID
		// trail. The enum-pinned `role` literal does not need the
		// `<tag>-cov-<slug>-<storyID>` token because OpenAPI's
		// closed-set enum already collapses the value space to two
		// reserved keywords; injecting a unique-but-invalid token
		// would defeat the schema-validator coverage this fixture is
		// designed to support.
		//
		// Responses 200/400/401/403/500 mirror every other
		// organization/* mutation peer — the 200 schema is `{}` with
		// `additionalProperties: false`, identical to API-0246/0247/
		// 0248/0249/0250/0251/0252/0253/0254 above; like every other
		// state-mutation peer (and unlike API-0251 `organization-one`,
		// the lookup-shape GET) the 404 response code is absent
		// because `updateMemberRole` is a state-mutation action whose
		// missing-target failure path collapses into 400 (validation)
		// rather than 404 (not found) per Dokploy's tRPC conventions.
		// The representative-failure leg therefore keeps the harness
		// default (401 → CodeAuth) because auth is the universal
		// failure mode every organization/* peer must re-prove —
		// 400 (validation) is exercised once at the package level by
		// the API-0001 entry rather than re-asserted on every
		// minimum-required-body POST in the roster.
		//
		// This entry closes the organization/* tag. The next API
		// story (API-0256+) opens a new tag whose first entry will
		// re-establish a fresh design-rationale header analogous to
		// API-0249's role for organization/*; future contributors
		// inheriting that next-tag arc should not back-reference the
		// organization/* literals here for body-shape templates,
		// because tag-spanning fixture sharing has historically
		// produced false-positive `git grep` collisions when the new
		// tag's slug overlaps with the closing tag's slug
		// (`org-update*` vs e.g. a future `*-update*` peer in another
		// tag). Treat the `<tag>-cov-<slug>-<storyID>` namespace as
		// strictly per-tag.
		SampleBody: json.RawMessage(`{
			"memberId": "yalla-coverage-org-updateMemberRole-0255-member",
			"role": "admin"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior organization/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0290",
		OperationID: "project-all",
		Method:      http.MethodGet,
		Path:        "/project.all",
		Tag:         "project",
		// First entry in the project/* roster, opening a fresh tag arc
		// after API-0255 closed organization/*. Per the per-tag fixture
		// rule the closing organization/* block flagged ("future
		// contributors inheriting that next-tag arc should not back-
		// reference the organization/* literals here for body-shape
		// templates"), this entry deliberately stands alone and any
		// project/* peers that follow (API-0291 `*-allForPermissions`,
		// API-0292 `*-create`, API-0293 `*-duplicate`, API-0294
		// `*-one`, API-0295 `*-remove`, API-0296 `*-search`, API-0297
		// `*-update`) should grep this block first to inherit the
		// project/* slug namespace rather than copying organization/*
		// fixtures across the tag boundary.
		//
		// Spec source `data/openapi.json > /project.all > get`: zero
		// `parameters`, no request body, responses
		// 200/400/401/403/404/500 where the 200 schema is `{}` with
		// `additionalProperties: false`. That places this operation
		// in the same parameter-free GET cohort as API-0246
		// `organization-active` and API-0247 `organization-all`: the
		// canonical agent invocation is `yalla api call project-all
		// --json` with no `--input`, so SampleQuery /
		// SamplePathParams / SampleBody all stay unset. The
		// representative-failure leg keeps the harness default
		// (401 → CodeAuth) because auth is the universal failure
		// every project/* peer must re-prove; 404 in the spec is
		// reserved for filter-shaped peers like the upcoming
		// API-0294 `project-one`, not this membership-scoped list.
		//
		// Naming convention rolls forward unchanged from the
		// organization/* roster: future project/* mutation fixtures
		// must use the `<tag>-cov-<slug>-<storyID>` pattern with the
		// `proj-` slug prefix (e.g. `proj-cov-create-0292`,
		// `proj-cov-one-0294`) so `git grep` stays per-story
		// traceable and never collides with the organization/*
		// `org-cov-*` namespace established by API-0249→API-0255.
		// This entry has no fixture token because it carries no
		// SampleBody / SampleQuery / SamplePathParams.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0291",
		OperationID: "project-allForPermissions",
		Method:      http.MethodGet,
		Path:        "/project.allForPermissions",
		Tag:         "project",
		// Second entry in the project/* roster opened by API-0290
		// `project-all`. Per the per-tag fixture rule that opening
		// block established ("project/* peers should grep this block
		// first to inherit the project/* slug namespace rather than
		// copying organization/* fixtures across the tag boundary"),
		// this entry inherits the parameter-free GET shape from
		// API-0290 unchanged: zero parameters, no request body, and
		// the canonical agent invocation `yalla api call
		// project-allForPermissions --json` with no `--input`.
		//
		// Spec source `internal/api/data/openapi.json >
		// /project.allForPermissions > get`: identical to
		// `/project.all` — zero `parameters`, no request body,
		// responses 200/400/401/403/404/500 where the 200 schema is
		// `{}` with `additionalProperties: false`. That keeps this
		// operation in the same parameter-free GET cohort as
		// API-0290 `project-all`, API-0246 `organization-active`, and
		// API-0247 `organization-all`. SampleQuery /
		// SamplePathParams / SampleBody all stay unset; the
		// representative-failure leg keeps the harness default
		// (401 → CodeAuth) because auth is the universal failure
		// every project/* peer must re-prove. 404 in the spec is
		// still reserved for filter-shaped peers like the upcoming
		// API-0294 `project-one`, not this permissions-scoped list
		// which differs from `project-all` only in server-side
		// authorisation filtering — the wire contract is identical.
		//
		// No fixture token: this entry carries no SampleBody /
		// SampleQuery / SamplePathParams, so the `proj-cov-*` slug
		// namespace reserved by API-0290 stays untouched until the
		// first project/* mutation peer (API-0292 `project-create`).
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
