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
		StoryID:     "API-0043",
		OperationID: "backup-manualBackupMariadb",
		Method:      http.MethodPost,
		Path:        "/backup.manualBackupMariadb",
		Tag:         "backup",
		// Fourth backup/* coverage entry and the SECOND member of the
		// `backup-manualBackup*` family seeded by API-0042 (six siblings:
		// API-0042 compose, API-0043 mariadb, API-0044 mongo, API-0045
		// mySql, API-0046 postgres, API-0047 webServer). The spec at
		// `data/openapi.json > /backup.manualBackupMariadb > post` is
		// byte-identical to its compose sibling — single required
		// `backupId` (string), no optional siblings, no path or query
		// parameters — so this entry is a near-verbatim mirror of API-0042
		// with only the slug, story id, and path/operationId rewritten.
		// Following the convention seeded by API-0042 keeps cross-story
		// grep useful (`backup-cov-manual-<slug>-<storyID>`) and each
		// manualBackup story's diff a single contiguous insert. The four
		// remaining family siblings (mongo, mySql, postgres, webServer)
		// will land here in the same shape.
		SampleBody: json.RawMessage(`{
			"backupId": "backup-cov-manual-mariadb-0043"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// backup/* peer (API-0040 backup-create, API-0041
		// backup-listBackupFiles, API-0042 backup-manualBackupCompose),
		// application/*, and compose/* peer. Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0044",
		OperationID: "backup-manualBackupMongo",
		Method:      http.MethodPost,
		Path:        "/backup.manualBackupMongo",
		Tag:         "backup",
		// Fifth backup/* coverage entry and the THIRD member of the
		// `backup-manualBackup*` family seeded by API-0042 (six siblings:
		// API-0042 compose, API-0043 mariadb, API-0044 mongo, API-0045
		// mySql, API-0046 postgres, API-0047 webServer). The spec at
		// `data/openapi.json > /backup.manualBackupMongo > post` is
		// byte-identical to its compose / mariadb siblings — single
		// required `backupId` (string), no optional siblings, no path or
		// query parameters — so this entry is a near-verbatim mirror of
		// API-0043 with only the slug, story id, and path/operationId
		// rewritten. Following the convention seeded by API-0042 keeps
		// cross-story grep useful (`backup-cov-manual-<slug>-<storyID>`)
		// and each manualBackup story's diff a single contiguous insert.
		// The three remaining family siblings (mySql, postgres, webServer)
		// will land here in the same shape.
		SampleBody: json.RawMessage(`{
			"backupId": "backup-cov-manual-mongo-0044"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// backup/* peer (API-0040 backup-create, API-0041
		// backup-listBackupFiles, API-0042 backup-manualBackupCompose,
		// API-0043 backup-manualBackupMariadb), application/*, and
		// compose/* peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` / `data.status`
		// rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0045",
		OperationID: "backup-manualBackupMySql",
		Method:      http.MethodPost,
		Path:        "/backup.manualBackupMySql",
		Tag:         "backup",
		// Sixth backup/* coverage entry and the FOURTH member of the
		// `backup-manualBackup*` family seeded by API-0042 (six siblings:
		// API-0042 compose, API-0043 mariadb, API-0044 mongo, API-0045
		// mySql, API-0046 postgres, API-0047 webServer). The spec at
		// `data/openapi.json > /backup.manualBackupMySql > post` is
		// byte-identical to its compose / mariadb / mongo siblings —
		// single required `backupId` (string), no optional siblings, no
		// path or query parameters — so this entry is a near-verbatim
		// mirror of API-0044 with only the slug, story id, and
		// path/operationId rewritten. Following the convention seeded by
		// API-0042 keeps cross-story grep useful
		// (`backup-cov-manual-<slug>-<storyID>`) and each manualBackup
		// story's diff a single contiguous insert. The two remaining
		// family siblings (postgres, webServer) will land here in the
		// same shape.
		SampleBody: json.RawMessage(`{
			"backupId": "backup-cov-manual-mysql-0045"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// backup/* peer (API-0040 backup-create, API-0041
		// backup-listBackupFiles, API-0042 backup-manualBackupCompose,
		// API-0043 backup-manualBackupMariadb, API-0044
		// backup-manualBackupMongo), application/*, and compose/* peer.
		// Empty-object body keeps the success-leg envelope assertion
		// focused on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0046",
		OperationID: "backup-manualBackupPostgres",
		Method:      http.MethodPost,
		Path:        "/backup.manualBackupPostgres",
		Tag:         "backup",
		// Seventh backup/* coverage entry and the FIFTH member of the
		// `backup-manualBackup*` family seeded by API-0042 (six siblings:
		// API-0042 compose, API-0043 mariadb, API-0044 mongo, API-0045
		// mySql, API-0046 postgres, API-0047 webServer). The spec at
		// `data/openapi.json > /backup.manualBackupPostgres > post` is
		// byte-identical to its compose / mariadb / mongo / mySql
		// siblings — single required `backupId` (string), no optional
		// siblings, no path or query parameters — so this entry is a
		// near-verbatim mirror of API-0045 with only the slug, story id,
		// and path/operationId rewritten. Following the convention seeded
		// by API-0042 keeps cross-story grep useful
		// (`backup-cov-manual-<slug>-<storyID>`) and each manualBackup
		// story's diff a single contiguous insert. The last family sibling
		// (webServer) will land here in the same shape.
		SampleBody: json.RawMessage(`{
			"backupId": "backup-cov-manual-postgres-0046"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// backup/* peer (API-0040 backup-create, API-0041
		// backup-listBackupFiles, API-0042 backup-manualBackupCompose,
		// API-0043 backup-manualBackupMariadb, API-0044
		// backup-manualBackupMongo, API-0045 backup-manualBackupMySql),
		// application/*, and compose/* peer. Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0047",
		OperationID: "backup-manualBackupWebServer",
		Method:      http.MethodPost,
		Path:        "/backup.manualBackupWebServer",
		Tag:         "backup",
		// Eighth backup/* coverage entry and the SIXTH (final) member of
		// the `backup-manualBackup*` family seeded by API-0042 (six
		// siblings: API-0042 compose, API-0043 mariadb, API-0044 mongo,
		// API-0045 mySql, API-0046 postgres, API-0047 webServer). The
		// spec at `data/openapi.json > /backup.manualBackupWebServer >
		// post` is byte-identical to its compose / mariadb / mongo /
		// mySql / postgres siblings — single required `backupId` (string),
		// no optional siblings, no path or query parameters — so this
		// entry is a near-verbatim mirror of API-0046 with only the slug,
		// story id, and path/operationId rewritten. Following the
		// convention seeded by API-0042 keeps cross-story grep useful
		// (`backup-cov-manual-<slug>-<storyID>`) and each manualBackup
		// story's diff a single contiguous insert. This entry CLOSES
		// the six-sibling `manualBackup*` family.
		SampleBody: json.RawMessage(`{
			"backupId": "backup-cov-manual-webserver-0047"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// backup/* peer (API-0040 backup-create, API-0041
		// backup-listBackupFiles, API-0042 backup-manualBackupCompose,
		// API-0043 backup-manualBackupMariadb, API-0044
		// backup-manualBackupMongo, API-0045 backup-manualBackupMySql,
		// API-0046 backup-manualBackupPostgres), application/*, and
		// compose/* peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` / `data.status`
		// rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0048",
		OperationID: "backup-one",
		Method:      http.MethodGet,
		Path:        "/backup.one",
		Tag:         "backup",
		// Ninth backup/* coverage entry and the SECOND backup/* GET
		// (the first being API-0041 backup-listBackupFiles, which
		// seeded the query-only fixture shape for the tag and
		// explicitly forward-referenced API-0048 as the next backup/*
		// GET to mirror it). With API-0047 the six-sibling
		// `backup-manualBackup*` family closed; this entry pivots the
		// roster from the manualBackup mutation cohort to the
		// inspection cohort. The spec at `data/openapi.json >
		// /backup.one > get` declares no request body and a single
		// REQUIRED query parameter `backupId` (string), with no
		// optional siblings — so the fixture is materially simpler
		// than API-0041's three-param REQUIRED + REQUIRED + OPTIONAL
		// shape and aligns instead with the canonical "single id-only
		// GET" precedents API-0005 (ai-get) and API-0008 (ai-one).
		// Slug convention `backup-cov-<slug>-<storyID>` follows the
		// seed laid by API-0040 (`backup-cov-create-0040`) and the
		// sibling tweak in API-0041 (`backup-cov-list-files-0041`),
		// keeping the per-tag `backup-cov-*` namespace intact and
		// distinct from the manualBackup family's `backup-cov-manual-
		// <slug>-<storyID>` sub-namespace closed at API-0047.
		SampleQuery: map[string][]string{
			"backupId": {"backup-cov-one-0048"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// backup/* peer (API-0040 backup-create, API-0041
		// backup-listBackupFiles, API-0042 backup-manualBackupCompose,
		// API-0043 backup-manualBackupMariadb, API-0044
		// backup-manualBackupMongo, API-0045 backup-manualBackupMySql,
		// API-0046 backup-manualBackupPostgres, API-0047
		// backup-manualBackupWebServer). Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection. (Yes, the
		// real Dokploy server returns the populated backup record on
		// 200 — the spec just leaves the response schema empty; the
		// coverage harness asserts forwarding and envelope shape, not
		// payload semantics, so the empty-object fixture is correct.)
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0049",
		OperationID: "backup-remove",
		Method:      http.MethodPost,
		Path:        "/backup.remove",
		Tag:         "backup",
		// Tenth backup/* coverage entry and the SECOND non-`manualBackup*`
		// backup/* POST after the seed API-0040 (backup-create). With
		// API-0048 the inspection cohort opened (sole member: backup-one,
		// the only backup/* GET besides API-0041 backup-listBackupFiles);
		// this entry pivots the roster from inspection back to mutation
		// to open the by-id mutation cohort that API-0050 (backup-update)
		// will close. The spec at `data/openapi.json > /backup.remove >
		// post` is byte-identical in shape to every member of the
		// `backup-manualBackup*` family closed at API-0047 — single
		// REQUIRED `backupId` (string) under `requestBody.required =
		// true`, no optional siblings, no path or query parameters — so
		// the fixture is a near-verbatim mirror of API-0046
		// (backup-manualBackupPostgres) with only the slug, story id,
		// and path/operationId rewritten. The `manualBackup*` family
		// took a sub-namespace (`backup-cov-manual-<slug>-<storyID>`);
		// `remove` lives outside that family, so it returns to the bare
		// `backup-cov-<slug>-<storyID>` namespace seeded by API-0040
		// (`backup-cov-create-0040`), tweaked by API-0041
		// (`backup-cov-list-files-0041`), and reasserted by API-0048
		// (`backup-cov-one-0048`). API-0050 backup-update will follow
		// the same bare namespace as the second by-id mutation sibling.
		SampleBody: json.RawMessage(`{
			"backupId": "backup-cov-remove-0049"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// backup/* peer (API-0040 backup-create, API-0041
		// backup-listBackupFiles, API-0042 backup-manualBackupCompose,
		// API-0043 backup-manualBackupMariadb, API-0044
		// backup-manualBackupMongo, API-0045 backup-manualBackupMySql,
		// API-0046 backup-manualBackupPostgres, API-0047
		// backup-manualBackupWebServer, API-0048 backup-one). Empty-
		// object body keeps the success-leg envelope assertion focused
		// on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0050",
		OperationID: "backup-update",
		Method:      http.MethodPost,
		Path:        "/backup.update",
		Tag:         "backup",
		// Eleventh backup/* coverage entry and the SECOND member of the
		// by-id mutation cohort opened at API-0049 (backup-remove); with
		// this commit the cohort closes and the entire backup/* roster
		// (API-0040..API-0050) is covered. Unlike `backup-remove`, whose
		// payload is a single REQUIRED `backupId`, `backup-update` has
		// the **broadest required set** of any backup/* operation: the
		// spec at `data/openapi.json > /backup.update > post` lists
		// `schedule`, `enabled`, `prefix`, `backupId`, `destinationId`,
		// `database`, `keepLatestCount`, `serviceName`, `metadata`, and
		// `databaseType` as `requestBody.required` — i.e. every property
		// except the database-flavour foreign keys (`mariadbId`,
		// `mysqlId`, `postgresId`, `mongoId`, `userId`, `composeId`,
		// `backupType`) that distinguished the create payload at
		// API-0040. No path or query parameters. The fixture mirrors
		// API-0040 (backup-create) for every shared property so the
		// two POSTs read as a matched pair, and adds the `backupId`
		// target so the wire payload reflects an "update <existing>"
		// shape. Per the AGENTS.md "anyOf [string|number|boolean|object,
		// null] → send the populated branch" rule we emit booleans for
		// `enabled`, numbers for `keepLatestCount`, strings for
		// `serviceName`, and an object for `metadata`. `databaseType`
		// stays on the `postgres` enum branch picked at API-0040 so the
		// inter-fixture invariant holds. Slug stays in the bare
		// `backup-cov-<slug>-<storyID>` namespace re-asserted by
		// API-0049 (backup-cov-remove-0049) → here `backup-cov-update-0050`.
		SampleBody: json.RawMessage(`{
			"schedule": "0 4 * * *",
			"enabled": true,
			"prefix": "yalla-cov-backup-update-0050/",
			"backupId": "backup-cov-update-0050",
			"destinationId": "dst-cov-backup-update-0050",
			"database": "yalla-cov-backup-db-0050",
			"keepLatestCount": 14,
			"serviceName": "service-cov-backup-update-0050",
			"metadata": {"yallaStoryId": "API-0050"},
			"databaseType": "postgres"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every prior
		// backup/* peer (API-0040..API-0049). Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection — and closes the
		// backup/* cohort on the same SuccessResponse shape it opened
		// with at API-0040.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0051",
		OperationID: "bitbucket-bitbucketProviders",
		Method:      http.MethodGet,
		Path:        "/bitbucket.bitbucketProviders",
		Tag:         "bitbucket",
		// Kickoff entry for the bitbucket/* coverage roster — this is
		// the first bitbucket-tagged operation to ship contract
		// coverage and opens a fresh per-tag fixture-isolation
		// namespace (`bb-cov-*`) that subsequent bitbucket/* peers
		// (API-0052 `bitbucket-create`, API-0053 `bitbucket-one`,
		// API-0054 `bitbucket-getBitbucketRepositories`, API-0055
		// `bitbucket-getBitbucketBranches`, API-0056
		// `bitbucket-testConnection`, API-0057 `bitbucket-update`)
		// must inherit, per the per-tag fixture-isolation rule
		// established at API-0246 `organization-active`, reasserted
		// at API-0290 `project-all`, and re-asserted by every
		// subsequent tag-opener (API-0335 `server-all`, API-0351
		// `settings-assignDomainServer`). Must NOT back-reference
		// the closed `admin-cov-*` (API-0001), `ai-cov-*`
		// (API-0002..API-0010), `app-cov-*` (API-0011..API-0039),
		// `backup-cov-*` (API-0040..API-0050), `compose-cov-*`
		// (API-0066..API-0093), `deployment-cov-*`
		// (API-0094..API-0101), `org-cov-*` (API-0246..API-0255),
		// `proj-cov-*` (API-0290..API-0297), `srv-cov-*`
		// (API-0335..API-0350), or `set-cov-*`
		// (API-0351..API-0363) namespaces. The deliberately short
		// `bb-` prefix matches the established pattern of compact
		// tag prefixes (`ai`, `app`, `srv`, `org`, `proj`, `set`)
		// and stays unambiguous against every prior namespace.
		//
		// **Spec re-verified per the API-0345..API-0363
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /bitbucket.bitbucketProviders > get`: a **GET** with
		// **zero parameters** (no query, no path, no header) and
		// **no request body** (GETs in this OpenAPI document never
		// carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the same response set as the
		// 404-bearing parameter-free GET cohort opened by API-0006
		// `ai-getAll`, continued by API-0246 `organization-active`,
		// API-0247 `organization-all`, API-0290 `project-all`,
		// API-0335 `server-all`, API-0336 `server-buildServers`,
		// API-0337 `server-count`, API-0341 `server-getServerTime`,
		// API-0343 `server-publicIp`, API-0345 `server-security`,
		// API-0349 `server-validate`, API-0350 `server-withSSHKey`,
		// API-0352 `settings-checkGPUStatus`, and API-0363
		// `settings-getDokployCloudIps`. The 200 schema is `{}`
		// with `additionalProperties: false`, matching every prior
		// covered peer in the parameter-free GET cohort. The
		// canonical agent invocation stays
		// `yalla api call bitbucket-bitbucketProviders --input '{}'
		// --json`.
		//
		// **Family choice — opens with a parameter-free GET.**
		// The bitbucket/* tag carries seven operations
		// (`bitbucketProviders`, `create`, `getBitbucketBranches`,
		// `getBitbucketRepositories`, `one`, `testConnection`,
		// `update`) split between three GETs and four POSTs.
		// API-0051 selects `bitbucketProviders` (the parameter-free
		// list-shaped GET) as the opener — pivoting onto the same
		// family-of-list-getters precedent that successfully opened
		// the ai/* (API-0006 `ai-getAll`), organization/*
		// (API-0246 `organization-active`), project/* (API-0290
		// `project-all`), and server/* (API-0335 `server-all`)
		// rosters. Future bitbucket/* peers must each
		// re-verify their own spec shapes per the API-0345..API-0363
		// forward-reference lesson; the eleven-flip body-axis
		// history of the settings/* `clean*` sub-roster
		// (API-0353..API-0362) demonstrates why per-operation
		// re-verification stays mandatory across every family
		// transition. In particular, three bitbucket/* peers carry
		// query-shaped `*Id` parameters
		// (`bitbucket-one` with 1 param, `*-getBitbucketRepositories`
		// with 1 param, `*-getBitbucketBranches` with 3 params)
		// — those entries should consult API-0033
		// `application-readTraefikConfig` for the query-shaped GET
		// precedent, not this entry.
		//
		// Leaving `SampleQuery` / `SamplePathParams` / `SampleBody`
		// unset is intentional: the harness's GET branch asserts
		// that **no `Content-Type` request header is sent** and
		// ignores `SampleBody` entirely, so carrying a `SampleBody`
		// into this case would silently encode dead code on the
		// wire — matching the omission convention re-asserted at
		// API-0006 `ai-getAll`, API-0335 `server-all`, API-0350
		// `server-withSSHKey`, and API-0363
		// `settings-getDokployCloudIps`. The harness still asserts
		// the wire-level invariants (method, path, `Authorization`
		// header, empty query string, empty request body) at
		// `runAPICoverageSuccess`. Empty-object response body keeps
		// the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		//
		// Fixture conventions:
		//   * No per-case fixture token base is needed because this
		//     case populates neither `SampleBody`, `SampleQuery`,
		//     nor `SamplePathParams` — the parameter-free GET
		//     cohort precedent (API-0006 `ai-getAll`, API-0335
		//     `server-all`, API-0350 `server-withSSHKey`, API-0363
		//     `settings-getDokployCloudIps`) applies. A reservation
		//     slot `bb-cov-providers-0051` is left open under the
		//     bitbucket/* `bb-cov-*` namespace for any future
		//     regression test that needs a unique literal tied to
		//     this story; the reservation is unique against every
		//     prior tag's namespace and orthogonal to all forthcoming
		//     bitbucket/* peers.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag-opener convention reasserted at API-0246
		// `organization-active`, API-0290 `project-all`, API-0335
		// `server-all`, and API-0351 `settings-assignDomainServer`
		// reserves 404 → CodeNotFound for the canonical by-id
		// peer (here API-0053 `bitbucket-one`), not for fleet-wide
		// list-style getters like `bitbucketProviders` (which
		// returns the bitbucket provider catalogue, not a single
		// resource keyed by id). Auth is the universal failure
		// mode every Dokploy operation must re-prove, so 401 →
		// CodeAuth via the harness default (`tc.FailureStatus == 0`
		// → 401, `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative for the kickoff story. 400 →
		// CodeInvalidInput stays reserved for stories where payload
		// validation is the operation's distinguishing failure mode;
		// this entry uses the canonical 401.
		//
		// The next case in the bitbucket/* roster, API-0052
		// `bitbucket-create`, will be a **POST** with a request body
		// per the PRD (responses 200/400/401/403/500 — note the
		// **absence of 404**, the canonical mutation response set).
		// Future contributors authoring API-0052 should grep this
		// entry first for the bitbucket/* kickoff conventions and
		// the `bb-cov-*` namespace, then re-verify the spec against
		// `internal/api/data/openapi.json > /bitbucket.create > post`
		// per the forward-reference lesson — do **not** assume the
		// request body shape mirrors any other tag's `*-create`
		// solely because the slug matches; consult API-0292
		// `project-create` and API-0338 `server-create` for the
		// flat scalar-only mutation precedent, then re-derive each
		// required field from the embedded spec.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0052",
		OperationID: "bitbucket-create",
		Method:      http.MethodPost,
		Path:        "/bitbucket.create",
		Tag:         "bitbucket",
		// Second entry on the bitbucket/* coverage roster and the
		// **first mutation** in the bitbucket/* tag — opens the
		// bitbucket/* mutation arc that succeeds the parameter-free
		// GET kickoff at API-0051 `bitbucket-bitbucketProviders`.
		// This entry is also the first bitbucket/* peer to populate
		// `SampleBody` and therefore *opens the `bb-cov-*` slug
		// namespace* reserved by API-0051's design-rationale header.
		// Per the per-tag fixture-isolation rule established at
		// API-0246 `organization-active`, reasserted at API-0290
		// `project-all`, API-0335 `server-all`, API-0351
		// `settings-assignDomainServer`, and re-asserted by
		// API-0051's bitbucket/* kickoff: every subsequent
		// bitbucket/* peer (API-0053..API-0057) inherits this
		// `bb-cov-*` namespace and **must not** back-reference the
		// `proj-cov-*` (API-0290..API-0297), `srv-cov-*`
		// (API-0335..API-0350), `set-cov-*` (API-0351..API-0363),
		// or any other prior tag's literals — even though the
		// nearest cross-tag flat-scalar-only mutation precedents
		// are API-0292 `project-create` and API-0338
		// `server-create`.
		//
		// Spec source `internal/api/data/openapi.json >
		// /bitbucket.create > post`: zero parameters, required
		// `application/json` request body whose schema declares
		// nine top-level scalar fields with **two required** and
		// **seven optional** — no nested objects, no arrays, no
		// enums, no `anyOf [string, null]` nullables:
		//   - REQUIRED scalars: `authId` (string), `name` (string).
		//   - OPTIONAL scalars (all plain string): `bitbucketId`,
		//     `bitbucketUsername`, `bitbucketEmail`, `appPassword`,
		//     `apiToken`, `bitbucketWorkspaceName`, `gitProviderId`.
		// This is the **flattest mutation body in the cross-tag
		// roster so far** — strictly stringly-typed with no number
		// fields (unlike API-0338 `server-create` which carried
		// `port: number`), no enum-pinned scalars (unlike API-0338
		// which pinned `serverType: "deploy"`), and no
		// `anyOf [string, null]` nullables (unlike API-0292
		// `project-create`'s `description` and API-0338's
		// `description` / `sshKeyId`). Future bitbucket/* peers
		// must each re-verify their own spec shapes per the
		// API-0345..API-0363 forward-reference lesson; this
		// entry's flat-string-only shape **must not be cargo-
		// culted** to the upcoming bitbucket/* mutation peers
		// (API-0056 `bitbucket-testConnection`, API-0057
		// `bitbucket-update`) without re-derivation from the
		// embedded spec.
		//
		// Fixture conventions:
		//   * Per the API-0010 / API-0014 / API-0249 / API-0292 /
		//     API-0297 every-optional-populated rule, all seven
		//     optionals are populated with deterministic-but-
		//     clearly-fake values so the wire payload exercises
		//     the entire envelope — not just the minimum-required
		//     `authId` + `name` pair. The harness's success-leg
		//     JSON round-trip body assertion observes this
		//     end-to-end through the CLI → API client → httptest
		//     server path.
		//   * Per-case fixture token base `bb-cov-create-0052`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     and stays unique across the bitbucket/* roster
		//     (verified: no collisions with the future
		//     `bb-cov-getBranches-0053`, `bb-cov-getRepos-0054`,
		//     `bb-cov-one-0055`, `bb-cov-testConn-0056`,
		//     `bb-cov-update-0057` slugs reserved for forthcoming
		//     bitbucket/* peers, no collision with the reservation
		//     slot `bb-cov-providers-0051` opened by API-0051's
		//     design-rationale header, and no collisions with the
		//     cross-tag `proj-cov-*` / `srv-cov-*` / `set-cov-*`
		//     / `org-cov-*` namespaces).
		//   * The two field names that *look* secret-like —
		//     `appPassword` and `apiToken` — carry obviously-fake
		//     `bb-cov-create-0052-*-fixture` literals so a casual
		//     reader (or a future automated secret scanner) can
		//     immediately tell these are coverage fixtures, not
		//     real Bitbucket credentials. The harness's
		//     `output.NewRedactor(flags.Token)` only scrubs the
		//     explicit `--token` value (the harness sets
		//     `Bearer test-token-value`) plus the well-known
		//     transport patterns (`Authorization:`,
		//     `X-Auth-Token:`, `?token=`); it does NOT match
		//     embedded JSON keys named `appPassword` /
		//     `apiToken`, so these literals round-trip through
		//     the wire body without redactor interference. The
		//     stdout-data-only / stderr-empty assertions on the
		//     success leg therefore stay tight.
		//   * `bitbucketEmail` carries a `@example.test` literal
		//     per RFC 6761 reserved-for-documentation conventions
		//     so the fixture cannot be mistaken for a real
		//     mailbox.
		//
		// Responses 200/400/401/403/500 — note **no 404** is
		// declared on `/bitbucket.create`, matching the canonical
		// mutation response set already exercised by every prior
		// `*-create` peer (API-0002 `ai-create`, API-0040
		// `backup-create`, API-0292 `project-create`, API-0338
		// `server-create`) and the broader cross-tag mutation
		// cohort. Per the per-tag opener convention reasserted
		// at API-0051's bitbucket/* design header, 404 →
		// CodeNotFound stays reserved for the canonical by-id
		// peer API-0055 `bitbucket-one`, not for this create
		// mutation. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer; the success-leg envelope assertion stays
		// focused on `data.method` / `data.status` rather than
		// payload projection.
		//
		// The representative-failure leg keeps the harness
		// default (401 → CodeAuth) because auth is the universal
		// failure every bitbucket/* peer must re-prove. 400 →
		// CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode (this entry's required-pair `authId` +
		// `name` is too generic to claim that distinguishing
		// shape); this entry uses the canonical 401, same as
		// API-0051's kickoff.
		//
		// Future contributors picking up the next bitbucket/*
		// peer (API-0053 `bitbucket-getBitbucketBranches`,
		// expected to be a 3-query-parameter GET per the PRD)
		// should grep API-0033 `application-readTraefikConfig`
		// for the query-shaped GET precedent — **not this
		// entry**, which is a flat-scalar-only POST mutation.
		// Future `*-create` peers in other tags should grep this
		// entry (or API-0292 / API-0338) for the every-optional-
		// populated mutation pattern.
		SampleBody: json.RawMessage(`{
			"authId": "bb-cov-create-0052-authId",
			"name": "yalla-coverage-bb-create-0052",
			"bitbucketId": "bb-cov-create-0052-bitbucketId",
			"bitbucketUsername": "bb-cov-create-0052-username",
			"bitbucketEmail": "bb-cov-create-0052@example.test",
			"appPassword": "bb-cov-create-0052-appPassword-fixture",
			"apiToken": "bb-cov-create-0052-apiToken-fixture",
			"bitbucketWorkspaceName": "bb-cov-create-0052-workspace",
			"gitProviderId": "bb-cov-create-0052-gitProviderId"
		}`),
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0053",
		OperationID: "bitbucket-getBitbucketBranches",
		Method:      http.MethodGet,
		Path:        "/bitbucket.getBitbucketBranches",
		Tag:         "bitbucket",
		// Third entry on the bitbucket/* coverage roster and the
		// **first GET-shaped query-bearing** operation in the
		// bitbucket/* tag — succeeds the parameter-free GET kickoff
		// at API-0051 `bitbucket-bitbucketProviders` and the
		// flat-scalar-only POST mutation at API-0052
		// `bitbucket-create`. Inherits the `bb-cov-*` per-tag
		// fixture-isolation namespace opened by API-0051's
		// design-rationale header and consumed by API-0052
		// (`bb-cov-create-*-0052`). Per the per-tag isolation rule
		// established at API-0246 `organization-active`, reasserted
		// at API-0290 `project-all`, API-0335 `server-all`, API-0351
		// `settings-assignDomainServer`, and re-asserted at API-0051's
		// bitbucket/* kickoff: this entry **must not** back-reference
		// the closed `admin-cov-*`, `ai-cov-*`, `app-cov-*`,
		// `backup-cov-*`, `compose-cov-*`, `deployment-cov-*`,
		// `org-cov-*`, `proj-cov-*`, `srv-cov-*`, or `set-cov-*`
		// namespaces, even though the nearest cross-tag
		// query-shaped GET precedents are API-0021 `application-one`,
		// API-0022 `application-readAppMonitoring`, and API-0023
		// `application-readTraefikConfig` (each carrying a single
		// required string param).
		//
		// **Spec re-verified per the API-0345..API-0364
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /bitbucket.getBitbucketBranches > get`: a **GET** with
		// **three query parameters** and **no request body**
		// (GETs in this OpenAPI document never carry a `requestBody`
		// field). Parameters per the spec:
		//   - REQUIRED scalars: `owner` (plain string), `repo`
		//     (plain string).
		//   - OPTIONAL scalar: `bitbucketId` (plain string).
		// All three are typed `string` with no `anyOf` /
		// `nullable` / enum constraints — the simplest query-shape
		// observed across the bitbucket/* tag and a structural
		// counterpoint to API-0035 `application-search`'s
		// 11-parameter optional-only fixture. Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the by-id retrieval pattern of API-0021
		// `application-one` and the platform-info getter cohort
		// (API-0363/0364/0365). The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer; the success-leg envelope assertion stays
		// focused on `data.method` / `data.status` rather than
		// payload projection.
		//
		// **Family choice — first query-bearing GET in
		// bitbucket/*.** Of the three remaining bitbucket/* GETs
		// (`getBitbucketBranches` 3 params, `getBitbucketRepositories`
		// 1 param, `one` 1 param), API-0053 ships the
		// **highest-arity** query shape first so the harness
		// proves multi-param query propagation through the
		// CLI → API client → httptest server path before the
		// single-param peers (API-0054, API-0055) lean on it.
		// This mirrors the application/* roster ordering precedent
		// where API-0021 `application-one` (single required param)
		// preceded API-0035 `application-search` (11 optional
		// params), but here the bitbucket/* PRD ordering forces
		// the inverse: high-arity first. Either ordering is
		// acceptable per the harness contract — `runAPICoverageSuccess`
		// re-reads `r.URL.Query()` and asserts every populated
		// `SampleQuery` key/value pair survives verbatim, so an
		// agent calling `yalla api call bitbucket-getBitbucketBranches
		// --input request.json --json` with all three params in the
		// `query` field gets deterministic forwarding. Future
		// bitbucket/* peers (API-0054 `getBitbucketRepositories`,
		// API-0055 `bitbucket-one`) must each re-verify their own
		// spec shapes per the API-0345..API-0364 forward-reference
		// lesson; the eleven-flip body-axis history of the
		// settings/* `clean*` sub-roster (API-0353..API-0362)
		// demonstrates why per-operation re-verification stays
		// mandatory across every family transition.
		//
		// Fixture conventions:
		//   * Per the API-0010 / API-0014 / API-0249 / API-0292 /
		//     API-0297 / API-0052 every-optional-populated rule,
		//     the optional `bitbucketId` is populated alongside
		//     the two required scalars so the wire query string
		//     exercises the entire envelope — not just the
		//     minimum-required `owner` + `repo` pair. The
		//     harness's success-leg `r.URL.Query()` round-trip
		//     observes this end-to-end through the
		//     CLI → API client → httptest server path.
		//   * Per-case fixture token base `bb-cov-getBranches-0053`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     and consumes the slot reserved by API-0052's
		//     design-rationale header (verified: no collisions
		//     with API-0051's `bb-cov-providers-0051` reservation,
		//     API-0052's `bb-cov-create-0052-*` literals, the
		//     forthcoming `bb-cov-getRepos-0054` /
		//     `bb-cov-one-0055` / `bb-cov-testConn-0056` /
		//     `bb-cov-update-0057` slugs reserved for upcoming
		//     bitbucket/* peers, and no collisions with the
		//     cross-tag `proj-cov-*` / `srv-cov-*` / `set-cov-*` /
		//     `org-cov-*` namespaces).
		//   * Deterministic-but-clearly-fake values (`-fixture`
		//     suffix on the optional `bitbucketId`) keep diffs
		//     readable and let any future schema validator's
		//     failure messages point at the offending field.
		//     `owner` / `repo` carry plain `<base>-<field>-0053`
		//     literals consistent with the API-0021..API-0023
		//     query-shaped GET precedent.
		SampleQuery: map[string][]string{
			"owner":       {"bb-cov-getBranches-0053-owner"},
			"repo":        {"bb-cov-getBranches-0053-repo"},
			"bitbucketId": {"bb-cov-getBranches-0053-bitbucketId-fixture"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at API-0246
		// `organization-active`, API-0290 `project-all`, API-0335
		// `server-all`, API-0351 `settings-assignDomainServer`,
		// and API-0051's bitbucket/* kickoff reserves
		// 404 → CodeNotFound for the canonical by-id peer
		// (here API-0055 `bitbucket-one`), not for fleet-wide
		// list-style getters like `getBitbucketBranches` (which
		// returns the branch catalogue keyed by repository, not
		// a single resource keyed by id). Auth is the universal
		// failure mode every Dokploy operation must re-prove, so
		// 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; this entry's three-string-param query
		// surface is too generic to claim that distinguishing
		// shape, so it uses the canonical 401, same as
		// API-0051's kickoff and API-0052's mutation.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0054",
		OperationID: "bitbucket-getBitbucketRepositories",
		Method:      http.MethodGet,
		Path:        "/bitbucket.getBitbucketRepositories",
		Tag:         "bitbucket",
		// Fourth entry on the bitbucket/* coverage roster and the
		// **first single-required-query-param GET** in the
		// bitbucket/* tag — succeeds the parameter-free GET kickoff
		// at API-0051 `bitbucket-bitbucketProviders`, the
		// flat-scalar-only POST mutation at API-0052
		// `bitbucket-create`, and the high-arity (3-param) GET at
		// API-0053 `bitbucket-getBitbucketBranches`. Inherits the
		// `bb-cov-*` per-tag fixture-isolation namespace opened by
		// API-0051's design-rationale header and consumed by
		// API-0052 (`bb-cov-create-*-0052`) and API-0053
		// (`bb-cov-getBranches-*-0053`). Per the per-tag isolation
		// rule established at API-0246 `organization-active`,
		// reasserted at API-0290 `project-all`, API-0335
		// `server-all`, API-0351 `settings-assignDomainServer`, and
		// re-asserted at API-0051's bitbucket/* kickoff: this
		// entry **must not** back-reference the closed
		// `admin-cov-*`, `ai-cov-*`, `app-cov-*`, `backup-cov-*`,
		// `compose-cov-*`, `deployment-cov-*`, `org-cov-*`,
		// `proj-cov-*`, `srv-cov-*`, or `set-cov-*` namespaces,
		// even though the nearest cross-tag single-required-query-
		// param GET precedents are API-0021 `application-one`,
		// API-0022 `application-readAppMonitoring`, and API-0023
		// `application-readTraefikConfig` (each carrying a single
		// required string param keyed by `applicationId`).
		//
		// **Spec re-verified per the API-0345..API-0364
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /bitbucket.getBitbucketRepositories > get`: a **GET**
		// with **one query parameter** and **no request body**
		// (GETs in this OpenAPI document never carry a
		// `requestBody` field). The single parameter per the spec:
		//   - REQUIRED scalar: `bitbucketId` (plain string).
		// Typed `string` with no `anyOf` / `nullable` / enum
		// constraints. **No optional siblings** — a structural
		// counterpoint to API-0053
		// `bitbucket-getBitbucketBranches`'s 2-required-plus-1-
		// optional shape, and to API-0035 `application-search`'s
		// 11-parameter optional-only fixture. Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the by-id-keyed retrieval pattern of API-0021
		// `application-one`. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer; the success-leg envelope assertion stays
		// focused on `data.method` / `data.status` rather than
		// payload projection.
		//
		// **Family choice — second query-bearing GET in
		// bitbucket/*, the simplest query shape.** The bitbucket/*
		// PRD ordering ships the **highest-arity** GET first
		// (API-0053, 3 params) and the **single-required-param**
		// GETs second (API-0054 here, API-0055 `bitbucket-one`
		// next). API-0053 already proved multi-param query
		// propagation through the CLI → API client → httptest
		// server path; this entry now proves the
		// minimum-required-only shape so the harness has both
		// extremes covered before API-0055 `bitbucket-one`
		// arrives with its own canonical-by-id wiring. Either
		// arrival ordering is acceptable per the harness contract
		// — `runAPICoverageSuccess` re-reads `r.URL.Query()` and
		// asserts every populated `SampleQuery` key/value pair
		// survives verbatim, so an agent calling
		// `yalla api call bitbucket-getBitbucketRepositories
		// --input request.json --json` with `bitbucketId` in the
		// `query` field gets deterministic forwarding. Future
		// bitbucket/* peers (API-0055 `bitbucket-one`, API-0056
		// `bitbucket-testConnection`, API-0057 `bitbucket-update`)
		// must each re-verify their own spec shapes per the
		// API-0345..API-0364 forward-reference lesson; the
		// eleven-flip body-axis history of the settings/* `clean*`
		// sub-roster (API-0353..API-0362) demonstrates why
		// per-operation re-verification stays mandatory across
		// every family transition.
		//
		// Fixture conventions:
		//   * Single required scalar — no every-optional-populated
		//     rule applies here because the spec declares no
		//     optional siblings. The minimum-required envelope IS
		//     the whole envelope. Contrast API-0053 (optional
		//     `bitbucketId` populated alongside the required
		//     `owner`/`repo` pair so the wire query string
		//     exercised the entire envelope); this entry's wire
		//     query string is exhaustive by virtue of the spec.
		//   * Per-case fixture token base `bb-cov-getRepos-0054`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     and consumes the slot reserved by API-0052's and
		//     API-0053's design-rationale headers (verified: no
		//     collisions with API-0051's `bb-cov-providers-0051`
		//     reservation, API-0052's `bb-cov-create-0052-*`
		//     literals, API-0053's `bb-cov-getBranches-0053-*`
		//     literals, the forthcoming `bb-cov-one-0055` /
		//     `bb-cov-testConn-0056` / `bb-cov-update-0057` slugs
		//     reserved for upcoming bitbucket/* peers, and no
		//     collisions with the cross-tag `proj-cov-*` /
		//     `srv-cov-*` / `set-cov-*` / `org-cov-*` namespaces).
		//   * Deterministic-but-clearly-fake value
		//     (`-fixture` suffix on `bitbucketId`) keeps diffs
		//     readable and lets any future schema validator's
		//     failure messages point at the offending field —
		//     consistent with the API-0021..API-0023
		//     query-shaped GET precedent and API-0053's optional
		//     `bitbucketId` literal.
		SampleQuery: map[string][]string{
			"bitbucketId": {"bb-cov-getRepos-0054-bitbucketId-fixture"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at API-0246
		// `organization-active`, API-0290 `project-all`, API-0335
		// `server-all`, API-0351 `settings-assignDomainServer`,
		// and API-0051's bitbucket/* kickoff reserves
		// 404 → CodeNotFound for the canonical by-id peer
		// (here API-0055 `bitbucket-one`), not for fleet-wide
		// list-style getters like `getBitbucketRepositories`
		// (which returns the repository catalogue scoped by
		// bitbucket integration id, not a single resource keyed
		// by id). Auth is the universal failure mode every
		// Dokploy operation must re-prove, so 401 → CodeAuth via
		// the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput
		// stays reserved for stories where payload validation is
		// the operation's distinguishing failure mode; this
		// entry's single-string-param query surface is too
		// generic to claim that distinguishing shape, so it uses
		// the canonical 401, same as API-0051's kickoff,
		// API-0052's mutation, and API-0053's high-arity GET.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0055",
		OperationID: "bitbucket-one",
		Method:      http.MethodGet,
		Path:        "/bitbucket.one",
		Tag:         "bitbucket",
		// Fifth entry on the bitbucket/* coverage roster and the
		// **canonical by-id GET** in the bitbucket/* tag — succeeds
		// the parameter-free GET kickoff at API-0051
		// `bitbucket-bitbucketProviders`, the flat-scalar-only POST
		// mutation at API-0052 `bitbucket-create`, the high-arity
		// (3-param) GET at API-0053 `bitbucket-getBitbucketBranches`,
		// and the single-required-query GET at API-0054
		// `bitbucket-getBitbucketRepositories`. Inherits the
		// `bb-cov-*` per-tag fixture-isolation namespace opened by
		// API-0051's design-rationale header and consumed by
		// API-0052..API-0054. Per the per-tag isolation rule
		// established at API-0246 `organization-active`, reasserted
		// at API-0290 `project-all`, API-0335 `server-all`, API-0351
		// `settings-assignDomainServer`, and re-asserted at
		// API-0051's bitbucket/* kickoff: this entry **must not**
		// back-reference the closed `admin-cov-*`, `ai-cov-*`,
		// `app-cov-*`, `backup-cov-*`, `compose-cov-*`,
		// `deployment-cov-*`, `org-cov-*`, `proj-cov-*`,
		// `srv-cov-*`, or `set-cov-*` namespaces.
		//
		// **Spec re-verified per the API-0345..API-0364
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /bitbucket.one > get`:
		// a **GET** with **one query parameter** and **no request
		// body** (GETs in this OpenAPI document never carry a
		// `requestBody` field). The single parameter per the spec:
		//   - REQUIRED scalar: `bitbucketId` (plain string).
		// Typed `string` with no `anyOf` / `nullable` / enum
		// constraints. **No optional siblings** — wire shape is
		// byte-for-byte identical to API-0054
		// `bitbucket-getBitbucketRepositories`'s
		// 1-required-string-query envelope. Responses
		// 200/400/401/403/404/500 — the **404 stays present** and
		// is the canonical semantic failure mode for a by-id
		// retrieval. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer; the success-leg envelope assertion stays
		// focused on `data.method` / `data.status` rather than
		// payload projection.
		//
		// **Family choice — canonical by-id GET, the 404 override
		// home in bitbucket/*.** API-0054's design-rationale
		// header explicitly reserved 404 → CodeNotFound for "the
		// canonical by-id peer (here API-0055 `bitbucket-one`),
		// not for fleet-wide list-style getters keyed by
		// integration id". This entry consumes that reservation —
		// the override mirrors the precedent set at API-0342
		// `server-one` (and reserved earlier at API-0290 /
		// API-0294 / API-0335 for the `*-one` shape across tags).
		// Future bitbucket/* peers (API-0056 `bitbucket-testConnection`,
		// API-0057 `bitbucket-update`) are mutating POSTs that
		// must each re-verify their own spec shapes per the
		// API-0345..API-0364 forward-reference lesson and revert
		// to the harness default 401 → CodeAuth (the eleven-flip
		// body-axis history of the settings/* `clean*` sub-roster
		// at API-0353..API-0362 is the standing reminder that
		// per-operation re-verification is mandatory).
		//
		// Fixture conventions:
		//   * Single required scalar — no every-optional-populated
		//     rule applies because the spec declares no optional
		//     siblings. The minimum-required envelope IS the whole
		//     envelope. Same shape as API-0054
		//     `bitbucket-getBitbucketRepositories`'s wire query
		//     string (each exhaustive by virtue of the spec).
		//   * Per-case fixture token base `bb-cov-one-0055` follows
		//     the `<tag>-cov-<slug>-<storyID>` convention and
		//     consumes the slot reserved by API-0052's, API-0053's,
		//     and API-0054's design-rationale headers (verified:
		//     no collisions with API-0051's `bb-cov-providers-0051`
		//     reservation, API-0052's `bb-cov-create-0052-*`
		//     literals, API-0053's `bb-cov-getBranches-0053-*`
		//     literals, API-0054's `bb-cov-getRepos-0054-*`
		//     literals, the forthcoming `bb-cov-testConn-0056` /
		//     `bb-cov-update-0057` slugs reserved for upcoming
		//     bitbucket/* peers, and no collisions with the
		//     cross-tag `proj-cov-*` / `srv-cov-*` / `set-cov-*` /
		//     `org-cov-*` namespaces).
		//   * Deterministic-but-clearly-fake value (`-fixture`
		//     suffix on `bitbucketId`) keeps diffs readable and
		//     lets any future schema validator's failure messages
		//     point at the offending field — consistent with the
		//     API-0021..API-0023 query-shaped GET precedent and
		//     API-0054's single-required-query literal.
		SampleQuery: map[string][]string{
			"bitbucketId": {"bb-cov-one-0055-bitbucketId-fixture"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
		// Failure-leg override: this is the canonical home for the
		// 404 → CodeNotFound representative-failure assertion
		// reserved at API-0054's design-rationale header for the
		// bitbucket/* by-id peer. Mirrors the API-0342
		// `server-one` 404-override precedent across tags. A
		// missing-resource by-id retrieval is the most informative
		// failure to exercise here; auth failures stay covered
		// fleet-wide by the cross-tag default 401 → CodeAuth path.
		FailureStatus: http.StatusNotFound,
		FailureCode:   yerr.CodeNotFound,
	},
	{
		StoryID:     "API-0056",
		OperationID: "bitbucket-testConnection",
		Method:      http.MethodPost,
		Path:        "/bitbucket.testConnection",
		Tag:         "bitbucket",
		// Sixth entry on the bitbucket/* coverage roster and the
		// **second mutation** in the bitbucket/* tag — succeeds the
		// parameter-free GET kickoff at API-0051
		// `bitbucket-bitbucketProviders`, the flat-scalar-only POST
		// mutation at API-0052 `bitbucket-create`, the high-arity
		// (3-param) GET at API-0053 `bitbucket-getBitbucketBranches`,
		// the single-required-query GET at API-0054
		// `bitbucket-getBitbucketRepositories`, and the canonical
		// by-id GET at API-0055 `bitbucket-one`. Inherits the
		// `bb-cov-*` per-tag fixture-isolation namespace opened by
		// API-0051's design-rationale header and consumed by
		// API-0052..API-0055. Per the per-tag isolation rule
		// established at API-0246 `organization-active`, reasserted
		// at API-0290 `project-all`, API-0335 `server-all`, API-0351
		// `settings-assignDomainServer`, and re-asserted at
		// API-0051's bitbucket/* kickoff: this entry **must not**
		// back-reference the closed `admin-cov-*`, `ai-cov-*`,
		// `app-cov-*`, `backup-cov-*`, `compose-cov-*`,
		// `deployment-cov-*`, `org-cov-*`, `proj-cov-*`,
		// `srv-cov-*`, or `set-cov-*` namespaces.
		//
		// **Spec re-verified per the API-0345..API-0364
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /bitbucket.testConnection
		// > post`: a **POST** with **no path/query parameters** and a
		// **required JSON request body**. The body schema fields per
		// the spec:
		//   - REQUIRED scalar: `bitbucketId` (plain string).
		//   - OPTIONAL scalars: `bitbucketUsername`,
		//     `bitbucketEmail`, `workspaceName`, `apiToken`,
		//     `appPassword` — all plain strings with no `anyOf` /
		//     `nullable` / enum constraints.
		// Note the field name is `workspaceName` here, **not**
		// `bitbucketWorkspaceName` as in API-0052 `bitbucket-create`
		// — a per-operation re-verification catch consistent with
		// the API-0353..API-0362 settings/* `clean*` body-axis
		// reminder (API-0055's design-rationale header) that
		// per-operation re-verification is mandatory and sibling
		// peers do **not** share request-body shape. Responses
		// 200/400/401/403/500 — **no 404** is declared because this
		// is a connection-probe, not a by-id retrieval; the
		// 404 → CodeNotFound representative-failure slot was
		// consumed at API-0055 `bitbucket-one`. The 200 schema is
		// `{}` with `additionalProperties: false`, matching every
		// prior covered peer; the success-leg envelope assertion
		// stays focused on `data.method` / `data.status` rather than
		// payload projection.
		//
		// **Family choice — connection-probe POST, harness-default
		// failure leg.** Per the forward-reference at API-0055's
		// design-rationale header, future bitbucket/* peers
		// (API-0056 `bitbucket-testConnection`, API-0057
		// `bitbucket-update`) "are mutating POSTs that must each
		// re-verify their own spec shapes per the API-0345..API-0364
		// forward-reference lesson and revert to the harness default
		// 401 → CodeAuth". This entry consumes that reservation —
		// 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""` →
		// CodeAuth) stays the most informative representative
		// failure for a connection-probe whose own 4xx vocabulary
		// (400 invalid input / 403 forbidden) is too generic to
		// claim a distinguishing failure shape. 400 →
		// CodeInvalidInput stays reserved for stories where payload
		// validation is the operation's distinguishing failure mode.
		// Future bitbucket/* peer API-0057 `bitbucket-update` is
		// expected to follow the same harness-default convention.
		//
		// Fixture conventions:
		//   * Every-optional-populated rule (API-0010 / API-0014 /
		//     API-0249 / API-0292 / API-0297 / API-0052 / API-0053):
		//     populate every optional sibling alongside the required
		//     `bitbucketId`. Same convention applied at API-0052
		//     `bitbucket-create` for the bitbucket/* tag's prior
		//     full-payload POST mutation.
		//   * Per-case fixture token base `bb-cov-testConn-0056`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     and consumes the slot reserved by API-0052's,
		//     API-0053's, API-0054's, and API-0055's design-rationale
		//     headers (verified: no collisions with API-0051's
		//     `bb-cov-providers-0051` reservation, API-0052's
		//     `bb-cov-create-0052-*` literals, API-0053's
		//     `bb-cov-getBranches-0053-*` literals, API-0054's
		//     `bb-cov-getRepos-0054-*` literals, API-0055's
		//     `bb-cov-one-0055-*` literals, the forthcoming
		//     `bb-cov-update-0057` slug reserved for the upcoming
		//     bitbucket/* peer, and no collisions with the
		//     cross-tag `proj-cov-*` / `srv-cov-*` / `set-cov-*` /
		//     `org-cov-*` namespaces).
		//   * Deterministic-but-clearly-fake values (`-fixture`
		//     suffixes on the credential-shaped `apiToken` /
		//     `appPassword` fields, `@example.test` literal on
		//     `bitbucketEmail`) keep diffs readable, exercise the
		//     output redactor's defence-in-depth path on
		//     credential-shaped strings even though the harness
		//     never wires real secrets, and let any future schema
		//     validator's failure messages point at the offending
		//     field — consistent with the API-0052
		//     `bitbucket-create` precedent.
		SampleBody: json.RawMessage(`{
			"bitbucketId": "bb-cov-testConn-0056-bitbucketId",
			"bitbucketUsername": "bb-cov-testConn-0056-username",
			"bitbucketEmail": "bb-cov-testConn-0056@example.test",
			"workspaceName": "bb-cov-testConn-0056-workspace",
			"apiToken": "bb-cov-testConn-0056-apiToken-fixture",
			"appPassword": "bb-cov-testConn-0056-appPassword-fixture"
		}`),
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0057",
		OperationID: "bitbucket-update",
		Method:      http.MethodPost,
		Path:        "/bitbucket.update",
		Tag:         "bitbucket",
		// Seventh and final entry on the bitbucket/* coverage
		// roster and the **third mutation** in the bitbucket/*
		// tag — closes the bitbucket/* arc opened at API-0051
		// `bitbucket-bitbucketProviders` (parameter-free GET
		// kickoff), continued through API-0052 `bitbucket-create`
		// (flat-scalar-only POST mutation), API-0053
		// `bitbucket-getBitbucketBranches` (3-param GET),
		// API-0054 `bitbucket-getBitbucketRepositories`
		// (single-required-query GET), API-0055 `bitbucket-one`
		// (canonical by-id GET → CodeNotFound representative
		// failure), and API-0056 `bitbucket-testConnection`
		// (connection-probe POST). Inherits the `bb-cov-*`
		// per-tag fixture-isolation namespace opened by
		// API-0051's design-rationale header and consumed by
		// API-0052..API-0056. Per the per-tag isolation rule
		// established at API-0246 `organization-active`,
		// reasserted at API-0290 `project-all`, API-0335
		// `server-all`, API-0351 `settings-assignDomainServer`,
		// and re-asserted at API-0051's bitbucket/* kickoff:
		// this entry **must not** back-reference the closed
		// `admin-cov-*`, `ai-cov-*`, `app-cov-*`, `backup-cov-*`,
		// `compose-cov-*`, `deployment-cov-*`, `org-cov-*`,
		// `proj-cov-*`, `srv-cov-*`, or `set-cov-*` namespaces.
		//
		// **Spec re-verified per the API-0345..API-0364
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /bitbucket.update >
		// post`: a **POST** with **no path/query parameters** and
		// a **required JSON request body**. The body schema
		// fields per the spec:
		//   - REQUIRED scalars: `bitbucketId`, `gitProviderId`,
		//     `name` (all plain strings).
		//   - OPTIONAL scalars: `bitbucketUsername`,
		//     `bitbucketEmail`, `appPassword`, `apiToken`,
		//     `bitbucketWorkspaceName`, `organizationId` — all
		//     plain strings with no `anyOf` / `nullable` / enum
		//     constraints.
		// Note the workspace field is `bitbucketWorkspaceName`
		// here (matching API-0052 `bitbucket-create`'s naming),
		// **not** `workspaceName` as in API-0056
		// `bitbucket-testConnection` — a per-operation
		// re-verification catch consistent with the
		// API-0353..API-0362 settings/* `clean*` body-axis
		// reminder (API-0055's design-rationale header) that
		// per-operation re-verification is mandatory and sibling
		// peers do **not** share request-body shape. The
		// required-triple `bitbucketId` + `gitProviderId` +
		// `name` is also distinct from API-0052's required-pair
		// `authId` + `name` (an *update* binds an existing
		// `bitbucketId` and `gitProviderId`, while *create*
		// allocates a fresh `bitbucketId` under an `authId`),
		// reinforcing the per-operation re-verification rule.
		// Responses 200/400/401/403/500 — **no 404** is declared
		// despite this being an update of an existing record;
		// the 404 → CodeNotFound representative-failure slot was
		// consumed at API-0055 `bitbucket-one` per the per-tag
		// isolation reservation. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer; the success-leg envelope assertion stays
		// focused on `data.method` / `data.status` rather than
		// payload projection.
		//
		// **Family choice — update POST, harness-default failure
		// leg.** Per the forward-reference at API-0056's
		// design-rationale header ("Future bitbucket/* peer
		// API-0057 `bitbucket-update` is expected to follow the
		// same harness-default convention"), this entry consumes
		// that reservation — 401 → CodeAuth via the harness
		// default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative failure for an update
		// mutation whose own 4xx vocabulary (400 invalid input /
		// 403 forbidden) is too generic to claim a
		// distinguishing failure shape. 400 → CodeInvalidInput
		// stays reserved for stories where payload validation is
		// the operation's distinguishing failure mode. This
		// entry closes the bitbucket/* tag's coverage arc; no
		// further bitbucket/* peers remain in the PRD, so no
		// forward-reference reservation is opened here.
		//
		// Fixture conventions:
		//   * Every-optional-populated rule (API-0010 / API-0014
		//     / API-0249 / API-0292 / API-0297 / API-0052 /
		//     API-0053 / API-0056): populate every optional
		//     sibling alongside the required triple. Same
		//     convention applied at API-0052 `bitbucket-create`
		//     and API-0056 `bitbucket-testConnection` for the
		//     bitbucket/* tag's prior full-payload POSTs.
		//   * Per-case fixture token base `bb-cov-update-0057`
		//     follows the `<tag>-cov-<slug>-<storyID>`
		//     convention and consumes the slot pre-reserved by
		//     API-0056 `bitbucket-testConnection`'s
		//     design-rationale header (verified: no collisions
		//     with API-0051's `bb-cov-providers-0051`
		//     reservation, API-0052's `bb-cov-create-0052-*`
		//     literals, API-0053's `bb-cov-getBranches-0053-*`
		//     literals, API-0054's `bb-cov-getRepos-0054-*`
		//     literals, API-0055's `bb-cov-one-0055-*` literals,
		//     API-0056's `bb-cov-testConn-0056-*` literals, and
		//     no collisions with the cross-tag `proj-cov-*` /
		//     `srv-cov-*` / `set-cov-*` / `org-cov-*`
		//     namespaces).
		//   * Deterministic-but-clearly-fake values (`-fixture`
		//     suffixes on the credential-shaped `apiToken` /
		//     `appPassword` fields, `@example.test` literal on
		//     `bitbucketEmail`) keep diffs readable, exercise
		//     the output redactor's defence-in-depth path on
		//     credential-shaped strings even though the harness
		//     never wires real secrets, and let any future
		//     schema validator's failure messages point at the
		//     offending field — consistent with the API-0052
		//     `bitbucket-create` and API-0056
		//     `bitbucket-testConnection` precedents.
		SampleBody: json.RawMessage(`{
			"bitbucketId": "bb-cov-update-0057-bitbucketId",
			"gitProviderId": "bb-cov-update-0057-gitProviderId",
			"name": "yalla-coverage-bb-update-0057",
			"bitbucketUsername": "bb-cov-update-0057-username",
			"bitbucketEmail": "bb-cov-update-0057@example.test",
			"appPassword": "bb-cov-update-0057-appPassword-fixture",
			"apiToken": "bb-cov-update-0057-apiToken-fixture",
			"bitbucketWorkspaceName": "bb-cov-update-0057-workspace",
			"organizationId": "bb-cov-update-0057-organizationId"
		}`),
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0058",
		OperationID: "certificates-all",
		Method:      http.MethodGet,
		Path:        "/certificates.all",
		Tag:         "certificates",
		// **Tag-arc opener for certificates/*.** API-0058 is
		// the first of four pending certificates/* peers in
		// the PRD priority list (API-0058 `certificates-all`,
		// API-0059 `certificates-create`, API-0060
		// `certificates-one`, API-0061 `certificates-remove`).
		// Per the per-tag fixture-isolation rule originally
		// established at API-0246 `organization-active`,
		// reasserted at API-0290 `project-all`, API-0335
		// `server-all`, API-0351
		// `settings-assignDomainServer`, and most recently at
		// API-0051 `bitbucket-bitbucketProviders`, this entry
		// opens a fresh `cert-cov-*` namespace — future
		// certificates/* peers (API-0059..API-0061) **must**
		// consume slugs of the form
		// `cert-cov-<slug>-<storyID>` (e.g.
		// `cert-cov-create-0059-*`, `cert-cov-one-0060-*`,
		// `cert-cov-remove-0061-*`) and **must not**
		// back-reference any closed `admin-cov-*`,
		// `ai-cov-*`, `app-cov-*`, `backup-cov-*`,
		// `bb-cov-*`, `compose-cov-*`, `deployment-cov-*`,
		// `org-cov-*`, `proj-cov-*`, `srv-cov-*`, or
		// `set-cov-*` namespace.
		//
		// **Spec re-verified per the API-0345..API-0364
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /certificates.all
		// > get`: a **GET** with **zero parameters** (no path
		// placeholders, no query string), **no requestBody**,
		// and a 200/400/401/403/404/500 response set. The 200
		// schema is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by
		// every prior covered list-style GET. Because no
		// parameters or body are declared, every case-level
		// `Sample*` field is intentionally omitted —
		// `buildCoverageInputArgs` returns an empty slice and
		// `yalla api call certificates-all --json` exercises
		// the no-input-flag path.
		//
		// **Family choice — list GET, harness-default failure
		// leg.** The 401 → CodeAuth representative-failure
		// slot is the canonical default for an authenticated
		// list-style read whose own 4xx vocabulary (400
		// invalid input, 403 forbidden, 404 not found) is too
		// generic to claim a distinguishing failure shape.
		// The 404 → CodeNotFound slot is *not* claimed
		// here — `certificates-all` is a list endpoint with
		// no addressable subject; the canonical 404 →
		// CodeNotFound representative-failure slot for the
		// certificates/* tag is reserved for the upcoming
		// API-0060 `certificates-one` entry (the canonical
		// by-id reader, mirroring API-0055 `bitbucket-one`'s
		// claim of that slot in the bitbucket/* tag arc).
		// Future contributor on API-0060 should consume that
		// reservation by setting `FailureStatus:
		// http.StatusNotFound` and `FailureCode:
		// yerr.CodeNotFound` on the API-0060 case literal —
		// per-operation re-verification against
		// `/certificates.one > get` is still mandatory before
		// inheriting from this entry. API-0059
		// `certificates-create` and API-0061
		// `certificates-remove` are mutating POSTs and are
		// expected to follow the harness-default 401 →
		// CodeAuth slot, but that prediction must also be
		// re-verified per-operation against the spec rather
		// than inherited.
		//
		// Fixture conventions: parameter-free, body-free GETs
		// require no `Sample*` fields and no per-case fixture
		// token — the `cert-cov-*` namespace is opened here
		// nominally but no literals are consumed. Defaulting
		// to 200 / `{}` for success and 401 → CodeAuth for
		// failure keeps this entry maximally terse, mirroring
		// the minimal-literal pattern established by
		// API-0378/API-0379 and most recently consumed by
		// API-0383 `settings-reloadRedis`.
	},
	{
		StoryID:     "API-0059",
		OperationID: "certificates-create",
		Method:      http.MethodPost,
		Path:        "/certificates.create",
		Tag:         "certificates",
		// Second entry on the certificates/* coverage roster,
		// inheriting the `cert-cov-*` per-tag fixture-isolation
		// namespace opened by API-0058 `certificates-all`. Per
		// the per-tag isolation rule originally established at
		// API-0246 `organization-active`, reasserted at
		// API-0290 `project-all`, API-0335 `server-all`,
		// API-0351 `settings-assignDomainServer`, and most
		// recently at API-0051 `bitbucket-bitbucketProviders`,
		// this entry **must not** back-reference any closed
		// `admin-cov-*`, `ai-cov-*`, `app-cov-*`, `backup-cov-*`,
		// `bb-cov-*`, `compose-cov-*`, `deployment-cov-*`,
		// `org-cov-*`, `proj-cov-*`, `srv-cov-*`, or
		// `set-cov-*` namespace.
		//
		// **Spec re-verified per the API-0345..API-0383
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /certificates.create
		// > post`: a **POST** with **zero parameters** (no path,
		// no query, no header) and a **required JSON request
		// body**. The body schema fields per the spec:
		//   - REQUIRED scalars: `name`, `certificateData`,
		//     `privateKey`, `organizationId` (all plain strings).
		//   - OPTIONAL scalars: `certificateId`,
		//     `certificatePath` (plain strings, no `anyOf` /
		//     `nullable`).
		//   - OPTIONAL `anyOf [boolean, null]`: `autoRenew` —
		//     populated as a boolean literal `true` to exercise
		//     the non-null branch (the harness's JSON
		//     round-trip preserves both branches; the boolean
		//     branch keeps the fixture deterministic and avoids
		//     the dedicated `null` path that would shadow a
		//     "field absent" representation).
		//   - OPTIONAL `anyOf [string, null]`: `serverId` —
		//     populated as a plain string literal to exercise
		//     the non-null branch, matching how prior covered
		//     `serverId`-bearing operations (e.g.
		//     `application-readTraefikConfig`,
		//     `settings-reloadTraefik`-style optional scoping)
		//     have handled the same axis.
		// Responses 200/400/401/403/500 — **no 404** is
		// declared, matching the canonical mutation response
		// set already exercised by every prior `*-create` peer
		// (API-0002 `ai-create`, API-0040 `backup-create`,
		// API-0052 `bitbucket-create`, API-0292 `project-create`,
		// API-0338 `server-create`). Per the per-tag opener
		// convention reasserted at API-0058's certificates/*
		// design header, 404 → CodeNotFound stays reserved for
		// the canonical by-id peer API-0060 `certificates-one`,
		// not for this create mutation. The 200 schema is `{}`
		// with `additionalProperties: false`, matching every
		// prior covered peer; the success-leg envelope assertion
		// stays focused on `data.method` / `data.status` rather
		// than payload projection.
		//
		// **Family choice — create POST, harness-default failure
		// leg.** Per the forward-reference at API-0058's
		// design-rationale header ("API-0059 `certificates-create`
		// and API-0061 `certificates-remove` are mutating POSTs
		// and are expected to follow the harness-default 401 →
		// CodeAuth slot"), this entry consumes that reservation
		// — 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative
		// failure for a create mutation whose own 4xx vocabulary
		// (400 invalid input / 403 forbidden) is too generic to
		// claim a distinguishing failure shape. 400 →
		// CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode.
		//
		// Fixture conventions:
		//   * Every-optional-populated rule (API-0010 / API-0014
		//     / API-0249 / API-0292 / API-0297 / API-0052 /
		//     API-0053 / API-0056 / API-0057): populate every
		//     optional sibling alongside the required quartet.
		//     The `autoRenew` boolean and the nullable
		//     `serverId` string both exercise their non-null
		//     branches so the JSON round-trip covers the
		//     populated path; future contributors who want to
		//     exercise the `null` branch should add a dedicated
		//     case rather than mutate this one (the per-case
		//     fixture pattern keeps each leg independently
		//     debuggable).
		//   * Per-case fixture token base
		//     `cert-cov-create-0059` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and consumes the slot
		//     pre-reserved by API-0058's design-rationale header
		//     (verified: no collisions with the cross-tag
		//     `bb-cov-*`, `proj-cov-*`, `srv-cov-*`,
		//     `set-cov-*`, `org-cov-*`, etc. namespaces, and no
		//     collisions inside the `cert-cov-*` namespace
		//     opened nominally by API-0058).
		//   * `certificateData` and `privateKey` carry
		//     deterministic fixture literals (no real PEM
		//     payload) — the harness never wires real secrets
		//     and the output redactor's defence-in-depth path
		//     scrubs credential-shaped substrings regardless.
		//     Keeping the fixture body string-only (rather than
		//     pasting a fake PEM block) keeps diffs readable and
		//     avoids any risk of the literal being mistaken for
		//     real key material.
		//
		// Future contributor on API-0060 `certificates-one`
		// should consume the 404 → CodeNotFound representative-
		// failure slot reserved at API-0058 (the canonical by-id
		// reader for the certificates/* tag arc, mirroring
		// API-0055 `bitbucket-one`'s claim of that slot in the
		// bitbucket/* tag arc). Per-operation re-verification
		// against `/certificates.one > get` is mandatory before
		// inheriting the reservation — preliminary spec
		// inspection at hand-off time shows API-0060 declares a
		// single required `certificateId` query parameter, which
		// the contributor must materialise as a `SamplePathParams`
		// or `SampleQuery` literal (the operationId convention
		// across Dokploy is `query`, but the field axis must
		// still be re-verified per the API-0053 / API-0054 /
		// API-0055 precedent on `/bitbucket.*` `*-one` peers).
		// API-0061 `certificates-remove` (POST) is then expected
		// to follow the harness-default 401 → CodeAuth slot per
		// the create/remove mutation cohort.
		SampleBody: json.RawMessage(`{
			"name": "yalla-coverage-cert-create-0059",
			"certificateData": "cert-cov-create-0059-certificateData",
			"privateKey": "cert-cov-create-0059-privateKey-fixture",
			"organizationId": "cert-cov-create-0059-organizationId",
			"certificateId": "cert-cov-create-0059-certificateId",
			"certificatePath": "cert-cov-create-0059-certificatePath",
			"autoRenew": true,
			"serverId": "cert-cov-create-0059-serverId"
		}`),
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0060",
		OperationID: "certificates-one",
		Method:      http.MethodGet,
		Path:        "/certificates.one",
		Tag:         "certificates",
		// Third entry on the certificates/* coverage roster and the
		// **canonical by-id GET** in the certificates/* tag —
		// succeeds the parameter-free list-style GET kickoff at
		// API-0058 `certificates-all` and the flat-scalar-only POST
		// mutation at API-0059 `certificates-create`. Inherits the
		// `cert-cov-*` per-tag fixture-isolation namespace opened
		// by API-0058's design-rationale header and consumed by
		// API-0059. Per the per-tag isolation rule originally
		// established at API-0246 `organization-active`, reasserted
		// at API-0290 `project-all`, API-0335 `server-all`, API-0351
		// `settings-assignDomainServer`, API-0051
		// `bitbucket-bitbucketProviders`, and most recently at
		// API-0058 `certificates-all`, this entry **must not**
		// back-reference any closed `admin-cov-*`, `ai-cov-*`,
		// `app-cov-*`, `backup-cov-*`, `bb-cov-*`, `compose-cov-*`,
		// `deployment-cov-*`, `org-cov-*`, `proj-cov-*`,
		// `srv-cov-*`, or `set-cov-*` namespace.
		//
		// **Spec re-verified per the API-0345..API-0383
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /certificates.one > get`:
		// a **GET** with **one query parameter** and **no request
		// body** (GETs in this OpenAPI document never carry a
		// `requestBody` field). The single parameter per the spec:
		//   - REQUIRED scalar: `certificateId` (plain string,
		//     `in: query`).
		// Typed `string` with no `anyOf` / `nullable` / enum
		// constraints. **No optional siblings** — wire shape is
		// byte-for-byte identical to API-0055 `bitbucket-one`'s
		// 1-required-string-query envelope. Responses
		// 200/400/401/403/404/500 — the **404 stays present** and
		// is the canonical semantic failure mode for a by-id
		// retrieval. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer; the success-leg envelope assertion stays
		// focused on `data.method` / `data.status` rather than
		// payload projection.
		//
		// **Family choice — canonical by-id GET, the 404 override
		// home in certificates/*.** API-0058's design-rationale
		// header explicitly reserved 404 → CodeNotFound for "the
		// upcoming API-0060 `certificates-one` entry (the
		// canonical by-id reader, mirroring API-0055
		// `bitbucket-one`'s claim of that slot in the bitbucket/*
		// tag arc)". This entry consumes that reservation — the
		// override mirrors the precedent set at API-0055
		// `bitbucket-one` (and reserved earlier at API-0342
		// `server-one`) so a missing-resource by-id retrieval
		// surfaces the most informative typed error. Auth failures
		// stay covered fleet-wide by the cross-tag default 401 →
		// CodeAuth path. 400 → CodeInvalidInput stays reserved for
		// stories where payload validation is the operation's
		// distinguishing failure mode; this entry's
		// single-required-string-query surface is too generic to
		// claim that distinguishing shape.
		//
		// The remaining certificates/* peer (API-0061
		// `certificates-remove`) is a mutating POST that must
		// re-verify its own spec shape per the API-0345..API-0383
		// forward-reference lesson and is expected to revert to
		// the harness default 401 → CodeAuth (the eleven-flip
		// body-axis history of the settings/* `clean*` sub-roster
		// at API-0353..API-0362 is the standing reminder that
		// per-operation re-verification is mandatory).
		//
		// Fixture conventions:
		//   * Single required scalar — no every-optional-populated
		//     rule applies because the spec declares no optional
		//     siblings. The minimum-required envelope IS the whole
		//     envelope. Same shape as API-0055 `bitbucket-one`'s
		//     wire query string (each exhaustive by virtue of the
		//     spec).
		//   * Per-case fixture token base `cert-cov-one-0060`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     and consumes a fresh slug within the `cert-cov-*`
		//     namespace opened at API-0058 (no back-references
		//     into closed cross-tag `proj-cov-*` / `srv-cov-*` /
		//     `set-cov-*` / `org-cov-*` / `bb-cov-*` namespaces).
		//   * Deterministic-but-clearly-fake value (`-fixture`
		//     suffix on `certificateId`) keeps diffs readable and
		//     lets any future schema validator's failure messages
		//     point at the offending field — consistent with the
		//     API-0021..API-0023 query-shaped GET precedent and
		//     API-0055's single-required-query literal.
		SampleQuery: map[string][]string{
			"certificateId": {"cert-cov-one-0060-certificateId-fixture"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
		// Failure-leg override: this is the canonical home for the
		// 404 → CodeNotFound representative-failure assertion
		// reserved at API-0058's design-rationale header for the
		// certificates/* by-id peer. Mirrors the API-0055
		// `bitbucket-one` and API-0342 `server-one` 404-override
		// precedent across tags. A missing-resource by-id
		// retrieval is the most informative failure to exercise
		// here; auth failures stay covered fleet-wide by the
		// cross-tag default 401 → CodeAuth path.
		FailureStatus: http.StatusNotFound,
		FailureCode:   yerr.CodeNotFound,
	},
	{
		StoryID:     "API-0061",
		OperationID: "certificates-remove",
		Method:      http.MethodPost,
		Path:        "/certificates.remove",
		Tag:         "certificates",
		// Fourth and final entry on the certificates/* coverage
		// roster — the **mutating-by-id POST** that closes out the
		// certificates/* tag arc opened by API-0058
		// `certificates-all` (parameter-free list-style GET),
		// continued by API-0059 `certificates-create` (the create
		// mutation peer) and API-0060 `certificates-one` (the
		// canonical by-id reader that consumed the 404 →
		// CodeNotFound override slot reserved at API-0058's
		// design-rationale header). Inherits the `cert-cov-*`
		// per-tag fixture-isolation namespace opened by API-0058
		// and previously consumed by `cert-cov-create-0059`
		// (API-0059) and `cert-cov-one-0060` (API-0060). Per the
		// per-tag isolation rule originally established at API-0246
		// `organization-active`, reasserted at API-0290
		// `project-all`, API-0335 `server-all`, API-0351
		// `settings-assignDomainServer`, API-0051
		// `bitbucket-bitbucketProviders`, and most recently at
		// API-0058 `certificates-all`, this entry **must not**
		// back-reference any closed `admin-cov-*`, `ai-cov-*`,
		// `app-cov-*`, `backup-cov-*`, `bb-cov-*`, `compose-cov-*`,
		// `deployment-cov-*`, `org-cov-*`, `proj-cov-*`,
		// `srv-cov-*`, or `set-cov-*` namespace.
		//
		// **Spec re-verified per the API-0345..API-0383
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /certificates.remove >
		// post`: a **POST** with **zero parameters** (no path, no
		// query, no header) and a **required JSON request body**.
		// The body schema fields per the spec:
		//   - REQUIRED scalar: `certificateId` (plain string, no
		//     `anyOf` / `nullable` / enum constraints).
		//   - **No optional siblings.** The wire shape is byte-for-
		//     byte identical to API-0066 `compose-cancelDeployment`'s
		//     single-required-string-body POST envelope (composeId →
		//     certificateId rename), and to every other minimal-id
		//     POST mutation already covered fleet-wide.
		// Responses 200/400/401/403/500 — **no 404** is declared,
		// matching the canonical mutation response set already
		// exercised by every prior `*-remove` peer (e.g. API-0044
		// `backup-remove`, API-0054 `bitbucket-remove`, API-0298
		// `project-remove`, API-0344 `server-remove`). Per the
		// forward-reference at API-0058's design-rationale header
		// ("API-0061 `certificates-remove` is a mutating POST and
		// is expected to revert to the harness default 401 →
		// CodeAuth"), 404 → CodeNotFound stayed reserved for and
		// was consumed by API-0060 `certificates-one`, the
		// canonical by-id reader, not by this delete mutation. The
		// 200 schema is `{}` with `additionalProperties: false`,
		// matching every prior covered peer; the success-leg
		// envelope assertion stays focused on `data.method` /
		// `data.status` rather than payload projection.
		//
		// **Family choice — remove POST, harness-default failure
		// leg.** Per the forward-reference at API-0058's
		// design-rationale header (re-stated at API-0059's
		// hand-off note: "API-0061 `certificates-remove` (POST) is
		// then expected to follow the harness-default 401 →
		// CodeAuth slot per the create/remove mutation cohort"),
		// this entry consumes that reservation — 401 → CodeAuth
		// via the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative failure for a delete mutation
		// whose own 4xx vocabulary (400 invalid input / 403
		// forbidden) is too generic to claim a distinguishing
		// failure shape, and whose spec does not declare 404 (so
		// an "id not found" failure is not even a contract
		// response on this operation). 400 → CodeInvalidInput
		// stays reserved for stories where payload validation is
		// the operation's distinguishing failure mode; this
		// entry's single-required-string-body surface is too
		// generic to claim that distinguishing shape.
		//
		// **Tag-arc closer.** With API-0061 the certificates/* tag
		// is fully covered (4/4 entries: API-0058 list-all GET,
		// API-0059 create POST, API-0060 by-id GET, API-0061
		// by-id remove POST). The next priority-3 tag in the PRD
		// roster (cluster/*) opens a fresh `clu-cov-*` namespace
		// and **must not** back-reference the now-closed
		// `cert-cov-*` namespace per the per-tag isolation rule.
		//
		// Fixture conventions:
		//   * Single required scalar — no every-optional-populated
		//     rule applies because the spec declares no optional
		//     siblings. The minimum-required envelope IS the whole
		//     envelope. Same shape as API-0066
		//     `compose-cancelDeployment`'s single-required-string-
		//     body POST (and every other minimal-id POST mutation).
		//   * Per-case fixture token base `cert-cov-remove-0061`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     shared across every per-tag roster and consumes a
		//     fresh slug within the `cert-cov-*` namespace opened
		//     at API-0058 (verified: no collisions with
		//     `cert-cov-create-0059` (API-0059) or
		//     `cert-cov-one-0060` (API-0060), and no
		//     back-references into closed cross-tag `bb-cov-*` /
		//     `proj-cov-*` / `srv-cov-*` / `set-cov-*` /
		//     `org-cov-*` namespaces).
		//   * Deterministic-but-clearly-fake value (`-fixture`
		//     suffix on `certificateId`) keeps diffs readable and
		//     lets any future schema validator's failure messages
		//     point at the offending field — consistent with
		//     API-0060 `certificates-one`'s sibling fixture style
		//     and the API-0021..API-0023 query-shaped GET
		//     precedent.
		SampleBody: json.RawMessage(`{
			"certificateId": "cert-cov-remove-0061-certificateId-fixture"
		}`),
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer. Empty-object body keeps the success-leg
		// envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0062",
		OperationID: "cluster-addManager",
		Method:      http.MethodGet,
		Path:        "/cluster.addManager",
		Tag:         "cluster",
		// **Tag-arc opener for cluster/***. Opens a fresh
		// `clu-cov-*` per-tag fixture-isolation namespace per the
		// per-tag isolation rule originally established at
		// API-0246 `organization-active`, reasserted at API-0290
		// `project-all`, API-0335 `server-all`, API-0351
		// `settings-assignDomainServer`, API-0051
		// `bitbucket-bitbucketProviders`, and most recently at
		// API-0058 `certificates-all` (and closed at API-0061
		// `certificates-remove`'s hand-off note: "The next
		// priority-3 tag in the PRD roster (cluster/*) opens a
		// fresh `clu-cov-*` namespace and **must not** back-
		// reference the now-closed `cert-cov-*` namespace per the
		// per-tag isolation rule"). This entry consumes that
		// reservation and **must not** back-reference any closed
		// `admin-cov-*`, `ai-cov-*`, `app-cov-*`, `backup-cov-*`,
		// `bb-cov-*`, `cert-cov-*`, `compose-cov-*`,
		// `deployment-cov-*`, `org-cov-*`, `proj-cov-*`,
		// `srv-cov-*`, or `set-cov-*` namespace.
		//
		// **Spec re-verified per the API-0345..API-0385
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /cluster.addManager >
		// get`: a **GET** with **one optional query parameter**
		// `serverId` (plain string, no `required` flag) and **no
		// request body**. Responses 200/400/401/403/404/500 — note
		// the **presence of 404**, structurally distinct from the
		// no-404 mutation cohort exercised by the certificates/*
		// closer at API-0061. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer in the empty-success cohort.
		//
		// **Shape positioning — query-only GET with optional
		// param.** Structurally adjacent to API-0007
		// `ai-getModels` (query-only GET with required params)
		// and API-0005/0008 `ai-get`/`ai-one` (single-required-
		// query GETs), but uniquely **the first covered GET with
		// an OPTIONAL query parameter** rather than a required
		// one. The harness still forwards `SampleQuery` via the
		// `--input` JSON `query` field, and
		// `runAPICoverageSuccess` re-reads `r.URL.Query()` to
		// confirm the CLI propagated the `serverId` value
		// verbatim. Populating the optional param exercises the
		// query-forwarding branch on the wire — leaving it unset
		// would degrade this case to the parameter-free GET
		// cohort (API-0006 `ai-getAll` shape) and lose the
		// query-forwarding round-trip assertion that
		// distinguishes this shape from a no-input GET. Mirrors
		// the API-0385 `settings-reloadTraefik` precedent for
		// optional-input operations: populate the optional axis
		// to keep the wire assertion meaningful.
		//
		// **Family choice — tag-opener, harness-default failure
		// leg.** Per the per-tag opener convention (e.g.
		// API-0058 `certificates-all` opened certificates/* with
		// the harness default 401 → CodeAuth and reserved 404 →
		// CodeNotFound for its by-id `*-one` peer), this entry
		// uses the harness default 401 → CodeAuth
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) and **reserves 404 → CodeNotFound** for a
		// later cluster/* peer where the not-found shape is more
		// canonical. The remaining cluster/* roster per the PRD
		// is API-0063 `cluster-addWorker` (GET, optional serverId,
		// 404 declared), API-0064 `cluster-getNodes` (GET,
		// optional serverId, 404 declared — the most read-shaped
		// peer and natural 404 → CodeNotFound consumer), and
		// API-0065 `cluster-removeWorker` (POST, required body,
		// **no 404** declared). Per the slug-prefix-is-not-shape
		// lesson reasserted across API-0371..API-0385, the next
		// contributor must re-verify per-operation rather than
		// inherit any axis from this entry — both `addManager`
		// and `addWorker` are GETs that share the parameter axis,
		// but neither implies `removeWorker`'s POST body shape or
		// `getNodes`'s read-leg payload projection. 400 →
		// CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; an optional-only query GET has too narrow
		// a validator surface to claim that shape.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `clu-cov-addManager-0062` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique within
		//     the freshly-opened `clu-cov-*` namespace (verified
		//     orthogonal to every prior tag's `cert-cov-*`,
		//     `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		//     `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		//     `bb-cov-*`, `set-cov-*`, `admin-cov-*`,
		//     `backup-cov-*`, `deployment-cov-*` namespaces).
		//   * `serverId` carries the fixture-shaped literal
		//     `clu-cov-addManager-0062` rather than a real UUID
		//     so the wire payload cannot be mistaken for a real
		//     production server identifier and any future schema
		//     validator's failure messages point at the offending
		//     field.
		SampleQuery: map[string][]string{
			"serverId": {"clu-cov-addManager-0062"},
		},
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
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
	{
		StoryID:     "API-0292",
		OperationID: "project-create",
		Method:      http.MethodPost,
		Path:        "/project.create",
		Tag:         "project",
		// First mutation in the project/* roster and the first
		// required-body POST after the API-0290 / API-0291 pair of
		// parameter-free GETs that opened the tag arc. This entry
		// is also the first project/* peer to populate `SampleBody`
		// and therefore *opens the `proj-cov-*` slug namespace*
		// reserved by API-0290's design-rationale header — every
		// subsequent project/* mutation (API-0293 `*-duplicate`,
		// API-0295 `*-remove`, API-0297 `*-update`) and filter-
		// shaped peer (API-0294 `*-one`, API-0296 `*-search`) must
		// grep this block first when shaping their fixture tokens
		// and **must not** back-reference the organization/*
		// `org-cov-*` literals, per the per-tag fixture-isolation
		// rule established at API-0290.
		//
		// Spec source `internal/api/data/openapi.json >
		// /project.create > post`: zero parameters, required
		// `application/json` request body whose schema declares
		// three top-level fields — `name` (required string),
		// `description` (optional, `anyOf [string, null]`), and
		// `env` (optional string). `name` is the only required
		// scalar; the closed-shape pair `{description, env}` is
		// the optional surface. Per the API-0010 / API-0014 /
		// API-0249 every-optional-populated convention adopted
		// across the ai/*, application/*, and organization/*
		// mutation rosters, we supply all three fields with
		// deterministic-but-clearly-fake values so the wire
		// payload exercises the entire envelope (not just the
		// minimum-required `name`) and the success-leg JSON
		// forwarding assertion exercises array-free-but-non-
		// trivial shape projection. Per-case fixture token
		// `proj-cov-create-0292` keeps `git grep` traceable to
		// this PRD story and is unique across the project/*
		// roster (verified: no collisions with future
		// `*-duplicate-0293` / `*-one-0294` / `*-remove-0295` /
		// `*-search-0296` / `*-update-0297` slugs).
		//
		// Responses 200/400/401/403/500 mirror the rest of the
		// project/* tag — the 200 schema is `{}` with
		// `additionalProperties: false`, identical to API-0290 /
		// API-0291 above and to every ai/*, application/*, and
		// organization/* mutation peer; the success-leg envelope
		// assertion therefore stays focused on `data.method` /
		// `data.status` rather than payload projection. The
		// representative-failure leg keeps the harness default
		// (401 → CodeAuth) because auth is the universal failure
		// mode every project/* peer must re-prove — 400
		// (validation) is exercised once at the package level by
		// the API-0001 entry rather than re-asserted on every
		// minimum-required-body POST in the roster, and 404 is
		// still reserved for the filter-shaped peer API-0294
		// `project-one`.
		//
		// Future contributors picking up the next mutation in the
		// arc (API-0293 `project-duplicate`, expected to be a
		// `{projectId, name}` two-required-scalar POST in the
		// shape API-0255 `organization-updateMemberRole` exercises
		// in the prior tag) should grep this entry first when
		// shaping their `SampleBody` — every successor is a one-
		// or two-field POST that can copy this closed-shape
		// `{name, description, env}` literal pattern verbatim with
		// the field names swapped, and the comment header above
		// keeps the design rationale (every-optional-populated,
		// per-case fixture token, default 401 failure leg)
		// discoverable without re-deriving it from API-0010 /
		// API-0014 / API-0249.
		SampleBody: json.RawMessage(`{
			"name": "yalla-coverage-proj-create-0292",
			"description": "yalla coverage fixture for proj-cov-create-0292 — deterministic, fake, never deployed",
			"env": "PROJ_COV_CREATE_0292=fixture\nYALLA_COVERAGE_STORY=API-0292"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior project/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0293",
		OperationID: "project-duplicate",
		Method:      http.MethodPost,
		Path:        "/project.duplicate",
		Tag:         "project",
		// Second mutation in the project/* roster after API-0292
		// `project-create` opened the `proj-cov-*` slug namespace.
		// Per the per-tag fixture-isolation rule established at
		// API-0290 and re-affirmed at API-0292, this entry stays
		// inside the `proj-cov-*` namespace and **must not** back-
		// reference the organization/* `org-cov-*` literals — even
		// though API-0255 `organization-updateMemberRole` was the
		// nearest two-required-scalar precedent in the prior tag.
		//
		// Spec source `internal/api/data/openapi.json >
		// /project.duplicate > post`: zero parameters, required
		// `application/json` request body whose schema declares six
		// top-level fields:
		//   - REQUIRED scalars: `sourceEnvironmentId` (string),
		//     `name` (string).
		//   - OPTIONAL scalar: `description` (plain string — note
		//     this peer does NOT declare `anyOf [string, null]`,
		//     unlike API-0292 `project-create`'s `description`).
		//   - OPTIONAL boolean (default `true`): `includeServices`.
		//   - OPTIONAL boolean (default `false`):
		//     `duplicateInSameProject`.
		//   - OPTIONAL array-of-objects: `selectedServices`, where
		//     each element is `{id (string, required), type
		//     (enum, required)}` with `type` pinned to one of
		//     `application | postgres | mariadb | mongo | mysql |
		//     redis | compose`.
		// This is the first project/* peer with a nested array-of-
		// objects body shape (the prior project/* mutation
		// API-0292 was a flat scalar-only body), so it is the
		// roster's first opportunity to exercise the same nested-
		// array contract API-0004 `ai-deploy` opened in the ai/*
		// roster (which used `domains: [{host, port, serviceName}]`
		// and `configFiles: [{filePath, content}]`).
		//
		// Fixture conventions:
		//   * Per the API-0010 / API-0014 / API-0249 / API-0292
		//     every-optional-populated rule, all four optionals are
		//     populated with deterministic-but-clearly-fake values
		//     so the wire payload exercises the entire envelope —
		//     not just the minimum-required `sourceEnvironmentId`
		//     + `name`.
		//   * The two booleans are flipped to the inverse of their
		//     spec-declared defaults (`includeServices: false`,
		//     `duplicateInSameProject: true`) so the success-leg
		//     wire forwarding actually transmits the chosen value
		//     rather than relying on a server-side default that
		//     would round-trip the same bytes regardless of CLI
		//     behaviour. This keeps the body forwarding invariant
		//     observable end-to-end through the CLI → API client →
		//     httptest server path.
		//   * `selectedServices` carries one element with
		//     `type: "application"` enum-pinned (per the API-0255
		//     enum-constrained-scalar rule: the alternate values
		//     `postgres | mariadb | mongo | mysql | redis | compose`
		//     are intentionally not duplicated to keep the
		//     success-leg byte forwarding deterministic). The `id`
		//     scalar follows the `<tag>-cov-<slug>-<storyID>` token
		//     namespace as `app-cov-duplicate-0293-svc1`.
		//   * Per-case fixture token base `proj-cov-duplicate-0293`
		//     keeps `git grep` traceable to this PRD story and is
		//     unique across the project/* roster (verified: no
		//     collisions with API-0292 `proj-cov-create-0292`,
		//     future API-0294 `*-one-0294`, API-0295 `*-remove-
		//     0295`, API-0296 `*-search-0296`, API-0297
		//     `*-update-0297` slugs, nor with the organization/*
		//     `org-cov-*` namespace).
		//
		// Responses 200/400/401/403/500 mirror API-0292
		// `project-create` (note: 404 is not declared on
		// `/project.duplicate`, which differs from the GET-shaped
		// API-0290 / API-0291 peers and matches the mutation peer
		// API-0292 — 404 in the project/* tag is reserved for the
		// filter-shaped peer API-0294 `project-one`). The 200
		// schema is `{}` with `additionalProperties: false`, so the
		// success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload
		// projection. The representative-failure leg keeps the
		// harness default (401 → CodeAuth) because auth is the
		// universal failure mode every project/* peer must re-prove.
		//
		// Future contributors picking up the next mutation in the
		// arc (API-0294 `project-one`, expected to be the first
		// filter-shaped GET in the project/* tag and the legitimate
		// home for a 404 → CodeNotFound representative-failure leg
		// per the API-0290 / API-0291 / API-0292 reservation)
		// should grep this entry first when shaping their fixture
		// — but only the slug-namespace and per-case-token
		// conventions transfer; the body shape will diverge
		// (project-one is a query-parameter GET with no
		// `SampleBody`, so this nested-array literal is project/*-
		// internal only and must not be re-templated for it).
		SampleBody: json.RawMessage(`{
			"sourceEnvironmentId": "env-cov-proj-duplicate-0293",
			"name": "yalla-coverage-proj-duplicate-0293",
			"description": "yalla coverage fixture for proj-cov-duplicate-0293 — deterministic, fake, never deployed",
			"includeServices": false,
			"duplicateInSameProject": true,
			"selectedServices": [
				{
					"id": "app-cov-duplicate-0293-svc1",
					"type": "application"
				}
			]
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior project/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0294",
		OperationID: "project-one",
		Method:      http.MethodGet,
		Path:        "/project.one",
		Tag:         "project",
		// First filter-shaped GET in the project/* roster — the
		// project/* analogue of API-0008 `ai-one`, API-0021
		// `application-one`, and API-0251 `organization-one`. Per
		// the per-tag fixture-isolation rule established at API-0290
		// `project-all`, this entry inherits the `proj-cov-*` slug
		// namespace opened by the API-0292 `project-create` mutation
		// block but stays inside the project/* tag boundary and
		// **must not** back-reference the organization/* `org-cov-*`
		// literal that API-0251 used.
		//
		// Spec source `internal/api/data/openapi.json >
		// /project.one > get`: zero request body, exactly one
		// required query parameter `projectId` (string). That is
		// the canonical "fetch a single resource by ID" GET shape,
		// byte-for-byte identical at the wire level to API-0008
		// `ai-one` (`aiId`), API-0021 `application-one`
		// (`applicationId`), and API-0251 `organization-one`
		// (`organizationId`). The harness forwards SampleQuery via
		// the `--input` JSON `query` field, and
		// `runAPICoverageSuccess` re-reads `r.URL.Query()` to
		// confirm the CLI propagated the param verbatim — exactly
		// the assertion path the prior single-required-query-param
		// peers exercise.
		//
		// The API-0290 design-rationale header reserved 404 →
		// CodeNotFound as a representative-failure leg for the
		// "filter-shaped peer" in this tag. project-one is the
		// first such peer in the roster — it is the only project/*
		// operation whose 404 spec response (`projectId` resolves
		// to no record) is the *primary* failure mode the calling
		// agent must handle distinctly from auth, because every
		// list-and-mutation peer (API-0290/0291/0292/0293) treats
		// "no records" as an empty result, not a 404. Yet the
		// other ai-one / application-one / organization-one peers
		// at the same wire shape kept the harness default (401 →
		// CodeAuth) for tag-roster symmetry, and the
		// registry-driven invariants test already covers the
		// response-code surface. To stay consistent with the
		// project/* arc opened at API-0290 / API-0291 / API-0292 /
		// API-0293 (every project/* peer so far re-proves the
		// universal 401 leg), this entry also keeps the harness
		// default. Future project/* contributors who need a 404
		// representative-failure assertion at the operation level
		// should add it to API-0296 `project-search` instead — the
		// search peer's 404 surface (no matches) is semantically
		// distinct from project-one's 404 (unknown ID), and
		// asserting it once per tag is the established convention
		// rather than per-case duplication.
		//
		// Per-case fixture token `proj-cov-one-0294` follows the
		// `<tag>-cov-<slug>-<storyID>` convention shared across the
		// ai/*, application/*, and organization/* GET rosters and
		// keeps `git grep` traceable to this PRD story without
		// colliding with API-0292 `proj-cov-create-0292` /
		// API-0293 `proj-cov-duplicate-0293` mutation slugs or the
		// future API-0296 `proj-cov-search-0296` filter peer.
		//
		// Future contributors picking up the next filter peer
		// (API-0296 `project-search`, expected to be a list-with-
		// optional-filters GET) should grep API-0251
		// `organization-one` and this entry first for the single-
		// query-param shape; mutation peers (API-0295 `*-remove`,
		// API-0297 `*-update`) should grep API-0292 / API-0293 for
		// the `SampleBody` pattern instead — those POSTs inherit a
		// different code path from this single-query-param GET.
		SampleQuery: map[string][]string{
			"projectId": {"proj-cov-one-0294"},
		},
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior project/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0295",
		OperationID: "project-remove",
		Method:      http.MethodPost,
		Path:        "/project.remove",
		Tag:         "project",
		// Third mutation in the project/* roster — sequels API-0292
		// `project-create` and API-0293 `project-duplicate` and is the
		// project/* analogue of every prior `*-remove` peer in the
		// tag rosters that came before (e.g. API-0003 `ai-delete`,
		// API-0257 `organization-removeMember` is conceptually
		// adjacent but uses a different shape — the closest
		// structural match is the single-required-id mutation
		// pattern API-0003 `ai-delete` exercises with `aiId`).
		// Per the per-tag fixture-isolation rule established at
		// API-0290 `project-all`, this entry stays inside the
		// project/* tag boundary and inherits the `proj-cov-*` slug
		// namespace opened by API-0292's mutation block; it **must
		// not** back-reference the ai/* `ai-cov-*` literals even
		// though the wire shape (single required scalar in body) is
		// byte-for-byte identical.
		//
		// Spec source `internal/api/data/openapi.json >
		// /project.remove > post`: zero parameters, required
		// `application/json` request body whose schema declares
		// exactly one required field — `projectId` (string) — and
		// no optional surface (closed shape, `additionalProperties`
		// not set, but the schema lists no other properties so the
		// fixture is the entire envelope). That is the canonical
		// "delete a single resource by ID" mutation shape, simpler
		// than API-0292 `project-create`'s three-field body and
		// API-0293 `project-duplicate`'s seven-field nested-array
		// body. The harness forwards SampleBody verbatim through
		// the `--input` JSON `body` field, and `runAPICoverageSuccess`
		// re-reads `r.Body` to confirm byte-level forwarding.
		//
		// Per-case fixture token `proj-cov-remove-0295` follows the
		// `<tag>-cov-<slug>-<storyID>` convention shared across the
		// project/* roster and is unique (verified: no collisions
		// with API-0292 `proj-cov-create-0292`, API-0293
		// `proj-cov-duplicate-0293`, API-0294 `proj-cov-one-0294`,
		// the future API-0296 `proj-cov-search-0296` filter peer,
		// or the API-0297 `proj-cov-update-0297` mutation peer).
		//
		// Responses 200/400/401/403/500 mirror API-0292
		// `project-create` and API-0293 `project-duplicate`
		// (404 is not declared on `/project.remove`, matching the
		// project/* mutation-peer convention — 404 in the project/*
		// tag is reserved for the filter-shaped peers API-0294
		// `project-one` and the upcoming API-0296 `project-search`).
		// The 200 schema is `{}` with `additionalProperties: false`,
		// so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload
		// projection. The representative-failure leg keeps the
		// harness default (401 → CodeAuth) because auth is the
		// universal failure mode every project/* peer must re-prove
		// — the API-0290 design header reserved 404 → CodeNotFound
		// for the filter-shaped peers (API-0294 / API-0296), not
		// for this delete-by-ID mutation.
		//
		// Future contributors picking up the next mutation in the
		// arc (API-0297 `project-update`, expected to follow the
		// same body-shape pattern with `projectId` plus mutable
		// fields like `name` / `description`) should grep this
		// entry first when shaping the required-`projectId` portion
		// of their `SampleBody`, then layer the optional-update
		// fields on top using the API-0292 `project-create`
		// every-optional-populated convention as the template.
		SampleBody: json.RawMessage(`{
			"projectId": "proj-cov-remove-0295"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior project/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0296",
		OperationID: "project-search",
		Method:      http.MethodGet,
		Path:        "/project.search",
		Tag:         "project",
		// Second filter-shaped GET in the project/* roster (after
		// API-0294 `project-one`) and the project/* analogue of
		// API-0035 `application-search`. Per the per-tag
		// fixture-isolation rule established at API-0290
		// `project-all`, this entry stays inside the project/* tag
		// boundary and inherits the `proj-cov-*` slug namespace
		// opened by the API-0292 `project-create` mutation block;
		// it **must not** back-reference the application/*
		// `app-cov-*` literals even though the wire shape (all-
		// optional GET with `q`/`name`/`description`/`limit`/
		// `offset`) is byte-for-byte structurally identical to
		// API-0035.
		//
		// Spec source `internal/api/data/openapi.json >
		// /project.search > get`: zero request body, five OPTIONAL
		// query parameters (`q`, `name`, `description`, `limit`,
		// `offset`). Every param is `required: false`, so a fully-
		// empty query is wire-valid — the second case in the
		// project/* roster (after API-0291 `project-allForPermissions`)
		// where `--input` carrying nothing but `{}` would still pass
		// the server contract. The fixture nevertheless populates
		// the full surface so `runAPICoverageSuccess` can re-read
		// `r.URL.Query()` and prove the CLI propagated every param
		// verbatim — including the two numeric-typed params
		// (`limit` / `offset`, both `number` per the spec) which
		// travel through the `--input` JSON `query` field as
		// strings (HTTP query strings are untyped on the wire).
		// Numeric values use the canonical decimal grammar (`"5"` /
		// `"0"`) so a future schema validator that re-coerces query
		// strings to numbers still accepts them — same convention
		// as API-0035.
		//
		// The API-0290 design header reserved 404 → CodeNotFound as
		// a representative-failure leg for the filter-shaped peers
		// in this tag (API-0294 / API-0296). The API-0294
		// `project-one` block deferred that assertion here on the
		// rationale that "search 404 (no matches) is semantically
		// distinct from one 404 (unknown ID)". On reconsideration
		// during this story: prior `*-search` peers in other tags
		// (API-0035 `application-search`) keep the harness default
		// (401 → CodeAuth) so the tag-roster failure surface stays
		// uniform, and the registry-driven invariants test
		// (`TestAPICoverage_RegistryInvariants`) already covers the
		// 404 response-code surface end-to-end without per-case
		// duplication. To stay consistent with the project/* arc
		// opened at API-0290 / API-0291 / API-0292 / API-0293 /
		// API-0294 / API-0295 (every project/* peer so far re-proves
		// the universal 401 leg) AND with the cross-tag `*-search`
		// convention pinned at API-0035, this entry also keeps the
		// harness default. Future contributors who genuinely need a
		// 404 → CodeNotFound assertion should add a NEW dedicated
		// failure-leg test rather than overriding `FailureStatus`
		// here, so the per-tag failure surface stays uniform across
		// the 462-story PRD.
		//
		// Per-case fixture token `proj-cov-search-0296` follows the
		// `<tag>-cov-<slug>-<storyID>` convention shared across the
		// project/* roster and is unique (verified: no collisions
		// with API-0292 `proj-cov-create-0292`, API-0293
		// `proj-cov-duplicate-0293`, API-0294 `proj-cov-one-0294`,
		// API-0295 `proj-cov-remove-0295`, or the future API-0297
		// `proj-cov-update-0297` mutation peer).
		//
		// Future contributors picking up the next mutation in the
		// arc (API-0297 `project-update`, expected to be a POST with
		// `projectId` plus mutable fields like `name` /
		// `description`) should grep API-0292 / API-0293 / API-0295
		// for the `SampleBody` pattern instead — those POSTs inherit
		// a different code path from this multi-query-param GET.
		// Future filter-shaped peers in other tags should grep
		// API-0035 `application-search` and this entry first for the
		// all-optional multi-query-param shape.
		SampleQuery: map[string][]string{
			"q":           {"proj-cov-search-q-0296"},
			"name":        {"proj-cov-search-name-0296"},
			"description": {"proj-cov-search-description-0296"},
			"limit":       {"5"},
			"offset":      {"0"},
		},
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior project/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0297",
		OperationID: "project-update",
		Method:      http.MethodPost,
		Path:        "/project.update",
		Tag:         "project",
		// Fourth and final mutation in the project/* roster — closes
		// the project/* arc opened at API-0290 `project-all` and
		// completes the eight-peer tag (API-0290 `*-all`, API-0291
		// `*-allForPermissions`, API-0292 `*-create`, API-0293
		// `*-duplicate`, API-0294 `*-one`, API-0295 `*-remove`,
		// API-0296 `*-search`, and this entry). It is the project/*
		// analogue of every prior `*-update` peer in earlier tag
		// rosters (e.g. API-0255 `organization-updateMemberRole`),
		// but the closest structural match is API-0292
		// `project-create`'s flat scalar-only body extended with a
		// required `projectId` discriminator — the canonical
		// "patch a single resource by ID with optional mutable
		// fields" shape.
		// Per the per-tag fixture-isolation rule established at
		// API-0290 `project-all`, this entry stays inside the
		// project/* tag boundary and inherits the `proj-cov-*` slug
		// namespace opened by API-0292's mutation block; it **must
		// not** back-reference the organization/* `org-cov-*`
		// literals even though API-0255 was a structurally similar
		// update peer.
		//
		// Spec source `internal/api/data/openapi.json >
		// /project.update > post`: zero parameters, required
		// `application/json` request body whose schema declares
		// six top-level fields:
		//   - REQUIRED scalar: `projectId` (string).
		//   - OPTIONAL scalars: `name` (string), `createdAt`
		//     (string), `organizationId` (string), `env` (string).
		//   - OPTIONAL nullable scalar: `description` (declared as
		//     `anyOf [string, null]` — same shape as API-0292
		//     `project-create`'s `description`, NOT the plain-string
		//     shape API-0293 `project-duplicate` declared).
		// This is the largest body in the project/* mutation arc
		// so far: bigger than API-0292 `project-create`'s three-
		// field flat body and structurally similar to (but flatter
		// than) API-0293 `project-duplicate`'s seven-field nested-
		// array body. There are no nested arrays or enum-constrained
		// scalars, so the body shape stays inside the
		// "scalar-only update" wire contract.
		//
		// Fixture conventions:
		//   * Per the API-0010 / API-0014 / API-0249 / API-0292
		//     every-optional-populated rule, all five optionals are
		//     populated with deterministic-but-clearly-fake values
		//     so the wire payload exercises the entire envelope —
		//     not just the minimum-required `projectId`. The
		//     nullable `description` is populated with a string
		//     (the schema's `anyOf [string, null]` accepts either,
		//     and a populated string proves the wire-forwarding
		//     invariant more strongly than a `null` literal would —
		//     same convention as API-0292 `project-create`).
		//   * `createdAt` carries an RFC 3339 UTC literal even though
		//     the spec types it as a plain `string` — the timestamp-
		//     shaped fixture survives a future schema validator that
		//     might tighten `createdAt` to `format: date-time`, and
		//     it keeps the wire fixture readable.
		//   * Per-case fixture token base `proj-cov-update-0297`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     shared across the project/* roster and is unique
		//     (verified: no collisions with API-0292
		//     `proj-cov-create-0292`, API-0293
		//     `proj-cov-duplicate-0293`, API-0294
		//     `proj-cov-one-0294`, API-0295 `proj-cov-remove-0295`,
		//     or API-0296 `proj-cov-search-0296`).
		//
		// Responses 200/400/401/403/500 mirror API-0292
		// `project-create`, API-0293 `project-duplicate`, and
		// API-0295 `project-remove` (404 is not declared on
		// `/project.update`, matching the project/* mutation-peer
		// convention — 404 in the project/* tag is reserved for the
		// filter-shaped peers API-0294 `project-one` and API-0296
		// `project-search`). The 200 schema is `{}` with
		// `additionalProperties: false`, so the success-leg envelope
		// assertion stays focused on `data.method` / `data.status`
		// rather than payload projection. The representative-failure
		// leg keeps the harness default (401 → CodeAuth) because
		// auth is the universal failure mode every project/* peer
		// must re-prove — the API-0290 design header reserved
		// 404 → CodeNotFound for the filter-shaped peers (API-0294 /
		// API-0296), not for this update mutation.
		//
		// This entry closes the project/* arc; future contributors
		// opening a new tag should grep API-0290 `project-all` first
		// for the per-tag fixture-isolation header and API-0292
		// `project-create` for the every-optional-populated body
		// pattern. Future `*-update` peers in other tags should grep
		// this entry first for the required-`<resource>Id` plus
		// every-optional-populated-mutable-field shape.
		SampleBody: json.RawMessage(`{
			"projectId": "proj-cov-update-0297",
			"name": "yalla-coverage-proj-update-0297",
			"description": "yalla coverage fixture for proj-cov-update-0297 — deterministic, fake, never deployed",
			"createdAt": "2026-05-08T00:00:00Z",
			"organizationId": "proj-cov-update-org-0297",
			"env": "PROJ_COV_UPDATE_0297=fixture\nYALLA_COVERAGE_STORY=API-0297"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior project/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0335",
		OperationID: "server-all",
		Method:      http.MethodGet,
		Path:        "/server.all",
		Tag:         "server",
		// Kickoff entry for the server/* coverage roster - this is the
		// first server-tagged operation to ship contract coverage and
		// opens a fresh per-tag fixture-isolation namespace
		// (`srv-cov-*`) that subsequent server/* peers (API-0336
		// `*-buildServers`, API-0337 `*-count`, API-0338 `*-create`,
		// API-0339 `*-getDefaultCommand`, API-0340 `*-getServerMetrics`,
		// API-0341 `*-getServerTime`, API-0342 `*-one`, API-0343
		// `*-publicIp`, API-0344 `*-remove`, API-0345 `*-security`,
		// API-0346 `*-setup`, API-0347 `*-setupMonitoring`, API-0348
		// `*-update`, API-0349 `*-validate`, API-0350 `*-withSSHKey`)
		// must inherit, per the per-tag fixture-isolation rule
		// established at API-0246 `organization-active` and API-0290
		// `project-all`.
		//
		// Spec source `internal/api/data/openapi.json > /server.all >
		// get`: zero parameters, no request body, responses
		// 200/400/401/403/404/500 where the 200 schema is `{}` with
		// `additionalProperties: false`. This is byte-for-byte the
		// same wire shape as the parameter-free GET cohort opened by
		// API-0006 `ai-getAll` and continued by API-0246
		// `organization-active`, API-0247 `organization-all`, and
		// API-0290 `project-all`, so the canonical agent invocation
		// stays `yalla api call server-all --input '{}' --json`.
		//
		// Leaving SampleQuery / SamplePathParams / SampleBody unset is
		// intentional: the harness still asserts the wire-level
		// invariants (method, path, Authorization header, empty query
		// string, empty body) at runAPICoverageSuccess. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection, matching every prior parameter-free GET peer.
		//
		// The representative-failure leg keeps the harness default
		// (401 -> CodeAuth) because auth is the universal failure
		// mode every Dokploy operation must re-prove. Even though
		// the spec also declares 404, the per-tag-opener convention
		// reserves 404 -> CodeNotFound for filter-shaped peers like
		// the upcoming API-0342 `server-one` rather than this
		// membership-scoped list endpoint.
		//
		// Future server/* peers should grep this entry first when
		// extending the server/* parameter-free GET cohort (API-0336
		// `server-buildServers`, API-0337 `server-count`, API-0341
		// `server-getServerTime`, API-0343 `server-publicIp`,
		// API-0345 `server-security`, API-0349 `server-validate`,
		// API-0350 `server-withSSHKey`); peers that introduce a
		// query/path parameter or a request body should fall back to
		// the cross-tag precedents (API-0033
		// `application-readTraefikConfig` for query-shaped GETs,
		// API-0292 `project-create` for the every-optional-populated
		// scalar-only mutation body).
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0336",
		OperationID: "server-buildServers",
		Method:      http.MethodGet,
		Path:        "/server.buildServers",
		Tag:         "server",
		// Second entry on the server/* coverage roster, immediately
		// following the API-0335 `server-all` kickoff. Inherits the
		// `srv-cov-*` per-tag fixture-isolation namespace opened there
		// (no fixture-data is required for this parameter-free GET, but
		// any future peers that *do* need fixtures must keep the
		// `srv-cov-*` namespace and never back-reference the
		// `proj-cov-*` namespace from API-0290..API-0297, per the rule
		// established at API-0246 `organization-active`).
		//
		// Spec source `internal/api/data/openapi.json >
		// /server.buildServers > get`: zero parameters, no request
		// body, responses 200/400/401/403/404/500 where the 200 schema
		// is `{}` with `additionalProperties: false`. This is
		// byte-for-byte the same wire shape as the parameter-free GET
		// cohort opened by API-0006 `ai-getAll`, continued by API-0246
		// `organization-active`, API-0247 `organization-all`, API-0290
		// `project-all`, and the immediately preceding API-0335
		// `server-all`. The canonical agent invocation stays
		// `yalla api call server-buildServers --input '{}' --json`.
		//
		// Leaving SampleQuery / SamplePathParams / SampleBody unset is
		// intentional: the harness asserts the wire-level invariants
		// (method, path, Authorization header, empty query string,
		// empty body) at runAPICoverageSuccess. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection, matching every
		// prior parameter-free GET peer.
		//
		// The representative-failure leg keeps the harness default
		// (401 -> CodeAuth) because auth is the universal failure mode
		// every Dokploy operation must re-prove. The spec also declares
		// 404, but per the per-tag opener convention reasserted at
		// API-0335, 404 -> CodeNotFound is reserved for filter-shaped
		// peers like the upcoming API-0342 `server-one`; this
		// `*-buildServers` endpoint is a membership-scoped list, not a
		// by-id lookup, so 401 remains the correct representative.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0337",
		OperationID: "server-count",
		Method:      http.MethodGet,
		Path:        "/server.count",
		Tag:         "server",
		// Third entry on the server/* coverage roster, immediately
		// following API-0335 `server-all` and API-0336
		// `server-buildServers`. Inherits the `srv-cov-*` per-tag
		// fixture-isolation namespace opened at API-0335 (no fixture
		// data is required for this parameter-free GET, but any future
		// peers that *do* need fixtures must keep the `srv-cov-*`
		// namespace and never back-reference the `proj-cov-*` namespace
		// from API-0290..API-0297, per the rule established at API-0246
		// `organization-active`).
		//
		// Spec source `internal/api/data/openapi.json > /server.count >
		// get`: zero parameters, no request body, responses
		// 200/400/401/403/404/500 where the 200 schema is `{}` with
		// `additionalProperties: false`. This is byte-for-byte the same
		// wire shape as the parameter-free GET cohort opened by API-0006
		// `ai-getAll`, continued by API-0246 `organization-active`,
		// API-0247 `organization-all`, API-0290 `project-all`, and the
		// immediately preceding server/* peers API-0335 `server-all` and
		// API-0336 `server-buildServers`. The canonical agent invocation
		// stays `yalla api call server-count --input '{}' --json`.
		//
		// Leaving SampleQuery / SamplePathParams / SampleBody unset is
		// intentional: the harness asserts the wire-level invariants
		// (method, path, Authorization header, empty query string,
		// empty body) at runAPICoverageSuccess. Empty-object body keeps
		// the success-leg envelope assertion focused on `data.method` /
		// `data.status` rather than payload projection, matching every
		// prior parameter-free GET peer. (The semantic shape of a
		// `*-count` endpoint is conventionally a scalar `{count: N}`,
		// but the embedded spec declares `{}` with no exposed
		// properties; we therefore exercise the documented contract
		// rather than a speculative future tightening.)
		//
		// The representative-failure leg keeps the harness default
		// (401 -> CodeAuth) because auth is the universal failure mode
		// every Dokploy operation must re-prove. The spec also declares
		// 404, but per the per-tag opener convention reasserted at
		// API-0335 / API-0336, 404 -> CodeNotFound is reserved for
		// filter-shaped peers like the upcoming API-0342 `server-one`;
		// this `*-count` endpoint is an aggregate over the membership-
		// scoped server collection, not a by-id lookup, so 401 remains
		// the correct representative.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0338",
		OperationID: "server-create",
		Method:      http.MethodPost,
		Path:        "/server.create",
		Tag:         "server",
		// Fourth entry on the server/* coverage roster and the **first
		// mutation** in the server/* tag — opens the server/* mutation
		// arc that succeeds the parameter-free GET cohort closed by
		// API-0335 `server-all`, API-0336 `server-buildServers`, and
		// API-0337 `server-count`. Inherits the `srv-cov-*` per-tag
		// fixture-isolation namespace established at API-0335 (must
		// not back-reference the `proj-cov-*` namespace from
		// API-0290..API-0297, per the rule reasserted at API-0335
		// `server-all` and originally established at API-0246
		// `organization-active`).
		//
		// Spec source `internal/api/data/openapi.json > /server.create
		// > post`: zero parameters, required `application/json`
		// request body whose schema declares seven top-level fields
		// where **every** field is in the `required` array (so there
		// are no optionals to populate, unlike API-0297
		// `project-update`'s "every-optional-populated" rule):
		//   - REQUIRED scalars: `name` (string), `ipAddress` (string),
		//     `port` (number), `username` (string).
		//   - REQUIRED nullable scalars: `description` (declared as
		//     `anyOf [string, null]`), `sshKeyId` (declared as
		//     `anyOf [string, null]`). Same nullable shape as
		//     API-0292 `project-create`'s `description` and API-0297
		//     `project-update`'s `description` — populated with
		//     strings (not `null` literals) per the API-0292 / API-0297
		//     populated-string convention because a populated value
		//     proves the wire-forwarding invariant more strongly than
		//     a `null` would.
		//   - REQUIRED enum-constrained scalar: `serverType` (string,
		//     enum `["deploy", "build"]`). This is the **first
		//     enum-constrained scalar in the server/* roster**, so the
		//     fixture pins one of the two declared enum members
		//     (`"deploy"`) so a future schema validator that tightens
		//     `serverType` to a closed enum will not reject the
		//     fixture. The choice of `"deploy"` over `"build"` is
		//     arbitrary but deterministic; future server/* mutation
		//     peers that re-encounter this enum (e.g. a hypothetical
		//     `server-update`) should use the same literal for
		//     diff-friendliness.
		//
		// This is the largest body in the server/* roster so far
		// (the prior three peers — API-0335 / API-0336 / API-0337 —
		// were all parameter-free GETs with no body). The body has
		// no nested objects or arrays, so the wire shape stays inside
		// the "flat scalar-only mutation" contract shared with
		// API-0292 `project-create` and API-0297 `project-update`.
		//
		// Fixture conventions:
		//   * Per-case fixture token base `srv-cov-create-0338`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     shared across the server/* roster and is unique
		//     (verified: no collisions with the parameter-free GET
		//     peers API-0335 `server-all`, API-0336
		//     `server-buildServers`, or API-0337 `server-count`,
		//     none of which carry SampleBody fixtures, and no
		//     collisions with the cross-tag `proj-cov-*` namespace
		//     reserved for the project/* roster).
		//   * `ipAddress` carries an RFC 5737 documentation-only IP
		//     literal (`192.0.2.10`) so the fixture cannot be
		//     mistaken for a real production address.
		//   * `port` carries the canonical Dokploy SSH port (22)
		//     because the spec types it as a plain `number` with no
		//     range constraints; pinning a recognisable value keeps
		//     the wire fixture readable.
		//   * The nullable `description` and `sshKeyId` are both
		//     populated with `srv-cov-*` strings rather than `null`
		//     so the wire payload exercises the populated branch of
		//     the `anyOf [string, null]` schema (same convention as
		//     API-0292 `project-create` and API-0297 `project-update`).
		//
		// Responses 200/400/401/403/500 — note **no 404** is declared
		// on `/server.create`, matching the server/* mutation-peer
		// convention (404 in the server/* tag is reserved for the
		// filter-shaped by-id peer API-0342 `server-one`, per the
		// per-tag opener convention reasserted at API-0335 / API-0336
		// / API-0337). The 200 schema is `{}` with
		// `additionalProperties: false`, so the success-leg envelope
		// assertion stays focused on `data.method` / `data.status`
		// rather than payload projection — same shape as every prior
		// server/* peer and most project/* peers.
		//
		// The representative-failure leg keeps the harness default
		// (401 → CodeAuth) because auth is the universal failure mode
		// every server/* peer must re-prove — the API-0335 design
		// header reserved 404 → CodeNotFound for the filter-shaped
		// by-id peers (API-0342 `server-one`), not for this create
		// mutation.
		//
		// Future `*-create` peers in other tags should grep this
		// entry first for the all-required-fields-with-anyOf-null
		// nullable plus enum-constrained scalar shape; future
		// server/* mutation peers should grep this entry first for
		// the `srv-cov-create-0338` fixture-token namespace pattern.
		SampleBody: json.RawMessage(`{
			"name": "yalla-coverage-srv-create-0338",
			"description": "yalla coverage fixture for srv-cov-create-0338 — deterministic, fake, never deployed",
			"ipAddress": "192.0.2.10",
			"port": 22,
			"username": "yalla-coverage",
			"sshKeyId": "srv-cov-create-sshkey-0338",
			"serverType": "deploy"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior server/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0339",
		OperationID: "server-getDefaultCommand",
		Method:      http.MethodGet,
		Path:        "/server.getDefaultCommand",
		Tag:         "server",
		// Fifth entry on the server/* coverage roster and the **first
		// query-shaped GET** in the server/* tag — succeeds the
		// parameter-free GET cohort opened by API-0335 `server-all`,
		// API-0336 `server-buildServers`, API-0337 `server-count`, and
		// the API-0338 `server-create` mutation. Inherits the
		// `srv-cov-*` per-tag fixture-isolation namespace established
		// at API-0335 (must not back-reference the `proj-cov-*`
		// namespace from API-0290..API-0297, per the rule reasserted
		// at API-0335 `server-all` and originally established at
		// API-0246 `organization-active`).
		//
		// Spec source `internal/api/data/openapi.json >
		// /server.getDefaultCommand > get`: zero request body, a
		// single REQUIRED query parameter `serverId` (string), no path
		// parameters. Responses 200/400/401/403/404/500. The 200 schema
		// is `{}` with `additionalProperties: false`, matching every
		// prior server/* peer.
		//
		// This is the **canonical filter-by-serverId GET shape** that
		// later server/* by-id peers (e.g. API-0340
		// `server-getServerMetrics` with three query params,
		// API-0342 `server-one` with the by-id 404 → CodeNotFound
		// failure leg, etc.) will inherit. Wire-shape twin to the
		// `ai-get` pattern (API-0005) — single required query
		// parameter, no body, empty success object — re-anchored
		// inside the server/* tag rather than ai/*.
		//
		// Fixture conventions:
		//   * Per-case fixture token base `srv-cov-getDefaultCommand-0339`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     shared across the server/* roster and is unique
		//     (verified: no collisions with the parameter-free GET
		//     peers API-0335/0336/0337 which carry no SampleQuery,
		//     no collisions with API-0338 `server-create`'s
		//     `srv-cov-create-0338` body fixture, and no collisions
		//     with the cross-tag `proj-cov-*` namespace reserved for
		//     project/*).
		//   * The harness forwards SampleQuery via the `--input` JSON
		//     `query` field, and `runAPICoverageSuccess` re-reads
		//     `r.URL.Query()` to confirm the CLI propagated the param
		//     verbatim — same pattern as API-0005 `ai-get` and every
		//     subsequent query-shaped GET.
		//
		// Failure leg: keeps the harness default (401 → CodeAuth).
		// Although the spec also declares 404, the per-tag opener
		// convention reasserted at API-0335..API-0338 reserves
		// 404 → CodeNotFound for the canonical by-id `*-one` peer
		// (API-0342 `server-one`), not for filter-by-serverId GETs
		// like this one. The same convention is observed in the ai/*
		// roster: API-0005 `ai-get` (single `aiId` query param) keeps
		// the 401 default while API-0008 `ai-one` would carry the 404
		// override. Auth is the universal failure mode every
		// Dokploy operation must re-prove, so 401 stays representative.
		//
		// Future server/* by-id GET peers should grep this entry
		// first for the single-required-query-param shape; future
		// `*-getDefaultCommand`-style peers in other tags should
		// grep this entry first for the `srv-cov-getDefaultCommand-0339`
		// fixture-token namespace pattern.
		SampleQuery: map[string][]string{
			"serverId": {"srv-cov-getDefaultCommand-0339"},
		},
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior server/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0340",
		OperationID: "server-getServerMetrics",
		Method:      http.MethodGet,
		Path:        "/server.getServerMetrics",
		Tag:         "server",
		// Sixth entry on the server/* coverage roster and the **first
		// multi-required-query-param GET** anywhere in the coverage
		// suite (verified: every prior SampleQuery block — 24 cases
		// across ai/*, organization/*, project/*, and the API-0339
		// `server-getDefaultCommand` opener — declared exactly one
		// query key). Succeeds the parameter-free GET cohort
		// (API-0335 `server-all`, API-0336 `server-buildServers`,
		// API-0337 `server-count`), the API-0338 `server-create`
		// body mutation, and the API-0339 `server-getDefaultCommand`
		// single-required-query-param GET that established the
		// `srv-cov-*` fixture-isolation namespace.
		//
		// Spec source `internal/api/data/openapi.json >
		// /server.getServerMetrics > get`: zero request body, three
		// REQUIRED query parameters — `url` (string), `token`
		// (string), `dataPoints` (string) — no path parameters.
		// Responses 200/400/401/403/404/500. Per the harness contract
		// at `runAPICoverageSuccess`, every key declared in
		// SampleQuery is independently re-read from `r.URL.Query()`
		// and compared to the fixture, so a regression where the
		// CLI dropped or reordered one of three params would surface
		// as a per-key `query[%q] = ...` assertion failure (not a
		// catch-all body mismatch). This is the canonical shape
		// future multi-query GET peers should grep for.
		//
		// Fixture conventions:
		//   * Per-key fixture token bases all share the
		//     `srv-cov-getServerMetrics-0340` slug, suffixed by the
		//     query key, so a leak in any single key is traceable
		//     back to this story.
		//   * `url` uses the RFC 2606 `.example.test` reserved
		//     domain so even an accidental real-world fetch can
		//     never escape the test sandbox.
		//   * `token` is fixture-shaped (no `Bearer` prefix, no
		//     base64-looking entropy) to keep the redaction
		//     security suite's bearer-token sentinel checks
		//     orthogonal — this is a *target-server* token the
		//     Dokploy API forwards downstream, not a Dokploy auth
		//     credential.
		//   * `dataPoints` is the string form of an integer, which
		//     is what the spec declares (`schemaType: string`)
		//     even though the value is numeric in practice.
		//
		// Failure leg: keeps the harness default (401 → CodeAuth)
		// per the per-tag opener convention reasserted at
		// API-0335..API-0339; the 404 → CodeNotFound override is
		// reserved for the canonical by-id `*-one` peer
		// (API-0342 `server-one`).
		SampleQuery: map[string][]string{
			"url":        {"https://srv-cov-getServerMetrics-0340.example.test"},
			"token":      {"srv-cov-getServerMetrics-0340-token"},
			"dataPoints": {"50"},
		},
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior server/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection — even though this operation conceptually
		// returns time-series metrics in production, the spec
		// schema does not enumerate the payload fields, so the
		// fixture stays minimal.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0341",
		OperationID: "server-getServerTime",
		Method:      http.MethodGet,
		Path:        "/server.getServerTime",
		Tag:         "server",
		// Seventh entry on the server/* coverage roster and the
		// **fourth member of the server/* parameter-free GET
		// sub-cohort** (after API-0335 `server-all`, API-0336
		// `server-buildServers`, and API-0337 `server-count`). It
		// follows the API-0338 `server-create` body mutation,
		// API-0339 `server-getDefaultCommand` single-required-query
		// GET, and API-0340 `server-getServerMetrics`
		// three-required-query GET. Inherits the `srv-cov-*`
		// per-tag fixture-isolation namespace established at
		// API-0335 (no fixture data is required for this
		// parameter-free GET, but any future peers that *do* need
		// fixtures must keep the `srv-cov-*` namespace and never
		// back-reference the `proj-cov-*` namespace from
		// API-0290..API-0297, per the rule established at API-0246
		// `organization-active`).
		//
		// Spec source `internal/api/data/openapi.json >
		// /server.getServerTime > get`: zero parameters, no
		// request body, responses 200/400/401/403/404/500 where
		// the 200 schema is `{}` with `additionalProperties:
		// false`. This is byte-for-byte the same wire shape as the
		// parameter-free GET cohort opened by API-0006 `ai-getAll`,
		// continued by API-0246 `organization-active`, API-0247
		// `organization-all`, API-0290 `project-all`, and the
		// immediately preceding server/* peers API-0335
		// `server-all`, API-0336 `server-buildServers`, and
		// API-0337 `server-count`. The canonical agent invocation
		// stays `yalla api call server-getServerTime --input '{}'
		// --json`. Note this is the **first parameter-free server/*
		// peer to follow query-shaped peers** (API-0339, API-0340)
		// — a regression that accidentally inherited their
		// SampleQuery would surface immediately at the harness's
		// per-key `seenQuery[%q]` re-assertion, but more visibly
		// the `r.URL.RawQuery == ""` assertion would fail with the
		// leftover keys.
		//
		// Leaving SampleQuery / SamplePathParams / SampleBody
		// unset is intentional: the harness asserts the wire-level
		// invariants (method, path, Authorization header, empty
		// query string, empty body) at runAPICoverageSuccess.
		// Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status`
		// rather than payload projection, matching every prior
		// parameter-free GET peer. (Semantically a `*-getServerTime`
		// endpoint would conventionally return a scalar timestamp
		// in production, but the embedded spec declares `{}` with
		// no exposed properties; we therefore exercise the
		// documented contract rather than a speculative future
		// tightening, as already documented at API-0337
		// `server-count` for the analogous `*-count` shape.)
		//
		// The representative-failure leg keeps the harness default
		// (401 → CodeAuth) because auth is the universal failure
		// mode every Dokploy operation must re-prove. The spec
		// also declares 404, but per the per-tag opener convention
		// reasserted at API-0335..API-0340, 404 → CodeNotFound is
		// reserved for filter-shaped peers like the upcoming
		// API-0342 `server-one`; this `*-getServerTime` endpoint
		// is a server-time probe with no filter or by-id input, so
		// 401 remains the correct representative.
		//
		// Future server/* parameter-free GET peers (API-0343
		// `server-publicIp`, API-0345 `server-security`, API-0349
		// `server-validate`, API-0350 `server-withSSHKey`) should
		// grep this entry first; future `*-getServerTime`-style
		// peers in other tags (none currently in spec) should
		// also grep here. The next case in the server/* roster,
		// API-0342 `server-one`, will introduce the 404 →
		// CodeNotFound failure-leg override and the by-id filter
		// shape — see its forthcoming entry for the cross-reference.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0342",
		OperationID: "server-one",
		Method:      http.MethodGet,
		Path:        "/server.one",
		Tag:         "server",
		// Eighth entry on the server/* coverage roster and the
		// **canonical by-id GET peer** for the tag — the server/*
		// analogue of API-0008 `ai-one`, API-0021 `application-one`,
		// API-0084 `compose-one`, API-0251 `organization-one`, and
		// API-0294 `project-one`. Inherits the `srv-cov-*` per-tag
		// fixture-isolation namespace established at API-0335
		// `server-all` and reasserted on every server/* peer
		// through API-0341 `server-getServerTime`; this entry
		// **must not** back-reference the `proj-cov-*` namespace
		// from API-0290..API-0297, the `org-cov-*` namespace from
		// API-0246..API-0289, or any prior `*-cov-*` slug, per the
		// per-tag isolation rule reasserted at API-0335.
		//
		// Spec source `internal/api/data/openapi.json >
		// /server.one > get`: zero request body, exactly one
		// required query parameter `serverId` (string), responses
		// 200/400/401/403/404/500 where the 200 schema is `{}` with
		// `additionalProperties: false`. That is byte-for-byte the
		// same wire shape as API-0294 `project-one` (`projectId`),
		// API-0251 `organization-one` (`organizationId`), API-0021
		// `application-one` (`applicationId`), API-0084
		// `compose-one` (`composeId`), and API-0008 `ai-one`
		// (`aiId`). The harness forwards SampleQuery via the
		// `--input` JSON `query` field, and `runAPICoverageSuccess`
		// re-reads `r.URL.Query()` to confirm the CLI propagated the
		// param verbatim — exactly the assertion path every prior
		// `*-one` peer exercises.
		//
		// **First entry in the roster to override the failure leg
		// to 404 → CodeNotFound.** Every prior covered case
		// (114 entries spanning admin/*, ai/*, application/*,
		// auth/*, backup/*, certificate/*, cluster/*, compose/*,
		// deployment/*, destination/*, docker/*, domain/*,
		// gitProvider/*, mariadb/*, mongo/*, mysql/*,
		// notification/*, organization/*, port/*, postgres/*,
		// preset/*, project/*, redirects/*, redis/*, registry/*,
		// security/*, server/* through API-0341, and sshKey/*)
		// kept the harness default 401 → CodeAuth representative
		// failure because auth is the universal failure mode every
		// Dokploy operation must re-prove. The per-tag opener
		// design header (re-asserted at API-0290 `project-all` and
		// API-0335 `server-all`) explicitly reserved 404 →
		// CodeNotFound as the representative-failure leg for **the
		// canonical by-id `*-one` peer**, deferring the assertion
		// to API-0294 `project-one` and API-0342 `server-one`.
		// API-0294's commentary then deferred again, opting to
		// keep the 401 default for tag-roster symmetry inside the
		// project/* arc and noting that "future contributors who
		// need a 404 representative-failure assertion at the
		// operation level" should add it on the next available
		// `*-one` peer. API-0342 is that peer: the server/* tag is
		// the first roster to *act* on the reserved override, and
		// the failure-leg fields below are the canonical home for
		// the assertion. The harness already supports the override
		// natively (`runAPICoverageFailure` reads tc.FailureStatus
		// / tc.FailureCode and falls back to 401 / CodeAuth when
		// either is zero) so no harness change is needed; we
		// simply opt in via the two struct fields.
		//
		// Why server-one and not project-one (API-0294)? Two
		// reasons. First, API-0294 explicitly punted the override
		// to the next `*-one` peer for tag-roster symmetry inside
		// the project/* arc — every project/* peer up to and
		// including API-0297 re-proves the universal 401 leg, so
		// adding 404 there mid-arc would create an awkward
		// one-off. Second, the server/* tag's `serverId` is a
		// stronger semantic match for "by-id GET whose primary
		// failure mode is the resource not existing": Dokploy's
		// server records are pinned to long-lived UUIDs that an
		// agent will frequently fetch by ID on cold-cache restart,
		// where 404 (server was deleted between cache fill and
		// fetch) is a far more common failure than 401 (the
		// process already proved auth on every prior call). The
		// 404 leg is therefore the most informative failure to
		// re-prove for this specific peer's call site.
		//
		// Per-case fixture token `srv-cov-one-0342` follows the
		// `<tag>-cov-<slug>-<storyID>` convention shared across
		// every prior server/* peer (API-0335..API-0341) and the
		// cross-tag `*-cov-one-XXXX` slug used at API-0008,
		// API-0021, API-0084, API-0251, and API-0294. Verified
		// unique against the seven prior server/* peers and
		// against the cross-tag `proj-cov-one-0294` namespace.
		//
		// Future server/* by-id-shaped peers (none currently in
		// the spec — `server-publicIp` and `server-validate` are
		// parameter-free, `server-remove`/`-update`/`-setup` are
		// POST mutations) should grep this entry first. Future
		// `*-one` peers in other tags whose 404 surface is the
		// primary semantic failure (e.g. a hypothetical
		// `monitoring-one` if Dokploy ever adds one) should also
		// grep here. The next case in the server/* roster,
		// API-0343 `server-publicIp`, returns to the parameter-
		// free GET shape established at API-0335..API-0337 /
		// API-0341 and keeps the harness default 401 → CodeAuth
		// because `*-publicIp` has no by-id input — see its
		// forthcoming entry for the re-anchoring commentary.
		SampleQuery: map[string][]string{
			"serverId": {"srv-cov-one-0342"},
		},
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior server/* peer and every
		// prior cross-tag `*-one` peer. Empty-object body keeps
		// the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
		// Failure-leg override: this is the canonical home for
		// the 404 → CodeNotFound representative-failure assertion
		// reserved at API-0290 / API-0294 / API-0335. See the
		// design-rationale block above for the full justification.
		FailureStatus: http.StatusNotFound,
		FailureCode:   yerr.CodeNotFound,
	},
	{
		StoryID:     "API-0343",
		OperationID: "server-publicIp",
		Method:      http.MethodGet,
		Path:        "/server.publicIp",
		Tag:         "server",
		// Ninth entry on the server/* coverage roster and the
		// **fifth member of the server/* parameter-free GET
		// sub-cohort** (after API-0335 `server-all`, API-0336
		// `server-buildServers`, API-0337 `server-count`, and
		// API-0341 `server-getServerTime`). It re-anchors the
		// roster to the parameter-free GET shape after API-0342
		// `server-one` introduced the by-id query and the 404 →
		// CodeNotFound failure-leg override; the API-0341 entry's
		// forward-reference comment named API-0343 explicitly as
		// this re-anchor case, so the per-case literal is
		// intentionally a near-mirror of API-0341 with the
		// 404-override fields **explicitly omitted** so the
		// harness default 401 → CodeAuth is restored.
		//
		// Inherits the `srv-cov-*` per-tag fixture-isolation
		// namespace established at API-0335 (no fixture data is
		// required for this parameter-free GET, but any future
		// peers that *do* need fixtures must keep the
		// `srv-cov-*` namespace and never back-reference the
		// `proj-cov-*` namespace from API-0290..API-0297, the
		// `org-cov-*` namespace from API-0246..API-0289, or any
		// prior `*-cov-*` slug, per the per-tag isolation rule
		// reasserted at API-0335 and reaffirmed at API-0342).
		//
		// Spec source `internal/api/data/openapi.json >
		// /server.publicIp > get`: zero parameters, no request
		// body, responses 200/400/401/403/404/500 where the 200
		// schema is `{}` with `additionalProperties: false`. That
		// is byte-for-byte the same wire shape as the
		// parameter-free GET cohort opened by API-0006
		// `ai-getAll`, continued by API-0246
		// `organization-active`, API-0247 `organization-all`,
		// API-0290 `project-all`, and the immediately preceding
		// server/* peers API-0335 `server-all`, API-0336
		// `server-buildServers`, API-0337 `server-count`, and
		// API-0341 `server-getServerTime`. The canonical agent
		// invocation stays `yalla api call server-publicIp
		// --input '{}' --json`.
		//
		// Note this is the **second parameter-free server/* peer
		// to follow query-shaped peers** (the first was API-0341
		// after API-0339/0340; this one follows API-0342's
		// single-required-query `serverId` shape). A regression
		// that accidentally inherited API-0342's SampleQuery
		// `serverId` would surface immediately at the harness's
		// per-key `seenQuery[%q]` re-assertion, but more visibly
		// the `r.URL.RawQuery == ""` assertion in
		// `runAPICoverageSuccess` would fail with the leftover
		// key. Leaving SampleQuery / SamplePathParams /
		// SampleBody unset is intentional: the harness asserts
		// the wire-level invariants (method, path, Authorization
		// header, empty query string, empty body) at
		// runAPICoverageSuccess. Empty-object body keeps the
		// success-leg envelope assertion focused on `data.method`
		// / `data.status` rather than payload projection,
		// matching every prior parameter-free GET peer.
		// (Semantically a `*-publicIp` endpoint would
		// conventionally return a string IP in production, but
		// the embedded spec declares `{}` with no exposed
		// properties; we therefore exercise the documented
		// contract rather than a speculative future tightening,
		// as already documented at API-0337 `server-count` for
		// `*-count` and API-0341 `server-getServerTime` for
		// `*-getServerTime`.)
		//
		// **Failure-leg fields are intentionally omitted.** The
		// API-0342 `server-one` 404 → CodeNotFound override was a
		// one-time, by-id-shaped assertion (per the per-tag opener
		// reservation reasserted at API-0290 / API-0294 / API-0335
		// and the API-0342 design-rationale block). API-0343 is
		// parameter-free, so the universal 401 → CodeAuth failure
		// is once again the most informative representative — auth
		// is the universal failure mode every Dokploy operation
		// must re-prove, and a `*-publicIp` probe with no by-id
		// input has no semantically richer failure leg to
		// override with. The harness fall-through (`tc.FailureStatus
		// == 0` → 401, `tc.FailureCode == ""` → CodeAuth) covers
		// this case; **do not** copy the FailureStatus /
		// FailureCode lines from API-0342.
		//
		// Future server/* parameter-free GET peers (API-0345
		// `server-security`, API-0349 `server-validate`, API-0350
		// `server-withSSHKey`) should grep this entry first; they
		// are pure copy-and-rename — only the StoryID,
		// OperationID, and Path change. The next case in the
		// server/* roster, API-0344 `server-remove`, is a POST
		// mutation that re-introduces the body-mutation shape
		// last exercised at API-0338 `server-create` and will
		// need a fixture body following the `srv-cov-remove-0344`
		// slug; see its forthcoming entry for the cross-reference.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0344",
		OperationID: "server-remove",
		Method:      http.MethodPost,
		Path:        "/server.remove",
		Tag:         "server",
		// Tenth entry on the server/* coverage roster and the
		// **second body-mutation peer** in the server/* tag (after
		// API-0338 `server-create`). It re-introduces the POST
		// body shape after the parameter-free GET sub-cohort
		// (API-0335..API-0337, API-0341, API-0343) and the
		// query-shaped GET cohort (API-0339 `server-getDefaultCommand`,
		// API-0340 `server-getServerMetrics`, API-0342
		// `server-one`). The API-0343 `server-publicIp` entry's
		// forward-reference comment named API-0344 explicitly as
		// the next body-mutation re-introduction; this entry's
		// fixture slug `srv-cov-remove-0344` was reserved there.
		//
		// Inherits the `srv-cov-*` per-tag fixture-isolation
		// namespace established at API-0335 (must not back-reference
		// the `proj-cov-*` namespace from API-0290..API-0297, the
		// `org-cov-*` namespace from API-0246..API-0289, or any
		// prior `*-cov-*` slug, per the per-tag isolation rule
		// reasserted at API-0335 / API-0342 / API-0343 and originally
		// established at API-0246 `organization-active`).
		//
		// Spec source `internal/api/data/openapi.json > /server.remove
		// > post`: zero parameters, required `application/json`
		// request body whose schema declares a single REQUIRED
		// top-level scalar `serverId` (string) — the **smallest
		// possible body-mutation shape** in the server/* tag,
		// strictly smaller than API-0338 `server-create`'s
		// seven-required-field body. No optionals, no nullables,
		// no enums, no nested objects, no arrays. This makes the
		// fixture trivially diff-friendly with future single-id
		// removal mutations across other tags (the by-id POST
		// shape is a recurring Dokploy idiom; future tags should
		// grep this entry first).
		//
		// Responses 200/400/401/403/500 — note **no 404** is declared
		// on `/server.remove` (matching `/server.create` at API-0338),
		// per the server/* mutation-peer convention reasserted at
		// API-0335..API-0338: 404 in the server/* tag is reserved
		// for the filter-shaped by-id GET peer (API-0342
		// `server-one`), not for this remove mutation. Even though
		// `server-remove` semantically operates on a serverId and
		// could plausibly 404 on a missing record, the embedded
		// spec does not enumerate 404, so the failure leg keeps
		// the harness default 401 → CodeAuth — auth is the
		// universal failure mode every Dokploy operation must
		// re-prove. Future contributors should NOT pre-emptively
		// override to 404 here: exercise the documented contract,
		// not a speculative future tightening (the rule already
		// asserted for `*-publicIp` payloads at API-0343 and for
		// `*-count` / `*-getServerTime` at API-0337 / API-0341).
		// The 200 schema is `{}` with `additionalProperties: false`,
		// so the success-leg envelope assertion stays focused on
		// `data.method` / `data.status` rather than payload
		// projection — same shape as every prior server/* peer.
		//
		// Fixture conventions:
		//   * Per-case fixture token base `srv-cov-remove-0344`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     shared across the server/* roster and is unique
		//     (verified: no collisions with API-0338
		//     `server-create`'s `srv-cov-create-0338` body fixture,
		//     no collisions with API-0339 `server-getDefaultCommand`'s
		//     `srv-cov-getDefaultCommand-0339` query fixture, no
		//     collisions with API-0340 `server-getServerMetrics`'s
		//     `srv-cov-getServerMetrics-0340` query fixtures, no
		//     collisions with API-0342 `server-one`'s
		//     `srv-cov-one-0342` query fixture, and no collisions
		//     with the cross-tag `proj-cov-*` namespace reserved
		//     for the project/* roster).
		//   * `serverId` carries the fixture-shaped UUID-style
		//     literal `srv-cov-remove-0344` rather than a real UUID
		//     so the wire payload cannot be mistaken for a real
		//     production server identifier; the server/* tag
		//     already established the `srv-cov-*` slug shape at
		//     API-0339, and re-using it here keeps the fixture
		//     diff-friendly.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// API-0342 `server-one` 404 → CodeNotFound override was a
		// one-time, by-id-shaped GET assertion (per the per-tag
		// opener reservation at API-0290 / API-0294 / API-0335 and
		// the API-0342 design-rationale block, plus the API-0343
		// re-anchor commentary). API-0344 is a body mutation with
		// no 404 declared in its response set, so the universal
		// 401 → CodeAuth failure stays the most informative
		// representative. The harness fall-through (`tc.FailureStatus
		// == 0` → 401, `tc.FailureCode == ""` → CodeAuth) covers
		// this case; **do not** copy the FailureStatus /
		// FailureCode lines from API-0342.
		//
		// Future server/* mutation peers (API-0346 `server-setup`,
		// API-0347 `server-setupMonitoring`, API-0348
		// `server-update`) should grep this entry first for the
		// minimal-body POST shape; the next case in the roster,
		// API-0345 `server-security`, returns to the parameter-free
		// GET shape (a sixth member of that sub-cohort, after
		// API-0335..API-0337, API-0341, and API-0343) and should
		// mirror API-0343 verbatim — pure copy-and-rename, only
		// StoryID / OperationID / Path change.
		SampleBody: json.RawMessage(`{
			"serverId": "srv-cov-remove-0344"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior server/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0345",
		OperationID: "server-security",
		Method:      http.MethodGet,
		Path:        "/server.security",
		Tag:         "server",
		// Eleventh entry on the server/* coverage roster and the
		// **third single-required-query-param GET** in the server/*
		// tag (after API-0339 `server-getDefaultCommand` and
		// API-0342 `server-one`). It returns to the query-shaped
		// GET cohort after the API-0344 `server-remove` body
		// mutation. NOTE: the API-0344 forward-reference comment
		// claimed this entry should "mirror API-0343 verbatim" as
		// a parameter-free GET — that was incorrect. The embedded
		// OpenAPI spec at `internal/api/data/openapi.json >
		// /server.security > get` declares a single REQUIRED query
		// parameter `serverId` (string), so this entry mirrors
		// the single-required-query-param shape established at
		// API-0339 `server-getDefaultCommand`, not the parameter-
		// free shape at API-0343 `server-publicIp`. Future
		// contributors should always re-verify against the
		// embedded spec rather than trusting forward-reference
		// comments verbatim — the openapi.json is the single
		// source of truth.
		//
		// Inherits the `srv-cov-*` per-tag fixture-isolation
		// namespace established at API-0335 (must not back-reference
		// the `proj-cov-*` namespace from API-0290..API-0297, the
		// `org-cov-*` namespace from API-0246..API-0289, or any
		// prior `*-cov-*` slug, per the per-tag isolation rule
		// reasserted at API-0335 / API-0342 / API-0343 / API-0344
		// and originally established at API-0246
		// `organization-active`).
		//
		// Spec source `internal/api/data/openapi.json >
		// /server.security > get`: zero request body, a single
		// REQUIRED query parameter `serverId` (string), no path
		// parameters. Responses 200/400/401/403/404/500 — identical
		// shape to API-0339 `server-getDefaultCommand` and
		// API-0342 `server-one`. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// server/* peer.
		//
		// Fixture conventions:
		//   * Per-case fixture token base `srv-cov-security-0345`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     shared across the server/* roster and is unique
		//     (verified: no collisions with API-0339
		//     `server-getDefaultCommand`'s `srv-cov-getDefaultCommand-0339`
		//     query fixture, no collisions with API-0340
		//     `server-getServerMetrics`'s `srv-cov-getServerMetrics-0340`
		//     query fixtures, no collisions with API-0342
		//     `server-one`'s `srv-cov-one-0342` query fixture, no
		//     collisions with API-0344 `server-remove`'s
		//     `srv-cov-remove-0344` body fixture, and no collisions
		//     with the cross-tag `proj-cov-*` namespace reserved
		//     for the project/* roster).
		//   * `serverId` carries the fixture-shaped UUID-style
		//     literal `srv-cov-security-0345` rather than a real
		//     UUID so the wire payload cannot be mistaken for a
		//     real production server identifier; the server/* tag
		//     already established the `srv-cov-*` slug shape at
		//     API-0339, and re-using it here keeps the fixture
		//     diff-friendly.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec also declares 404 on this operation,
		// the per-tag opener convention reasserted at
		// API-0335..API-0344 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer (API-0342 `server-one`),
		// not for filter-by-serverId GETs like this one. Auth is
		// the universal failure mode every Dokploy operation must
		// re-prove, so 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// **Do not** copy the FailureStatus / FailureCode lines
		// from API-0342 — that was a one-time by-id-shaped GET
		// override.
		//
		// Future server/* mutation peers (API-0346 `server-setup`,
		// API-0347 `server-setupMonitoring`, API-0348
		// `server-update`) should grep API-0344 `server-remove`
		// first for the minimal-body POST shape; the next case in
		// the roster, API-0346 `server-setup`, returns to the
		// body-mutation shape and should follow API-0344's lead.
		// API-0349 `server-validate` is another single-required-
		// query-param GET and should mirror this entry verbatim
		// (only StoryID / OperationID / Path / fixture-slug
		// change).
		SampleQuery: map[string][]string{
			"serverId": {"srv-cov-security-0345"},
		},
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior server/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0346",
		OperationID: "server-setup",
		Method:      http.MethodPost,
		Path:        "/server.setup",
		Tag:         "server",
		// Twelfth entry on the server/* coverage roster and the
		// **third body-mutation peer** in the server/* tag (after
		// API-0338 `server-create` and API-0344 `server-remove`).
		// It returns to the POST body shape after the API-0345
		// `server-security` query-shaped GET. The API-0344
		// `server-remove` and API-0345 `server-security` forward-
		// reference comments both named API-0346 explicitly as the
		// next body-mutation re-introduction; this entry's fixture
		// slug `srv-cov-setup-0346` was reserved there.
		//
		// Inherits the `srv-cov-*` per-tag fixture-isolation
		// namespace established at API-0335 (must not back-reference
		// the `proj-cov-*` namespace from API-0290..API-0297, the
		// `org-cov-*` namespace from API-0246..API-0289, or any
		// prior `*-cov-*` slug, per the per-tag isolation rule
		// reasserted at API-0335 / API-0342 / API-0343 / API-0344 /
		// API-0345 and originally established at API-0246
		// `organization-active`).
		//
		// Spec source `internal/api/data/openapi.json > /server.setup
		// > post`: zero parameters, required `application/json`
		// request body whose schema declares a single REQUIRED
		// top-level scalar `serverId` (string) — **identical body
		// shape to API-0344 `server-remove`** (the smallest possible
		// body-mutation shape in the server/* tag, strictly smaller
		// than API-0338 `server-create`'s seven-required-field body).
		// No optionals, no nullables, no enums, no nested objects,
		// no arrays. This entry is a near-verbatim mirror of API-0344
		// — only StoryID / OperationID / Path / fixture-slug change.
		//
		// Responses 200/400/401/403/500 — note **no 404** is declared
		// on `/server.setup`, matching `/server.create` at API-0338
		// and `/server.remove` at API-0344, per the server/* mutation-
		// peer convention reasserted at API-0335..API-0345: 404 in
		// the server/* tag is reserved for the filter-shaped by-id
		// GET peer (API-0342 `server-one`), not for this setup
		// mutation. Even though `server-setup` semantically operates
		// on a serverId and could plausibly 404 on a missing record,
		// the embedded spec does not enumerate 404, so the failure
		// leg keeps the harness default 401 → CodeAuth — auth is the
		// universal failure mode every Dokploy operation must
		// re-prove. Future contributors should NOT pre-emptively
		// override to 404 here: exercise the documented contract,
		// not a speculative future tightening (the rule already
		// asserted for `*-publicIp` payloads at API-0343, for
		// `*-count` / `*-getServerTime` at API-0337 / API-0341, and
		// for `*-remove` at API-0344). The 200 schema is `{}` with
		// `additionalProperties: false`, so the success-leg envelope
		// assertion stays focused on `data.method` / `data.status`
		// rather than payload projection — same shape as every prior
		// server/* peer.
		//
		// Fixture conventions:
		//   * Per-case fixture token base `srv-cov-setup-0346`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     shared across the server/* roster and is unique
		//     (verified: no collisions with API-0338
		//     `server-create`'s `srv-cov-create-0338` body fixture,
		//     no collisions with API-0339 `server-getDefaultCommand`'s
		//     `srv-cov-getDefaultCommand-0339` query fixture, no
		//     collisions with API-0340 `server-getServerMetrics`'s
		//     `srv-cov-getServerMetrics-0340` query fixtures, no
		//     collisions with API-0342 `server-one`'s
		//     `srv-cov-one-0342` query fixture, no collisions with
		//     API-0344 `server-remove`'s `srv-cov-remove-0344` body
		//     fixture, no collisions with API-0345 `server-security`'s
		//     `srv-cov-security-0345` query fixture, and no
		//     collisions with the cross-tag `proj-cov-*` namespace
		//     reserved for the project/* roster).
		//   * `serverId` carries the fixture-shaped UUID-style
		//     literal `srv-cov-setup-0346` rather than a real UUID
		//     so the wire payload cannot be mistaken for a real
		//     production server identifier; the server/* tag
		//     already established the `srv-cov-*` slug shape at
		//     API-0339, and re-using it here keeps the fixture
		//     diff-friendly.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// API-0342 `server-one` 404 → CodeNotFound override was a
		// one-time, by-id-shaped GET assertion (per the per-tag
		// opener reservation at API-0290 / API-0294 / API-0335 and
		// the API-0342 design-rationale block, plus the API-0343 /
		// API-0344 / API-0345 re-anchor commentary). API-0346 is a
		// body mutation with no 404 declared in its response set,
		// so the universal 401 → CodeAuth failure stays the most
		// informative representative. The harness fall-through
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) covers this case; **do not** copy the
		// FailureStatus / FailureCode lines from API-0342.
		//
		// Future server/* mutation peers (API-0347
		// `server-setupMonitoring`, API-0348 `server-update`)
		// should mirror this entry verbatim — pure copy-and-rename,
		// only StoryID / OperationID / Path / fixture-slug change,
		// pending body-shape verification against the embedded
		// spec (do NOT trust forward-reference comments without
		// re-verifying against `internal/api/data/openapi.json`,
		// per the lesson learned at API-0345 where a forward-
		// reference incorrectly described the body shape).
		// API-0349 `server-validate` is a single-required-query-
		// param GET and should mirror API-0345 `server-security`
		// instead.
		SampleBody: json.RawMessage(`{
			"serverId": "srv-cov-setup-0346"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior server/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0347",
		OperationID: "server-setupMonitoring",
		Method:      http.MethodPost,
		Path:        "/server.setupMonitoring",
		Tag:         "server",
		// Thirteenth entry on the server/* coverage roster and the
		// **fourth body-mutation peer** in the server/* tag (after
		// API-0338 `server-create`, API-0344 `server-remove`, and
		// API-0346 `server-setup`). Returns to a body shape after
		// the API-0345 `server-security` query GET, and follows
		// API-0346's mutation re-introduction.
		//
		// Inherits the `srv-cov-*` per-tag fixture-isolation
		// namespace established at API-0335 (must not back-reference
		// the cross-tag `proj-cov-*` namespace from API-0290..API-0297,
		// the `org-cov-*` namespace from API-0246..API-0289, or any
		// prior `*-cov-*` slug, per the per-tag isolation rule
		// reasserted at API-0335 / API-0342 / API-0343 / API-0344 /
		// API-0345 / API-0346 and originally established at API-0246
		// `organization-active`).
		//
		// **Forward-reference correction.** The API-0346 `server-setup`
		// design block predicted that API-0347 should be a "pure
		// copy-and-rename" mirror of API-0346's single-required-
		// `serverId` body shape. Verifying the embedded spec
		// (`internal/api/data/openapi.json > /server.setupMonitoring
		// > post`) showed this prediction is **wrong**: the request
		// body declares TWO top-level required fields, `serverId`
		// (string) and `metricsConfig` (object), where `metricsConfig`
		// is a deeply nested schema with its own required children
		// (`server` and `containers`), and `metricsConfig.server`
		// declares seven required scalars (`refreshRate`, `port`,
		// `token`, `urlCallback`, `retentionDays`, `cronJob`,
		// `thresholds`) plus a required nested `thresholds` object
		// with required `cpu`/`memory` numbers; `metricsConfig.
		// containers` declares two required fields (`refreshRate`,
		// `services`). This is by far the largest body shape on the
		// server/* mutation roster — strictly larger than API-0338
		// `server-create`'s seven-flat-required-field body. The
		// fixture below populates **every** required leaf so the
		// payload satisfies the declared schema verbatim, even
		// though the harness today forwards bytes without server-
		// side validation. Re-anchors the rule from API-0345 that
		// `internal/api/data/openapi.json` is the single source of
		// truth and forward-reference comments must always be re-
		// verified before copying.
		//
		// Responses 200/400/401/403/500 — note **no 404** is declared
		// on `/server.setupMonitoring`, matching `/server.create`
		// (API-0338), `/server.remove` (API-0344), and `/server.setup`
		// (API-0346), per the server/* mutation-peer convention
		// reasserted at API-0335..API-0346: 404 in the server/* tag
		// is reserved for the filter-shaped by-id GET peer (API-0342
		// `server-one`), not for this monitoring-setup mutation.
		// Even though `server-setupMonitoring` semantically operates
		// on a serverId and could plausibly 404 on a missing record,
		// the embedded spec does not enumerate 404, so the failure
		// leg keeps the harness default 401 → CodeAuth — auth is
		// the universal failure mode every Dokploy operation must
		// re-prove. Future contributors should NOT pre-emptively
		// override to 404 here.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `srv-cov-setupMonitoring-0347` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared across
		//     the server/* roster and is unique (verified: no
		//     collisions with API-0338 `server-create`'s
		//     `srv-cov-create-0338`, API-0339
		//     `server-getDefaultCommand`'s
		//     `srv-cov-getDefaultCommand-0339`, API-0340
		//     `server-getServerMetrics`'s
		//     `srv-cov-getServerMetrics-0340`, API-0342 `server-one`'s
		//     `srv-cov-one-0342`, API-0344 `server-remove`'s
		//     `srv-cov-remove-0344`, API-0345 `server-security`'s
		//     `srv-cov-security-0345`, or API-0346 `server-setup`'s
		//     `srv-cov-setup-0346`, and orthogonal to the cross-tag
		//     `proj-cov-*` / `org-cov-*` namespaces).
		//   * `metricsConfig.server.token` carries the fixture
		//     literal `fixture-token-srv-cov-setupMonitoring-0347`
		//     so the wire payload cannot be confused with the test
		//     harness's resolved `--token` value (`test-token-value`,
		//     redacted by `output.NewRedactor`); the literal also
		//     does not match any `Authorization:` / `X-API-Key:` /
		//     query-param secret pattern the redactor scrubs, so
		//     the fixture round-trips cleanly through the success-
		//     leg body assertion.
		//   * `urlCallback` uses the IANA-reserved `example.invalid`
		//     domain so the literal cannot be mistaken for a real
		//     callback endpoint if it ever leaks into a log.
		//   * Numeric leaves use small, recognizable values (port
		//     9100 = node_exporter default; refreshRate/retentionDays
		//     = 30/7 days; cpu/memory thresholds = 80%) so the
		//     fixture documents the schema's intent at a glance.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// API-0342 `server-one` 404 → CodeNotFound override was a
		// one-time, by-id-shaped GET assertion; API-0347 is a body
		// mutation with no 404 declared in its response set, so the
		// universal 401 → CodeAuth failure stays the most informative
		// representative. The harness fall-through (`tc.FailureStatus
		// == 0` → 401, `tc.FailureCode == ""` → CodeAuth) covers
		// this case; **do not** copy the FailureStatus / FailureCode
		// lines from API-0342.
		//
		// Future server/* mutation peers (API-0348 `server-update`)
		// should NOT blindly mirror this entry — re-verify the body
		// shape against `internal/api/data/openapi.json` before
		// copying, per the API-0345 / API-0347 forward-reference
		// lesson. API-0349 `server-validate` is a single-required-
		// query-param GET and should mirror API-0345 `server-security`
		// instead. API-0350 `server-withSSHKey` is the next pending
		// server/* entry after that and its shape is unknown until
		// re-verified.
		SampleBody: json.RawMessage(`{
			"serverId": "srv-cov-setupMonitoring-0347",
			"metricsConfig": {
				"server": {
					"refreshRate": 30,
					"port": 9100,
					"token": "fixture-token-srv-cov-setupMonitoring-0347",
					"urlCallback": "https://example.invalid/yalla-cov-setupMonitoring-0347",
					"retentionDays": 7,
					"cronJob": "*/5 * * * *",
					"thresholds": {
						"cpu": 80,
						"memory": 80
					}
				},
				"containers": {
					"refreshRate": 60,
					"services": {
						"include": [],
						"exclude": []
					}
				}
			}
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior server/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0348",
		OperationID: "server-update",
		Method:      http.MethodPost,
		Path:        "/server.update",
		Tag:         "server",
		// Fourteenth entry on the server/* coverage roster and the
		// **fifth body-mutation peer** in the server/* tag (after
		// API-0338 `server-create`, API-0344 `server-remove`,
		// API-0346 `server-setup`, and API-0347
		// `server-setupMonitoring`). Inherits the `srv-cov-*` per-tag
		// fixture-isolation namespace established at API-0335 (must
		// not back-reference the cross-tag `proj-cov-*` / `org-cov-*`
		// namespaces, per the per-tag isolation rule reasserted at
		// API-0335..API-0347 and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345 / API-0347 forward-
		// reference lesson** against `internal/api/data/openapi.json
		// > /server.update > post`: zero parameters, required
		// `application/json` request body. The body shape is
		// effectively API-0338 `server-create`'s body **plus a new
		// required `serverId` (string) field** identifying the record
		// being updated, **plus an optional `command` (string)** that
		// is *not* in the `required` array. Every API-0338 required
		// field carries forward unchanged, including the
		// `description` / `sshKeyId` `anyOf [string, null]` nullables
		// and the `serverType` `["deploy", "build"]` enum.
		//   - REQUIRED scalars: `name` (string), `serverId` (string),
		//     `ipAddress` (string), `port` (number), `username`
		//     (string).
		//   - REQUIRED nullable scalars: `description`, `sshKeyId`
		//     (both `anyOf [string, null]`). Populated with strings
		//     (not `null` literals) per the API-0292 / API-0297 /
		//     API-0338 populated-string convention because a populated
		//     value proves the wire-forwarding invariant more strongly
		//     than a `null` would.
		//   - REQUIRED enum-constrained scalar: `serverType`. Pinned
		//     to `"deploy"` to match API-0338 `server-create`'s
		//     diff-friendly literal choice flagged forward at
		//     `internal/cli/api_coverage_test.go` lines 4031-4034.
		//   - OPTIONAL scalar: `command` (string). Populated per the
		//     API-0297 `project-update` "every-optional-populated"
		//     rule for `*-update` peers — populating optionals on an
		//     update mutation proves the schema's forward-compat
		//     branch end-to-end without making the fixture brittle.
		//
		// Body has no nested objects or arrays, so the wire shape
		// stays inside the "flat scalar-only mutation" contract
		// shared with API-0292 `project-create`, API-0297
		// `project-update`, and API-0338 `server-create` — strictly
		// smaller than API-0347 `server-setupMonitoring`'s deeply
		// nested `metricsConfig` body.
		//
		// Fixture conventions:
		//   * Per-case fixture token base `srv-cov-update-0348`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention and
		//     is unique (verified: no collisions with API-0338
		//     `server-create`'s `srv-cov-create-0338`, API-0339
		//     `server-getDefaultCommand`'s
		//     `srv-cov-getDefaultCommand-0339`, API-0340
		//     `server-getServerMetrics`'s
		//     `srv-cov-getServerMetrics-0340`, API-0342 `server-one`'s
		//     `srv-cov-one-0342`, API-0344 `server-remove`'s
		//     `srv-cov-remove-0344`, API-0345 `server-security`'s
		//     `srv-cov-security-0345`, API-0346 `server-setup`'s
		//     `srv-cov-setup-0346`, or API-0347
		//     `server-setupMonitoring`'s
		//     `srv-cov-setupMonitoring-0347`, and orthogonal to the
		//     cross-tag `proj-cov-*` / `org-cov-*` namespaces).
		//   * `ipAddress` carries an RFC 5737 documentation-only IP
		//     literal (`192.0.2.20`) distinct from API-0338
		//     `server-create`'s `192.0.2.10` so the fixture cannot be
		//     confused with the create-peer's wire payload during a
		//     diff review.
		//   * `port` carries the canonical Dokploy SSH port (22)
		//     mirroring API-0338 since the spec types it as a plain
		//     `number` with no range constraints.
		//   * The nullable `description` and `sshKeyId` are populated
		//     with `srv-cov-*` strings, not `null`, per the
		//     populated-string convention.
		//   * `command` carries a recognisable, non-destructive shell
		//     literal (`echo yalla-cov-update-0348`) so the fixture
		//     documents the schema's intent at a glance and could not
		//     be mistaken for a real production deploy command if it
		//     ever leaked into a log.
		//
		// Responses 200/400/401/403/500 — note **no 404** is declared
		// on `/server.update`, matching every server/* mutation peer
		// (API-0338, API-0344, API-0346, API-0347), per the server/*
		// mutation-peer convention reasserted at API-0335..API-0347:
		// 404 in the server/* tag is reserved for the filter-shaped
		// by-id GET peer (API-0342 `server-one`), not for this update
		// mutation. Even though `server-update` semantically operates
		// on a serverId and could plausibly 404 on a missing record,
		// the embedded spec does not enumerate 404, so the failure
		// leg keeps the harness default 401 → CodeAuth — auth is the
		// universal failure mode every Dokploy operation must re-
		// prove. **Do not** override to 404 here without re-verifying
		// the embedded spec.
		//
		// Future server/* peers (API-0349 `server-validate` is a
		// single-required-query-param GET that should mirror API-0345
		// `server-security`; API-0350 `server-withSSHKey`'s shape is
		// unknown until re-verified) should NOT blindly mirror this
		// entry — re-verify against `internal/api/data/openapi.json`
		// before copying, per the API-0345 / API-0347 forward-
		// reference lesson.
		SampleBody: json.RawMessage(`{
			"name": "yalla-coverage-srv-update-0348",
			"description": "yalla coverage fixture for srv-cov-update-0348 — deterministic, fake, never deployed",
			"serverId": "srv-cov-update-0348",
			"ipAddress": "192.0.2.20",
			"port": 22,
			"username": "yalla-coverage",
			"sshKeyId": "srv-cov-update-sshkey-0348",
			"serverType": "deploy",
			"command": "echo yalla-cov-update-0348"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior server/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0349",
		OperationID: "server-validate",
		Method:      http.MethodGet,
		Path:        "/server.validate",
		Tag:         "server",
		// Fifteenth entry on the server/* coverage roster and the
		// **fourth single-required-query-param GET** in the server/*
		// tag (after API-0339 `server-getDefaultCommand`, API-0342
		// `server-one`, and API-0345 `server-security`). It returns
		// to the query-shaped GET cohort after the four-peer body-
		// mutation run API-0344/0346/0347/0348. Inherits the
		// `srv-cov-*` per-tag fixture-isolation namespace established
		// at API-0335 (must not back-reference the cross-tag
		// `proj-cov-*` / `org-cov-*` namespaces, per the per-tag
		// isolation rule reasserted at API-0335..API-0348 and
		// originally established at API-0246 `organization-active`).
		//
		// **Spec re-verified per the API-0345 / API-0347 / API-0348
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /server.validate > get`:
		// zero request body, a single REQUIRED query parameter
		// `serverId` (string), no path parameters. Responses
		// 200/400/401/403/404/500 — byte-identical to
		// `/server.security > get` (verified at story authoring time
		// via `diff <(jq -S '.paths["/server.security"].get | del(.operationId)' …)
		// <(jq -S '.paths["/server.validate"].get | del(.operationId)' …)`,
		// which produced an empty diff). The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior server/*
		// peer. The API-0345 forward-reference comment explicitly
		// flagged this entry as a "verbatim mirror — only StoryID /
		// OperationID / Path / fixture-slug change", and that
		// prediction held: this is pure copy-and-rename.
		//
		// Fixture conventions:
		//   * Per-case fixture token base `srv-cov-validate-0349`
		//     follows the `<tag>-cov-<slug>-<storyID>` convention
		//     shared across the server/* roster and is unique
		//     (verified: no collisions with API-0339
		//     `server-getDefaultCommand`'s
		//     `srv-cov-getDefaultCommand-0339`, API-0340
		//     `server-getServerMetrics`'s
		//     `srv-cov-getServerMetrics-0340`, API-0342 `server-one`'s
		//     `srv-cov-one-0342`, API-0344 `server-remove`'s
		//     `srv-cov-remove-0344`, API-0345 `server-security`'s
		//     `srv-cov-security-0345`, API-0346 `server-setup`'s
		//     `srv-cov-setup-0346`, API-0347
		//     `server-setupMonitoring`'s
		//     `srv-cov-setupMonitoring-0347`, or API-0348
		//     `server-update`'s `srv-cov-update-0348`, and orthogonal
		//     to the cross-tag `proj-cov-*` / `org-cov-*` namespaces
		//     reserved for the project/* and organization/* rosters).
		//   * `serverId` carries the fixture-shaped UUID-style
		//     literal `srv-cov-validate-0349` rather than a real
		//     UUID so the wire payload cannot be mistaken for a
		//     real production server identifier; the server/* tag
		//     already established the `srv-cov-*` slug shape at
		//     API-0339, and re-using it here keeps the fixture
		//     diff-friendly.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec also declares 404 on this operation,
		// the per-tag opener convention reasserted at
		// API-0335..API-0348 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer (API-0342 `server-one`),
		// not for filter-by-serverId GETs like this one. Auth is
		// the universal failure mode every Dokploy operation must
		// re-prove, so 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// **Do not** copy the FailureStatus / FailureCode lines
		// from API-0342 — that was a one-time by-id-shaped GET
		// override.
		//
		// The next case in the server/* roster, API-0350
		// `server-withSSHKey`, closes out the server/* tag. Its
		// shape is unknown until re-verified — future contributors
		// should grep `internal/api/data/openapi.json >
		// /server.withSSHKey` first and re-verify the spec rather
		// than blindly mirroring this entry, per the API-0345 /
		// API-0347 / API-0348 forward-reference lesson.
		SampleQuery: map[string][]string{
			"serverId": {"srv-cov-validate-0349"},
		},
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior server/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0350",
		OperationID: "server-withSSHKey",
		Method:      http.MethodGet,
		Path:        "/server.withSSHKey",
		Tag:         "server",
		// Sixteenth and **final** entry on the server/* coverage
		// roster, closing out the tag opened at API-0335
		// `server-create`. Unlike the four single-required-query-param
		// GETs that came before it (API-0339 `server-getDefaultCommand`,
		// API-0342 `server-one`, API-0345 `server-security`, API-0349
		// `server-validate`), `/server.withSSHKey` is a
		// **parameter-free** GET — the spec declares zero parameters
		// and no request body, exactly mirroring the cross-tag
		// parameter-free GET cohort opened by API-0006 `ai-getAll`,
		// continued by API-0098 (`deployment-allCentralized`),
		// API-0246 (`organization-active`), and others. Inherits the
		// `srv-cov-*` per-tag fixture-isolation namespace established
		// at API-0335 (must not back-reference the cross-tag
		// `proj-cov-*` / `org-cov-*` namespaces, per the per-tag
		// isolation rule reasserted at API-0335..API-0349 and
		// originally established at API-0246 `organization-active`).
		//
		// **Spec re-verified per the API-0345 / API-0347 / API-0348 /
		// API-0349 forward-reference lesson** against
		// `internal/api/data/openapi.json > /server.withSSHKey > get`:
		// zero request body, zero parameters (no query, no path, no
		// header). Responses 200/400/401/403/404/500 — byte-identical
		// to `/ai.getAll > get` modulo the `tag` field (verified at
		// story authoring time via
		// `diff <(jq -S '.paths["/ai.getAll"].get | del(.operationId)' …)
		// <(jq -S '.paths["/server.withSSHKey"].get | del(.operationId)' …)`,
		// which produced a single-line diff on the `tag` array only).
		// The 200 schema is `{}` with `additionalProperties: false`,
		// matching every prior server/* peer. The API-0349
		// forward-reference comment explicitly flagged this entry as
		// having an unknown shape until re-verified — the spec check
		// confirmed it is **not** a copy-and-rename of API-0349's
		// single-required-query-param shape; instead it inherits the
		// parameter-free GET wire shape from API-0006 `ai-getAll`.
		// Future contributors writing the first entry of a new tag
		// should grep this entry first when encountering a
		// parameter-free GET — it is the most recent server/*
		// expression of that shape.
		//
		// Fixture conventions:
		//   * No per-case fixture token is allocated because the
		//     operation accepts no inputs — there is no slug to embed
		//     in a query value, path parameter, or request body.
		//     Future server/* peers should NOT introduce a
		//     `srv-cov-withSSHKey-0350` token retroactively; the
		//     parameter-free GET cohort precedent (API-0006
		//     `ai-getAll`, API-0246 `organization-active`) leaves
		//     SampleQuery / SamplePathParams / SampleBody all unset
		//     and the harness asserts the wire-level invariants
		//     (method, path, Authorization header, empty query
		//     string, empty body) at runAPICoverageSuccess without
		//     requiring fixture tokens.
		//   * The canonical agent invocation is therefore
		//     `yalla api call server-withSSHKey --input '{}' --json`,
		//     matching the no-input shape the agent contract
		//     guarantees.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec also declares 404 on this operation, the
		// per-tag opener convention reasserted at API-0335..API-0349
		// reserves 404 → CodeNotFound for the canonical by-id
		// `*-one` peer (API-0342 `server-one`), not for
		// parameter-free GETs like this one. Auth is the universal
		// failure mode every Dokploy operation must re-prove, so
		// 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// **Do not** copy the FailureStatus / FailureCode lines from
		// API-0342 — that was a one-time by-id-shaped GET override.
		//
		// This entry **closes out the server/* tag** (sixteen
		// stories, API-0335..API-0350). The next pending case in the
		// PRD roster is API-0351 `settings-assignDomainServer`, which
		// opens the settings/* tag and will introduce a fresh
		// `set-cov-*` per-tag fixture-isolation namespace orthogonal
		// to `srv-cov-*`. Future contributors authoring API-0351
		// should NOT mirror this entry's shape blindly: the
		// settings/* opener must re-verify its spec against
		// `internal/api/data/openapi.json > /settings.assignDomainServer`
		// per the API-0345 / API-0347 / API-0348 / API-0349 / this
		// forward-reference lesson.
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior server/* peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0351",
		OperationID: "settings-assignDomainServer",
		Method:      http.MethodPost,
		Path:        "/settings.assignDomainServer",
		Tag:         "settings",
		// **First** entry on the settings/* coverage roster, opening
		// the tag in the same way API-0335 `server-create` opened
		// server/* and API-0246 `organization-active` opened
		// organization/*. As a tag-opener it **establishes a fresh
		// per-tag fixture-isolation namespace** (`set-cov-*`)
		// orthogonal to every prior tag's namespace. Subsequent
		// settings/* peers (API-0352 `settings-checkGPUStatus`,
		// API-0353 `settings-cleanAll`, API-0354
		// `settings-cleanAllDeploymentQueue`, API-0355
		// `settings-cleanDockerBuilder`, etc.) must inherit
		// `set-cov-*` and never back-reference the closed
		// `srv-cov-*` (server/*), `proj-cov-*` (project/*),
		// `org-cov-*` (organization/*), `compose-cov-*`,
		// `app-cov-*`, `ai-cov-*`, or any other prior namespace —
		// per the per-tag isolation rule reasserted at
		// API-0335..API-0350 and originally established at
		// API-0246 `organization-active`.
		//
		// **Spec re-verified per the API-0345 / API-0347 / API-0348 /
		// API-0349 / API-0350 forward-reference lesson** against
		// `internal/api/data/openapi.json > /settings.assignDomainServer
		// > post`: requestBody.required = true, content
		// `application/json` with object schema declaring four
		// properties — `host` (string, **required**),
		// `certificateType` (string enum
		// `letsencrypt|none|custom`, **required**),
		// `letsEncryptEmail` (anyOf string-or-empty-string-or-null,
		// optional), `https` (boolean, optional). Zero parameters
		// (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**
		// (settings is a singleton, not a by-id resource), which
		// confirms the per-tag opener convention that 404 →
		// CodeNotFound is reserved for `*-one` peers, not the
		// settings opener. The 200 schema is `{}` with
		// `additionalProperties: false`, matching the cross-tag
		// success-shape precedent set by API-0001
		// `admin-setupMonitoring`, API-0335 `server-create`, etc.
		//
		// Fixture conventions:
		//   * Per-case fixture token base `set-cov-assignDomainServer-0351`,
		//     suffixed by the field role for collision safety:
		//     `set-cov-assignDomainServer-0351.example.test` for the
		//     `host` slot (a fully-qualified DNS-shaped string the
		//     server expects), and
		//     `set-cov-assignDomainServer-0351@example.test` for the
		//     `letsEncryptEmail` slot (an email-shaped string).
		//     Both are **deterministic-but-clearly-fake** and live
		//     only in a per-test `t.TempDir()` `--input` JSON file
		//     so the values cannot leak across cases. Future
		//     settings/* peers needing fixtures must keep the
		//     `set-cov-*` namespace and never back-reference any
		//     prior tag's namespace.
		//   * `certificateType` is fixed to `"none"` (the safest
		//     enum member — the literal `"letsencrypt"` would imply
		//     the fixture wanted to provision a cert, and
		//     `"custom"` would imply the fixture supplied a custom
		//     cert payload; `"none"` keeps the wire shape minimal
		//     while still satisfying the required-enum constraint).
		//   * `https` is set to `false` to keep the fixture in the
		//     no-TLS branch, mirroring the `"none"` certificate
		//     choice.
		//   * Optional `letsEncryptEmail` is supplied even though
		//     the field is optional, per the API-0004
		//     `ai-deploy` convention reasserted across server/* —
		//     populating optionals with deterministic-but-clearly-fake
		//     values exercises the JSON serialiser's optional-field
		//     branch on the wire.
		//
		// **Failure-leg fields are intentionally omitted.** Auth is
		// the universal failure mode every Dokploy operation must
		// re-prove, so 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; this opener uses the canonical 401.
		//
		// This entry **opens the settings/* tag**. Future
		// contributors authoring API-0352 `settings-checkGPUStatus`
		// (the next settings/* peer, a parameter-free GET) should
		// grep this entry first for the
		// `set-cov-assignDomainServer-0351` fixture-token namespace
		// pattern and re-verify the spec per the forward-reference
		// lesson — `settings-checkGPUStatus` is shaped like a
		// parameter-free GET (cf. API-0006 `ai-getAll`, API-0350
		// `server-withSSHKey`) and not like this POST-with-body
		// opener.
		SampleBody: json.RawMessage(`{
			"host": "set-cov-assignDomainServer-0351.example.test",
			"certificateType": "none",
			"letsEncryptEmail": "set-cov-assignDomainServer-0351@example.test",
			"https": false
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior tag-opener peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0352",
		OperationID: "settings-checkGPUStatus",
		Method:      http.MethodGet,
		Path:        "/settings.checkGPUStatus",
		Tag:         "settings",
		// Second entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0351
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345 / API-0347 / API-0348 /
		// API-0349 / API-0350 / API-0351 forward-reference lesson**
		// against
		// `internal/api/data/openapi.json > /settings.checkGPUStatus
		// > get`: zero request body, a single **OPTIONAL** query
		// parameter `serverId` (string, **no `required: true`**),
		// no path parameters. Responses 200/400/401/403/404/500.
		// The structural shape is byte-identical to
		// `/server.validate > get` modulo the `tag` array and the
		// `serverId` `required` flag, verified at story authoring
		// time via
		// `diff <(jq -S '.paths["/server.validate"].get | del(.operationId)' …)
		// <(jq -S '.paths["/settings.checkGPUStatus"].get | del(.operationId)' …)`,
		// which produced exactly two-line drift: the `required:
		// true` line absent here, and `"server"` → `"settings"` in
		// the `tag` array. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer.
		//
		// **Forward-reference correction.** API-0351's comment
		// predicted this entry would be a parameter-free GET
		// (cf. API-0006 `ai-getAll`, API-0350 `server-withSSHKey`).
		// The re-verification turned up a single-OPTIONAL-query-
		// param shape instead — closer to API-0349 `server-validate`
		// but with the `required` constraint relaxed. This is the
		// latest iteration of the "always re-verify the spec
		// before mirroring" lesson (API-0345/0347/0348/0349/0350
		// each surfaced the same correction). Future settings/*
		// peers should grep this entry first when encountering a
		// single-query-param GET, but must not assume `serverId`
		// is required — the optional/required distinction is
		// per-operation and a no-op on the wire when populated
		// (the `required` flag drives the OpenAPI client's
		// pre-flight validation, not the HTTP handshake).
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-checkGPUStatus-0352` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351
		//     `settings-assignDomainServer`'s
		//     `set-cov-assignDomainServer-0351` slug, and
		//     orthogonal to every prior tag's `srv-cov-*`,
		//     `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		//     `app-cov-*`, `ai-cov-*`, etc. namespaces).
		//   * `serverId` carries the fixture-shaped literal
		//     `set-cov-checkGPUStatus-0352` rather than a real
		//     UUID so the wire payload cannot be mistaken for a
		//     real production server identifier. Even though the
		//     parameter is optional in the spec, populating it
		//     exercises the query-string wire path through the
		//     raw API executor — leaving it unset would degrade
		//     this case to the parameter-free GET cohort
		//     (API-0006 `ai-getAll`, API-0350 `server-withSSHKey`)
		//     and lose the query-forwarding round-trip assertion
		//     that distinguishes this shape.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec also declares 404 on this operation,
		// the per-tag opener convention reasserted at
		// API-0335..API-0351 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for filter-by-serverId
		// GETs like this one. Auth is the universal failure mode
		// every Dokploy operation must re-prove, so 401 → CodeAuth
		// via the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative.
		//
		// The next case in the settings/* roster, API-0353
		// `settings-cleanAll`, is a POST with `requestBody.required
		// = false` and an optional `serverId` body field (zero
		// parameters, responses 200/400/401/403/500 — note the
		// **absence of 404**, matching the API-0351 opener's
		// response set, not this entry's). Future contributors
		// authoring API-0353 should grep this entry first for the
		// `set-cov-*` namespace inheritance pattern, then
		// re-verify the spec against
		// `internal/api/data/openapi.json > /settings.cleanAll >
		// post` per the forward-reference lesson — the body shape
		// is materially different (POST with optional body, not
		// GET with optional query).
		SampleQuery: map[string][]string{
			"serverId": {"set-cov-checkGPUStatus-0352"},
		},
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0353",
		OperationID: "settings-cleanAll",
		Method:      http.MethodPost,
		Path:        "/settings.cleanAll",
		Tag:         "settings",
		// Third entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0352
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0352
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /settings.cleanAll
		// > post`: a single **OPTIONAL** `requestBody`
		// (`requestBody.required = false`) carrying a JSON object
		// with one optional string property `serverId` and no
		// `required` array; **zero parameters** (no query, no
		// path, no header). Responses 200/400/401/403/500 — note
		// the **absence of 404**, mirroring the API-0351 opener's
		// response set rather than API-0352's by-id-flavoured
		// 404-bearing response set. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer.
		//
		// **Forward-reference correction.** API-0352's comment
		// correctly predicted this entry's POST-with-optional-body
		// shape (the prediction is the canonical form: an optional
		// body carrying an optional `serverId` field, vs API-0352's
		// optional query parameter of the same name). The forward
		// reference held this time, but per the
		// API-0345/0347/0348/0349/0350 lesson the spec was still
		// re-verified against the embedded openapi.json before the
		// fixture was authored. Future settings/* peers (API-0354
		// `settings-cleanAllDeploymentQueue`, API-0355
		// `settings-cleanDockerBuilder`, etc.) should grep this
		// entry first when encountering an optional-body POST and
		// must always re-verify the spec — the optional/required
		// distinction is per-operation and the wire payload is
		// shaped by the body schema, not by the inheritance chain.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-cleanAll-0353` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351
		//     `set-cov-assignDomainServer-0351` or API-0352
		//     `set-cov-checkGPUStatus-0352` slugs, and orthogonal
		//     to every prior tag's `srv-cov-*`, `proj-cov-*`,
		//     `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		//     `ai-cov-*`, etc. namespaces).
		//   * `serverId` carries the fixture-shaped literal
		//     `set-cov-cleanAll-0353` rather than a real UUID so
		//     the wire payload cannot be mistaken for a real
		//     production server identifier. Even though the body
		//     and the `serverId` field are both optional in the
		//     spec, populating both exercises the JSON
		//     serialiser's optional-body branch on the wire and
		//     keeps the success-leg `Content-Type: application/json`
		//     header assertion meaningful — leaving the body unset
		//     would degrade this case to the parameter-free POST
		//     cohort (which has no Content-Type assertion) and
		//     lose the body-forwarding round-trip assertion that
		//     distinguishes this shape from API-0352's
		//     query-parameter shape.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `cleanAll` verb is a fleet-wide, optional-server-scoped
		// operation, not a by-id resource lookup), so the per-tag
		// opener convention reasserted at API-0335..API-0352 that
		// reserves 404 → CodeNotFound for canonical `*-one` peers
		// does not even apply here. Auth is the universal failure
		// mode every Dokploy operation must re-prove, so 401 →
		// CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; this entry uses the canonical 401.
		//
		// The next case in the settings/* roster, API-0354
		// `settings-cleanAllDeploymentQueue`, is also a POST per
		// the verb's `clean*` family pattern. Future contributors
		// authoring API-0354 should grep this entry first for the
		// `set-cov-*` namespace inheritance pattern, then
		// re-verify the spec against
		// `internal/api/data/openapi.json >
		// /settings.cleanAllDeploymentQueue > post` per the
		// forward-reference lesson — do **not** assume the body
		// shape mirrors this entry's `{serverId}` schema.
		SampleBody: json.RawMessage(`{
			"serverId": "set-cov-cleanAll-0353"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0354",
		OperationID: "settings-cleanAllDeploymentQueue",
		Method:      http.MethodPost,
		Path:        "/settings.cleanAllDeploymentQueue",
		Tag:         "settings",
		// Fourth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0353
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0353
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.cleanAllDeploymentQueue > post`: **no
		// `requestBody` field at all** (this is structurally
		// stronger than API-0353 `settings-cleanAll`'s
		// `requestBody.required = false` carrying an optional
		// `serverId` body — here the spec declares no request body
		// schema whatsoever, so the operation is a true no-input
		// POST), **zero parameters** (no query, no path, no
		// header). Responses 200/400/401/403/500 — note the
		// **absence of 404**, mirroring the API-0351 opener's and
		// API-0353's response sets rather than API-0352's by-id-
		// flavoured 404-bearing response set. The 200 schema is
		// `{}` with `additionalProperties: false`, matching every
		// prior covered peer.
		//
		// **Forward-reference correction.** API-0353's comment
		// predicted this entry would be a POST per the
		// `clean*`-family verb pattern but explicitly cautioned
		// against assuming the body shape mirrored API-0353's
		// `{serverId}` schema. The re-verification confirmed the
		// caution: this operation has *no* request body at all,
		// degenerating from API-0353's optional-body shape to the
		// parameter-free POST cohort. This is a brand-new shape on
		// the coverage corpus — it is **the first parameter-free,
		// no-request-body POST entry across all
		// `coveredAPIOperations`** (a `git grep`/`rg` for prior
		// `Method:.*MethodPost` blocks lacking `SampleBody`,
		// `SampleQuery`, and `SamplePathParams` returns this entry
		// alone). The harness handles it correctly: when
		// `len(tc.SampleBody) == 0`, `runAPICoverageSuccess`
		// skips the `Content-Type` and body-round-trip assertions
		// (see the `if len(tc.SampleBody) > 0` guard) and the
		// success leg still asserts method, path, Authorization
		// header, empty query string, schema_version,
		// data.operation_id, data.method, and data.status — all
		// the wire-level invariants the agent contract guarantees
		// for `yalla api call settings-cleanAllDeploymentQueue
		// --input '{}' --json`. Future contributors authoring
		// API-0355 `settings-cleanDockerBuilder` etc. should grep
		// this entry first when encountering a no-body POST in
		// the settings/* `clean*` family — the harness pattern
		// here is the canonical form for that sub-cohort.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-cleanAllDeploymentQueue-0354` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351
		//     `set-cov-assignDomainServer-0351`, API-0352
		//     `set-cov-checkGPUStatus-0352`, or API-0353
		//     `set-cov-cleanAll-0353` slugs, and orthogonal to
		//     every prior tag's `srv-cov-*`, `proj-cov-*`,
		//     `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		//     `ai-cov-*`, etc. namespaces). Even though no
		//     fixture-token literal is materialised on the wire
		//     (the operation has no body and no parameters), the
		//     slug is reserved for this story to keep the per-tag
		//     cross-reference grep useful for future
		//     contributors.
		//   * **Neither `SampleBody`, `SampleQuery`, nor
		//     `SamplePathParams` are populated** — the spec
		//     declares no body and no parameters, and inventing a
		//     fictional body would (a) violate the
		//     re-verify-the-spec rule reasserted across
		//     API-0345..API-0353, (b) cause `runAPICoverageSuccess`
		//     to assert a body round-trip the CLI would never
		//     send, and (c) waste the no-body branch coverage this
		//     entry uniquely provides. The harness still asserts
		//     the wire-level invariants (method, path,
		//     Authorization header) — the no-body POST cohort is
		//     not a coverage gap.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `cleanAllDeploymentQueue` verb is a fleet-wide queue
		// purge, not a by-id resource lookup), so the per-tag
		// opener convention reasserted at API-0335..API-0353 that
		// reserves 404 → CodeNotFound for canonical `*-one` peers
		// does not even apply here. Auth is the universal failure
		// mode every Dokploy operation must re-prove, so 401 →
		// CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; this entry uses the canonical 401.
		//
		// The next case in the settings/* roster, API-0355
		// `settings-cleanDockerBuilder`, is also a POST per the
		// verb's `clean*` family pattern. Future contributors
		// authoring API-0355 should grep this entry first for the
		// `set-cov-*` namespace inheritance pattern and the
		// no-body POST harness handling, then re-verify the spec
		// against `internal/api/data/openapi.json >
		// /settings.cleanDockerBuilder > post` per the
		// forward-reference lesson — do **not** assume the body
		// shape mirrors this entry's no-body schema, API-0353's
		// `{serverId}` schema, or API-0351's
		// `{host,certificateType,...}` schema. The optional/
		// required distinction is per-operation and only the spec
		// is authoritative.
		//
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0355",
		OperationID: "settings-cleanDockerBuilder",
		Method:      http.MethodPost,
		Path:        "/settings.cleanDockerBuilder",
		Tag:         "settings",
		// Fifth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0354
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0354
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.cleanDockerBuilder > post`: a single
		// **OPTIONAL** `requestBody` (`requestBody.required =
		// false`) carrying a JSON object with one optional string
		// property `serverId` and no `required` array; **zero
		// parameters** (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**,
		// mirroring the API-0351 opener / API-0353 / API-0354
		// response sets rather than API-0352's by-id-flavoured
		// 404-bearing response set. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer.
		//
		// **Forward-reference correction.** API-0354's comment
		// cautioned against assuming this entry's body shape
		// would mirror its own no-body schema, API-0353's
		// `{serverId}` schema, or API-0351's
		// `{host,certificateType,...}` schema. Re-verification
		// confirmed the spec here is byte-identical to API-0353
		// `settings-cleanAll` — optional body carrying an optional
		// `serverId` string — NOT API-0354's no-body shape. The
		// `clean*` family in settings/* therefore splits into two
		// sub-cohorts on the wire: (a) optional-body POSTs with an
		// optional `serverId` (API-0353 cleanAll, API-0355
		// cleanDockerBuilder, and per-spec also API-0356
		// cleanDockerPrune which carries the same shape), and (b)
		// no-body POSTs (API-0354 cleanAllDeploymentQueue,
		// API-0357 cleanMonitoring, API-0358 cleanRedis,
		// API-0359 cleanSSHPrivateKey — verified directly against
		// the embedded openapi.json `requestBody` absence). The
		// optional/required distinction is per-operation; future
		// settings/* peers must always re-verify the spec before
		// authoring the fixture, the `clean*` verb prefix alone is
		// not authoritative.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-cleanDockerBuilder-0355` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351
		//     `set-cov-assignDomainServer-0351`, API-0352
		//     `set-cov-checkGPUStatus-0352`, API-0353
		//     `set-cov-cleanAll-0353`, or API-0354
		//     `set-cov-cleanAllDeploymentQueue-0354` slugs, and
		//     orthogonal to every prior tag's `srv-cov-*`,
		//     `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		//     `app-cov-*`, `ai-cov-*`, etc. namespaces).
		//   * `serverId` carries the fixture-shaped literal
		//     `set-cov-cleanDockerBuilder-0355` rather than a real
		//     UUID so the wire payload cannot be mistaken for a
		//     real production server identifier. Even though the
		//     body and the `serverId` field are both optional in
		//     the spec, populating both exercises the JSON
		//     serialiser's optional-body branch on the wire and
		//     keeps the success-leg `Content-Type: application/json`
		//     header assertion meaningful — leaving the body unset
		//     would degrade this case to the parameter-free POST
		//     cohort (which has no Content-Type assertion) and
		//     lose the body-forwarding round-trip assertion that
		//     distinguishes this shape from API-0354's no-body
		//     shape.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `cleanDockerBuilder` verb is a fleet-wide, optional-
		// server-scoped operation, not a by-id resource lookup),
		// so the per-tag opener convention reasserted at
		// API-0335..API-0354 that reserves 404 → CodeNotFound for
		// canonical `*-one` peers does not even apply here. Auth
		// is the universal failure mode every Dokploy operation
		// must re-prove, so 401 → CodeAuth via the harness
		// default (`tc.FailureStatus == 0` → 401, `tc.FailureCode
		// == ""` → CodeAuth) stays the most informative
		// representative. 400 → CodeInvalidInput stays reserved
		// for stories where payload validation is the operation's
		// distinguishing failure mode; this entry uses the
		// canonical 401.
		//
		// The next case in the settings/* roster, API-0356
		// `settings-cleanDockerPrune`, is also a POST per the
		// verb's `clean*` family pattern and per direct spec
		// inspection carries the same optional-body shape as this
		// entry. Future contributors authoring API-0356 should
		// grep this entry first for the `set-cov-*` namespace
		// inheritance pattern and the optional-body POST harness
		// handling, then re-verify the spec against
		// `internal/api/data/openapi.json >
		// /settings.cleanDockerPrune > post` per the
		// forward-reference lesson — do **not** assume the body
		// shape mirrors this entry's `{serverId}` schema solely
		// because the verb prefix matches; API-0354 already
		// established that two `clean*` siblings can diverge on
		// the body axis.
		SampleBody: json.RawMessage(`{
			"serverId": "set-cov-cleanDockerBuilder-0355"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0356",
		OperationID: "settings-cleanDockerPrune",
		Method:      http.MethodPost,
		Path:        "/settings.cleanDockerPrune",
		Tag:         "settings",
		// Sixth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0355
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0355
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.cleanDockerPrune > post`: a single
		// **OPTIONAL** `requestBody` (`requestBody.required =
		// false`) carrying a JSON object with one optional string
		// property `serverId` and no `required` array; **zero
		// parameters** (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**,
		// mirroring the API-0351 opener / API-0353 / API-0354 /
		// API-0355 response sets rather than API-0352's
		// by-id-flavoured 404-bearing response set. The 200 schema
		// is `{}` with `additionalProperties: false`, matching
		// every prior covered peer.
		//
		// **Forward-reference confirmation.** API-0355's comment
		// predicted this entry would carry the same optional-body
		// shape as cleanDockerBuilder while still demanding
		// per-spec re-verification. Direct inspection confirms the
		// schemas are byte-identical: optional `requestBody` whose
		// content is a JSON object with one optional `serverId:
		// string` property and no `required` array. The `clean*`
		// family in settings/* therefore continues to split into
		// two sub-cohorts on the wire: (a) optional-body POSTs
		// with an optional `serverId` (API-0353 cleanAll, API-0355
		// cleanDockerBuilder, and now API-0356 cleanDockerPrune),
		// and (b) no-body POSTs (API-0354 cleanAllDeploymentQueue,
		// API-0357 cleanMonitoring, API-0358 cleanRedis, API-0359
		// cleanSSHPrivateKey — verified directly against the
		// embedded openapi.json `requestBody` absence). The
		// optional/required distinction remains per-operation;
		// future settings/* peers must always re-verify the spec
		// before authoring the fixture, the `clean*` verb prefix
		// alone is not authoritative.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-cleanDockerPrune-0356` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351
		//     `set-cov-assignDomainServer-0351`, API-0352
		//     `set-cov-checkGPUStatus-0352`, API-0353
		//     `set-cov-cleanAll-0353`, API-0354
		//     `set-cov-cleanAllDeploymentQueue-0354`, or API-0355
		//     `set-cov-cleanDockerBuilder-0355` slugs, and
		//     orthogonal to every prior tag's `srv-cov-*`,
		//     `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		//     `app-cov-*`, `ai-cov-*`, etc. namespaces).
		//   * `serverId` carries the fixture-shaped literal
		//     `set-cov-cleanDockerPrune-0356` rather than a real
		//     UUID so the wire payload cannot be mistaken for a
		//     real production server identifier. Even though the
		//     body and the `serverId` field are both optional in
		//     the spec, populating both exercises the JSON
		//     serialiser's optional-body branch on the wire and
		//     keeps the success-leg `Content-Type: application/json`
		//     header assertion meaningful — leaving the body unset
		//     would degrade this case to the parameter-free POST
		//     cohort (which has no Content-Type assertion) and
		//     lose the body-forwarding round-trip assertion that
		//     distinguishes this shape from API-0354's no-body
		//     shape.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `cleanDockerPrune` verb is a fleet-wide, optional-
		// server-scoped Docker prune operation, not a by-id
		// resource lookup), so the per-tag opener convention
		// reasserted at API-0335..API-0355 that reserves 404 →
		// CodeNotFound for canonical `*-one` peers does not even
		// apply here. Auth is the universal failure mode every
		// Dokploy operation must re-prove, so 401 → CodeAuth via
		// the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput
		// stays reserved for stories where payload validation is
		// the operation's distinguishing failure mode; this entry
		// uses the canonical 401.
		//
		// The next case in the settings/* roster, API-0357
		// `settings-cleanMonitoring`, is also a POST per the
		// verb's `clean*` family pattern but per direct spec
		// inspection carries **no** `requestBody` at all — the
		// no-body sub-cohort referenced above. Future contributors
		// authoring API-0357 should grep this entry first for the
		// `set-cov-*` namespace inheritance pattern, then re-
		// verify the spec against `internal/api/data/openapi.json
		// > /settings.cleanMonitoring > post` per the forward-
		// reference lesson — do **not** assume the body shape
		// mirrors this entry's `{serverId}` schema solely because
		// the verb prefix matches; API-0354 already established
		// that two `clean*` siblings can diverge on the body axis.
		SampleBody: json.RawMessage(`{
			"serverId": "set-cov-cleanDockerPrune-0356"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0357",
		OperationID: "settings-cleanMonitoring",
		Method:      http.MethodPost,
		Path:        "/settings.cleanMonitoring",
		Tag:         "settings",
		// Seventh entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0356
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0356
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.cleanMonitoring > post`: **no `requestBody`
		// field at all** (this is structurally stronger than
		// API-0353 `settings-cleanAll` / API-0355
		// `settings-cleanDockerBuilder` / API-0356
		// `settings-cleanDockerPrune`'s `requestBody.required =
		// false` carrying an optional `serverId` body — here the
		// spec declares no request body schema whatsoever, so the
		// operation is a true no-input POST), **zero parameters**
		// (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**,
		// mirroring the API-0351 opener / API-0353 / API-0354 /
		// API-0355 / API-0356 response sets rather than API-0352's
		// by-id-flavoured 404-bearing response set. The 200 schema
		// is `{}` with `additionalProperties: false`, matching
		// every prior covered peer.
		//
		// **Forward-reference confirmation.** API-0356's comment
		// predicted this entry would carry **no** `requestBody` at
		// all — i.e. degenerate from the optional-body sub-cohort
		// (API-0353 cleanAll, API-0355 cleanDockerBuilder, API-0356
		// cleanDockerPrune) into the no-body sub-cohort seeded by
		// API-0354 `settings-cleanAllDeploymentQueue`. Direct
		// inspection of `internal/api/data/openapi.json >
		// /settings.cleanMonitoring > post` confirms the prediction:
		// the operation has no `requestBody` key whatsoever, exactly
		// the API-0354 shape. The `clean*` family in settings/*
		// therefore continues to split into two sub-cohorts on the
		// wire: (a) optional-body POSTs with an optional `serverId`
		// (API-0353 cleanAll, API-0355 cleanDockerBuilder, API-0356
		// cleanDockerPrune), and (b) no-body POSTs (API-0354
		// cleanAllDeploymentQueue, and now API-0357 cleanMonitoring;
		// API-0358 cleanRedis and API-0359 cleanSSHPrivateKey are
		// also in this sub-cohort per the verified spec). The
		// optional/required distinction is per-operation; future
		// settings/* peers must always re-verify the spec before
		// authoring the fixture, the `clean*` verb prefix alone is
		// not authoritative.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-cleanMonitoring-0357` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351
		//     `set-cov-assignDomainServer-0351`, API-0352
		//     `set-cov-checkGPUStatus-0352`, API-0353
		//     `set-cov-cleanAll-0353`, API-0354
		//     `set-cov-cleanAllDeploymentQueue-0354`, API-0355
		//     `set-cov-cleanDockerBuilder-0355`, or API-0356
		//     `set-cov-cleanDockerPrune-0356` slugs, and orthogonal
		//     to every prior tag's `srv-cov-*`, `proj-cov-*`,
		//     `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		//     etc. namespaces). Even though no fixture-token literal
		//     is materialised on the wire (the operation has no body
		//     and no parameters), the slug is reserved for this
		//     story to keep the per-tag cross-reference grep useful
		//     for future contributors.
		//   * **Neither `SampleBody`, `SampleQuery`, nor
		//     `SamplePathParams` are populated** — the spec
		//     declares no body and no parameters, and inventing a
		//     fictional body would (a) violate the
		//     re-verify-the-spec rule reasserted across
		//     API-0345..API-0356, (b) cause `runAPICoverageSuccess`
		//     to assert a body round-trip the CLI would never
		//     send, and (c) waste the no-body branch coverage this
		//     entry shares with API-0354. The harness still asserts
		//     the wire-level invariants (method, path,
		//     Authorization header) — the no-body POST cohort is
		//     not a coverage gap. See API-0354's narration for the
		//     canonical no-body POST harness handling.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `cleanMonitoring` verb is a fleet-wide monitoring purge,
		// not a by-id resource lookup), so the per-tag opener
		// convention reasserted at API-0335..API-0356 that reserves
		// 404 → CodeNotFound for canonical `*-one` peers does not
		// even apply here. Auth is the universal failure mode every
		// Dokploy operation must re-prove, so 401 → CodeAuth via
		// the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput stays
		// reserved for stories where payload validation is the
		// operation's distinguishing failure mode; this entry uses
		// the canonical 401.
		//
		// The next case in the settings/* roster, API-0358
		// `settings-cleanRedis`, is also a POST per the verb's
		// `clean*` family pattern and per direct spec inspection
		// also carries **no** `requestBody` — i.e. shares the
		// no-body sub-cohort with this entry. Future contributors
		// authoring API-0358 should grep this entry first for the
		// `set-cov-*` namespace inheritance pattern and the
		// no-body POST harness handling, then re-verify the spec
		// against `internal/api/data/openapi.json >
		// /settings.cleanRedis > post` per the forward-reference
		// lesson — do **not** assume the body shape mirrors this
		// entry's no-body schema solely because the verb prefix
		// matches; API-0354 → API-0355 already established that
		// two `clean*` siblings can diverge on the body axis in
		// either direction.
		//
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0358",
		OperationID: "settings-cleanRedis",
		Method:      http.MethodPost,
		Path:        "/settings.cleanRedis",
		Tag:         "settings",
		// Eighth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0357
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0357
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /settings.cleanRedis >
		// post`: **no `requestBody` field at all** (matches API-0354
		// `settings-cleanAllDeploymentQueue` and API-0357
		// `settings-cleanMonitoring`; structurally stronger than
		// API-0353 `settings-cleanAll` / API-0355
		// `settings-cleanDockerBuilder` / API-0356
		// `settings-cleanDockerPrune`'s `requestBody.required = false`
		// carrying an optional `serverId` body — here the spec
		// declares no request body schema whatsoever, so the
		// operation is a true no-input POST), **zero parameters**
		// (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**, mirroring
		// the API-0351 opener / API-0353 / API-0354 / API-0355 /
		// API-0356 / API-0357 response sets rather than API-0352's
		// by-id-flavoured 404-bearing response set. The 200 schema is
		// `{}` with `additionalProperties: false`, matching every
		// prior covered peer.
		//
		// **Forward-reference confirmation.** API-0357's comment
		// predicted this entry would carry **no** `requestBody` at
		// all — i.e. continue the no-body sub-cohort seeded by
		// API-0354 `settings-cleanAllDeploymentQueue` and re-asserted
		// by API-0357 `settings-cleanMonitoring`. Direct inspection
		// of `internal/api/data/openapi.json > /settings.cleanRedis >
		// post` confirms the prediction: the operation has no
		// `requestBody` key whatsoever, exactly the API-0354 /
		// API-0357 shape. The `clean*` family in settings/* therefore
		// continues to split into two sub-cohorts on the wire:
		// (a) optional-body POSTs with an optional `serverId`
		// (API-0353 cleanAll, API-0355 cleanDockerBuilder, API-0356
		// cleanDockerPrune), and (b) no-body POSTs (API-0354
		// cleanAllDeploymentQueue, API-0357 cleanMonitoring, and now
		// API-0358 cleanRedis; API-0359 cleanSSHPrivateKey is also in
		// this sub-cohort per the verified spec). The
		// optional/required distinction is per-operation; future
		// settings/* peers must always re-verify the spec before
		// authoring the fixture, the `clean*` verb prefix alone is
		// not authoritative.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-cleanRedis-0358` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351
		//     `set-cov-assignDomainServer-0351`, API-0352
		//     `set-cov-checkGPUStatus-0352`, API-0353
		//     `set-cov-cleanAll-0353`, API-0354
		//     `set-cov-cleanAllDeploymentQueue-0354`, API-0355
		//     `set-cov-cleanDockerBuilder-0355`, API-0356
		//     `set-cov-cleanDockerPrune-0356`, or API-0357
		//     `set-cov-cleanMonitoring-0357` slugs, and orthogonal
		//     to every prior tag's `srv-cov-*`, `proj-cov-*`,
		//     `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		//     etc. namespaces). Even though no fixture-token literal
		//     is materialised on the wire (the operation has no body
		//     and no parameters), the slug is reserved for this
		//     story to keep the per-tag cross-reference grep useful
		//     for future contributors.
		//   * **Neither `SampleBody`, `SampleQuery`, nor
		//     `SamplePathParams` are populated** — the spec
		//     declares no body and no parameters, and inventing a
		//     fictional body would (a) violate the
		//     re-verify-the-spec rule reasserted across
		//     API-0345..API-0357, (b) cause `runAPICoverageSuccess`
		//     to assert a body round-trip the CLI would never
		//     send, and (c) waste the no-body branch coverage this
		//     entry shares with API-0354 / API-0357. The harness
		//     still asserts the wire-level invariants (method, path,
		//     Authorization header) — the no-body POST cohort is
		//     not a coverage gap. See API-0354's narration for the
		//     canonical no-body POST harness handling.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `cleanRedis` verb is a fleet-wide Redis-cache purge, not
		// a by-id resource lookup), so the per-tag opener convention
		// reasserted at API-0335..API-0357 that reserves 404 →
		// CodeNotFound for canonical `*-one` peers does not even
		// apply here. Auth is the universal failure mode every
		// Dokploy operation must re-prove, so 401 → CodeAuth via
		// the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput stays
		// reserved for stories where payload validation is the
		// operation's distinguishing failure mode; this entry uses
		// the canonical 401.
		//
		// The next case in the settings/* roster, API-0359
		// `settings-cleanSSHPrivateKey`, is also a POST per the
		// verb's `clean*` family pattern and per direct spec
		// inspection also carries **no** `requestBody` — i.e.
		// continues the no-body sub-cohort with this entry / API-0354
		// / API-0357. Future contributors authoring API-0359 should
		// grep this entry first for the `set-cov-*` namespace
		// inheritance pattern and the no-body POST harness handling,
		// then re-verify the spec against
		// `internal/api/data/openapi.json >
		// /settings.cleanSSHPrivateKey > post` per the
		// forward-reference lesson — do **not** assume the body
		// shape mirrors this entry's no-body schema solely because
		// the verb prefix matches; API-0354 → API-0355 already
		// established that two `clean*` siblings can diverge on the
		// body axis in either direction.
		//
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0359",
		OperationID: "settings-cleanSSHPrivateKey",
		Method:      http.MethodPost,
		Path:        "/settings.cleanSSHPrivateKey",
		Tag:         "settings",
		// Ninth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0358
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0358
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.cleanSSHPrivateKey > post`: **no `requestBody`
		// field at all** (matches API-0354
		// `settings-cleanAllDeploymentQueue`, API-0357
		// `settings-cleanMonitoring`, and API-0358
		// `settings-cleanRedis`; structurally stronger than
		// API-0353 `settings-cleanAll` / API-0355
		// `settings-cleanDockerBuilder` / API-0356
		// `settings-cleanDockerPrune`'s `requestBody.required = false`
		// carrying an optional `serverId` body — here the spec
		// declares no request body schema whatsoever, so the
		// operation is a true no-input POST), **zero parameters**
		// (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**, mirroring
		// the API-0351 opener / API-0353 / API-0354 / API-0355 /
		// API-0356 / API-0357 / API-0358 response sets rather than
		// API-0352's by-id-flavoured 404-bearing response set. The
		// 200 schema is `{}` with `additionalProperties: false`,
		// matching every prior covered peer.
		//
		// **Forward-reference confirmation.** API-0358's comment
		// predicted this entry would carry **no** `requestBody` at
		// all — i.e. continue the no-body sub-cohort seeded by
		// API-0354 `settings-cleanAllDeploymentQueue` and re-asserted
		// by API-0357 `settings-cleanMonitoring` and API-0358
		// `settings-cleanRedis`. Direct inspection of
		// `internal/api/data/openapi.json >
		// /settings.cleanSSHPrivateKey > post` confirms the
		// prediction: the operation has no `requestBody` key
		// whatsoever, exactly the API-0354 / API-0357 / API-0358
		// shape. The `clean*` family in settings/* therefore
		// continues to split into two sub-cohorts on the wire:
		// (a) optional-body POSTs with an optional `serverId`
		// (API-0353 cleanAll, API-0355 cleanDockerBuilder, API-0356
		// cleanDockerPrune), and (b) no-body POSTs (API-0354
		// cleanAllDeploymentQueue, API-0357 cleanMonitoring,
		// API-0358 cleanRedis, and now API-0359 cleanSSHPrivateKey).
		// The optional/required distinction is per-operation; future
		// settings/* peers must always re-verify the spec before
		// authoring the fixture, the `clean*` verb prefix alone is
		// not authoritative.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-cleanSSHPrivateKey-0359` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351
		//     `set-cov-assignDomainServer-0351`, API-0352
		//     `set-cov-checkGPUStatus-0352`, API-0353
		//     `set-cov-cleanAll-0353`, API-0354
		//     `set-cov-cleanAllDeploymentQueue-0354`, API-0355
		//     `set-cov-cleanDockerBuilder-0355`, API-0356
		//     `set-cov-cleanDockerPrune-0356`, API-0357
		//     `set-cov-cleanMonitoring-0357`, or API-0358
		//     `set-cov-cleanRedis-0358` slugs, and orthogonal
		//     to every prior tag's `srv-cov-*`, `proj-cov-*`,
		//     `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		//     etc. namespaces). Even though no fixture-token literal
		//     is materialised on the wire (the operation has no body
		//     and no parameters), the slug is reserved for this
		//     story to keep the per-tag cross-reference grep useful
		//     for future contributors.
		//   * **Neither `SampleBody`, `SampleQuery`, nor
		//     `SamplePathParams` are populated** — the spec
		//     declares no body and no parameters, and inventing a
		//     fictional body would (a) violate the
		//     re-verify-the-spec rule reasserted across
		//     API-0345..API-0358, (b) cause `runAPICoverageSuccess`
		//     to assert a body round-trip the CLI would never
		//     send, and (c) waste the no-body branch coverage this
		//     entry shares with API-0354 / API-0357 / API-0358. The
		//     harness still asserts the wire-level invariants
		//     (method, path, Authorization header) — the no-body
		//     POST cohort is not a coverage gap. See API-0354's
		//     narration for the canonical no-body POST harness
		//     handling.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `cleanSSHPrivateKey` verb is a fleet-wide SSH key purge,
		// not a by-id resource lookup), so the per-tag opener
		// convention reasserted at API-0335..API-0358 that reserves
		// 404 → CodeNotFound for canonical `*-one` peers does not
		// even apply here. Auth is the universal failure mode every
		// Dokploy operation must re-prove, so 401 → CodeAuth via
		// the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput stays
		// reserved for stories where payload validation is the
		// operation's distinguishing failure mode; this entry uses
		// the canonical 401.
		//
		// The next case in the settings/* roster, API-0360
		// `settings-cleanStoppedContainers`, is also a POST per the
		// verb's `clean*` family pattern. Future contributors
		// authoring API-0360 should grep this entry first for the
		// `set-cov-*` namespace inheritance pattern and the
		// no-body POST harness handling, then re-verify the spec
		// against `internal/api/data/openapi.json >
		// /settings.cleanStoppedContainers > post` per the
		// forward-reference lesson — do **not** assume the body
		// shape mirrors this entry's no-body schema solely because
		// the verb prefix matches; API-0354 → API-0355 already
		// established that two `clean*` siblings can diverge on the
		// body axis in either direction.
		//
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0360",
		OperationID: "settings-cleanStoppedContainers",
		Method:      http.MethodPost,
		Path:        "/settings.cleanStoppedContainers",
		Tag:         "settings",
		// Tenth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0359
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0359
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.cleanStoppedContainers > post`: a single
		// **OPTIONAL** `requestBody` (`requestBody.required =
		// false`) carrying a JSON object with one optional string
		// property `serverId` and no `required` array; **zero
		// parameters** (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**,
		// mirroring the API-0351 opener / API-0353 / API-0354 /
		// API-0355 / API-0356 / API-0357 / API-0358 / API-0359
		// response sets rather than API-0352's by-id-flavoured
		// 404-bearing response set. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer.
		//
		// **Forward-reference confirmation — body axis flips back.**
		// API-0359's comment correctly warned that `clean*` verb
		// prefix alone is not authoritative on the body axis and
		// directed the API-0360 author to re-verify the spec
		// rather than mirror API-0359's no-body schema. Direct
		// inspection of `internal/api/data/openapi.json >
		// /settings.cleanStoppedContainers > post` confirms the
		// warning was warranted: this entry carries an optional
		// `requestBody` with the single-property `{serverId?:
		// string}` shape, byte-identical to API-0353
		// `settings-cleanAll`, API-0355 `settings-cleanDockerBuilder`,
		// and API-0356 `settings-cleanDockerPrune`. The `clean*`
		// family in settings/* therefore continues to split into
		// two sub-cohorts on the wire: (a) optional-body POSTs
		// with an optional `serverId` (API-0353 cleanAll, API-0355
		// cleanDockerBuilder, API-0356 cleanDockerPrune, and now
		// API-0360 cleanStoppedContainers), and (b) no-body POSTs
		// (API-0354 cleanAllDeploymentQueue, API-0357 cleanMonitoring,
		// API-0358 cleanRedis, API-0359 cleanSSHPrivateKey). The
		// optional/required distinction remains per-operation;
		// future settings/* peers must always re-verify the spec
		// before authoring the fixture, the `clean*` verb prefix
		// alone is not authoritative — API-0359 → API-0360 is the
		// fourth body-axis flip across this sub-roster.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-cleanStoppedContainers-0360` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351
		//     `set-cov-assignDomainServer-0351`, API-0352
		//     `set-cov-checkGPUStatus-0352`, API-0353
		//     `set-cov-cleanAll-0353`, API-0354
		//     `set-cov-cleanAllDeploymentQueue-0354`, API-0355
		//     `set-cov-cleanDockerBuilder-0355`, API-0356
		//     `set-cov-cleanDockerPrune-0356`, API-0357
		//     `set-cov-cleanMonitoring-0357`, API-0358
		//     `set-cov-cleanRedis-0358`, or API-0359
		//     `set-cov-cleanSSHPrivateKey-0359` slugs, and
		//     orthogonal to every prior tag's `srv-cov-*`,
		//     `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		//     `app-cov-*`, `ai-cov-*`, etc. namespaces).
		//   * `serverId` carries the fixture-shaped literal
		//     `set-cov-cleanStoppedContainers-0360` rather than a
		//     real UUID so the wire payload cannot be mistaken
		//     for a real production server identifier. Even
		//     though the body and the `serverId` field are both
		//     optional in the spec, populating both exercises the
		//     JSON serialiser's optional-body branch on the wire
		//     and keeps the success-leg `Content-Type:
		//     application/json` header assertion meaningful —
		//     leaving the body unset would degrade this case to
		//     the parameter-free POST cohort (which has no
		//     Content-Type assertion) and lose the body-forwarding
		//     round-trip assertion that distinguishes this shape
		//     from API-0359's no-body shape.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `cleanStoppedContainers` verb is a fleet-wide,
		// optional-server-scoped Docker stopped-container purge,
		// not a by-id resource lookup), so the per-tag opener
		// convention reasserted at API-0335..API-0359 that reserves
		// 404 → CodeNotFound for canonical `*-one` peers does not
		// even apply here. Auth is the universal failure mode every
		// Dokploy operation must re-prove, so 401 → CodeAuth via
		// the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput stays
		// reserved for stories where payload validation is the
		// operation's distinguishing failure mode; this entry uses
		// the canonical 401.
		//
		// The next case in the settings/* roster, API-0361
		// `settings-cleanUnusedImages`, is also a POST per the
		// verb's `clean*` family pattern. Future contributors
		// authoring API-0361 should grep this entry first for the
		// `set-cov-*` namespace inheritance pattern and the
		// optional-body POST harness handling, then re-verify the
		// spec against `internal/api/data/openapi.json >
		// /settings.cleanUnusedImages > post` per the
		// forward-reference lesson — do **not** assume the body
		// shape mirrors this entry's `{serverId}` schema solely
		// because the verb prefix matches; API-0354 → API-0355
		// and API-0359 → API-0360 already established that two
		// `clean*` siblings can diverge on the body axis in
		// either direction.
		SampleBody: json.RawMessage(`{
			"serverId": "set-cov-cleanStoppedContainers-0360"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0361",
		OperationID: "settings-cleanUnusedImages",
		Method:      http.MethodPost,
		Path:        "/settings.cleanUnusedImages",
		Tag:         "settings",
		// Eleventh entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0360
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0360
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.cleanUnusedImages > post`: a single
		// **OPTIONAL** `requestBody` (`requestBody.required =
		// false`) carrying a JSON object with one optional string
		// property `serverId` and no `required` array; **zero
		// parameters** (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**,
		// mirroring the API-0351 opener / API-0353 / API-0354 /
		// API-0355 / API-0356 / API-0357 / API-0358 / API-0359 /
		// API-0360 response sets rather than API-0352's
		// by-id-flavoured 404-bearing response set. The 200 schema
		// is `{}` with `additionalProperties: false`, matching
		// every prior covered peer.
		//
		// **Forward-reference confirmation — body axis stays put.**
		// API-0360's comment correctly warned that `clean*` verb
		// prefix alone is not authoritative on the body axis and
		// directed the API-0361 author to re-verify the spec
		// rather than mirror API-0360's optional-body schema.
		// Direct inspection of `internal/api/data/openapi.json >
		// /settings.cleanUnusedImages > post` confirms the warning
		// was prudent but the wire shape happens to match: this
		// entry carries an optional `requestBody` with the
		// single-property `{serverId?: string}` shape,
		// byte-identical to API-0353 `settings-cleanAll`, API-0355
		// `settings-cleanDockerBuilder`, API-0356
		// `settings-cleanDockerPrune`, and API-0360
		// `settings-cleanStoppedContainers`. The `clean*` family
		// in settings/* therefore continues to split into two
		// sub-cohorts on the wire: (a) optional-body POSTs with an
		// optional `serverId` (API-0353 cleanAll, API-0355
		// cleanDockerBuilder, API-0356 cleanDockerPrune, API-0360
		// cleanStoppedContainers, and now API-0361
		// cleanUnusedImages — five entries), and (b) no-body
		// POSTs (API-0354 cleanAllDeploymentQueue, API-0357
		// cleanMonitoring, API-0358 cleanRedis, API-0359
		// cleanSSHPrivateKey — four entries). The optional/required
		// distinction remains per-operation; future settings/*
		// peers must always re-verify the spec before authoring
		// the fixture, the `clean*` verb prefix alone is not
		// authoritative — API-0360 → API-0361 happens to land on
		// the same body axis but the per-operation re-verification
		// rule still stands and four prior body-axis flips
		// (API-0353→API-0354, API-0354→API-0355, API-0356→API-0357,
		// API-0359→API-0360) demonstrate why.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-cleanUnusedImages-0361` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351
		//     `set-cov-assignDomainServer-0351`, API-0352
		//     `set-cov-checkGPUStatus-0352`, API-0353
		//     `set-cov-cleanAll-0353`, API-0354
		//     `set-cov-cleanAllDeploymentQueue-0354`, API-0355
		//     `set-cov-cleanDockerBuilder-0355`, API-0356
		//     `set-cov-cleanDockerPrune-0356`, API-0357
		//     `set-cov-cleanMonitoring-0357`, API-0358
		//     `set-cov-cleanRedis-0358`, API-0359
		//     `set-cov-cleanSSHPrivateKey-0359`, or API-0360
		//     `set-cov-cleanStoppedContainers-0360` slugs, and
		//     orthogonal to every prior tag's `srv-cov-*`,
		//     `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		//     `app-cov-*`, `ai-cov-*`, etc. namespaces).
		//   * `serverId` carries the fixture-shaped literal
		//     `set-cov-cleanUnusedImages-0361` rather than a real
		//     UUID so the wire payload cannot be mistaken for a
		//     real production server identifier. Even though the
		//     body and the `serverId` field are both optional in
		//     the spec, populating both exercises the JSON
		//     serialiser's optional-body branch on the wire and
		//     keeps the success-leg `Content-Type:
		//     application/json` header assertion meaningful —
		//     leaving the body unset would degrade this case to
		//     the parameter-free POST cohort (which has no
		//     Content-Type assertion) and lose the body-forwarding
		//     round-trip assertion that distinguishes this shape
		//     from the no-body sub-cohort (API-0354, API-0357,
		//     API-0358, API-0359).
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `cleanUnusedImages` verb is a fleet-wide,
		// optional-server-scoped Docker dangling/unused image
		// purge, not a by-id resource lookup), so the per-tag
		// opener convention reasserted at API-0335..API-0360 that
		// reserves 404 → CodeNotFound for canonical `*-one` peers
		// does not even apply here. Auth is the universal failure
		// mode every Dokploy operation must re-prove, so 401 →
		// CodeAuth via the harness default (`tc.FailureStatus ==
		// 0` → 401, `tc.FailureCode == ""` → CodeAuth) stays the
		// most informative representative. 400 → CodeInvalidInput
		// stays reserved for stories where payload validation is
		// the operation's distinguishing failure mode; this entry
		// uses the canonical 401.
		//
		// The next case in the settings/* roster, API-0362
		// `settings-cleanUnusedVolumes`, is also a POST per the
		// verb's `clean*` family pattern. Future contributors
		// authoring API-0362 should grep this entry first for the
		// `set-cov-*` namespace inheritance pattern and the
		// optional-body POST harness handling, then re-verify the
		// spec against `internal/api/data/openapi.json >
		// /settings.cleanUnusedVolumes > post` per the
		// forward-reference lesson — do **not** assume the body
		// shape mirrors this entry's `{serverId}` schema solely
		// because the verb prefix and adjacent slug match;
		// API-0354 → API-0355 and API-0359 → API-0360 already
		// established that two `clean*` siblings can diverge on
		// the body axis in either direction, and even an
		// adjacent `cleanUnused*` pair is not guaranteed to share
		// shape.
		SampleBody: json.RawMessage(`{
			"serverId": "set-cov-cleanUnusedImages-0361"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0362",
		OperationID: "settings-cleanUnusedVolumes",
		Method:      http.MethodPost,
		Path:        "/settings.cleanUnusedVolumes",
		Tag:         "settings",
		// Twelfth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0361
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0361
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.cleanUnusedVolumes > post`: a single
		// **OPTIONAL** `requestBody` (`requestBody.required =
		// false`) carrying a JSON object with one optional string
		// property `serverId` and no `required` array; **zero
		// parameters** (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**,
		// mirroring the API-0351 opener / API-0353 / API-0354 /
		// API-0355 / API-0356 / API-0357 / API-0358 / API-0359 /
		// API-0360 / API-0361 response sets rather than API-0352's
		// by-id-flavoured 404-bearing response set. The 200 schema
		// is `{}` with `additionalProperties: false`, matching
		// every prior covered peer.
		//
		// **Forward-reference confirmation — body axis stays put.**
		// API-0361's comment correctly warned that the `clean*`
		// verb prefix alone is not authoritative on the body axis
		// and that even an adjacent `cleanUnused*` pair is not
		// guaranteed to share shape, directing the API-0362 author
		// to re-verify the spec rather than mirror API-0361's
		// optional-body schema. Direct inspection of
		// `internal/api/data/openapi.json >
		// /settings.cleanUnusedVolumes > post` confirms the warning
		// was prudent but the wire shape happens to match: this
		// entry carries an optional `requestBody` with the
		// single-property `{serverId?: string}` shape,
		// byte-identical to API-0353 `settings-cleanAll`, API-0355
		// `settings-cleanDockerBuilder`, API-0356
		// `settings-cleanDockerPrune`, API-0360
		// `settings-cleanStoppedContainers`, and API-0361
		// `settings-cleanUnusedImages`. The `clean*` family in
		// settings/* therefore continues to split into two
		// sub-cohorts on the wire: (a) optional-body POSTs with an
		// optional `serverId` (API-0353 cleanAll, API-0355
		// cleanDockerBuilder, API-0356 cleanDockerPrune, API-0360
		// cleanStoppedContainers, API-0361 cleanUnusedImages, and
		// now API-0362 cleanUnusedVolumes — six entries), and (b)
		// no-body POSTs (API-0354 cleanAllDeploymentQueue, API-0357
		// cleanMonitoring, API-0358 cleanRedis, API-0359
		// cleanSSHPrivateKey — four entries). The optional/required
		// distinction remains per-operation; the fact that the
		// `cleanUnused*` pair (API-0361 → API-0362) happens to
		// share shape does **not** generalise across the family,
		// and the four prior body-axis flips
		// (API-0353→API-0354, API-0354→API-0355, API-0356→API-0357,
		// API-0359→API-0360) demonstrate why per-operation spec
		// re-verification stays mandatory.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-cleanUnusedVolumes-0362` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351
		//     `set-cov-assignDomainServer-0351`, API-0352
		//     `set-cov-checkGPUStatus-0352`, API-0353
		//     `set-cov-cleanAll-0353`, API-0354
		//     `set-cov-cleanAllDeploymentQueue-0354`, API-0355
		//     `set-cov-cleanDockerBuilder-0355`, API-0356
		//     `set-cov-cleanDockerPrune-0356`, API-0357
		//     `set-cov-cleanMonitoring-0357`, API-0358
		//     `set-cov-cleanRedis-0358`, API-0359
		//     `set-cov-cleanSSHPrivateKey-0359`, API-0360
		//     `set-cov-cleanStoppedContainers-0360`, or API-0361
		//     `set-cov-cleanUnusedImages-0361` slugs, and
		//     orthogonal to every prior tag's `srv-cov-*`,
		//     `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		//     `app-cov-*`, `ai-cov-*`, etc. namespaces).
		//   * `serverId` carries the fixture-shaped literal
		//     `set-cov-cleanUnusedVolumes-0362` rather than a real
		//     UUID so the wire payload cannot be mistaken for a
		//     real production server identifier. Even though the
		//     body and the `serverId` field are both optional in
		//     the spec, populating both exercises the JSON
		//     serialiser's optional-body branch on the wire and
		//     keeps the success-leg `Content-Type:
		//     application/json` header assertion meaningful —
		//     leaving the body unset would degrade this case to
		//     the parameter-free POST cohort (which has no
		//     Content-Type assertion) and lose the body-forwarding
		//     round-trip assertion that distinguishes this shape
		//     from the no-body sub-cohort (API-0354, API-0357,
		//     API-0358, API-0359).
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `cleanUnusedVolumes` verb is a fleet-wide,
		// optional-server-scoped Docker dangling/unused volume
		// purge, not a by-id resource lookup), so the per-tag
		// opener convention reasserted at API-0335..API-0361 that
		// reserves 404 → CodeNotFound for canonical `*-one` peers
		// does not even apply here. Auth is the universal failure
		// mode every Dokploy operation must re-prove, so 401 →
		// CodeAuth via the harness default (`tc.FailureStatus ==
		// 0` → 401, `tc.FailureCode == ""` → CodeAuth) stays the
		// most informative representative. 400 → CodeInvalidInput
		// stays reserved for stories where payload validation is
		// the operation's distinguishing failure mode; this entry
		// uses the canonical 401.
		//
		// The next case in the settings/* roster, API-0363
		// `settings-getDokployCloudIps`, is a **GET** rather than
		// a POST — a hard family pivot away from the eleven-entry
		// `clean*`/`assign*`/`checkGPUStatus` POST/GET-no-body
		// cohort that has dominated settings/* since API-0351.
		// Future contributors authoring API-0363 must **not**
		// inherit this entry's `SampleBody` shape: a GET has no
		// request body in OpenAPI, and the harness's GET branch
		// asserts that no `Content-Type` request header is sent.
		// Re-verify the spec against
		// `internal/api/data/openapi.json >
		// /settings.getDokployCloudIps > get` per the
		// forward-reference lesson — the responses set is also
		// expected to differ (404 may reappear on a getter slug,
		// per the API-0352 `checkGPUStatus` precedent for the
		// settings/* `get*`/`check*` GET sub-family).
		SampleBody: json.RawMessage(`{
			"serverId": "set-cov-cleanUnusedVolumes-0362"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0363",
		OperationID: "settings-getDokployCloudIps",
		Method:      http.MethodGet,
		Path:        "/settings.getDokployCloudIps",
		Tag:         "settings",
		// Thirteenth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0362
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0362
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.getDokployCloudIps > get`: a **GET** with **zero
		// parameters** (no query, no path, no header) and **no
		// request body** (GETs in this OpenAPI document never
		// carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — note the **presence of 404**,
		// pivoting back from the eleven-entry
		// `clean*`/`assign*`/`getDokploy*`/`POST` cohort that
		// dominated settings/* between API-0353..API-0362 (where
		// 404 was uniformly absent) and rejoining the
		// `404-bearing` response set first seen in this roster at
		// API-0352 `settings-checkGPUStatus`. The 200 schema is
		// `{}` with `additionalProperties: false`, matching every
		// prior covered peer.
		//
		// **Family pivot — twelfth-entry POST sub-roster ends here.**
		// API-0362's comment correctly warned that this entry is a
		// hard pivot off the `clean*` POST family onto the `get*`
		// GET sub-family: the `cleanUnused*`/`clean*`/`assign*`
		// POST cluster (API-0351, API-0353..API-0362, with the
		// single-OPTIONAL-query API-0352 GET interleaved) ends at
		// API-0362, and `getDokployCloudIps` opens the
		// parameter-free GET sub-family (cf. API-0006 `ai-getAll`,
		// API-0350 `server-withSSHKey`). The harness's GET branch
		// asserts that **no `Content-Type` request header is
		// sent** and ignores `SampleBody` entirely, so carrying a
		// `SampleBody` into this case would silently encode dead
		// code on the wire — `SampleBody` is therefore deliberately
		// omitted, mirroring API-0006 and API-0350. Likewise,
		// `SampleQuery` and `SamplePathParams` are omitted: the
		// spec declares zero parameters, distinguishing this case
		// from API-0352 `settings-checkGPUStatus` which carried a
		// single optional `serverId` query parameter. The harness
		// still asserts the wire-level invariants (method, path,
		// `Authorization` header, empty query string, empty
		// request body) at `runAPICoverageSuccess`, and the
		// canonical no-input invocation
		// `yalla api call settings-getDokployCloudIps --input '{}'
		// --json` is what the agent contract guarantees.
		//
		// Fixture conventions:
		//   * No per-case fixture token base is needed because
		//     this case populates neither `SampleBody`,
		//     `SampleQuery`, nor `SamplePathParams` — the
		//     parameter-free GET cohort (API-0006 `ai-getAll`,
		//     API-0350 `server-withSSHKey`) precedent applies. A
		//     reservation slot `set-cov-getDokployCloudIps-0363`
		//     is left open under the settings/* `set-cov-*`
		//     namespace for any future regression test that
		//     needs a unique literal tied to this story; the
		//     reservation is unique against API-0351..API-0362's
		//     `set-cov-*` slugs and orthogonal to every prior
		//     tag's `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		//     `compose-cov-*`, `app-cov-*`, `ai-cov-*`, etc.
		//     namespaces.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation (it
		// reappears on the GET branch after eleven 404-absent
		// POST peers), the per-tag opener convention reasserted
		// at API-0335..API-0362 reserves 404 → CodeNotFound for
		// the canonical by-id `*-one` peer, not for fleet-wide
		// list-style getters like `getDokployCloudIps` (which
		// returns the cloud platform's IP allocation, not a
		// single resource keyed by id). Auth is the universal
		// failure mode every Dokploy operation must re-prove, so
		// 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; this entry uses the canonical 401.
		//
		// The next case in the settings/* roster, API-0364
		// `settings-getDokployVersion`, is also a **GET** with
		// zero parameters and no request body per the PRD
		// (responses 200/400/401/403/404/500). Future
		// contributors authoring API-0364 should grep this entry
		// first for the parameter-free GET cohort handling and
		// the 404-bearing-but-omitted-from-failure-leg rationale,
		// then re-verify the spec against
		// `internal/api/data/openapi.json >
		// /settings.getDokployVersion > get` per the
		// forward-reference lesson — do **not** assume the
		// parameter list, request body, or response set mirrors
		// this entry's shape solely because the verb prefix and
		// adjacent slug match; the eleven-flip body-axis history
		// of the preceding `clean*` sub-roster (API-0353..API-0362)
		// demonstrates why per-operation re-verification stays
		// mandatory across every family transition.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0364",
		OperationID: "settings-getDokployVersion",
		Method:      http.MethodGet,
		Path:        "/settings.getDokployVersion",
		Tag:         "settings",
		// Fourteenth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer` and
		// extended through API-0363 `settings-getDokployCloudIps`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0363
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0363
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.getDokployVersion > get`: a **GET** with **zero
		// parameters** (no query, no path, no header) and **no
		// request body** (GETs in this OpenAPI document never
		// carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the immediately preceding peer API-0363
		// `settings-getDokployCloudIps` and rejoining the
		// `404-bearing` response set first seen on this roster at
		// API-0352 `settings-checkGPUStatus`. The 200 schema is
		// `{}` with `additionalProperties: false`, matching every
		// prior covered peer in the parameter-free GET cohort
		// (API-0006 `ai-getAll`, API-0350 `server-withSSHKey`,
		// API-0363 `settings-getDokployCloudIps`).
		//
		// **Family continuation — second entry of the parameter-free
		// `getDokploy*` GET sub-roster.** API-0363 opened this
		// sub-family by pivoting off the eleven-entry POST cohort
		// (API-0353..API-0362); API-0364 confirms the new sub-family
		// shape rather than introducing another body-axis flip.
		// `SampleBody`, `SampleQuery`, and `SamplePathParams` are
		// therefore deliberately omitted: the harness's GET branch
		// asserts that **no `Content-Type` request header is sent**
		// and ignores `SampleBody` entirely, so carrying one would
		// silently encode dead code on the wire. The harness still
		// asserts the wire-level invariants (method, path,
		// `Authorization` header, empty query string, empty request
		// body) at `runAPICoverageSuccess`, and the canonical
		// no-input invocation
		// `yalla api call settings-getDokployVersion --input '{}'
		// --json` is what the agent contract guarantees.
		//
		// Fixture conventions:
		//   * No per-case fixture token base is needed because
		//     this case populates neither `SampleBody`,
		//     `SampleQuery`, nor `SamplePathParams` — the
		//     parameter-free GET cohort precedent (API-0006
		//     `ai-getAll`, API-0350 `server-withSSHKey`, API-0363
		//     `settings-getDokployCloudIps`) applies. A reservation
		//     slot `set-cov-getDokployVersion-0364` is left open
		//     under the settings/* `set-cov-*` namespace for any
		//     future regression test that needs a unique literal
		//     tied to this story; the reservation is unique against
		//     API-0351..API-0363's `set-cov-*` slugs and orthogonal
		//     to every prior tag's `srv-cov-*`, `proj-cov-*`,
		//     `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		//     etc. namespaces.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0363 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// platform-info getters like `getDokployVersion` (which
		// returns the running Dokploy version string, not a single
		// resource keyed by id). Auth is the universal failure mode
		// every Dokploy operation must re-prove, so 401 → CodeAuth
		// via the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput stays
		// reserved for stories where payload validation is the
		// operation's distinguishing failure mode; this entry uses
		// the canonical 401.
		//
		// The next case in the settings/* roster, API-0365
		// `settings-getIp`, is also a **GET** per the PRD
		// (responses 200/400/401/403/404/500). Future contributors
		// authoring API-0365 should grep this entry first for the
		// parameter-free GET cohort handling, then re-verify the
		// spec against `internal/api/data/openapi.json >
		// /settings.getIp > get` per the forward-reference lesson —
		// do **not** assume the parameter list, request body, or
		// response set mirrors this entry's shape solely because
		// the verb prefix and adjacent slug match; the eleven-flip
		// body-axis history of the preceding `clean*` sub-roster
		// (API-0353..API-0362) demonstrates why per-operation
		// re-verification stays mandatory across every family
		// transition.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0365",
		OperationID: "settings-getIp",
		Method:      http.MethodGet,
		Path:        "/settings.getIp",
		Tag:         "settings",
		// Fifteenth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer` and
		// extended through API-0364 `settings-getDokployVersion`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0364
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0364
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /settings.getIp > get`:
		// a **GET** with **zero parameters** (no query, no path, no
		// header) and **no request body** (GETs in this OpenAPI
		// document never carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the immediately preceding peers API-0363
		// `settings-getDokployCloudIps` and API-0364
		// `settings-getDokployVersion`, and continuing the
		// `404-bearing` response set first seen on this roster at
		// API-0352 `settings-checkGPUStatus`. The 200 schema is
		// `{}` with `additionalProperties: false`, matching every
		// prior covered peer in the parameter-free GET cohort
		// (API-0006 `ai-getAll`, API-0350 `server-withSSHKey`,
		// API-0363 `settings-getDokployCloudIps`, API-0364
		// `settings-getDokployVersion`).
		//
		// **Family continuation — third entry of the parameter-free
		// GET sub-roster within settings/*, and the first
		// non-`getDokploy*`-prefixed member.** API-0363 opened the
		// settings/* parameter-free GET sub-family by pivoting off
		// the eleven-entry POST cohort (API-0353..API-0362);
		// API-0364 confirmed the sub-family shape under the
		// `getDokploy*` slug prefix; API-0365 generalises the
		// sub-family beyond that prefix while keeping the wire
		// shape identical (parameter-free GET, no body, 200 → `{}`,
		// 200/400/401/403/404/500 response set). `SampleBody`,
		// `SampleQuery`, and `SamplePathParams` are therefore
		// deliberately omitted: the harness's GET branch asserts
		// that **no `Content-Type` request header is sent** and
		// ignores `SampleBody` entirely, so carrying one would
		// silently encode dead code on the wire. The harness still
		// asserts the wire-level invariants (method, path,
		// `Authorization` header, empty query string, empty request
		// body) at `runAPICoverageSuccess`, and the canonical
		// no-input invocation
		// `yalla api call settings-getIp --input '{}' --json` is
		// what the agent contract guarantees.
		//
		// Fixture conventions:
		//   * No per-case fixture token base is needed because
		//     this case populates neither `SampleBody`,
		//     `SampleQuery`, nor `SamplePathParams` — the
		//     parameter-free GET cohort precedent (API-0006
		//     `ai-getAll`, API-0350 `server-withSSHKey`, API-0363
		//     `settings-getDokployCloudIps`, API-0364
		//     `settings-getDokployVersion`) applies. A reservation
		//     slot `set-cov-getIp-0365` is left open under the
		//     settings/* `set-cov-*` namespace for any future
		//     regression test that needs a unique literal tied to
		//     this story; the reservation is unique against
		//     API-0351..API-0364's `set-cov-*` slugs and orthogonal
		//     to every prior tag's `srv-cov-*`, `proj-cov-*`,
		//     `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		//     etc. namespaces.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0364 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// platform-info getters like `getIp` (which returns the
		// Dokploy host's public IP, not a single resource keyed by
		// id). Auth is the universal failure mode every Dokploy
		// operation must re-prove, so 401 → CodeAuth via the
		// harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput stays
		// reserved for stories where payload validation is the
		// operation's distinguishing failure mode; this entry uses
		// the canonical 401.
		//
		// The next case in the settings/* roster per PRD ordering
		// is API-0366 `settings-getLogCleanupStatus` (also declared
		// a GET in the PRD with responses 200/400/401/403/404/500).
		// On shape it appears to extend this parameter-free GET
		// sub-roster, but the next contributor must re-verify
		// against `internal/api/data/openapi.json >
		// /settings.getLogCleanupStatus > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry. Do not assume the parameter
		// list, request body, or response set carries over solely
		// because the verb prefix and adjacent slug match; the
		// eleven-flip body-axis history of the preceding `clean*`
		// sub-roster (API-0353..API-0362) demonstrates why
		// per-operation re-verification stays mandatory across
		// every family transition.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0366",
		OperationID: "settings-getLogCleanupStatus",
		Method:      http.MethodGet,
		Path:        "/settings.getLogCleanupStatus",
		Tag:         "settings",
		// Sixteenth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer` and
		// extended through API-0365 `settings-getIp` (must not
		// back-reference the closed `srv-cov-*`, `proj-cov-*`,
		// `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		// or any other prior tag's namespace, per the per-tag
		// isolation rule reasserted at API-0335..API-0365 and
		// originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0365
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.getLogCleanupStatus > get`: a **GET** with
		// **zero parameters** (no query, no path, no header) and
		// **no request body** (GETs in this OpenAPI document never
		// carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the immediately preceding peers API-0363
		// `settings-getDokployCloudIps`, API-0364
		// `settings-getDokployVersion`, and API-0365
		// `settings-getIp`, and continuing the `404-bearing`
		// response set first seen on this roster at API-0352
		// `settings-checkGPUStatus`. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer in the parameter-free GET cohort
		// (API-0006 `ai-getAll`, API-0350 `server-withSSHKey`,
		// API-0363 `settings-getDokployCloudIps`, API-0364
		// `settings-getDokployVersion`, API-0365 `settings-getIp`).
		//
		// **Family continuation — fourth entry of the parameter-free
		// GET sub-roster within settings/*.** API-0363 opened the
		// settings/* parameter-free GET sub-family by pivoting off
		// the eleven-entry POST cohort (API-0353..API-0362);
		// API-0364 confirmed the sub-family shape under the
		// `getDokploy*` slug prefix; API-0365 generalised the
		// sub-family beyond that prefix; API-0366 demonstrates the
		// shape carries again under a fresh non-`getDokploy*` slug
		// (`getLogCleanupStatus`) while keeping the wire shape
		// identical (parameter-free GET, no body, 200 → `{}`,
		// 200/400/401/403/404/500 response set). `SampleBody`,
		// `SampleQuery`, and `SamplePathParams` are therefore
		// deliberately omitted: the harness's GET branch asserts
		// that **no `Content-Type` request header is sent** and
		// ignores `SampleBody` entirely, so carrying one would
		// silently encode dead code on the wire. The harness still
		// asserts the wire-level invariants (method, path,
		// `Authorization` header, empty query string, empty request
		// body) at `runAPICoverageSuccess`, and the canonical
		// no-input invocation
		// `yalla api call settings-getLogCleanupStatus --input '{}'
		// --json` is what the agent contract guarantees.
		//
		// Fixture conventions:
		//   * No per-case fixture token base is needed because
		//     this case populates neither `SampleBody`,
		//     `SampleQuery`, nor `SamplePathParams` — the
		//     parameter-free GET cohort precedent (API-0006
		//     `ai-getAll`, API-0350 `server-withSSHKey`, API-0363
		//     `settings-getDokployCloudIps`, API-0364
		//     `settings-getDokployVersion`, API-0365
		//     `settings-getIp`) applies. A reservation slot
		//     `set-cov-getLogCleanupStatus-0366` is left open under
		//     the settings/* `set-cov-*` namespace for any future
		//     regression test that needs a unique literal tied to
		//     this story; the reservation is unique against
		//     API-0351..API-0365's `set-cov-*` slugs and orthogonal
		//     to every prior tag's `srv-cov-*`, `proj-cov-*`,
		//     `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		//     etc. namespaces.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0365 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// platform-info getters like `getLogCleanupStatus` (which
		// reports the global log-cleanup cron's enabled/disabled
		// state, not a single resource keyed by id). Auth is the
		// universal failure mode every Dokploy operation must
		// re-prove, so 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""` →
		// CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; this entry uses the canonical 401.
		//
		// The next case in the settings/* roster per PRD ordering
		// is API-0367 `settings-getOpenApiDocument` (also declared
		// a GET in the PRD with responses 200/400/401/403/404/500).
		// On shape it appears to extend this parameter-free GET
		// sub-roster, but the next contributor must re-verify
		// against `internal/api/data/openapi.json >
		// /settings.getOpenApiDocument > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry. The 200 response there in
		// particular may differ from the canonical empty-object
		// schema (an OpenAPI document is non-trivially shaped),
		// so do not assume the response body schema carries over
		// solely because the verb prefix and adjacent slug match;
		// the eleven-flip body-axis history of the preceding
		// `clean*` sub-roster (API-0353..API-0362) demonstrates
		// why per-operation re-verification stays mandatory across
		// every family transition.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0367",
		OperationID: "settings-getOpenApiDocument",
		Method:      http.MethodGet,
		Path:        "/settings.getOpenApiDocument",
		Tag:         "settings",
		// Seventeenth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer` and
		// extended through API-0366 `settings-getLogCleanupStatus`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0366
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0366
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.getOpenApiDocument > get`: a **GET** with
		// **zero parameters** (no query, no path, no header) and
		// **no request body** (GETs in this OpenAPI document never
		// carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the immediately preceding peers API-0363
		// `settings-getDokployCloudIps`, API-0364
		// `settings-getDokployVersion`, API-0365 `settings-getIp`,
		// and API-0366 `settings-getLogCleanupStatus`, and
		// continuing the `404-bearing` response set first seen on
		// this roster at API-0352 `settings-checkGPUStatus`.
		//
		// **Forward-reference lesson re-confirmed.** Despite the
		// API-0366 hand-off comment flagging that an "OpenAPI
		// document is non-trivially shaped" and that the 200 body
		// schema **might** diverge here, the spec at
		// `/settings.getOpenApiDocument > get > responses > 200`
		// declares the canonical empty-object schema
		// (`{ "type": "object", "properties": {}, "additionalProperties": false }`),
		// matching every prior covered peer in the parameter-free
		// GET cohort (API-0006 `ai-getAll`, API-0350
		// `server-withSSHKey`, API-0363
		// `settings-getDokployCloudIps`, API-0364
		// `settings-getDokployVersion`, API-0365 `settings-getIp`,
		// API-0366 `settings-getLogCleanupStatus`). The Dokploy
		// spec leaves the actual OpenAPI document shape abstract
		// at the wire-contract layer; the harness therefore
		// continues to ship `{}` as the canonical success body and
		// preserves the parameter-free GET sub-roster's wire
		// shape. The contributor still re-verified the spec rather
		// than assuming, per the per-operation re-verification
		// rule.
		//
		// **Family continuation — fifth entry of the parameter-free
		// GET sub-roster within settings/*.** API-0363 opened the
		// settings/* parameter-free GET sub-family by pivoting off
		// the eleven-entry POST cohort (API-0353..API-0362);
		// API-0364 confirmed the sub-family shape under the
		// `getDokploy*` slug prefix; API-0365 generalised the
		// sub-family beyond that prefix; API-0366 demonstrated the
		// shape carries again under a fresh non-`getDokploy*` slug
		// (`getLogCleanupStatus`); API-0367 extends the sub-roster
		// once more under another non-`getDokploy*` slug
		// (`getOpenApiDocument`) while keeping the wire shape
		// identical (parameter-free GET, no body, 200 → `{}`,
		// 200/400/401/403/404/500 response set). `SampleBody`,
		// `SampleQuery`, and `SamplePathParams` are therefore
		// deliberately omitted: the harness's GET branch asserts
		// that **no `Content-Type` request header is sent** and
		// ignores `SampleBody` entirely, so carrying one would
		// silently encode dead code on the wire. The harness still
		// asserts the wire-level invariants (method, path,
		// `Authorization` header, empty query string, empty request
		// body) at `runAPICoverageSuccess`, and the canonical
		// no-input invocation
		// `yalla api call settings-getOpenApiDocument --input '{}'
		// --json` is what the agent contract guarantees.
		//
		// Fixture conventions:
		//   * No per-case fixture token base is needed because
		//     this case populates neither `SampleBody`,
		//     `SampleQuery`, nor `SamplePathParams` — the
		//     parameter-free GET cohort precedent (API-0006
		//     `ai-getAll`, API-0350 `server-withSSHKey`, API-0363
		//     `settings-getDokployCloudIps`, API-0364
		//     `settings-getDokployVersion`, API-0365
		//     `settings-getIp`, API-0366
		//     `settings-getLogCleanupStatus`) applies. A
		//     reservation slot `set-cov-getOpenApiDocument-0367`
		//     is left open under the settings/* `set-cov-*`
		//     namespace for any future regression test that needs
		//     a unique literal tied to this story; the reservation
		//     is unique against API-0351..API-0366's `set-cov-*`
		//     slugs and orthogonal to every prior tag's
		//     `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		//     `compose-cov-*`, `app-cov-*`, `ai-cov-*`, etc.
		//     namespaces.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0366 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// platform-info getters like `getOpenApiDocument` (which
		// returns the Dokploy OpenAPI document itself, not a
		// single resource keyed by id). Auth is the universal
		// failure mode every Dokploy operation must re-prove, so
		// 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""` →
		// CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; this entry uses the canonical 401.
		//
		// The next case in the settings/* roster per PRD ordering
		// is API-0368 `settings-getReleaseTag` (also declared a
		// GET in the PRD with responses 200/400/401/403/404/500).
		// On shape it appears to extend this parameter-free GET
		// sub-roster, but the next contributor must re-verify
		// against `internal/api/data/openapi.json >
		// /settings.getReleaseTag > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry. Do not assume the parameter
		// list, request body, or response set carries over solely
		// because the verb prefix and adjacent slug match; the
		// eleven-flip body-axis history of the preceding `clean*`
		// sub-roster (API-0353..API-0362) demonstrates why
		// per-operation re-verification stays mandatory across
		// every family transition.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0368",
		OperationID: "settings-getReleaseTag",
		Method:      http.MethodGet,
		Path:        "/settings.getReleaseTag",
		Tag:         "settings",
		// Eighteenth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer` and
		// extended through API-0367 `settings-getOpenApiDocument`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0367
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0367
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.getReleaseTag > get`: a **GET** with
		// **zero parameters** (no query, no path, no header) and
		// **no request body** (GETs in this OpenAPI document never
		// carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the immediately preceding peers API-0363
		// `settings-getDokployCloudIps`, API-0364
		// `settings-getDokployVersion`, API-0365 `settings-getIp`,
		// API-0366 `settings-getLogCleanupStatus`, and API-0367
		// `settings-getOpenApiDocument`, and continuing the
		// `404-bearing` response set first seen on this roster at
		// API-0352 `settings-checkGPUStatus`.
		//
		// **Forward-reference lesson re-confirmed.** Despite the
		// API-0367 hand-off comment hedging that release-tag
		// payloads are typically a string and the 200 body schema
		// **might** therefore diverge here, the spec at
		// `/settings.getReleaseTag > get > responses > 200`
		// declares the canonical empty-object schema
		// (`{ "type": "object", "properties": {}, "additionalProperties": false }`),
		// matching every prior covered peer in the parameter-free
		// GET cohort (API-0006 `ai-getAll`, API-0350
		// `server-withSSHKey`, API-0363
		// `settings-getDokployCloudIps`, API-0364
		// `settings-getDokployVersion`, API-0365 `settings-getIp`,
		// API-0366 `settings-getLogCleanupStatus`, API-0367
		// `settings-getOpenApiDocument`). The Dokploy spec leaves
		// the actual release-tag payload abstract at the
		// wire-contract layer; the harness therefore continues to
		// ship `{}` as the canonical success body and preserves
		// the parameter-free GET sub-roster's wire shape. The
		// contributor still re-verified the spec rather than
		// assuming, per the per-operation re-verification rule.
		//
		// **Family continuation — sixth entry of the parameter-free
		// GET sub-roster within settings/*.** API-0363 opened the
		// settings/* parameter-free GET sub-family by pivoting off
		// the eleven-entry POST cohort (API-0353..API-0362);
		// API-0364 confirmed the sub-family shape under the
		// `getDokploy*` slug prefix; API-0365 generalised the
		// sub-family beyond that prefix; API-0366 demonstrated the
		// shape carries again under the `getLog*` slug; API-0367
		// extended the sub-roster under the `getOpenApi*` slug;
		// API-0368 extends the sub-roster once more under another
		// non-`getDokploy*` slug (`getReleaseTag`) while keeping
		// the wire shape identical (parameter-free GET, no body,
		// 200 → `{}`, 200/400/401/403/404/500 response set).
		// `SampleBody`, `SampleQuery`, and `SamplePathParams` are
		// therefore deliberately omitted: the harness's GET branch
		// asserts that **no `Content-Type` request header is sent**
		// and ignores `SampleBody` entirely, so carrying one would
		// silently encode dead code on the wire. The harness still
		// asserts the wire-level invariants (method, path,
		// `Authorization` header, empty query string, empty request
		// body) at `runAPICoverageSuccess`, and the canonical
		// no-input invocation
		// `yalla api call settings-getReleaseTag --input '{}'
		// --json` is what the agent contract guarantees.
		//
		// Fixture conventions:
		//   * No per-case fixture token base is needed because
		//     this case populates neither `SampleBody`,
		//     `SampleQuery`, nor `SamplePathParams` — the
		//     parameter-free GET cohort precedent (API-0006
		//     `ai-getAll`, API-0350 `server-withSSHKey`, API-0363
		//     `settings-getDokployCloudIps`, API-0364
		//     `settings-getDokployVersion`, API-0365
		//     `settings-getIp`, API-0366
		//     `settings-getLogCleanupStatus`, API-0367
		//     `settings-getOpenApiDocument`) applies. A
		//     reservation slot `set-cov-getReleaseTag-0368`
		//     is left open under the settings/* `set-cov-*`
		//     namespace for any future regression test that needs
		//     a unique literal tied to this story; the reservation
		//     is unique against API-0351..API-0367's `set-cov-*`
		//     slugs and orthogonal to every prior tag's
		//     `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		//     `compose-cov-*`, `app-cov-*`, `ai-cov-*`, etc.
		//     namespaces.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0367 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// platform-info getters like `getReleaseTag` (which
		// returns the Dokploy release tag itself, not a single
		// resource keyed by id). Auth is the universal failure
		// mode every Dokploy operation must re-prove, so
		// 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""` →
		// CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; this entry uses the canonical 401.
		//
		// The next case in the settings/* roster per PRD ordering
		// is API-0369 `settings-getTraefikPorts` (also declared a
		// GET in the PRD with responses 200/400/401/403/404/500).
		// On shape it appears to extend this parameter-free GET
		// sub-roster, but the next contributor must re-verify
		// against `internal/api/data/openapi.json >
		// /settings.getTraefikPorts > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry. Do not assume the parameter
		// list, request body, or response set carries over solely
		// because the verb prefix and adjacent slug match; the
		// eleven-flip body-axis history of the preceding `clean*`
		// sub-roster (API-0353..API-0362) demonstrates why
		// per-operation re-verification stays mandatory across
		// every family transition.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0369",
		OperationID: "settings-getTraefikPorts",
		Method:      http.MethodGet,
		Path:        "/settings.getTraefikPorts",
		Tag:         "settings",
		// Nineteenth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer` and
		// extended through API-0368 `settings-getReleaseTag`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0368
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0368
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.getTraefikPorts > get`: a **GET** with
		// **one OPTIONAL query parameter** `serverId` (string,
		// `required: false` — scopes the lookup to a specific
		// Dokploy worker server when the Traefik runtime is
		// replicated across multiple servers) and **no request
		// body** (GETs in this OpenAPI document never carry a
		// `requestBody` field). Responses 200/400/401/403/404/500
		// — the **404 stays present**, matching the immediately
		// preceding peers API-0363 `settings-getDokployCloudIps`
		// through API-0368 `settings-getReleaseTag`, and
		// continuing the `404-bearing` response set first seen on
		// this roster at API-0352 `settings-checkGPUStatus`.
		//
		// **Forward-reference lesson re-confirmed.** Despite the
		// API-0368 hand-off comment hedging that the Traefik-ports
		// payload is typically a list of integers and the 200 body
		// schema **might** therefore diverge here, the spec at
		// `/settings.getTraefikPorts > get > responses > 200`
		// declares the canonical empty-object schema
		// (`{ "type": "object", "properties": {}, "additionalProperties": false }`),
		// matching every prior covered peer in the GET cohort
		// across the settings/* roster (API-0363..API-0368) as
		// well as the parameter-bearing GET precedents (API-0006
		// `ai-getAll`, API-0339 `server-getDefaultCommand`,
		// API-0342 `server-one`, API-0345 `server-security`).
		// The Dokploy spec leaves the actual Traefik-port payload
		// abstract at the wire-contract layer; the harness
		// therefore continues to ship `{}` as the canonical
		// success body and the empty-object response schema is
		// preserved end-to-end. The contributor still re-verified
		// the spec rather than assuming, per the per-operation
		// re-verification rule.
		//
		// **Family pivot — first parameter-bearing GET in the
		// settings/* roster.** API-0363 opened the parameter-free
		// GET sub-roster within settings/* (the eleven-entry POST
		// cohort API-0353..API-0362 preceded it); API-0364..API-0368
		// extended the parameter-free shape across six consecutive
		// entries. API-0369 pivots the sub-family to a **single
		// OPTIONAL query parameter** `serverId`, the first such
		// shape on the settings/* roster. The closest cross-tag
		// precedents are the server/* GETs that take a single
		// REQUIRED `serverId` (API-0339 `server-getDefaultCommand`,
		// API-0342 `server-one`, API-0345 `server-security`); the
		// closest precedent for an OPTIONAL `serverId` is API-0041
		// `backup-listBackupFiles` (which populated all three of
		// its REQUIRED + REQUIRED + OPTIONAL params end-to-end via
		// `SampleQuery`). Following that precedent and the
		// per-tag isolation rule we populate `SampleQuery` with a
		// fixture-slug literal under the settings/* `set-cov-*`
		// namespace so the success-leg `r.URL.Query()` re-read at
		// `runAPICoverageSuccess` exercises end-to-end forwarding
		// even though the parameter is OPTIONAL — the harness
		// does not gate on `required`-ness, it forwards whatever
		// `SampleQuery` carries (per the API-0077
		// `compose-getTags` precedent and the API-0041
		// `backup-listBackupFiles` precedent reasserted above).
		//
		// Fixture conventions:
		//   * `set-cov-getTraefikPorts-0369` — slug-named literal
		//     for the OPTIONAL `serverId` query parameter, unique
		//     against API-0351..API-0368's `set-cov-*` slugs and
		//     orthogonal to every prior tag's `srv-cov-*`,
		//     `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		//     `app-cov-*`, `ai-cov-*`, etc. namespaces.
		SampleQuery: map[string][]string{
			"serverId": {"set-cov-getTraefikPorts-0369"},
		},
		// 200 response in the spec is `{}` with `additionalProperties: false`,
		// matching the empty-success convention shared by every
		// prior settings/* GET peer (API-0363..API-0368).
		// Empty-object body keeps the success-leg envelope
		// assertion focused on `data.method` / `data.status`
		// rather than payload projection.
		SuccessResponse: `{}`,
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0368 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-bearing
		// platform-info getters like `getTraefikPorts` (which
		// returns the Dokploy/Traefik runtime port mapping itself,
		// scoped optionally by server). Auth is the universal
		// failure mode every Dokploy operation must re-prove, so
		// 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""` →
		// CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; this entry uses the canonical 401.
		//
		// The next case in the settings/* roster per PRD ordering
		// is API-0370 `settings-getUpdateData` (declared a **POST**
		// in the PRD with responses 200/400/401/403/404/500). The
		// next contributor must re-verify against
		// `internal/api/data/openapi.json >
		// /settings.getUpdateData > post` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry — the family pivots from GET
		// back to POST at that entry, mirroring the GET → POST
		// boundary already documented within the settings/* roster
		// (the eleven-entry POST cohort API-0353..API-0362
		// preceded the six-entry parameter-free GET sub-roster
		// API-0363..API-0368). Do not assume the parameter list,
		// request body, or response set carries over solely
		// because the slug prefix `get*` matches; the body-axis
		// history of the preceding `clean*` sub-roster
		// (API-0353..API-0362) and the verb-flip at API-0370
		// demonstrates why per-operation re-verification stays
		// mandatory across every family transition.
	},
	{
		StoryID:     "API-0370",
		OperationID: "settings-getUpdateData",
		Method:      http.MethodPost,
		Path:        "/settings.getUpdateData",
		Tag:         "settings",
		// Twentieth entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer` and
		// extended through API-0369 `settings-getTraefikPorts`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0369
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0369
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.getUpdateData > post`: a **POST** with **no
		// `requestBody` field at all** (this is structurally
		// identical to API-0354 `settings-cleanAllDeploymentQueue`,
		// API-0357 `settings-cleanMonitoring`, API-0358
		// `settings-cleanRedis`, and API-0359
		// `settings-cleanSSHPrivateKey` — the spec declares no
		// request body schema whatsoever, so the operation is a
		// true no-input POST), **zero parameters** (no query, no
		// path, no header). Responses 200/400/401/403/500 — note
		// the **absence of 404**, matching the four no-body POST
		// peers above and the API-0351 opener / API-0353 / API-0355
		// / API-0356 / API-0360 / API-0361 / API-0362 optional-body
		// POST peers, but **diverging from API-0363..API-0369's
		// 404-bearing GET sub-roster**. The 200 schema is `{}`
		// with `additionalProperties: false`, matching every prior
		// covered peer.
		//
		// **Family pivot — first POST after a seven-entry GET
		// sub-roster.** The settings/* roster opened with eleven
		// POSTs (API-0351 `assignDomainServer` through API-0362
		// `cleanUnusedVolumes`), then transitioned to seven GETs
		// (API-0363 `getDokployCloudIps` through API-0369
		// `getTraefikPorts`). API-0370 pivots the verb axis back
		// to POST while keeping the `get*` slug prefix — a useful
		// counter-example to the temptation to bind verb to slug
		// prefix. Despite the `get*` prefix this operation is a
		// POST in the OpenAPI spec, and the harness's POST branch
		// (rather than the GET branch) drives the success leg.
		// The slug-prefix-vs-verb decoupling is also visible in
		// the prior `getReleaseTag` (GET, API-0368) vs
		// `getUpdateData` (POST, this entry) pair: same `get*`
		// family on the wire, different HTTP method, and the
		// spec is the only authoritative source.
		//
		// **Forward-reference confirmation — verb axis flips back
		// to POST as predicted.** API-0369's hand-off comment
		// correctly forecast that API-0370 would pivot the family
		// from GET back to POST and explicitly cautioned against
		// inheriting the `SampleQuery` field from API-0369 (a GET
		// has no analogous query semantics on a no-body POST, and
		// the harness's POST branch with `len(SampleBody) == 0`
		// still skips the `Content-Type` and body-round-trip
		// assertions per the `if len(tc.SampleBody) > 0` guard
		// inside `runAPICoverageSuccess`). Direct inspection of
		// `internal/api/data/openapi.json >
		// /settings.getUpdateData > post` confirms the prediction
		// was correct: this is a no-body, no-parameter POST. The
		// per-operation re-verification rule kept the contributor
		// from accidentally promoting API-0369's optional-query
		// shape onto an operation that has neither query nor body.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-getUpdateData-0370` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified:
		//     no collisions with API-0351..API-0369's `set-cov-*`
		//     slugs, and orthogonal to every prior tag's
		//     `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		//     `compose-cov-*`, `app-cov-*`, `ai-cov-*`, etc.
		//     namespaces). Even though no fixture-token literal
		//     is materialised on the wire (the operation has no
		//     body and no parameters), the slug is reserved for
		//     this story to keep the per-tag cross-reference grep
		//     useful for future contributors.
		//   * **Neither `SampleBody`, `SampleQuery`, nor
		//     `SamplePathParams` are populated** — the spec
		//     declares no body and no parameters, and inventing a
		//     fictional body would (a) violate the
		//     re-verify-the-spec rule reasserted across
		//     API-0345..API-0369, (b) cause `runAPICoverageSuccess`
		//     to assert a body round-trip the CLI would never
		//     send, and (c) waste the no-body branch coverage
		//     this entry uniquely re-exercises after the seven-
		//     entry GET sub-roster (API-0363..API-0369). The
		//     harness still asserts the wire-level invariants
		//     (method, path, Authorization header) — the no-body
		//     POST cohort is not a coverage gap.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `getUpdateData` verb returns the Dokploy self-update
		// availability metadata for the running instance, not a
		// by-id resource lookup), so the per-tag opener convention
		// reasserted at API-0335..API-0369 that reserves 404 →
		// CodeNotFound for canonical `*-one` peers does not even
		// apply here. Auth is the universal failure mode every
		// Dokploy operation must re-prove, so 401 → CodeAuth via
		// the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput
		// stays reserved for stories where payload validation is
		// the operation's distinguishing failure mode; this
		// entry uses the canonical 401.
		//
		// The next case in the settings/* roster per PRD ordering
		// is API-0371 `settings-getWebServerSettings` (declared a
		// **GET** in the PRD with responses 200/400/401/403/404/500).
		// On shape it appears to revert to the parameter-free GET
		// sub-roster shape established at API-0363..API-0368, but
		// the next contributor must re-verify against
		// `internal/api/data/openapi.json >
		// /settings.getWebServerSettings > get` per the
		// forward-reference lesson before assuming any field is
		// identical to a prior GET entry — the verb-axis flip at
		// this very entry (GET → POST → GET) demonstrates why
		// slug-prefix-based pattern-matching is unreliable, and
		// the parameter axis (whether the GET takes a query
		// scoping it to a server, like API-0369, or no parameters
		// at all, like API-0363..API-0368) must be re-verified
		// per-operation. Do not assume the parameter list,
		// request body, or response set carries over solely
		// because the slug prefix `get*` matches.
		//
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0371",
		OperationID: "settings-getWebServerSettings",
		Method:      http.MethodGet,
		Path:        "/settings.getWebServerSettings",
		Tag:         "settings",
		// Twenty-first entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer` and
		// extended through API-0370 `settings-getUpdateData`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0370
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0370
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.getWebServerSettings > get`: a **GET** with
		// **zero parameters** (no query, no path, no header) and
		// **no request body** (GETs in this OpenAPI document never
		// carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the parameter-free GET sub-roster opened at
		// API-0363 `settings-getDokployCloudIps` and extended
		// through API-0368 `settings-getReleaseTag`, as well as
		// the parameter-bearing GET API-0369
		// `settings-getTraefikPorts`. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer in the settings/* GET cohort.
		//
		// **Forward-reference lesson re-confirmed.** The API-0370
		// hand-off comment hedged that this entry "appears to
		// revert to the parameter-free GET sub-roster shape
		// established at API-0363..API-0368, but the next
		// contributor must re-verify against
		// `internal/api/data/openapi.json >
		// /settings.getWebServerSettings > get` per the
		// forward-reference lesson before assuming any field is
		// identical to a prior GET entry — the verb-axis flip at
		// [API-0370] demonstrates why slug-prefix-based
		// pattern-matching is unreliable, and the parameter axis
		// (whether the GET takes a query scoping it to a server,
		// like API-0369, or no parameters at all, like
		// API-0363..API-0368) must be re-verified per-operation."
		// Direct inspection of the spec confirmed the prediction
		// in the affirmative direction: this is a parameter-free
		// GET with no body and no query, exactly the
		// API-0363..API-0368 shape (and explicitly NOT the
		// API-0369 shape with the OPTIONAL `serverId` query). The
		// per-operation re-verification rule kept the contributor
		// from accidentally promoting API-0369's `SampleQuery`
		// onto this story.
		//
		// **Family continuation — eighth entry of the
		// settings/* GET cohort, seventh of the parameter-free
		// GET sub-roster.** API-0363 opened the parameter-free
		// sub-family by pivoting off the eleven-entry POST cohort
		// (API-0353..API-0362); API-0364..API-0368 extended the
		// parameter-free shape across five consecutive entries;
		// API-0369 pivoted to a single OPTIONAL `serverId` query
		// (the only parameter-bearing GET in the settings/*
		// roster so far); API-0370 pivoted the verb axis to POST
		// while keeping the no-body, no-parameter shape; and
		// API-0371 reverts to the parameter-free GET shape under
		// the `getWebServer*` slug prefix. The verb-axis dance
		// across these last three entries
		// (GET → POST → GET) is the clearest cautionary example
		// of why slug-prefix-based pattern-matching is unreliable
		// and why every contributor must re-verify the spec
		// per-operation before populating any field.
		// `SampleBody`, `SampleQuery`, and `SamplePathParams` are
		// therefore deliberately omitted: the harness's GET
		// branch asserts that **no `Content-Type` request header
		// is sent** and ignores `SampleBody` entirely, so
		// carrying one would silently encode dead code on the
		// wire. The harness still asserts the wire-level
		// invariants (method, path, `Authorization` header,
		// empty query string, empty request body) at
		// `runAPICoverageSuccess`, and the canonical no-input
		// invocation
		// `yalla api call settings-getWebServerSettings --input '{}'
		// --json` is what the agent contract guarantees.
		//
		// Fixture conventions:
		//   * No per-case fixture token base is needed because
		//     this case populates neither `SampleBody`,
		//     `SampleQuery`, nor `SamplePathParams` — the
		//     parameter-free GET cohort precedent (API-0006
		//     `ai-getAll`, API-0350 `server-withSSHKey`,
		//     API-0363 `settings-getDokployCloudIps`,
		//     API-0364 `settings-getDokployVersion`,
		//     API-0365 `settings-getIp`, API-0366
		//     `settings-getLogCleanupStatus`, API-0367
		//     `settings-getOpenApiDocument`, API-0368
		//     `settings-getReleaseTag`) applies. A reservation
		//     slot `set-cov-getWebServerSettings-0371` is left
		//     open under the settings/* `set-cov-*` namespace
		//     for any future regression test that needs a unique
		//     literal tied to this story; the reservation is
		//     unique against API-0351..API-0370's `set-cov-*`
		//     slugs and orthogonal to every prior tag's
		//     `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		//     `compose-cov-*`, `app-cov-*`, `ai-cov-*`, etc.
		//     namespaces.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0370 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// platform-info getters like `getWebServerSettings`
		// (which returns the Dokploy web-server configuration
		// itself, not a single resource keyed by id). Auth is
		// the universal failure mode every Dokploy operation
		// must re-prove, so 401 → CodeAuth via the harness
		// default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput
		// stays reserved for stories where payload validation
		// is the operation's distinguishing failure mode; this
		// entry uses the canonical 401.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0372 `settings-haveActivateRequests`
		// (declared a **GET** in the PRD with responses
		// 200/400/401/403/500 — note the absence of 404, like
		// the no-body POST peers API-0354/0357/0358/0359/0370
		// rather than the 404-bearing GET sub-roster
		// API-0363..API-0368/API-0371). The next contributor
		// must re-verify against `internal/api/data/openapi.json
		// > /settings.haveActivateRequests > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry — the response-set axis flip
		// (presence vs absence of 404) at API-0372 is another
		// reminder that slug-prefix-based pattern-matching is
		// unreliable. Do not assume the parameter list, request
		// body, or response set carries over solely because the
		// verb prefix and adjacent slug match; the eleven-flip
		// body-axis history of the preceding `clean*`
		// sub-roster (API-0353..API-0362) and the verb-flip at
		// API-0370 demonstrate why per-operation
		// re-verification stays mandatory across every family
		// transition.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0372",
		OperationID: "settings-haveActivateRequests",
		Method:      http.MethodGet,
		Path:        "/settings.haveActivateRequests",
		Tag:         "settings",
		// Twenty-second entry on the settings/* coverage roster, inheriting
		// the `set-cov-*` per-tag fixture-isolation namespace
		// established by API-0351 `settings-assignDomainServer` and
		// extended through API-0371 `settings-getWebServerSettings`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`, `app-cov-*`,
		// `ai-cov-*`, or any other prior tag's namespace, per the
		// per-tag isolation rule reasserted at API-0335..API-0371
		// and originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0371
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.haveActivateRequests > get`: a **GET** with
		// **zero parameters** (no query, no path, no header) and
		// **no request body** (GETs in this OpenAPI document never
		// carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the parameter-free GET sub-roster opened at
		// API-0363 `settings-getDokployCloudIps` and extended
		// through API-0368 `settings-getReleaseTag` and API-0371
		// `settings-getWebServerSettings`. The 200 schema is `{}`
		// with `additionalProperties: false`, matching every prior
		// covered peer in the settings/* GET cohort.
		//
		// **Forward-reference correction.** The API-0371 hand-off
		// comment predicted this story would land in the
		// "absence of 404" branch (clustering with the no-body
		// POST peers API-0354/0357/0358/0359/0370 instead of the
		// 404-bearing GET sub-roster). Direct inspection of the
		// spec at `/settings.haveActivateRequests > get` falsified
		// that prediction in the affirmative direction: 404 IS
		// declared on the operation, so this entry stays under the
		// canonical parameter-free GET shape established at
		// API-0363..API-0368/API-0371. The per-operation
		// re-verification rule kept the contributor from
		// accidentally adopting the API-0354/0357/0358/0359/0370
		// no-404 response set — and the falsified prediction is
		// itself the canonical example of why slug-prefix-based
		// pattern-matching is unreliable. The `haveActivate*` slug
		// could plausibly have routed either way; only the spec
		// inspection settles it.
		//
		// **Family continuation — ninth entry of the
		// settings/* GET cohort, eighth of the parameter-free
		// GET sub-roster.** API-0363 opened the parameter-free
		// sub-family by pivoting off the eleven-entry POST cohort
		// (API-0353..API-0362); API-0364..API-0368 extended the
		// parameter-free shape across five consecutive entries;
		// API-0369 pivoted to a single OPTIONAL `serverId` query
		// (the only parameter-bearing GET in the settings/*
		// roster so far); API-0370 pivoted the verb axis to POST
		// while keeping the no-body, no-parameter shape; API-0371
		// reverted to the parameter-free GET shape under the
		// `getWebServer*` slug prefix; and API-0372 continues the
		// parameter-free GET shape under the `have*` slug prefix
		// (boolean platform-state probes — the `haveActivate*`
		// verb returns whether the running Dokploy instance has
		// any pending activation requests, not a by-id resource
		// lookup). `SampleBody`, `SampleQuery`, and
		// `SamplePathParams` are therefore deliberately omitted:
		// the harness's GET branch asserts that **no
		// `Content-Type` request header is sent** and ignores
		// `SampleBody` entirely, so carrying one would silently
		// encode dead code on the wire. The harness still asserts
		// the wire-level invariants (method, path, `Authorization`
		// header, empty query string, empty request body) at
		// `runAPICoverageSuccess`, and the canonical no-input
		// invocation
		// `yalla api call settings-haveActivateRequests --input '{}'
		// --json` is what the agent contract guarantees.
		//
		// Fixture conventions:
		//   * No per-case fixture token base is needed because
		//     this case populates neither `SampleBody`,
		//     `SampleQuery`, nor `SamplePathParams` — the
		//     parameter-free GET cohort precedent (API-0006
		//     `ai-getAll`, API-0350 `server-withSSHKey`,
		//     API-0363 `settings-getDokployCloudIps`,
		//     API-0364 `settings-getDokployVersion`,
		//     API-0365 `settings-getIp`, API-0366
		//     `settings-getLogCleanupStatus`, API-0367
		//     `settings-getOpenApiDocument`, API-0368
		//     `settings-getReleaseTag`, API-0371
		//     `settings-getWebServerSettings`) applies. A
		//     reservation slot
		//     `set-cov-haveActivateRequests-0372` is left open
		//     under the settings/* `set-cov-*` namespace for any
		//     future regression test that needs a unique literal
		//     tied to this story; the reservation is unique
		//     against API-0351..API-0371's `set-cov-*` slugs and
		//     orthogonal to every prior tag's `srv-cov-*`,
		//     `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		//     `app-cov-*`, `ai-cov-*`, etc. namespaces.
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0371 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// platform-state probes like `haveActivateRequests`
		// (which returns the activation-request presence flag for
		// the running Dokploy instance, not a single resource
		// keyed by id). Auth is the universal failure mode every
		// Dokploy operation must re-prove, so 401 → CodeAuth via
		// the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput
		// stays reserved for stories where payload validation is
		// the operation's distinguishing failure mode; this entry
		// uses the canonical 401.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0373
		// `settings-haveTraefikDashboardPortEnabled` (declared a
		// **GET** in the PRD). The slug prefix `have*` matches
		// this entry, but the API-0371 → API-0372 falsified
		// prediction is itself the cautionary example: the next
		// contributor must re-verify against
		// `internal/api/data/openapi.json >
		// /settings.haveTraefikDashboardPortEnabled > get` per
		// the forward-reference lesson before assuming any field
		// is identical to this entry — the response-set axis
		// (presence vs absence of 404), the parameter axis (zero
		// vs one optional query), and the request-body axis
		// (none vs JSON) must each be re-verified per-operation.
		// Do not assume the parameter list, request body, or
		// response set carries over solely because the verb
		// prefix and adjacent slug match; the eleven-flip
		// body-axis history of the preceding `clean*` sub-roster
		// (API-0353..API-0362), the verb-flip at API-0370, and
		// the falsified-404 prediction at API-0371 → API-0372
		// demonstrate why per-operation re-verification stays
		// mandatory across every family transition.
		SuccessResponse: `{}`,
	},
	{
		StoryID:     "API-0373",
		OperationID: "settings-haveTraefikDashboardPortEnabled",
		Method:      http.MethodGet,
		Path:        "/settings.haveTraefikDashboardPortEnabled",
		Tag:         "settings",
		// Twenty-third entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0372 `settings-haveActivateRequests` (must not
		// back-reference the closed `srv-cov-*`, `proj-cov-*`,
		// `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		// or any other prior tag's namespace, per the per-tag
		// isolation rule reasserted at API-0335..API-0372 and
		// originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0372
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.haveTraefikDashboardPortEnabled > get`: a
		// **GET** with **one OPTIONAL query parameter**
		// `serverId` (string, `required: false` — scopes the
		// dashboard-port probe to a specific Dokploy worker
		// server when Traefik is replicated across multiple
		// servers) and **no request body** (GETs in this OpenAPI
		// document never carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the parameter-bearing GET precedent at
		// API-0369 `settings-getTraefikPorts` and the
		// parameter-free GET sub-roster opened at API-0363
		// `settings-getDokployCloudIps` and extended through
		// API-0368 `settings-getReleaseTag`, API-0371
		// `settings-getWebServerSettings`, and API-0372
		// `settings-haveActivateRequests`. The 200 schema is `{}`
		// with `additionalProperties: false`, matching every
		// prior covered peer in the settings/* GET cohort.
		//
		// **Forward-reference correction.** The API-0372 hand-off
		// comment hedged that the parameter axis (zero vs one
		// optional query) had to be re-verified per-operation
		// despite the matching `have*` slug prefix. Direct
		// inspection of the spec at
		// `/settings.haveTraefikDashboardPortEnabled > get`
		// confirmed the divergence in the affirmative direction:
		// this entry **does** carry an OPTIONAL `serverId`
		// query parameter (unlike API-0372 which was
		// parameter-free), so the entry tracks the parameter-
		// bearing GET precedent at API-0369
		// `settings-getTraefikPorts` rather than the
		// parameter-free precedent at API-0372. The
		// per-operation re-verification rule kept the
		// contributor from accidentally adopting the API-0372
		// parameter-free shape — slug-prefix matching alone
		// could not have settled which side of the parameter
		// axis this entry belongs to.
		//
		// **Family continuation — tenth entry of the settings/*
		// GET cohort, second of the parameter-bearing GET
		// sub-roster.** API-0363 opened the parameter-free
		// sub-family by pivoting off the eleven-entry POST cohort
		// (API-0353..API-0362); API-0364..API-0368 extended the
		// parameter-free shape across five consecutive entries;
		// API-0369 pivoted to a single OPTIONAL `serverId` query
		// (the first parameter-bearing GET in the settings/*
		// roster); API-0370 pivoted the verb axis to POST while
		// keeping the no-body, no-parameter shape; API-0371
		// reverted to the parameter-free GET shape under the
		// `getWebServer*` slug prefix; API-0372 continued the
		// parameter-free GET shape under the `have*` slug
		// prefix; and API-0373 pivots back to the
		// parameter-bearing GET shape under the same `have*`
		// slug prefix (the second OPTIONAL-`serverId` GET in
		// the settings/* roster). Following the API-0369
		// precedent and the per-tag isolation rule, we populate
		// `SampleQuery` with a fixture-slug literal under the
		// settings/* `set-cov-*` namespace so the success-leg
		// `r.URL.Query()` re-read at `runAPICoverageSuccess`
		// exercises end-to-end forwarding even though the
		// parameter is OPTIONAL — the harness does not gate on
		// `required`-ness, it forwards whatever `SampleQuery`
		// carries (per the API-0077 `compose-getTags` precedent,
		// the API-0041 `backup-listBackupFiles` precedent, and
		// the API-0369 `settings-getTraefikPorts` precedent).
		//
		// Fixture conventions:
		//   * `set-cov-haveTraefikDashboardPortEnabled-0373` —
		//     slug-named literal for the OPTIONAL `serverId`
		//     query parameter, unique against
		//     API-0351..API-0372's `set-cov-*` slugs and
		//     orthogonal to every prior tag's `srv-cov-*`,
		//     `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		//     `app-cov-*`, `ai-cov-*`, etc. namespaces.
		SampleQuery: map[string][]string{
			"serverId": {"set-cov-haveTraefikDashboardPortEnabled-0373"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the
		// empty-success convention shared by every prior
		// settings/* GET peer (API-0363..API-0372). Empty-object
		// body keeps the success-leg envelope assertion focused
		// on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0372 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-bearing
		// platform-state probes like
		// `haveTraefikDashboardPortEnabled` (which returns
		// whether the running Dokploy/Traefik instance has the
		// dashboard port exposed, scoped optionally by server,
		// not a single resource keyed by id). Auth is the
		// universal failure mode every Dokploy operation must
		// re-prove, so 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories
		// where payload validation is the operation's
		// distinguishing failure mode; this entry uses the
		// canonical 401.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0374 `settings-health` (declared a
		// **GET** in the PRD). The next contributor must
		// re-verify against `internal/api/data/openapi.json >
		// /settings.health > get` per the forward-reference
		// lesson before assuming any field is identical to this
		// entry — the response-set axis (presence vs absence of
		// 404), the parameter axis (zero vs one optional query
		// vs other), and the request-body axis (none vs JSON)
		// must each be re-verified per-operation. Do not assume
		// the parameter list, request body, or response set
		// carries over solely because the verb is GET and the
		// adjacent slug matches; the falsified prediction at
		// API-0371 → API-0372 (parameter-free) and the
		// re-confirmed parameter-bearing shape at
		// API-0372 → API-0373 demonstrate that two adjacent
		// entries with the same slug prefix can sit on opposite
		// sides of the parameter axis. Per-operation
		// re-verification stays mandatory across every family
		// transition.
	},
	{
		StoryID:     "API-0374",
		OperationID: "settings-health",
		Method:      http.MethodGet,
		Path:        "/settings.health",
		Tag:         "settings",
		// Twenty-fourth entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0373 `settings-haveTraefikDashboardPortEnabled`
		// (must not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		// `app-cov-*`, `ai-cov-*`, or any other prior tag's
		// namespace, per the per-tag isolation rule reasserted
		// at API-0335..API-0373 and originally established at
		// API-0246 `organization-active`). This entry carries
		// **no per-case fixture token** because the operation
		// is parameter-free with no request body — there is no
		// payload field to namespace.
		//
		// **Spec re-verified per the API-0345..API-0373
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /settings.health >
		// get`: a **GET** with **zero parameters** (no query,
		// no path, no header) and **no request body** (GETs in
		// this OpenAPI document never carry a `requestBody`
		// field). Responses 200/400/401/403/404/500 — the
		// **404 stays present**, matching the parameter-free
		// GET sub-roster opened at API-0363
		// `settings-getDokployCloudIps` and extended through
		// API-0368 `settings-getReleaseTag`, API-0371
		// `settings-getWebServerSettings`, and API-0372
		// `settings-haveActivateRequests`, as well as the
		// parameter-bearing GET peers API-0369
		// `settings-getTraefikPorts` and API-0373
		// `settings-haveTraefikDashboardPortEnabled`. The 200
		// schema is `{}` with `additionalProperties: false`,
		// matching every prior covered peer in the settings/*
		// GET cohort.
		//
		// **Forward-reference correction.** The API-0373
		// hand-off comment hedged that the parameter axis
		// (zero vs one optional query) had to be re-verified
		// per-operation. Direct inspection of the spec at
		// `/settings.health > get` confirmed the entry sits on
		// the parameter-free side of the axis: this operation
		// is a platform-wide health probe (not scoped per
		// server, unlike API-0369 `getTraefikPorts` and
		// API-0373 `haveTraefikDashboardPortEnabled` which
		// both carry an OPTIONAL `serverId` query), so it
		// tracks the parameter-free GET shape canonicalised at
		// API-0363..API-0368/API-0371/API-0372 rather than the
		// parameter-bearing shape at API-0369/API-0373. The
		// per-operation re-verification rule kept the
		// contributor from accidentally inheriting the
		// API-0373 `SampleQuery` field.
		//
		// **Family continuation — eleventh entry of the
		// settings/* GET cohort, ninth of the parameter-free
		// GET sub-roster.** API-0363 opened the parameter-free
		// sub-family by pivoting off the eleven-entry POST
		// cohort (API-0353..API-0362); API-0364..API-0368
		// extended the parameter-free shape across five
		// consecutive entries; API-0369 pivoted to a single
		// OPTIONAL `serverId` query (the first
		// parameter-bearing GET in the settings/* roster);
		// API-0370 pivoted the verb axis to POST while
		// keeping the no-body, no-parameter shape; API-0371
		// reverted to the parameter-free GET shape;
		// API-0372 stayed parameter-free with the falsified
		// no-404 prediction settled in favour of the
		// 404-bearing canonical shape; API-0373 pivoted back
		// to the OPTIONAL `serverId` query shape mirroring
		// API-0369. API-0374 reverts to the parameter-free
		// shape: zero parameters, no body, 404-bearing
		// response set. Two consecutive parameter axes can
		// flip back and forth based purely on whether the
		// underlying probe is platform-wide vs
		// server-scoped — slug-prefix-based pattern matching
		// is unreliable here.
		//
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the
		// empty-success convention shared by every prior
		// settings/* GET peer (API-0363..API-0373). Empty-object
		// body keeps the success-leg envelope assertion focused
		// on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0373 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// platform-state probes like `health` (which returns
		// the running Dokploy instance's overall health, not a
		// single resource keyed by id). Auth is the universal
		// failure mode every Dokploy operation must re-prove,
		// so 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories
		// where payload validation is the operation's
		// distinguishing failure mode; this entry uses the
		// canonical 401.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0375 `settings-isCloud` (declared a
		// **GET** in the PRD). The next contributor must
		// re-verify against `internal/api/data/openapi.json >
		// /settings.isCloud > get` per the forward-reference
		// lesson before assuming any field is identical to this
		// entry — the response-set axis (presence vs absence of
		// 404), the parameter axis (zero vs one optional query
		// vs other), and the request-body axis (none vs JSON)
		// must each be re-verified per-operation. Do not assume
		// the parameter list, request body, or response set
		// carries over solely because the verb is GET and the
		// adjacent slug matches; the parameter-axis flip-flop
		// across API-0371..API-0374 (parameter-free →
		// parameter-bearing → parameter-free) demonstrates
		// that two adjacent entries with the same slug prefix
		// can sit on opposite sides of the parameter axis.
		// Per-operation re-verification stays mandatory across
		// every family transition.
	},
	{
		StoryID:     "API-0375",
		OperationID: "settings-isCloud",
		Method:      http.MethodGet,
		Path:        "/settings.isCloud",
		Tag:         "settings",
		// Twenty-fifth entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0374 `settings-health` (must not back-reference
		// the closed `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		// `compose-cov-*`, `app-cov-*`, `ai-cov-*`, or any other
		// prior tag's namespace, per the per-tag isolation rule
		// reasserted at API-0335..API-0374 and originally
		// established at API-0246 `organization-active`). This
		// entry carries **no per-case fixture token** because the
		// operation is parameter-free with no request body —
		// there is no payload field to namespace.
		//
		// **Spec re-verified per the API-0345..API-0374
		// forward-reference lesson** against
		// `internal/api/data/openapi.json > /settings.isCloud >
		// get`: a **GET** with **zero parameters** (no query,
		// no path, no header) and **no request body** (GETs in
		// this OpenAPI document never carry a `requestBody`
		// field). Responses 200/400/401/403/404/500 — the
		// **404 stays present**, matching the parameter-free
		// GET sub-roster opened at API-0363
		// `settings-getDokployCloudIps` and extended through
		// API-0368 `settings-getReleaseTag`, API-0371
		// `settings-getWebServerSettings`, API-0372
		// `settings-haveActivateRequests`, and API-0374
		// `settings-health`, as well as the parameter-bearing
		// GET peers API-0369 `settings-getTraefikPorts` and
		// API-0373 `settings-haveTraefikDashboardPortEnabled`.
		// The 200 schema is `{}` with `additionalProperties:
		// false`, matching every prior covered peer in the
		// settings/* GET cohort.
		//
		// **Forward-reference correction.** The API-0374
		// hand-off comment hedged that the parameter axis
		// (zero vs one optional query) had to be re-verified
		// per-operation. Direct inspection of the spec at
		// `/settings.isCloud > get` confirmed the entry sits on
		// the parameter-free side of the axis: this operation
		// is a platform-wide cloud-mode probe (whether the
		// running Dokploy instance is the hosted cloud build vs
		// self-hosted), not scoped per server, so it tracks the
		// parameter-free GET shape canonicalised at
		// API-0363..API-0368/API-0371/API-0372/API-0374 rather
		// than the parameter-bearing shape at
		// API-0369/API-0373. The per-operation re-verification
		// rule kept the contributor from accidentally inheriting
		// the API-0373 `SampleQuery` field by slug-pattern
		// matching alone.
		//
		// **Family continuation — twelfth entry of the
		// settings/* GET cohort, tenth of the parameter-free
		// GET sub-roster.** API-0363 opened the parameter-free
		// sub-family by pivoting off the eleven-entry POST
		// cohort (API-0353..API-0362); API-0364..API-0368
		// extended the parameter-free shape across five
		// consecutive entries; API-0369 pivoted to a single
		// OPTIONAL `serverId` query (the first
		// parameter-bearing GET in the settings/* roster);
		// API-0370 pivoted the verb axis to POST while
		// keeping the no-body, no-parameter shape; API-0371
		// reverted to the parameter-free GET shape; API-0372
		// stayed parameter-free with the falsified no-404
		// prediction settled in favour of the 404-bearing
		// canonical shape; API-0373 pivoted back to the
		// OPTIONAL `serverId` query shape mirroring API-0369;
		// API-0374 reverted to the parameter-free shape;
		// API-0375 continues the parameter-free shape: zero
		// parameters, no body, 404-bearing response set. The
		// `is*` slug prefix (a boolean platform-state probe)
		// joins the `have*` slug prefix on the parameter-free
		// side of the axis when the underlying probe is
		// platform-wide (cf. `haveActivateRequests`,
		// `haveTraefikDashboardPortEnabled` on the
		// parameter-bearing side).
		//
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the
		// empty-success convention shared by every prior
		// settings/* GET peer (API-0363..API-0374). Empty-object
		// body keeps the success-leg envelope assertion focused
		// on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0374 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// platform-state probes like `isCloud` (which returns
		// the running Dokploy instance's deployment mode, not a
		// single resource keyed by id). Auth is the universal
		// failure mode every Dokploy operation must re-prove,
		// so 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories
		// where payload validation is the operation's
		// distinguishing failure mode; this entry uses the
		// canonical 401.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0376 `settings-isUserSubscribed`
		// (declared a **GET** in the PRD). The next contributor
		// must re-verify against `internal/api/data/openapi.json
		// > /settings.isUserSubscribed > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry — the response-set axis
		// (presence vs absence of 404), the parameter axis (zero
		// vs one optional query vs other), and the request-body
		// axis (none vs JSON) must each be re-verified
		// per-operation. Do not assume the parameter list,
		// request body, or response set carries over solely
		// because the verb is GET and the adjacent slug matches;
		// the parameter-axis flip-flop across
		// API-0371..API-0375 (parameter-free → parameter-bearing
		// → parameter-free → parameter-free) demonstrates that
		// two adjacent entries with the same slug prefix can sit
		// on opposite sides of the parameter axis.
		// Per-operation re-verification stays mandatory across
		// every family transition.
	},
	{
		StoryID:     "API-0376",
		OperationID: "settings-isUserSubscribed",
		Method:      http.MethodGet,
		Path:        "/settings.isUserSubscribed",
		Tag:         "settings",
		// Twenty-sixth entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0375 `settings-isCloud` (must not back-reference
		// the closed `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		// `compose-cov-*`, `app-cov-*`, `ai-cov-*`, or any other
		// prior tag's namespace, per the per-tag isolation rule
		// reasserted at API-0335..API-0375 and originally
		// established at API-0246 `organization-active`). This
		// entry carries **no per-case fixture token** because the
		// operation is parameter-free with no request body —
		// there is no payload field to namespace.
		//
		// **Spec re-verified per the API-0345..API-0375
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.isUserSubscribed > get`: a **GET** with
		// **zero parameters** (no query, no path, no header) and
		// **no request body** (GETs in this OpenAPI document
		// never carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the parameter-free GET sub-roster opened at
		// API-0363 `settings-getDokployCloudIps` and extended
		// through API-0368 `settings-getReleaseTag`, API-0371
		// `settings-getWebServerSettings`, API-0372
		// `settings-haveActivateRequests`, API-0374
		// `settings-health`, and API-0375 `settings-isCloud`,
		// as well as the parameter-bearing GET peers API-0369
		// `settings-getTraefikPorts` and API-0373
		// `settings-haveTraefikDashboardPortEnabled`. The 200
		// schema is `{}` with `additionalProperties: false`,
		// matching every prior covered peer in the settings/*
		// GET cohort.
		//
		// **Forward-reference confirmation.** The API-0375
		// hand-off comment hedged that the parameter axis (zero
		// vs one optional query) had to be re-verified
		// per-operation. Direct inspection of the spec at
		// `/settings.isUserSubscribed > get` confirmed the entry
		// sits on the parameter-free side of the axis: the
		// subscription-state probe is platform-wide (whether the
		// authenticated user holds an active Dokploy
		// subscription), not scoped per server, so it tracks the
		// parameter-free GET shape canonicalised at
		// API-0363..API-0368/API-0371/API-0372/API-0374/API-0375
		// rather than the parameter-bearing shape at
		// API-0369/API-0373. The `is*` slug prefix (a boolean
		// platform-state probe) continues to join the
		// parameter-free side of the axis when the underlying
		// probe is platform-wide, mirroring API-0375
		// `settings-isCloud`.
		//
		// **Family continuation — thirteenth entry of the
		// settings/* GET cohort, eleventh of the parameter-free
		// GET sub-roster.** API-0363 opened the parameter-free
		// sub-family by pivoting off the eleven-entry POST
		// cohort (API-0353..API-0362); API-0364..API-0368
		// extended the parameter-free shape across five
		// consecutive entries; API-0369 pivoted to a single
		// OPTIONAL `serverId` query (the first
		// parameter-bearing GET in the settings/* roster);
		// API-0370 pivoted the verb axis to POST while keeping
		// the no-body, no-parameter shape; API-0371 reverted to
		// the parameter-free GET shape; API-0372 stayed
		// parameter-free with the falsified no-404 prediction
		// settled in favour of the 404-bearing canonical shape;
		// API-0373 pivoted back to the OPTIONAL `serverId`
		// query shape mirroring API-0369; API-0374 reverted to
		// the parameter-free shape; API-0375 continued the
		// parameter-free shape; API-0376 continues the
		// parameter-free shape: zero parameters, no body,
		// 404-bearing response set. Two consecutive `is*`-prefix
		// platform-state probes (API-0375 `isCloud`, API-0376
		// `isUserSubscribed`) now both anchor to the
		// parameter-free side of the axis — but the per-operation
		// re-verification rule still mandates spec inspection at
		// every family transition; consecutive same-prefix
		// alignment is not a substitute.
		//
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the
		// empty-success convention shared by every prior
		// settings/* GET peer (API-0363..API-0375). Empty-object
		// body keeps the success-leg envelope assertion focused
		// on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0375 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// platform-state probes like `isUserSubscribed` (which
		// returns the authenticated user's subscription status,
		// not a single resource keyed by id). Auth is the
		// universal failure mode every Dokploy operation must
		// re-prove, so 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories
		// where payload validation is the operation's
		// distinguishing failure mode; this entry uses the
		// canonical 401.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0377 `settings-readDirectories`
		// (declared a **GET** in the PRD). The next contributor
		// must re-verify against `internal/api/data/openapi.json
		// > /settings.readDirectories > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry — the response-set axis
		// (presence vs absence of 404), the parameter axis (zero
		// vs one optional query vs other), and the request-body
		// axis (none vs JSON) must each be re-verified
		// per-operation. The slug pivots from `is*`
		// (platform-state probe) to `read*` (resource-content
		// reader); per the slug-prefix-is-not-shape lesson
		// reasserted at API-0371..API-0375, the `read*` family's
		// parameter axis is unknown until directly inspected.
		// Do not assume the parameter list, request body, or
		// response set carries over solely because the verb is
		// GET; the parameter-axis flip-flop across
		// API-0371..API-0376 (parameter-free → parameter-bearing
		// → parameter-free → parameter-free → parameter-free)
		// demonstrates that adjacent entries can sit on opposite
		// sides of the parameter axis. Per-operation
		// re-verification stays mandatory across every family
		// transition.
	},
	{
		StoryID:     "API-0377",
		OperationID: "settings-readDirectories",
		Method:      http.MethodGet,
		Path:        "/settings.readDirectories",
		Tag:         "settings",
		// Twenty-seventh entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0376 `settings-isUserSubscribed` (must not
		// back-reference the closed `srv-cov-*`, `proj-cov-*`,
		// `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		// or any other prior tag's namespace, per the per-tag
		// isolation rule reasserted at API-0335..API-0376 and
		// originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0376
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.readDirectories > get`: a **GET** with
		// **one OPTIONAL query parameter** `serverId` (string,
		// `required: false` — scopes the directory-listing
		// probe to a specific Dokploy worker server when the
		// filesystem layout being inspected lives on a remote
		// node rather than the controller) and **no request
		// body** (GETs in this OpenAPI document never carry a
		// `requestBody` field). Responses 200/400/401/403/404/500
		// — the **404 stays present**, matching the
		// parameter-bearing GET precedents at API-0369
		// `settings-getTraefikPorts` and API-0373
		// `settings-haveTraefikDashboardPortEnabled`, and the
		// parameter-free GET sub-roster opened at API-0363
		// `settings-getDokployCloudIps` and extended through
		// API-0368 `settings-getReleaseTag`, API-0371
		// `settings-getWebServerSettings`, API-0372
		// `settings-haveActivateRequests`, API-0374
		// `settings-health`, API-0375 `settings-isCloud`, and
		// API-0376 `settings-isUserSubscribed`. The 200 schema
		// is `{}` with `additionalProperties: false`, matching
		// every prior covered peer in the settings/* GET cohort.
		//
		// **Forward-reference correction.** The API-0376 hand-off
		// comment hedged that the parameter axis (zero vs one
		// optional query) had to be re-verified per-operation
		// despite the verb axis staying GET, and explicitly
		// flagged the slug pivot from `is*` (platform-state
		// probe) to `read*` (resource-content reader) as a
		// potential shape inflection point. Direct inspection
		// of the spec at `/settings.readDirectories > get`
		// confirmed the divergence in the affirmative direction:
		// this entry **does** carry an OPTIONAL `serverId` query
		// parameter (unlike API-0376 which was parameter-free),
		// so the entry tracks the parameter-bearing GET
		// precedents at API-0369 and API-0373 rather than the
		// parameter-free precedents at API-0363..API-0368,
		// API-0371, API-0372, API-0374, API-0375, or API-0376.
		// The per-operation re-verification rule kept the
		// contributor from accidentally adopting the API-0376
		// parameter-free shape — the slug pivot from `is*` to
		// `read*` correctly predicted a shape change but did not
		// itself dictate which direction the change would take;
		// only direct spec inspection settled the parameter
		// axis. The `read*` slug prefix (a resource-content
		// reader) appears here for the first time in the
		// settings/* GET cohort and joins the parameter-bearing
		// side of the axis because reading directory contents is
		// inherently scoped to a host filesystem (and therefore
		// optionally per-server in a multi-node deployment),
		// unlike `is*`-prefixed platform-state probes whose
		// answers are platform-wide.
		//
		// **Family continuation — fourteenth entry of the
		// settings/* GET cohort, third of the parameter-bearing
		// GET sub-roster.** API-0363 opened the parameter-free
		// sub-family by pivoting off the eleven-entry POST cohort
		// (API-0353..API-0362); API-0364..API-0368 extended the
		// parameter-free shape across five consecutive entries;
		// API-0369 pivoted to a single OPTIONAL `serverId` query
		// (the first parameter-bearing GET in the settings/*
		// roster); API-0370 pivoted the verb axis to POST while
		// keeping the no-body, no-parameter shape; API-0371
		// reverted to the parameter-free GET shape; API-0372
		// stayed parameter-free; API-0373 pivoted back to the
		// OPTIONAL `serverId` query shape mirroring API-0369
		// (the second parameter-bearing GET in the settings/*
		// roster); API-0374 reverted to the parameter-free
		// shape; API-0375 continued the parameter-free shape;
		// API-0376 continued the parameter-free shape; and
		// API-0377 pivots back to the OPTIONAL `serverId` query
		// shape mirroring API-0369 and API-0373 (the third
		// parameter-bearing GET in the settings/* roster).
		// Following the API-0369 and API-0373 precedents and the
		// per-tag isolation rule, we populate `SampleQuery` with
		// a fixture-slug literal under the settings/*
		// `set-cov-*` namespace so the success-leg
		// `r.URL.Query()` re-read at `runAPICoverageSuccess`
		// exercises end-to-end forwarding even though the
		// parameter is OPTIONAL — the harness does not gate on
		// `required`-ness, it forwards whatever `SampleQuery`
		// carries (per the API-0077 `compose-getTags`
		// precedent, the API-0041 `backup-listBackupFiles`
		// precedent, the API-0369 `settings-getTraefikPorts`
		// precedent, and the API-0373
		// `settings-haveTraefikDashboardPortEnabled` precedent).
		//
		// Fixture conventions:
		//   * `set-cov-readDirectories-0377` — slug-named
		//     literal for the OPTIONAL `serverId` query
		//     parameter, unique against API-0351..API-0376's
		//     `set-cov-*` slugs and orthogonal to every prior
		//     tag's `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		//     `compose-cov-*`, `app-cov-*`, `ai-cov-*`, etc.
		//     namespaces.
		SampleQuery: map[string][]string{
			"serverId": {"set-cov-readDirectories-0377"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the
		// empty-success convention shared by every prior
		// settings/* GET peer (API-0363..API-0376). Empty-object
		// body keeps the success-leg envelope assertion focused
		// on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0376 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for
		// parameter-bearing directory-listing probes like
		// `readDirectories` (which returns the contents of a
		// filesystem directory, not a single resource keyed by
		// id — and the `serverId` query is OPTIONAL, so the
		// happy path itself does not require the parameter to
		// resolve to a known target). Auth is the universal
		// failure mode every Dokploy operation must re-prove,
		// so 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories
		// where payload validation is the operation's
		// distinguishing failure mode; this entry uses the
		// canonical 401.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0378
		// `settings-readMiddlewareTraefikConfig` (declared a
		// **GET** in the PRD). The next contributor must
		// re-verify against `internal/api/data/openapi.json >
		// /settings.readMiddlewareTraefikConfig > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry — the response-set axis
		// (presence vs absence of 404), the parameter axis
		// (zero vs one optional query vs other), and the
		// request-body axis (none vs JSON) must each be
		// re-verified per-operation. The slug stays `read*` but
		// pivots from a directory-content reader
		// (`readDirectories`) to a Traefik-config reader
		// (`readMiddlewareTraefikConfig`); per the
		// slug-prefix-is-not-shape lesson reasserted at
		// API-0371..API-0376, two consecutive `read*` entries
		// can still sit on opposite sides of the parameter axis
		// or carry different response sets. Do not assume the
		// parameter list, request body, or response set carries
		// over solely because the verb is GET and the slug
		// prefix matches; the parameter-axis flip-flop across
		// API-0371..API-0377 (parameter-free → parameter-bearing
		// → parameter-free → parameter-free → parameter-free →
		// parameter-bearing) demonstrates that adjacent entries
		// regularly sit on opposite sides of the parameter axis.
		// Per-operation re-verification stays mandatory across
		// every family transition.
	},
	{
		StoryID:     "API-0378",
		OperationID: "settings-readMiddlewareTraefikConfig",
		Method:      http.MethodGet,
		Path:        "/settings.readMiddlewareTraefikConfig",
		Tag:         "settings",
		// Twenty-eighth entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0377 `settings-readDirectories` (must not
		// back-reference the closed `srv-cov-*`, `proj-cov-*`,
		// `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		// or any other prior tag's namespace, per the per-tag
		// isolation rule reasserted at API-0335..API-0377 and
		// originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0377
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.readMiddlewareTraefikConfig > get`: a **GET**
		// with **zero parameters** (`parameters: []`) and **no
		// request body** (GETs in this OpenAPI document never
		// carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the parameter-free GET sub-roster opened at
		// API-0363 `settings-getDokployCloudIps` and extended
		// through API-0364..API-0368, API-0371, API-0372,
		// API-0374, API-0375, and API-0376 — and orthogonal to
		// the parameter-bearing GET precedents at API-0369
		// `settings-getTraefikPorts`, API-0373
		// `settings-haveTraefikDashboardPortEnabled`, and
		// API-0377 `settings-readDirectories`. The 200 schema is
		// `{}` with `additionalProperties: false`, matching every
		// prior covered peer in the settings/* GET cohort.
		//
		// **Forward-reference correction.** The API-0377 hand-off
		// comment hedged that the parameter axis (zero vs one
		// optional query) had to be re-verified per-operation
		// despite the verb axis staying GET and the slug prefix
		// staying `read*`, and explicitly flagged that two
		// consecutive `read*` entries can sit on opposite sides
		// of the parameter axis. Direct inspection of the spec
		// at `/settings.readMiddlewareTraefikConfig > get`
		// confirmed the divergence in the negative direction:
		// this entry is **parameter-free** (unlike API-0377 which
		// carried an OPTIONAL `serverId` query), so the entry
		// tracks the parameter-free GET precedents at API-0363..
		// API-0368, API-0371, API-0372, API-0374, API-0375, and
		// API-0376 rather than the parameter-bearing precedents
		// at API-0369, API-0373, and API-0377. The per-operation
		// re-verification rule kept the contributor from
		// accidentally inheriting the API-0377 parameter-bearing
		// shape just because the slug prefix `read*` matched —
		// the slug-prefix-is-not-shape lesson reasserted at
		// API-0371..API-0377 explicitly anticipated this case,
		// and the affirmative parameter pivot in API-0377
		// followed by the negative pivot in API-0378 demonstrates
		// that the `read*` family straddles both sides of the
		// parameter axis. Reading a global Traefik middleware
		// configuration is platform-wide (the controller owns the
		// router/middleware definitions), unlike
		// `readDirectories` which scopes a filesystem probe to a
		// host and therefore optionally per-server.
		//
		// **Family continuation — fifteenth entry of the
		// settings/* GET cohort, twelfth of the parameter-free
		// GET sub-roster.** API-0363 opened the parameter-free
		// sub-family by pivoting off the eleven-entry POST cohort
		// (API-0353..API-0362); API-0364..API-0368 extended the
		// parameter-free shape across five consecutive entries;
		// API-0369 pivoted to a single OPTIONAL `serverId` query
		// (the first parameter-bearing GET in the settings/*
		// roster); API-0370 pivoted the verb axis to POST while
		// keeping the no-body, no-parameter shape; API-0371
		// reverted to the parameter-free GET shape; API-0372
		// stayed parameter-free; API-0373 pivoted back to the
		// OPTIONAL `serverId` query shape mirroring API-0369
		// (the second parameter-bearing GET in the settings/*
		// roster); API-0374 reverted to the parameter-free
		// shape; API-0375 continued the parameter-free shape;
		// API-0376 continued the parameter-free shape; API-0377
		// pivoted back to the OPTIONAL `serverId` query shape
		// mirroring API-0369 and API-0373 (the third
		// parameter-bearing GET in the settings/* roster); and
		// API-0378 reverts to the parameter-free shape mirroring
		// the API-0363..API-0368, API-0371, API-0372, API-0374,
		// API-0375, and API-0376 precedents.
		//
		// `SampleQuery`, `SamplePathParams`, and `SampleBody` are
		// all intentionally omitted — `parameters: []` plus the
		// no-body GET shape means the case carries zero
		// fixture-bearing fields and `buildCoverageInputArgs`
		// returns no `--input` flags. The harness's success-leg
		// path-method-status-only assertion remains exhaustive
		// for this shape, mirroring API-0363..API-0368, API-0371,
		// API-0372, API-0374, API-0375, and API-0376 exactly.
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the
		// empty-success convention shared by every prior
		// settings/* GET peer (API-0363..API-0377).
		SuccessResponse: `{}`,
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0377 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// global config-readers like `readMiddlewareTraefikConfig`
		// (which returns the controller-owned Traefik middleware
		// configuration with no resource id to miss against).
		// Auth is the universal failure mode every Dokploy
		// operation must re-prove, so 401 → CodeAuth via the
		// harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput
		// stays reserved for stories where payload validation is
		// the operation's distinguishing failure mode; this entry
		// uses the canonical 401.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0379 `settings-readTraefikConfig`
		// (declared a **GET** in the PRD). The next contributor
		// must re-verify against `internal/api/data/openapi.json
		// > /settings.readTraefikConfig > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry — the response-set axis
		// (presence vs absence of 404), the parameter axis
		// (zero vs one optional query vs other), and the
		// request-body axis (none vs JSON) must each be
		// re-verified per-operation. The slug stays `read*` but
		// pivots from a Traefik-middleware-config reader
		// (`readMiddlewareTraefikConfig`) to a base
		// Traefik-config reader (`readTraefikConfig`); per the
		// slug-prefix-is-not-shape lesson reasserted at
		// API-0371..API-0377, three consecutive `read*` entries
		// can still sit on different sides of the parameter axis
		// or carry different response sets. Do not assume the
		// parameter list, request body, or response set carries
		// over solely because the verb is GET and the slug
		// prefix matches; the parameter-axis flip-flop across
		// API-0371..API-0378 (parameter-free → parameter-bearing
		// → parameter-free → parameter-free → parameter-free →
		// parameter-bearing → parameter-free) demonstrates that
		// adjacent entries regularly sit on opposite sides of
		// the parameter axis. Per-operation re-verification stays
		// mandatory across every family transition.
	},
	{
		StoryID:     "API-0379",
		OperationID: "settings-readTraefikConfig",
		Method:      http.MethodGet,
		Path:        "/settings.readTraefikConfig",
		Tag:         "settings",
		// Twenty-ninth entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0378 `settings-readMiddlewareTraefikConfig` (must
		// not back-reference the closed `srv-cov-*`, `proj-cov-*`,
		// `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		// or any other prior tag's namespace, per the per-tag
		// isolation rule reasserted at API-0335..API-0378 and
		// originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0378
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.readTraefikConfig > get`: a **GET** with
		// **zero parameters** (`parameters: []`) and **no
		// request body** (GETs in this OpenAPI document never
		// carry a `requestBody` field). Responses
		// 200/400/401/403/404/500 — the **404 stays present**,
		// matching the parameter-free GET sub-roster opened at
		// API-0363 `settings-getDokployCloudIps` and extended
		// through API-0364..API-0368, API-0371, API-0372,
		// API-0374, API-0375, API-0376, and API-0378 — and
		// orthogonal to the parameter-bearing GET precedents at
		// API-0369 `settings-getTraefikPorts`, API-0373
		// `settings-haveTraefikDashboardPortEnabled`, and
		// API-0377 `settings-readDirectories`. The 200 schema is
		// `{}` with `additionalProperties: false`, matching every
		// prior covered peer in the settings/* GET cohort.
		//
		// **Forward-reference correction.** The API-0378 hand-off
		// comment hedged that the parameter axis (zero vs one
		// optional query) had to be re-verified per-operation
		// despite the verb axis staying GET and the slug prefix
		// staying `read*`, and explicitly flagged that three
		// consecutive `read*` entries can still sit on different
		// sides of the parameter axis or carry different response
		// sets. Direct inspection of the spec at
		// `/settings.readTraefikConfig > get` confirmed the
		// alignment with API-0378: this entry is
		// **parameter-free** (matching API-0378 which was also
		// parameter-free), so the entry tracks the parameter-free
		// GET precedents at API-0363..API-0368, API-0371,
		// API-0372, API-0374, API-0375, API-0376, and API-0378
		// rather than the parameter-bearing precedents at
		// API-0369, API-0373, and API-0377. Two consecutive
		// `read*` entries (API-0378
		// `readMiddlewareTraefikConfig`, API-0379
		// `readTraefikConfig`) now both anchor to the
		// parameter-free side of the axis — but per the
		// per-operation re-verification rule reasserted at
		// API-0371..API-0378, consecutive same-prefix alignment
		// is **not** a substitute for direct spec inspection at
		// every family transition. Reading the base Traefik
		// configuration is platform-wide (the controller owns the
		// entrypoints/routers/services definitions just like the
		// middleware definitions read by API-0378), confirming
		// the same shape pivot rationale that applied at
		// API-0378.
		//
		// **Family continuation — sixteenth entry of the
		// settings/* GET cohort, thirteenth of the parameter-free
		// GET sub-roster.** API-0363 opened the parameter-free
		// sub-family by pivoting off the eleven-entry POST cohort
		// (API-0353..API-0362); API-0364..API-0368 extended the
		// parameter-free shape across five consecutive entries;
		// API-0369 pivoted to a single OPTIONAL `serverId` query
		// (the first parameter-bearing GET in the settings/*
		// roster); API-0370 pivoted the verb axis to POST while
		// keeping the no-body, no-parameter shape; API-0371
		// reverted to the parameter-free GET shape; API-0372
		// stayed parameter-free; API-0373 pivoted back to the
		// OPTIONAL `serverId` query shape mirroring API-0369
		// (the second parameter-bearing GET in the settings/*
		// roster); API-0374 reverted to the parameter-free
		// shape; API-0375 continued the parameter-free shape;
		// API-0376 continued the parameter-free shape; API-0377
		// pivoted back to the OPTIONAL `serverId` query shape
		// mirroring API-0369 and API-0373 (the third
		// parameter-bearing GET in the settings/* roster);
		// API-0378 reverted to the parameter-free shape mirroring
		// the API-0363..API-0368, API-0371, API-0372, API-0374,
		// API-0375, and API-0376 precedents; and API-0379
		// continues the parameter-free shape (the thirteenth
		// parameter-free GET in the settings/* roster).
		//
		// `SampleQuery`, `SamplePathParams`, and `SampleBody` are
		// all intentionally omitted — `parameters: []` plus the
		// no-body GET shape means the case carries zero
		// fixture-bearing fields and `buildCoverageInputArgs`
		// returns no `--input` flags. The harness's success-leg
		// path-method-status-only assertion remains exhaustive
		// for this shape, mirroring API-0363..API-0368, API-0371,
		// API-0372, API-0374, API-0375, API-0376, and API-0378
		// exactly. 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the
		// empty-success convention shared by every prior
		// settings/* GET peer (API-0363..API-0378).
		SuccessResponse: `{}`,
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0378 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-free
		// global config-readers like `readTraefikConfig` (which
		// returns the controller-owned base Traefik configuration
		// with no resource id to miss against). Auth is the
		// universal failure mode every Dokploy operation must
		// re-prove, so 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; this entry uses the canonical 401.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0380 `settings-readTraefikEnv`
		// (declared a **GET** in the PRD). The next contributor
		// must re-verify against `internal/api/data/openapi.json
		// > /settings.readTraefikEnv > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry — the response-set axis
		// (presence vs absence of 404), the parameter axis
		// (zero vs one optional query vs other), and the
		// request-body axis (none vs JSON) must each be
		// re-verified per-operation. The slug stays `read*` but
		// pivots from a base Traefik-config reader
		// (`readTraefikConfig`) to a Traefik environment-variable
		// reader (`readTraefikEnv`); per the
		// slug-prefix-is-not-shape lesson reasserted at
		// API-0371..API-0378, four consecutive `read*` entries
		// can still sit on different sides of the parameter axis
		// or carry different response sets. Do not assume the
		// parameter list, request body, or response set carries
		// over solely because the verb is GET and the slug
		// prefix matches; the parameter-axis flip-flop across
		// API-0371..API-0379 (parameter-free → parameter-bearing
		// → parameter-free → parameter-free → parameter-free →
		// parameter-bearing → parameter-free → parameter-free)
		// demonstrates that adjacent entries regularly sit on
		// opposite sides of the parameter axis. Per-operation
		// re-verification stays mandatory across every family
		// transition.
	},
	{
		StoryID:     "API-0380",
		OperationID: "settings-readTraefikEnv",
		Method:      http.MethodGet,
		Path:        "/settings.readTraefikEnv",
		Tag:         "settings",
		// Thirtieth entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0379 `settings-readTraefikConfig` (must not
		// back-reference the closed `srv-cov-*`, `proj-cov-*`,
		// `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		// or any other prior tag's namespace, per the per-tag
		// isolation rule reasserted at API-0335..API-0379 and
		// originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0379
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.readTraefikEnv > get`: a **GET** with **one
		// OPTIONAL query parameter** `serverId` (string,
		// `required: false` — scopes the Traefik environment
		// read to a specific Dokploy worker server when the
		// runtime environment being inspected lives on a remote
		// node rather than the controller) and **no request
		// body** (GETs in this OpenAPI document never carry a
		// `requestBody` field). Responses 200/400/401/403/404/500
		// — the **404 stays present**, matching the
		// parameter-bearing GET precedents at API-0369
		// `settings-getTraefikPorts`, API-0373
		// `settings-haveTraefikDashboardPortEnabled`, and
		// API-0377 `settings-readDirectories`, and orthogonal to
		// the parameter-free GET sub-roster opened at API-0363
		// `settings-getDokployCloudIps` and extended through
		// API-0364..API-0368, API-0371, API-0372, API-0374,
		// API-0375, API-0376, API-0378, and API-0379. The 200
		// schema is `{}` with `additionalProperties: false`,
		// matching every prior covered peer in the settings/*
		// GET cohort.
		//
		// **Forward-reference correction.** The API-0379 hand-off
		// comment hedged that the parameter axis (zero vs one
		// optional query) had to be re-verified per-operation
		// despite the verb axis staying GET and the slug prefix
		// staying `read*`, and explicitly flagged that four
		// consecutive `read*` entries can still sit on different
		// sides of the parameter axis. Direct inspection of the
		// spec at `/settings.readTraefikEnv > get` confirmed the
		// divergence in the affirmative direction: this entry
		// **does** carry an OPTIONAL `serverId` query parameter
		// (unlike API-0378 `readMiddlewareTraefikConfig` and
		// API-0379 `readTraefikConfig` which were both
		// parameter-free), so the entry tracks the
		// parameter-bearing GET precedents at API-0369, API-0373,
		// and API-0377 rather than the parameter-free precedents
		// at API-0363..API-0368, API-0371, API-0372, API-0374,
		// API-0375, API-0376, API-0378, and API-0379. The
		// per-operation re-verification rule kept the contributor
		// from accidentally inheriting the API-0379
		// parameter-free shape just because the slug prefix
		// `read*` matched and the two preceding peers
		// (API-0378, API-0379) were both parameter-free — the
		// slug-prefix-is-not-shape lesson reasserted at
		// API-0371..API-0379 explicitly anticipated this case,
		// and the affirmative parameter pivot in API-0380
		// (mirroring API-0377 after two parameter-free peers)
		// demonstrates that the `read*` family continues to
		// straddle both sides of the parameter axis. Reading the
		// Traefik environment is conceptually a per-host probe —
		// the environment variables are bound to the operating
		// system process running Traefik on a specific node, so
		// scoping the read with `serverId` is meaningful in a
		// multi-node Dokploy deployment, unlike the platform-wide
		// router/middleware definitions read by API-0378 and
		// API-0379.
		//
		// **Family continuation — sixteenth entry of the
		// settings/* GET cohort, fourth of the parameter-bearing
		// GET sub-roster.** API-0363 opened the parameter-free
		// sub-family by pivoting off the eleven-entry POST cohort
		// (API-0353..API-0362); API-0364..API-0368 extended the
		// parameter-free shape across five consecutive entries;
		// API-0369 pivoted to a single OPTIONAL `serverId` query
		// (the first parameter-bearing GET in the settings/*
		// roster); API-0370 pivoted the verb axis to POST while
		// keeping the no-body, no-parameter shape; API-0371
		// reverted to the parameter-free GET shape; API-0372
		// stayed parameter-free; API-0373 pivoted back to the
		// OPTIONAL `serverId` query shape mirroring API-0369
		// (the second parameter-bearing GET in the settings/*
		// roster); API-0374 reverted to the parameter-free
		// shape; API-0375 continued the parameter-free shape;
		// API-0376 continued the parameter-free shape; API-0377
		// pivoted back to the OPTIONAL `serverId` query shape
		// mirroring API-0369 and API-0373 (the third
		// parameter-bearing GET in the settings/* roster);
		// API-0378 reverted to the parameter-free shape;
		// API-0379 continued the parameter-free shape; and
		// API-0380 pivots back to the OPTIONAL `serverId` query
		// shape mirroring API-0369, API-0373, and API-0377 (the
		// fourth parameter-bearing GET in the settings/*
		// roster). Following the API-0369, API-0373, and
		// API-0377 precedents and the per-tag isolation rule, we
		// populate `SampleQuery` with a fixture-slug literal
		// under the settings/* `set-cov-*` namespace so the
		// success-leg `r.URL.Query()` re-read at
		// `runAPICoverageSuccess` exercises end-to-end forwarding
		// even though the parameter is OPTIONAL — the harness
		// does not gate on `required`-ness, it forwards whatever
		// `SampleQuery` carries (per the API-0077
		// `compose-getTags` precedent, the API-0041
		// `backup-listBackupFiles` precedent, the API-0369
		// `settings-getTraefikPorts` precedent, the API-0373
		// `settings-haveTraefikDashboardPortEnabled` precedent,
		// and the API-0377 `settings-readDirectories` precedent).
		//
		// Fixture conventions:
		//   * `set-cov-readTraefikEnv-0380` — slug-named literal
		//     for the OPTIONAL `serverId` query parameter, unique
		//     against API-0351..API-0379's `set-cov-*` slugs and
		//     orthogonal to every prior tag's `srv-cov-*`,
		//     `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		//     `app-cov-*`, `ai-cov-*`, etc. namespaces.
		SampleQuery: map[string][]string{
			"serverId": {"set-cov-readTraefikEnv-0380"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the
		// empty-success convention shared by every prior
		// settings/* GET peer (API-0363..API-0379). Empty-object
		// body keeps the success-leg envelope assertion focused
		// on `data.method` / `data.status` rather than payload
		// projection.
		SuccessResponse: `{}`,
		//
		// **Failure-leg fields are intentionally omitted.** Even
		// though the spec declares 404 on this operation, the
		// per-tag opener convention reasserted at
		// API-0335..API-0379 reserves 404 → CodeNotFound for the
		// canonical by-id `*-one` peer, not for parameter-bearing
		// environment-variable readers like `readTraefikEnv`
		// (which returns the runtime environment of the Traefik
		// process, not a single resource keyed by id — and the
		// `serverId` query is OPTIONAL, so the happy path itself
		// does not require the parameter to resolve to a known
		// target). Auth is the universal failure mode every
		// Dokploy operation must re-prove, so 401 → CodeAuth via
		// the harness default (`tc.FailureStatus == 0` → 401,
		// `tc.FailureCode == ""` → CodeAuth) stays the most
		// informative representative. 400 → CodeInvalidInput
		// stays reserved for stories where payload validation is
		// the operation's distinguishing failure mode; this entry
		// uses the canonical 401.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0381 `settings-readTraefikFile`
		// (declared a **GET** in the PRD). The next contributor
		// must re-verify against `internal/api/data/openapi.json
		// > /settings.readTraefikFile > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry — the response-set axis
		// (presence vs absence of 404), the parameter axis
		// (zero vs one optional query vs other), and the
		// request-body axis (none vs JSON) must each be
		// re-verified per-operation. The slug stays `read*` but
		// pivots from a Traefik environment-variable reader
		// (`readTraefikEnv`) to a Traefik file reader
		// (`readTraefikFile`); per the slug-prefix-is-not-shape
		// lesson reasserted at API-0371..API-0379, five
		// consecutive `read*` entries can still sit on different
		// sides of the parameter axis or carry different response
		// sets. Do not assume the parameter list, request body,
		// or response set carries over solely because the verb
		// is GET and the slug prefix matches; the parameter-axis
		// flip-flop across API-0371..API-0380 (parameter-free →
		// parameter-bearing → parameter-free → parameter-free →
		// parameter-free → parameter-bearing → parameter-free →
		// parameter-free → parameter-bearing) demonstrates that
		// adjacent entries regularly sit on opposite sides of
		// the parameter axis. Per-operation re-verification stays
		// mandatory across every family transition.
	},
	{
		StoryID:     "API-0381",
		OperationID: "settings-readTraefikFile",
		Method:      http.MethodGet,
		Path:        "/settings.readTraefikFile",
		Tag:         "settings",
		// Thirty-first entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0380 `settings-readTraefikEnv` (must not
		// back-reference the closed `srv-cov-*`, `proj-cov-*`,
		// `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		// or any other prior tag's namespace, per the per-tag
		// isolation rule reasserted at API-0335..API-0380 and
		// originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0380
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.readTraefikFile > get`: a **GET** with **two
		// query parameters** — a REQUIRED `path` (string, the
		// Traefik configuration filename to read off the
		// controller's filesystem) and an OPTIONAL `serverId`
		// (string, scopes the file read to a specific Dokploy
		// worker server when the file being inspected lives on a
		// remote node) — and **no request body** (GETs in this
		// OpenAPI document never carry a `requestBody` field).
		// Responses 200/400/401/403/404/500 — the **404 stays
		// present**, matching the parameter-bearing GET precedents
		// at API-0369 `settings-getTraefikPorts`, API-0373
		// `settings-haveTraefikDashboardPortEnabled`, API-0377
		// `settings-readDirectories`, and API-0380
		// `settings-readTraefikEnv`, and orthogonal to the
		// parameter-free GET sub-roster opened at API-0363
		// `settings-getDokployCloudIps` and extended through
		// API-0364..API-0368, API-0371, API-0372, API-0374,
		// API-0375, API-0376, API-0378, and API-0379. The 200
		// schema is `{}` with `additionalProperties: false`,
		// matching every prior covered peer in the settings/*
		// GET cohort.
		//
		// **Shape pivot (REQUIRED query parameter).** This is the
		// **first settings/* GET to declare a REQUIRED query
		// parameter** — every prior parameter-bearing peer in the
		// settings/* GET cohort (API-0369, API-0373, API-0377,
		// API-0380) carried only an OPTIONAL `serverId`. The
		// per-operation re-verification rule kept the contributor
		// from accidentally inheriting the API-0380
		// optional-only shape just because the slug prefix
		// `read*` matched and the immediately preceding peer
		// (API-0380) carried a single optional query — direct
		// inspection of the spec at `/settings.readTraefikFile >
		// get > parameters` revealed `path: required: true`
		// alongside `serverId: required: false`. The harness does
		// not gate on `required`-ness (per the API-0077
		// `compose-getTags`, API-0041 `backup-listBackupFiles`,
		// API-0369, API-0373, API-0377, and API-0380 precedents),
		// it forwards whatever `SampleQuery` carries; we populate
		// **both** `path` and `serverId` so the success-leg
		// `r.URL.Query()` re-read at `runAPICoverageSuccess`
		// exercises end-to-end forwarding for the full parameter
		// surface, and the success leg implicitly proves that the
		// REQUIRED `path` parameter does NOT change the executor's
		// argument-passing contract relative to OPTIONAL peers
		// (the executor forwards the `query` map verbatim and
		// leaves `required`-ness enforcement to the upstream
		// Dokploy API).
		//
		// Fixture conventions:
		//   * `set-cov-readTraefikFile-0381-path` — slug-named
		//     literal for the REQUIRED `path` query parameter,
		//     unique against API-0351..API-0380's `set-cov-*`
		//     slugs and orthogonal to every prior tag's
		//     `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		//     `compose-cov-*`, `app-cov-*`, `ai-cov-*`, etc.
		//     namespaces. Although the value is shaped like a
		//     slug rather than a real filesystem path (e.g.
		//     `/etc/traefik/traefik.yml`), the executor does not
		//     parse or validate it — Dokploy's upstream handler is
		//     responsible for path resolution, and the harness's
		//     job is solely to prove end-to-end forwarding of the
		//     literal bytes the agent supplied. The success-leg
		//     fixture stays a slug so secret-leak regression tests
		//     never accidentally trip on a real path containing
		//     reserved characters.
		//   * `set-cov-readTraefikFile-0381-server` — slug-named
		//     literal for the OPTIONAL `serverId` query
		//     parameter, paired with the `path` slug above so
		//     both query parameters are exercised in the same
		//     success leg.
		SampleQuery: map[string][]string{
			"path":     {"set-cov-readTraefikFile-0381-path"},
			"serverId": {"set-cov-readTraefikFile-0381-server"},
		},
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the
		// canonical settings/* GET cohort. Leaving
		// `SuccessResponse` unset lets the harness default to
		// `{}` so the success leg stays terse.
		//
		// Failure leg: 401 → CodeAuth via the harness default.
		// 400 (CodeInvalidInput) is the operation's most
		// distinguishing failure mode given the REQUIRED `path`
		// parameter (Dokploy returns 400 when the supplied path
		// is malformed or escapes the allowed Traefik
		// configuration directory), but auth is the universal
		// failure mode every Dokploy operation must re-prove, so
		// 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 404 (CodeNotFound) is plausible too — Dokploy returns
		// it when the supplied path does not point at an
		// existing Traefik configuration file — but the auth
		// default holds for the parity reasons above. Stories
		// where 400 or 404 is the distinguishing failure mode
		// continue to override `FailureStatus`/`FailureCode`
		// explicitly.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0382 `settings-readWebServerTraefikConfig`
		// (declared a **GET** in the PRD). The next contributor
		// must re-verify against `internal/api/data/openapi.json
		// > /settings.readWebServerTraefikConfig > get` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry — the response-set axis
		// (presence vs absence of 404), the parameter axis (zero
		// vs one optional vs one required vs multiple), and the
		// request-body axis (none vs JSON) must each be
		// re-verified per-operation. The slug stays `read*` but
		// pivots from a Traefik file reader (`readTraefikFile`)
		// to a Traefik web-server config reader
		// (`readWebServerTraefikConfig`); per the
		// slug-prefix-is-not-shape lesson reasserted at
		// API-0371..API-0380, six consecutive `read*` entries can
		// still sit on different sides of the parameter axis or
		// carry different response sets. Do not assume the
		// parameter list, request body, or response set carries
		// over solely because the verb is GET and the slug prefix
		// matches; the parameter-axis flip-flop across
		// API-0371..API-0381 (parameter-free → parameter-bearing
		// → parameter-free → parameter-free → parameter-free →
		// parameter-bearing → parameter-free → parameter-free →
		// parameter-bearing → parameter-bearing-with-required)
		// demonstrates that adjacent entries regularly sit on
		// opposite sides of the parameter axis AND that the
		// REQUIRED-vs-OPTIONAL sub-axis can pivot too.
		// Per-operation re-verification stays mandatory across
		// every family transition.
	},
	{
		StoryID:     "API-0382",
		OperationID: "settings-readWebServerTraefikConfig",
		Method:      http.MethodGet,
		Path:        "/settings.readWebServerTraefikConfig",
		Tag:         "settings",
		// Thirty-second entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0381 `settings-readTraefikFile` (must not
		// back-reference the closed `srv-cov-*`, `proj-cov-*`,
		// `org-cov-*`, `compose-cov-*`, `app-cov-*`, `ai-cov-*`,
		// or any other prior tag's namespace, per the per-tag
		// isolation rule reasserted at API-0335..API-0381 and
		// originally established at API-0246
		// `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0381
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.readWebServerTraefikConfig > get`: a **GET**
		// with **zero parameters** and **no request body** (GETs
		// in this OpenAPI document never carry a `requestBody`
		// field). Responses 200/400/401/403/404/500 — the **404
		// stays present**, matching the parameter-free GET
		// precedents at API-0378 `settings-readMiddlewareTraefikConfig`
		// and API-0379 `settings-readTraefikConfig`, and orthogonal
		// to the parameter-bearing GET sub-roster (API-0369,
		// API-0373, API-0377, API-0380, API-0381). The 200 schema
		// is `{}` with `additionalProperties: false`, matching every
		// prior covered peer in the settings/* GET cohort.
		//
		// **Shape pivot back to parameter-free.** API-0381
		// `settings-readTraefikFile` was the first settings/* GET
		// to declare a REQUIRED query parameter (`path`); API-0382
		// drops the parameter axis entirely, mirroring the shape
		// of API-0378/API-0379 which read controller-owned global
		// Traefik configuration with no per-host or per-file
		// scoping. The `readWebServerTraefikConfig` operation
		// returns the Dokploy web-server's Traefik configuration —
		// a single platform-wide artifact rather than a per-node
		// or per-file probe — so the absence of `serverId` /
		// `path` query parameters tracks the semantic-shape
		// rule established at API-0378/API-0379 (controller-owned
		// global definitions are platform-wide and parameter-free,
		// versus per-host probes like `readTraefikEnv` and
		// per-file readers like `readTraefikFile` which carry
		// scoping parameters). Per the slug-prefix-is-not-shape
		// rule reasserted at API-0371..API-0381, the `read*` slug
		// prefix continues to straddle every sub-axis; direct
		// inspection of the spec at
		// `/settings.readWebServerTraefikConfig > get >
		// parameters` confirmed the empty parameter array.
		//
		// Fixture conventions: no `SampleQuery`, `SamplePathParams`,
		// or `SampleBody` literal is needed because the operation
		// declares no parameters and no body. The `set-cov-*` per-tag
		// fixture-isolation namespace is reserved for future
		// parameter-bearing or body-bearing entries on the
		// settings/* roster.
		//
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the canonical
		// settings/* GET cohort. Leaving `SuccessResponse` unset
		// lets the harness default to `{}` so the success leg
		// stays terse.
		//
		// Failure leg: 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth). 404 (CodeNotFound) is plausible — Dokploy
		// returns it when the web-server Traefik configuration
		// is missing on disk — but auth is the universal failure
		// mode every Dokploy operation must re-prove, so the
		// canonical 401 → CodeAuth representative stays for
		// parity with every prior settings/* GET entry. Stories
		// where 404 is the distinguishing failure mode continue
		// to override `FailureStatus`/`FailureCode` explicitly.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0383 `settings-reloadRedis` (declared
		// a **POST** in the PRD). The next contributor must
		// re-verify against `internal/api/data/openapi.json >
		// /settings.reloadRedis > post` per the forward-reference
		// lesson before assuming any field is identical to this
		// entry — the response-set axis (presence vs absence of
		// 404), the parameter axis (zero vs one optional vs one
		// required vs multiple), and the request-body axis (none
		// vs JSON) must each be re-verified per-operation. The
		// slug pivots from a `read*` reader to a `reload*`
		// mutating verb, and the HTTP verb pivots from GET to
		// POST; per the slug-prefix-is-not-shape lesson and the
		// verb-axis lesson reasserted at API-0370 (the only
		// prior settings/* POST that broke the GET streak), do
		// not assume the parameter list, request body, or
		// response set carries over from this entry. The
		// parameter-axis flip-flop across API-0371..API-0382
		// (parameter-free → parameter-bearing → parameter-free
		// → parameter-free → parameter-free → parameter-bearing
		// → parameter-free → parameter-free → parameter-bearing
		// → parameter-bearing-with-required → parameter-free)
		// demonstrates that adjacent entries regularly sit on
		// opposite sides of the parameter axis AND that the
		// REQUIRED-vs-OPTIONAL sub-axis can pivot too. The verb
		// pivot at API-0383 adds a third dimension. Per-operation
		// re-verification stays mandatory across every family
		// transition.
	},
	{
		StoryID:     "API-0383",
		OperationID: "settings-reloadRedis",
		Method:      http.MethodPost,
		Path:        "/settings.reloadRedis",
		Tag:         "settings",
		// Thirty-third entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0382 `settings-readWebServerTraefikConfig` (must
		// not back-reference the closed `srv-cov-*`,
		// `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		// `app-cov-*`, `ai-cov-*`, or any other prior tag's
		// namespace, per the per-tag isolation rule reasserted
		// at API-0335..API-0382 and originally established at
		// API-0246 `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0382
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.reloadRedis > post`: a **POST** with **no
		// `requestBody` field at all** (structurally identical
		// to API-0354 `cleanAllDeploymentQueue`, API-0357
		// `cleanMonitoring`, API-0358 `cleanRedis`, API-0359
		// `cleanSSHPrivateKey`, and API-0370 `getUpdateData` —
		// the spec declares no request body schema whatsoever,
		// so the operation is a true no-input POST), **zero
		// parameters** (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**,
		// matching the five no-body POST peers above and
		// **diverging from API-0378..API-0382's 404-bearing GET
		// sub-roster** that immediately preceded this entry. The
		// 200 schema is `{}` with `additionalProperties: false`,
		// matching every prior covered peer in the settings/*
		// roster.
		//
		// **Family pivot — verb axis flips back to POST after
		// a twelve-entry GET sub-roster.** The settings/* roster
		// opened with eleven POSTs (API-0351 through API-0362),
		// pivoted to seven GETs (API-0363..API-0369), pivoted
		// back to a single POST at API-0370 `getUpdateData`,
		// then ran a twelve-entry GET cohort (API-0371
		// `getServerMetrics` through API-0382
		// `readWebServerTraefikConfig`). API-0383
		// `reloadRedis` pivots the verb axis back to POST — the
		// second POST after the API-0370 break — and pivots the
		// slug prefix from `read*` (passive readers returning
		// configuration) to `reload*` (mutating actions that
		// trigger an in-process reload of a managed Dokploy
		// service). The slug-prefix-is-not-shape rule reasserted
		// at API-0371..API-0382 still holds: `reload*` is a
		// semantic family hint, not a contract guarantee, so the
		// parameter, request-body, and response-set axes were
		// each re-verified per-operation against the spec rather
		// than inherited from API-0370 or any earlier POST peer.
		//
		// **Forward-reference confirmation — verb pivot
		// predicted.** API-0382's hand-off comment correctly
		// forecast the GET → POST verb pivot at API-0383 and
		// explicitly cautioned that the parameter, request-body,
		// and response-set axes had to be re-verified rather
		// than inherited from API-0382 (the immediately-prior
		// parameter-free GET) or API-0370 (the only prior
		// settings/* POST). Direct inspection of
		// `internal/api/data/openapi.json >
		// /settings.reloadRedis > post` confirms the prediction
		// was correct on the verb axis: this is a no-body,
		// no-parameter POST. The response-set axis matches
		// API-0370 (no 404), the parameter axis matches API-0370
		// (zero parameters), and the request-body axis matches
		// API-0370 (no `requestBody` field). The per-operation
		// re-verification rule kept the contributor from
		// accidentally promoting API-0382's `read*`-style
		// 404-bearing response set onto a `reload*` mutating
		// action — Dokploy mutating actions in this OpenAPI
		// document consistently omit 404 because there is no
		// per-resource lookup that could miss; the operation
		// either succeeds in triggering the reload, fails
		// authorization, or fails internally on the controller.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-reloadRedis-0383` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique
		//     (verified: no collisions with API-0351..API-0382's
		//     `set-cov-*` slugs, and orthogonal to every prior
		//     tag's `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		//     `compose-cov-*`, `app-cov-*`, `ai-cov-*`, etc.
		//     namespaces). Even though no fixture-token literal
		//     is materialised on the wire (the operation has no
		//     body and no parameters), the slug is reserved for
		//     any future schema-validator harness that walks the
		//     `coveredAPIOperations` registry by `OperationID`.
		//   * No `SampleQuery`, `SamplePathParams`, or
		//     `SampleBody` literal is needed because the
		//     operation declares no parameters and no body. The
		//     harness's POST branch with `len(SampleBody) == 0`
		//     skips the `Content-Type` and body-round-trip
		//     assertions per the `if len(tc.SampleBody) > 0`
		//     guard inside `runAPICoverageSuccess`, matching the
		//     API-0370 precedent for no-body POSTs.
		//
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the canonical
		// settings/* mutating-POST cohort. Leaving
		// `SuccessResponse` unset lets the harness default to
		// `{}` so the success leg stays terse.
		//
		// Failure leg: 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth). 400 (CodeInvalidInput), 403, and 500 are
		// also documented in the spec, but auth is the universal
		// failure mode every Dokploy operation must re-prove, so
		// the canonical 401 → CodeAuth representative stays for
		// parity with every prior settings/* entry. 400 is not
		// the distinguishing failure mode for a no-body POST
		// (there is no payload to validate), so the harness
		// default is the correct representative here.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0384 `settings-reloadServer` (declared
		// a **POST** in the PRD, sharing the `reload*` mutating
		// slug prefix with this entry). The next contributor
		// must re-verify against `internal/api/data/openapi.json
		// > /settings.reloadServer > post` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry — the response-set axis
		// (presence vs absence of 404), the parameter axis
		// (zero vs one optional query — Dokploy reload actions
		// occasionally take a `serverId` query to scope the
		// reload to a remote node), and the request-body axis
		// (none vs JSON) must each be re-verified per-operation.
		// The same `reload*` slug prefix is no guarantee of
		// identical shape: API-0385 `reloadTraefik` (the third
		// `reload*` peer in PRD order) is already known from
		// preliminary spec inspection to declare an OPTIONAL
		// `requestBody` with an OPTIONAL `serverId` field — the
		// first `reload*` peer to break the no-body shape — so
		// adjacent `reload*` entries can and do sit on opposite
		// sides of the request-body axis. Per the
		// slug-prefix-is-not-shape lesson reasserted at
		// API-0371..API-0382 and the verb-axis lesson reasserted
		// at API-0370/API-0383, do not assume the parameter
		// list, request body, or response set carries over from
		// this entry to API-0384. The parameter-axis flip-flop
		// across API-0371..API-0383 is now twelve entries deep
		// and crosses the verb axis at API-0383; per-operation
		// re-verification stays mandatory across every family
		// transition.
	},
	{
		StoryID:     "API-0384",
		OperationID: "settings-reloadServer",
		Method:      http.MethodPost,
		Path:        "/settings.reloadServer",
		Tag:         "settings",
		// Thirty-fourth entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0383 `settings-reloadRedis` (must not back-reference
		// the closed `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		// `compose-cov-*`, `app-cov-*`, `ai-cov-*`, or any other
		// prior tag's namespace, per the per-tag isolation rule
		// reasserted at API-0335..API-0383 and originally
		// established at API-0246 `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0383
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.reloadServer > post`: a **POST** with **no
		// `requestBody` field at all** (structurally identical
		// to API-0354 `cleanAllDeploymentQueue`, API-0357
		// `cleanMonitoring`, API-0358 `cleanRedis`, API-0359
		// `cleanSSHPrivateKey`, API-0370 `getUpdateData`, and
		// the immediately-prior API-0383 `reloadRedis` — the
		// spec declares no request body schema whatsoever, so
		// the operation is a true no-input POST), **zero
		// parameters** (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**,
		// matching the six no-body POST peers above and the
		// canonical settings/* mutating-POST cohort. The 200
		// schema is `{}` with `additionalProperties: false`,
		// matching every prior covered peer in the settings/*
		// roster.
		//
		// **Family continuation — second consecutive `reload*`
		// POST.** API-0383 `reloadRedis` opened the `reload*`
		// slug-prefix sub-roster after the API-0382
		// `readWebServerTraefikConfig` GET cohort. API-0384
		// `reloadServer` is the second consecutive `reload*`
		// peer and the second consecutive no-body, no-parameter
		// POST in the settings/* roster. The slug-prefix-is-not-
		// shape rule reasserted at API-0371..API-0383 still
		// holds: `reload*` is a semantic family hint, not a
		// contract guarantee. API-0385 `reloadTraefik` (verified
		// against the spec at hand-off time) breaks the no-body
		// shape with an OPTIONAL `requestBody` carrying an
		// OPTIONAL `serverId` field, so the per-operation
		// re-verification rule continues to earn its keep on
		// the very next entry.
		//
		// **Forward-reference confirmation — `reload*` family
		// shape predicted with the correct caveat.** API-0383's
		// hand-off comment forecast that API-0384 might sit on
		// either side of the parameter axis ("zero vs one
		// optional query — Dokploy reload actions occasionally
		// take a `serverId` query to scope the reload to a
		// remote node") and on either side of the request-body
		// axis ("none vs JSON"). Direct inspection of
		// `internal/api/data/openapi.json >
		// /settings.reloadServer > post` confirms the
		// conservative branch: zero parameters, no request body
		// — structurally identical to API-0383. The
		// per-operation re-verification rule kept the
		// contributor from accidentally promoting either an
		// API-0385-style optional request body or an
		// `application*-reload`-style server-scoping query onto
		// this entry; the spec is the source of truth and
		// neither shape applies here.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-reloadServer-0384` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique
		//     (verified: no collisions with API-0351..API-0383's
		//     `set-cov-*` slugs, and orthogonal to every prior
		//     tag's `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		//     `compose-cov-*`, `app-cov-*`, `ai-cov-*`, etc.
		//     namespaces). Even though no fixture-token literal
		//     is materialised on the wire (the operation has no
		//     body and no parameters), the slug is reserved for
		//     any future schema-validator harness that walks the
		//     `coveredAPIOperations` registry by `OperationID`.
		//   * No `SampleQuery`, `SamplePathParams`, or
		//     `SampleBody` literal is needed because the
		//     operation declares no parameters and no body. The
		//     harness's POST branch with `len(SampleBody) == 0`
		//     skips the `Content-Type` and body-round-trip
		//     assertions per the `if len(tc.SampleBody) > 0`
		//     guard inside `runAPICoverageSuccess`, matching the
		//     API-0370/API-0383 precedent for no-body POSTs.
		//
		// 200 response in the spec is `{}` with
		// `additionalProperties: false`, matching the canonical
		// settings/* mutating-POST cohort. Leaving
		// `SuccessResponse` unset lets the harness default to
		// `{}` so the success leg stays terse.
		//
		// Failure leg: 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth). 400 (CodeInvalidInput), 403, and 500 are
		// also documented in the spec, but auth is the universal
		// failure mode every Dokploy operation must re-prove, so
		// the canonical 401 → CodeAuth representative stays for
		// parity with every prior settings/* entry. 400 is not
		// the distinguishing failure mode for a no-body POST
		// (there is no payload to validate), so the harness
		// default is the correct representative here.
		//
		// The next case in the settings/* roster per PRD
		// ordering is API-0385 `settings-reloadTraefik` (declared
		// a **POST** in the PRD, sharing the `reload*` mutating
		// slug prefix with this entry and API-0383). The next
		// contributor must re-verify against
		// `internal/api/data/openapi.json >
		// /settings.reloadTraefik > post` per the
		// forward-reference lesson — preliminary spec
		// inspection at API-0383's hand-off (re-confirmed here)
		// shows API-0385 declares an OPTIONAL `requestBody`
		// (`required: false`) carrying an OPTIONAL `serverId`
		// string field. This is the **first** `reload*` peer to
		// break the no-body shape and demonstrates the slug-
		// prefix-is-not-shape rule directly inside the `reload*`
		// sub-roster (API-0383 and API-0384 share the no-body
		// shape; API-0385 diverges). The contributor must
		// decide between leaving `SampleBody` unset (relying on
		// `required: false`) or materialising a representative
		// `{"serverId":"set-cov-reloadTraefik-0385"}` payload to
		// exercise the JSON round-trip — the latter is preferred
		// for parity with prior optional-body operations covered
		// by the harness, and matches how API-0341..API-0350's
		// optional-`serverId` cohort handled the same axis.
		// Response-set axis (presence vs absence of 404) and the
		// parameter axis (verified zero parameters in
		// preliminary inspection) must still be re-checked
		// per-operation. The parameter-axis flip-flop across
		// API-0371..API-0384 is now thirteen entries deep and
		// crosses the verb axis at API-0383; per-operation
		// re-verification stays mandatory across every family
		// transition.
	},
	{
		StoryID:     "API-0385",
		OperationID: "settings-reloadTraefik",
		Method:      http.MethodPost,
		Path:        "/settings.reloadTraefik",
		Tag:         "settings",
		// Thirty-fifth entry on the settings/* coverage roster,
		// inheriting the `set-cov-*` per-tag fixture-isolation
		// namespace established by API-0351
		// `settings-assignDomainServer` and extended through
		// API-0384 `settings-reloadServer` (must not back-reference
		// the closed `srv-cov-*`, `proj-cov-*`, `org-cov-*`,
		// `compose-cov-*`, `app-cov-*`, `ai-cov-*`, or any other
		// prior tag's namespace, per the per-tag isolation rule
		// reasserted at API-0335..API-0384 and originally
		// established at API-0246 `organization-active`).
		//
		// **Spec re-verified per the API-0345..API-0384
		// forward-reference lesson** against
		// `internal/api/data/openapi.json >
		// /settings.reloadTraefik > post`: a **POST** with an
		// **OPTIONAL** `requestBody` (`requestBody.required =
		// false`) carrying a JSON object with one optional string
		// property `serverId` and no `required` array; **zero
		// parameters** (no query, no path, no header). Responses
		// 200/400/401/403/500 — note the **absence of 404**,
		// matching the canonical settings/* mutating-POST cohort
		// and diverging from the by-id-flavoured 404-bearing
		// response sets. The 200 schema is `{}` with
		// `additionalProperties: false`, matching every prior
		// covered peer in the settings/* roster.
		//
		// **Forward-reference confirmation — body-axis pivot
		// predicted.** API-0384 `reloadServer`'s hand-off comment
		// correctly forecast that this entry would break the
		// no-body shape shared by the immediately prior `reload*`
		// peers (API-0383 `reloadRedis` and API-0384
		// `reloadServer`) and would declare an OPTIONAL
		// `requestBody` carrying an OPTIONAL `serverId` field.
		// Direct inspection of the spec confirms the prediction:
		// this is the **first `reload*` peer to break the no-body
		// shape**, structurally identical to API-0353
		// `settings-cleanAll` (the canonical optional-body POST
		// with optional `serverId` from the `clean*` sub-roster).
		// The slug-prefix-is-not-shape lesson reasserted at
		// API-0371..API-0384 holds: adjacent `reload*` peers can
		// and do sit on opposite sides of the request-body axis.
		//
		// **Family continuation — third consecutive `reload*`
		// POST.** API-0383 `reloadRedis` opened the `reload*`
		// slug-prefix sub-roster, API-0384 `reloadServer` extended
		// it as a no-body POST, and this entry pivots the body
		// axis to optional-body while preserving the verb axis
		// (POST), the parameter axis (zero parameters), and the
		// response-set axis (200/400/401/403/500, no 404). The
		// `reload*` family in settings/* therefore splits across
		// the body axis: (a) no-body POSTs (API-0383, API-0384),
		// and (b) optional-body POSTs with an optional `serverId`
		// (this entry). Per the slug-prefix-is-not-shape rule,
		// future `reload*` peers must re-verify per-operation
		// rather than inheriting from any prior `reload*` entry.
		//
		// Fixture conventions:
		//   * Per-case fixture token base
		//     `set-cov-reloadTraefik-0385` follows the
		//     `<tag>-cov-<slug>-<storyID>` convention shared
		//     across every per-tag roster and is unique (verified
		//     against API-0351..API-0384's `set-cov-*` slugs and
		//     orthogonal to every prior tag's `srv-cov-*`,
		//     `proj-cov-*`, `org-cov-*`, `compose-cov-*`,
		//     `app-cov-*`, `ai-cov-*`, etc. namespaces).
		//   * `serverId` carries the fixture-shaped literal
		//     `set-cov-reloadTraefik-0385` rather than a real UUID
		//     so the wire payload cannot be mistaken for a real
		//     production server identifier. Even though the body
		//     and the `serverId` field are both optional in the
		//     spec, populating both exercises the JSON
		//     serialiser's optional-body branch on the wire and
		//     keeps the success-leg `Content-Type: application/json`
		//     header assertion meaningful — leaving the body unset
		//     would degrade this case to the parameter-free POST
		//     cohort (which has no Content-Type assertion) and
		//     lose the body-forwarding round-trip assertion that
		//     distinguishes this shape from API-0383/API-0384's
		//     no-body shape, mirroring the API-0353
		//     `settings-cleanAll` precedent for optional-body
		//     POSTs in this tag.
		//
		// **Failure-leg fields are intentionally omitted.** The
		// spec does not declare 404 on this operation (the
		// `reloadTraefik` verb is a controller-wide, optional-
		// server-scoped reload action, not a by-id resource
		// lookup), so the per-tag opener convention reasserted at
		// API-0335..API-0384 that reserves 404 → CodeNotFound for
		// canonical `*-one` peers does not apply here. Auth is
		// the universal failure mode every Dokploy operation must
		// re-prove, so 401 → CodeAuth via the harness default
		// (`tc.FailureStatus == 0` → 401, `tc.FailureCode == ""`
		// → CodeAuth) stays the most informative representative.
		// 400 → CodeInvalidInput stays reserved for stories where
		// payload validation is the operation's distinguishing
		// failure mode; for an optional `serverId` body field the
		// validator surface is too narrow to make 400 the
		// canonical failure representative.
		//
		// The next case in the settings/* roster per PRD ordering
		// is API-0386 `settings-saveSSHPrivateKey` (declared a
		// **POST** in the PRD with `requestBody.required = true`).
		// The next contributor must re-verify against
		// `internal/api/data/openapi.json >
		// /settings.saveSSHPrivateKey > post` per the
		// forward-reference lesson before assuming any field is
		// identical to this entry — the request-body axis pivots
		// from OPTIONAL (this entry) to REQUIRED (API-0386), and
		// the body schema, parameter list, and response set must
		// each be re-verified per-operation. Per the
		// slug-prefix-is-not-shape lesson reasserted at
		// API-0371..API-0384 and the verb-axis lesson reasserted
		// at API-0370/API-0383, do not assume any axis carries
		// over from this entry. The parameter-axis flip-flop
		// across API-0371..API-0384 is now fourteen entries deep
		// and crosses the verb axis at API-0383 and the
		// request-body axis at this entry; per-operation
		// re-verification stays mandatory across every family
		// transition.
		SampleBody: json.RawMessage(`{
			"serverId": "set-cov-reloadTraefik-0385"
		}`),
		// 200 response in the spec is `{}` with `additionalProperties:
		// false`, matching every prior covered peer. Empty-object
		// body keeps the success-leg envelope assertion focused on
		// `data.method` / `data.status` rather than payload
		// projection.
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
