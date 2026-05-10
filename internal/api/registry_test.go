package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// expectedOperationCount locks the exact size of the Dokploy registry. A
// drift here means either the embedded openapi.json was updated without
// also bumping this constant + EmbeddedSpecSHA256 (a contract violation)
// or the registry started skipping operations (a code bug). Either way the
// test should fail loudly so a release cannot silently lose API coverage.
const expectedOperationCount = 450

func TestEmbeddedSpec_SHA256IsPinned(t *testing.T) {
	sum := sha256.Sum256(EmbeddedSpec)
	got := hex.EncodeToString(sum[:])
	if got != EmbeddedSpecSHA256 {
		t.Fatalf("embedded openapi sha256 drift: got %s, pinned %s", got, EmbeddedSpecSHA256)
	}
}

func TestDefault_ParsesEmbeddedSpec(t *testing.T) {
	r := Default()
	if r == nil {
		t.Fatal("Default returned nil")
	}
	if r.SHA256 != EmbeddedSpecSHA256 {
		t.Errorf("registry sha256 = %s, want %s", r.SHA256, EmbeddedSpecSHA256)
	}
	if r.Title == "" {
		t.Error("registry title is empty; openapi.info.title should populate it")
	}
	if r.Version == "" {
		t.Error("registry version is empty; openapi.info.version should populate it")
	}
}

// TestDefault_ServerPathFromEmbeddedSpec locks the spec's server path
// to "/api". The path is part of the public wire contract: the HTTP
// client prepends it whenever the user-supplied YALLA_BASE_URL has no
// path of its own, so a drift here would silently relocate every
// production request.
func TestDefault_ServerPathFromEmbeddedSpec(t *testing.T) {
	r := Default()
	if r.ServerPath != "/api" {
		t.Errorf("ServerPath = %q, want %q", r.ServerPath, "/api")
	}
}

// TestDefault_PrimarySecuritySchemeIsAPIKey pins the security scheme
// the client uses by default. The Dokploy server rejects Bearer auth in
// favour of the spec-declared `x-api-key` header, so any drift here
// signals either an upstream auth migration we have not absorbed yet or
// a parser regression that would silently break every authenticated
// call.
func TestDefault_PrimarySecuritySchemeIsAPIKey(t *testing.T) {
	r := Default()
	scheme, ok := r.PrimarySecurityScheme()
	if !ok {
		t.Fatal("PrimarySecurityScheme returned !ok; embedded spec declares a global apiKey requirement")
	}
	if scheme.Type != "apiKey" {
		t.Errorf("scheme.Type = %q, want apiKey", scheme.Type)
	}
	if !strings.EqualFold(scheme.In, "header") {
		t.Errorf("scheme.In = %q, want header", scheme.In)
	}
	if !strings.EqualFold(scheme.HeaderName, "x-api-key") {
		t.Errorf("scheme.HeaderName = %q, want x-api-key", scheme.HeaderName)
	}
}

// TestLoad_PrimarySecuritySchemeAbsent confirms the registry tolerates a
// spec that declares no global `security` block: callers (the HTTP
// client builder) fall back to the legacy Bearer transport rather than
// panicking, so a partially-spec'd document can still feed yalla.
func TestLoad_PrimarySecuritySchemeAbsent(t *testing.T) {
	spec := []byte(`{
		"openapi":"3.1.0",
		"info":{"title":"x","version":"0"},
		"paths":{}
	}`)
	r, err := Load(spec)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := r.PrimarySecurityScheme(); ok {
		t.Error("PrimarySecurityScheme should return false when the spec declares no global security")
	}
	if r.ServerPath != "" {
		t.Errorf("ServerPath = %q, want empty when spec declares no servers", r.ServerPath)
	}
}

// TestLoad_PrimarySecuritySchemeDangling exercises the case where the
// global `security[0]` references a scheme name that
// `components.securitySchemes` does not declare. The Dokploy spec does
// the inverse (per-op refs to a missing "Authorization") but a future
// drop could reverse them; either way the client must fall back to the
// legacy Bearer transport rather than crash.
func TestLoad_PrimarySecuritySchemeDangling(t *testing.T) {
	spec := []byte(`{
		"openapi":"3.1.0",
		"info":{"title":"x","version":"0"},
		"security":[{"missingScheme":[]}],
		"paths":{}
	}`)
	r, err := Load(spec)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := r.PrimarySecurityScheme(); ok {
		t.Error("PrimarySecurityScheme should return false when the referenced scheme is undeclared")
	}
}

// TestLoad_ServerPathExtractsPathOnly verifies that only the path
// component of the first declared server URL contributes to the
// registry. The host placeholder Dokploy ships in its servers block
// (`https://your-dokploy-instance.com/api`) is meaningless against a
// real install — yalla pulls the host from YALLA_BASE_URL.
func TestLoad_ServerPathExtractsPathOnly(t *testing.T) {
	spec := []byte(`{
		"openapi":"3.1.0",
		"info":{"title":"x","version":"0"},
		"servers":[{"url":"https://placeholder.example.com/api/"}],
		"paths":{}
	}`)
	r, err := Load(spec)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.ServerPath != "/api" {
		t.Errorf("ServerPath = %q, want /api (trailing slash trimmed)", r.ServerPath)
	}
}

// TestLoad_ServerPathRootIsEmpty normalises the "/" path to "" so
// callers can use a plain non-empty check rather than a string compare
// to detect "no prefix needed".
func TestLoad_ServerPathRootIsEmpty(t *testing.T) {
	spec := []byte(`{
		"openapi":"3.1.0",
		"info":{"title":"x","version":"0"},
		"servers":[{"url":"https://placeholder.example.com/"}],
		"paths":{}
	}`)
	r, err := Load(spec)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.ServerPath != "" {
		t.Errorf("ServerPath = %q, want empty for root path", r.ServerPath)
	}
}

func TestDefault_OperationCountMatchesPRD(t *testing.T) {
	r := Default()
	if r.Len() != expectedOperationCount {
		t.Fatalf("operation count = %d, pinned %d (update PRD + EmbeddedSpecSHA256 + this constant deliberately)", r.Len(), expectedOperationCount)
	}
}

func TestDefault_OperationIDsAreUniqueAndSorted(t *testing.T) {
	r := Default()
	ops := r.Operations()
	seen := make(map[string]struct{}, len(ops))
	for i, op := range ops {
		if op.OperationID == "" {
			t.Fatalf("operation %d has empty operationId", i)
		}
		if _, dup := seen[op.OperationID]; dup {
			t.Fatalf("duplicate operationId %q at index %d", op.OperationID, i)
		}
		seen[op.OperationID] = struct{}{}
		if i > 0 && ops[i-1].OperationID >= op.OperationID {
			t.Fatalf("operations are not sorted: %q before %q", ops[i-1].OperationID, op.OperationID)
		}
	}
}

// canonicalOperations is a deterministic sample of operationIds that MUST
// remain present. The sample covers high-traffic surfaces (application,
// project, deployment), every database family (mysql/postgres/redis/mongo/
// mariadb), the schema-heavy admin endpoint, the AI suite, and a couple of
// settings-tagged operations that often see churn upstream.
//
// This list is curated rather than exhaustive because the count test above
// already locks the cardinality. A drift in either signal is enough to
// fail the build.
var canonicalOperations = []string{
	"admin-setupMonitoring",
	"ai-create",
	"ai-delete",
	"application-deploy",
	"application-cancelDeployment",
	"backup-create",
	"compose-deploy",
	"deployment-all",
	"docker-getContainers",
	"mariadb-deploy",
	"mongo-deploy",
	"mysql-deploy",
	"organization-create",
	"postgres-deploy",
	"project-all",
	"redis-deploy",
	"server-create",
}

func TestDefault_HasCanonicalOperationIDs(t *testing.T) {
	r := Default()
	for _, id := range canonicalOperations {
		if _, ok := r.Get(id); !ok {
			t.Errorf("registry missing canonical operationId %q", id)
		}
	}
}

func TestRegistry_GetReturnsByValue(t *testing.T) {
	r := Default()
	op, ok := r.Get("application-deploy")
	if !ok {
		t.Fatal("application-deploy missing")
	}
	if op.Method == "" || op.Path == "" {
		t.Fatalf("application-deploy missing method/path: %+v", op)
	}
	if op.RequiresAuth != (len(op.Security) > 0) {
		t.Errorf("RequiresAuth out of sync with Security: %v vs %v", op.RequiresAuth, op.Security)
	}
	// Mutating the returned value must not affect the registry.
	op.OperationID = "tampered"
	again, _ := r.Get("application-deploy")
	if again.OperationID != "application-deploy" {
		t.Errorf("registry mutated through Get(): %q", again.OperationID)
	}
}

func TestRegistry_OperationsReturnsCopy(t *testing.T) {
	r := Default()
	ops := r.Operations()
	if len(ops) == 0 {
		t.Fatal("Operations() empty")
	}
	first := ops[0].OperationID
	ops[0].OperationID = "tampered"
	again := r.Operations()
	if again[0].OperationID != first {
		t.Errorf("Operations() shared backing array: %q vs %q", again[0].OperationID, first)
	}
}

func TestRegistry_IDsMatchesOperations(t *testing.T) {
	r := Default()
	ids := r.IDs()
	ops := r.Operations()
	if len(ids) != len(ops) {
		t.Fatalf("IDs/Operations length mismatch: %d vs %d", len(ids), len(ops))
	}
	for i := range ids {
		if ids[i] != ops[i].OperationID {
			t.Fatalf("IDs[%d]=%q, Operations[%d].OperationID=%q", i, ids[i], i, ops[i].OperationID)
		}
	}
	if !sort.StringsAreSorted(ids) {
		t.Error("IDs are not sorted")
	}
}

func TestRegistry_TagsCoverPRDSummary(t *testing.T) {
	r := Default()
	tags := r.Tags()
	if len(tags) == 0 {
		t.Fatal("Tags returned empty")
	}
	// Spot-check a handful of tags drawn from the PRD apiCoverageSummary.
	want := []string{"admin", "ai", "application", "settings", "server"}
	have := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		have[t] = struct{}{}
	}
	for _, w := range want {
		if _, ok := have[w]; !ok {
			t.Errorf("Tags() missing %q", w)
		}
	}
}

func TestRegistry_OperationsAreSecured(t *testing.T) {
	r := Default()
	// Dokploy's spec marks every operation as requiring auth via the
	// per-operation `security` block (the components.securitySchemes map
	// references "apiKey" but every op block references "Authorization").
	// Either way, the registry's RequiresAuth bool should be true for all
	// 450 operations. If a future spec drop adds an unauthenticated
	// endpoint this test must be updated deliberately.
	for _, op := range r.Operations() {
		if !op.RequiresAuth {
			t.Errorf("operation %q is unauthenticated; the Dokploy spec marks every endpoint as auth-required", op.OperationID)
		}
	}
}

func TestRegistry_MethodsAreCanonical(t *testing.T) {
	r := Default()
	allowed := map[string]struct{}{
		"GET": {}, "POST": {}, "PUT": {}, "PATCH": {},
		"DELETE": {}, "HEAD": {}, "OPTIONS": {}, "TRACE": {},
	}
	for _, op := range r.Operations() {
		if _, ok := allowed[op.Method]; !ok {
			t.Errorf("operation %q has non-canonical method %q", op.OperationID, op.Method)
		}
	}
}

func TestSchema_GetReturnsBodyAndOutputs(t *testing.T) {
	r := Default()
	doc, err := r.Schema("application-deploy")
	if err != nil {
		t.Fatalf("Schema: %v", err)
	}
	if doc.OperationID != "application-deploy" {
		t.Errorf("operation_id = %q", doc.OperationID)
	}
	if doc.Input == nil {
		t.Fatal("Input is nil")
	}
	if doc.Input.Body == nil {
		t.Fatal("application-deploy should declare a request body")
	}
	if doc.Input.Body.ContentType != "application/json" {
		t.Errorf("body content_type = %q", doc.Input.Body.ContentType)
	}
	if len(doc.Outputs) == 0 {
		t.Error("Outputs is empty")
	}
	// Body schema must be valid JSON if present.
	if len(doc.Input.Body.Schema) > 0 {
		var any interface{}
		if err := json.Unmarshal(doc.Input.Body.Schema, &any); err != nil {
			t.Errorf("body schema is not valid JSON: %v", err)
		}
	}
}

func TestSchema_GetUnknownOperationFails(t *testing.T) {
	r := Default()
	_, err := r.Schema("does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown operationId")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error should mention the missing id: %v", err)
	}
}

func TestSchema_OutputsAreNumericSorted(t *testing.T) {
	r := Default()
	doc, err := r.Schema("application-deploy")
	if err != nil {
		t.Fatalf("Schema: %v", err)
	}
	prev := -1
	for _, o := range doc.Outputs {
		n, ok := atoi(o.Status)
		if !ok {
			// "default" sorts after numeric codes; once we see it, all
			// subsequent statuses must be non-numeric too.
			prev = -2
			continue
		}
		if prev == -2 {
			t.Errorf("numeric status %q after non-numeric status", o.Status)
		}
		if n < prev {
			t.Errorf("status order violated: %d before %d", prev, n)
		}
		prev = n
	}
}

func TestSchema_AllSchemasMatchesRegistry(t *testing.T) {
	r := Default()
	all := r.AllSchemas()
	if len(all) != r.Len() {
		t.Fatalf("AllSchemas len=%d, registry len=%d", len(all), r.Len())
	}
	for i, s := range all {
		if s == nil {
			t.Fatalf("AllSchemas[%d] is nil", i)
		}
		if s.OperationID == "" {
			t.Fatalf("AllSchemas[%d] missing operation_id", i)
		}
	}
}

func TestLoad_RejectsDuplicateOperationID(t *testing.T) {
	spec := `{
		"openapi": "3.1.0",
		"info": {"title": "x", "version": "1"},
		"paths": {
			"/a": {"post": {"operationId": "dup", "responses": {"200": {"description": "ok"}}}},
			"/b": {"post": {"operationId": "dup", "responses": {"200": {"description": "ok"}}}}
		}
	}`
	_, err := Load([]byte(spec))
	if err == nil {
		t.Fatal("expected duplicate operationId error")
	}
	if !strings.Contains(err.Error(), "duplicate operationId") {
		t.Errorf("error should mention duplicate: %v", err)
	}
}

func TestLoad_RejectsMissingOperationID(t *testing.T) {
	spec := `{
		"openapi": "3.1.0",
		"info": {"title": "x", "version": "1"},
		"paths": {"/a": {"post": {"responses": {"200": {"description": "ok"}}}}}
	}`
	_, err := Load([]byte(spec))
	if err == nil {
		t.Fatal("expected missing operationId error")
	}
	if !strings.Contains(err.Error(), "operationId") {
		t.Errorf("error should mention operationId: %v", err)
	}
}

func TestLoad_RejectsMultiTaggedOperation(t *testing.T) {
	spec := `{
		"openapi": "3.1.0",
		"info": {"title": "x", "version": "1"},
		"paths": {"/a": {"post": {"operationId": "multi", "tags": ["a", "b"], "responses": {"200": {"description": "ok"}}}}}
	}`
	_, err := Load([]byte(spec))
	if err == nil {
		t.Fatal("expected multi-tag error")
	}
	if !strings.Contains(err.Error(), "tags") {
		t.Errorf("error should mention tags: %v", err)
	}
}
