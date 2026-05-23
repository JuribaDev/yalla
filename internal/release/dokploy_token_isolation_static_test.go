package release_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// BE-0361: Security verification — Dokploy token isolation.
//
// Threat model.
//
//  1. The privileged Dokploy bearer token (`YALLA_DOKPLOY_TOKEN`) is the
//     master credential that can mutate any Dokploy resource. It is loaded
//     by `internal/controlplane/config` into `RuntimeConfig.DokployToken`
//     and is intended to flow into exactly one in-process consumer: the
//     typed Dokploy `*Client` in `internal/controlplane/dokploy/client.go`,
//     where it is bound to the unexported `token` field of `*Client` and
//     injected as `"Bearer "+c.token` at one and only one HTTP header set
//     site (the `attempt` method's `Authorization` header). Any other
//     production source that constructs a `dokploy.Client`, reads
//     `config.DokployToken`, or references the `EnvDokployToken` constant
//     widens the blast radius and the matcher rejects it.
//
//  2. The customer-facing surface MUST be quarantined from the Dokploy
//     client API. The HTTP handler tree at `internal/controlplane/httpapi`
//     legitimately imports the `dokploy` package to consume the value
//     enum (`dokploy.ServiceType`, `dokploy.ServiceApplication`,
//     `dokploy.ServiceDatabase`, `dokploy.ServiceCompose`) for desired-
//     state rendering; that surface carries no token. The matcher rejects
//     ANY selector against `dokploy.Client`, `dokploy.NewClient`, or
//     `dokploy.Config` from customer-facing production sources so a
//     regression that imported the client (and therefore the bearer-
//     token-bearing path) into a handler is caught at build time. The
//     gate also rejects ANY selector against `config.DokployToken` or
//     `EnvDokployToken` from those files — a handler that read the
//     secret out of the runtime config could mint requests against
//     Dokploy directly, bypassing the worker, the audit trail, and the
//     idempotency guarantees.
//
//  3. The bearer token's reach inside the dokploy package is itself
//     bounded. The `Client` struct's `token` field MUST remain
//     unexported (lowercase) so no external caller can read it via a
//     selector, and the `.token` selector against the receiver MUST
//     appear in exactly one production file (`client.go`) at exactly
//     one line — the `req.Header.Set("Authorization", "Bearer "+c.token)`
//     call in the `attempt` method. The constructor assignment
//     (`token: token` inside the composite literal) and that one header
//     injection are the only legitimate token-touching sites. A
//     regression that added a `fmt.Errorf("dokploy: token %q rejected",
//     c.token)` or `slog.String("token", c.token)` would surface the
//     secret in logs, errors, and the audit ring buffer; the matcher
//     rejects any further `c.token` selector in the production package.
//
//  4. The operator-visible projections of the token MUST go through the
//     redactor. `RuntimeConfig.Redacted()` MUST stamp the `DokployToken`
//     field via the local `redact(...)` closure so the returned
//     `RedactedConfig` carries the sentinel, not the secret;
//     `(*Config).LogValue()` MUST consult `c.Redacted()` first and MUST
//     NOT touch `c.DokployToken` directly so a stray
//     `slog.Any("config", c)` capture cannot leak the bearer token.
//     The matcher pins both shapes; a regression that emitted a bare
//     `c.DokployToken` from either projection would land the secret in
//     the structured log stream or in the JSON `/version` envelope and
//     from there into log shippers, on-call dashboards, and post-
//     incident transcripts.
//
//  5. The operator-facing posture is part of the public security
//     contract. SECURITY.md MUST document (a) the token-confinement
//     rules, (b) the customer-surface quarantine, and (c) the redacted-
//     projection requirement so an operator scanning the deployment
//     learns what we intentionally do and do not do with the Dokploy
//     bearer token. The matcher pins the heading, the required
//     substrings, and the verification-gates table row; a silent
//     removal of either is a regression on equal footing with a code
//     change.
//
// This is a worked instance of the BE-0344 two-test template, applied
// to a cross-package secret-confinement invariant: the static half lives
// here (the AST/literal gates plus the doc pin); the runtime half is
// `internal/controlplane/dokploy.TestClientRedactsSecrets` (already
// landed) and `internal/controlplane/dokploy.TestClientErrorsNeverLeakBearerToken`
// plus `internal/controlplane/config.TestRuntimeConfigDokployTokenRedactionNeverLeaks`
// (landed alongside this gate). The
// TestDokployTokenIsolationStaticAnalyzerDetectsRegressions self-check
// feeds synthetic known-bad and known-good fixtures through every
// matcher so over- and under-tightening of the analyser are both
// caught.

// dokployTokenHTTPAPIDir is the relative directory whose non-test `.go`
// files are scanned for forbidden Dokploy-client selectors and forbidden
// runtime-config-secret references. The customer-facing surface is the
// quarantine boundary the gate enforces.
const dokployTokenHTTPAPIDir = "internal/controlplane/httpapi"

// dokployTokenPackageDir is the relative directory containing the
// privileged Dokploy client. The `.token` selector audit is bounded to
// this directory's non-test, non-`dokployfake` sources; the fake server
// legitimately stores its own `Token` for the in-test bearer check and
// is not subject to the single-use rule.
const dokployTokenPackageDir = "internal/controlplane/dokploy"

// dokployTokenClientPath is the absolute production file owning the
// `Client` struct and the one allowed `.token` selector. Pinned by
// path so a future split or rename forces an explicit update of this
// test rather than silently disabling the gate.
const dokployTokenClientPath = "internal/controlplane/dokploy/client.go"

// dokployTokenConfigPath is the absolute production file owning the
// `RuntimeConfig.Redacted()` and `(*Config).LogValue()` projections.
// Pinned by path so a future move of the redaction seam forces an
// explicit update.
const dokployTokenConfigPath = "internal/controlplane/config/config.go"

// dokployTokenSecurityDocPath is the operator-facing security posture
// document. The test pins both the dedicated section heading and the
// verification-gates table row so a silent doc deletion is caught
// alongside a silent code regression.
const dokployTokenSecurityDocPath = "SECURITY.md"

// forbiddenDokployClientSelectors enumerates the package-qualified
// selectors a customer-facing handler MUST NOT name. Each one identifies
// a token-bearing entry point:
//   - `dokploy.Client` is the typed HTTP wrapper that holds the bearer
//     token in its unexported `token` field; a handler that received
//     `*dokploy.Client` could mint privileged Dokploy requests.
//   - `dokploy.NewClient` is the constructor that accepts a `Config`
//     containing the bearer token; calling it from a handler would
//     embed the secret into the customer-facing surface.
//   - `dokploy.Config` is the configuration struct whose `Token` field
//     accepts the bearer token; passing it through a handler signature
//     would similarly route the secret into the customer surface.
var forbiddenDokployClientSelectors = map[string]struct{}{
	"dokploy.Client":    {},
	"dokploy.NewClient": {},
	"dokploy.Config":    {},
}

// forbiddenDokployFieldSelectorNames enumerates the *trailing* selector
// names that, when matched against any SelectorExpr's `Sel.Name`,
// identify a read of the privileged Dokploy bearer token regardless of
// the receiver. This catches `config.DokployToken` (package-qualified),
// `cfg.DokployToken` (local handle), and `c.DokployToken` (receiver)
// alike — every shape ends with `.DokployToken`, and the field name is
// unambiguously the bearer token in this codebase.
var forbiddenDokployFieldSelectorNames = map[string]struct{}{
	"DokployToken": {},
}

// forbiddenDokployConfigEnvIdent is the bare-identifier form of the
// env-var constant. A handler that imported
// `internal/controlplane/config` under a dot-import or used the same
// package would surface `EnvDokployToken` without a package qualifier.
// The bare-ident scan catches that variant; the SelectorExpr scan
// catches the `config.EnvDokployToken` variant and suppresses descent
// into the inner Ident so the diagnostic is single-counted.
const forbiddenDokployConfigEnvIdent = "EnvDokployToken"

// requiredDokployTokenSecurityHeading is the literal Markdown heading
// SECURITY.md MUST carry to document this story's posture. The exact
// heading is part of the public contract — operators and downstream
// auditors deep-link to it — so changes are deliberate.
const requiredDokployTokenSecurityHeading = "## Dokploy Token Isolation"

// requiredDokployTokenSecuritySubstrings is the closed set of literal
// substrings SECURITY.md MUST contain to satisfy the documentation
// half of the gate. Each captures a different load-bearing fact so an
// operator and auditor learn the contract without reading the test
// file:
//   - `YALLA_DOKPLOY_TOKEN` so the env-var name is unambiguously
//     documented,
//   - `internal/controlplane/dokploy` so the single allowed in-process
//     consumer is named,
//   - `Authorization: Bearer` so the one allowed wire emission is
//     named,
//   - `Redacted()` so the operator-visible projection's safety contract
//     is named,
//   - the test file path so the gate is self-locating.
var requiredDokployTokenSecuritySubstrings = []string{
	"YALLA_DOKPLOY_TOKEN",
	"internal/controlplane/dokploy",
	"Authorization: Bearer",
	"Redacted()",
	"dokploy_token_isolation_static_test.go",
}

// requiredDokployTokenGateRow is the literal substring of the row that
// MUST appear in SECURITY.md's Required Verification Gates table. The
// substring is the gate name; a contributor who renames the test
// functions must also update this row.
const requiredDokployTokenGateRow = "Dokploy token isolation"

// TestDokployTokenIsolationCustomerSurfaceFreeOfClient proves that no
// production source file under `internal/controlplane/httpapi` names
// `dokploy.Client`, `dokploy.NewClient`, `dokploy.Config`,
// `config.DokployToken`, or `EnvDokployToken`. The customer-facing
// HTTP tree may consume the typed value enum (`dokploy.ServiceType`
// and its constants), but it MUST NOT touch the token-bearing API.
func TestDokployTokenIsolationCustomerSurfaceFreeOfClient(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	files := dokployTokenHTTPAPIProductionFiles(t, root)
	fset := token.NewFileSet()
	for _, rel := range files {
		path := filepath.Join(root, rel)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		for _, v := range findForbiddenDokployTokenSurface(fset, file) {
			t.Error(v)
		}
	}
}

// TestDokployTokenIsolationClientTokenFieldUnexported proves that the
// `Client` struct's bearer-token field is declared with a lowercase
// name. A regression that exported the field (`Token string`) would
// let any caller read the secret via a selector, defeating the entire
// confinement story.
func TestDokployTokenIsolationClientTokenFieldUnexported(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, dokployTokenClientPath)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", dokployTokenClientPath, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", dokployTokenClientPath, err)
	}
	for _, v := range findClientExportedTokenField(fset, file) {
		t.Error(v)
	}
}

// TestDokployTokenIsolationClientTokenSelectorSingleUse proves that
// the `.token` selector against a `*Client` receiver appears in
// exactly one location inside the production Dokploy package, and
// that the location is the canonical Authorization-header injection
// in `client.go`'s `attempt` method. A regression that added a
// second `c.token` selector — a `fmt.Errorf("token %q rejected",
// c.token)`, a `slog.String("token", c.token)`, an envelope field
// projecting the bearer — would land the bytes in operator logs,
// error messages, or customer-facing responses.
func TestDokployTokenIsolationClientTokenSelectorSingleUse(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	files := dokployTokenPackageProductionFiles(t, root)
	fset := token.NewFileSet()
	var allHits []string
	for _, rel := range files {
		path := filepath.Join(root, rel)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		allHits = append(allHits, findClientTokenSelectorSites(fset, file, rel)...)
	}
	sort.Strings(allHits)
	if len(allHits) != 1 {
		t.Errorf("expected exactly one `.token` selector against a *Client receiver in production sources of %s; got %d:\n  %s\n"+
			"The bearer token MUST be referenced ONLY at the canonical Authorization-header injection in client.go's attempt method. "+
			"Any other `c.token` selector — a fmt.Errorf, slog field, audit metadata stamp, or envelope projection — would surface the secret. "+
			"See internal/release/dokploy_token_isolation_static_test.go (BE-0361) and SECURITY.md \"Dokploy Token Isolation\" for the threat model.",
			dokployTokenPackageDir, len(allHits), strings.Join(allHits, "\n  "))
		return
	}
	if !strings.HasPrefix(allHits[0], dokployTokenClientPath+":") {
		t.Errorf("the single `.token` selector MUST live in %s; got %s. "+
			"See internal/release/dokploy_token_isolation_static_test.go (BE-0361).",
			dokployTokenClientPath, allHits[0])
	}
}

// TestDokployTokenIsolationConfigRedactedStampsToken proves that the
// `(*Config).Redacted()` method's returned `RedactedConfig` composite
// literal stamps the `DokployToken` field through the local
// `redact(...)` closure, NOT through a bare `c.DokployToken` selector.
// A regression that returned the plaintext token would land it in
// every operator surface that consumes `Redacted()` — the `/version`
// JSON envelope, the structured log line in `LogValue`, and the
// `String()` projection.
func TestDokployTokenIsolationConfigRedactedStampsToken(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, dokployTokenConfigPath)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", dokployTokenConfigPath, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", dokployTokenConfigPath, err)
	}
	for _, v := range findConfigRedactedRegressions(fset, file) {
		t.Error(v)
	}
}

// TestDokployTokenIsolationConfigLogValueUsesRedacted proves that the
// `(*Config).LogValue()` method consults `c.Redacted()` first and
// never references `c.DokployToken` directly. The defence-in-depth
// rationale is documented on the method itself: an accidental
// `slog.Any("config", c)` capture MUST NOT leak the bearer.
func TestDokployTokenIsolationConfigLogValueUsesRedacted(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, dokployTokenConfigPath)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", dokployTokenConfigPath, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", dokployTokenConfigPath, err)
	}
	for _, v := range findConfigLogValueRegressions(fset, file) {
		t.Error(v)
	}
}

// TestDokployTokenIsolationSecurityDocumented proves that SECURITY.md
// documents the operator-facing Dokploy-token-isolation contract. The
// pinned heading and required substrings are part of the public
// security posture; a silent removal is a regression on equal footing
// with a code change.
func TestDokployTokenIsolationSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, dokployTokenSecurityDocPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", dokployTokenSecurityDocPath, err)
	}
	doc := string(b)
	if !strings.Contains(doc, requiredDokployTokenSecurityHeading) {
		t.Errorf("%s: missing required heading %q; "+
			"the public security posture for Dokploy token isolation must stay documented.",
			dokployTokenSecurityDocPath, requiredDokployTokenSecurityHeading)
	}
	for _, want := range requiredDokployTokenSecuritySubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; "+
				"the documented contract MUST name every load-bearing fact so operators and auditors do not have to read the test file.",
				dokployTokenSecurityDocPath, want, requiredDokployTokenSecurityHeading)
		}
	}
	if !strings.Contains(doc, requiredDokployTokenGateRow) {
		t.Errorf("%s: missing verification-gates table row containing %q; "+
			"every security-verification story must surface as a row operators and reviewers can see at a glance.",
			dokployTokenSecurityDocPath, requiredDokployTokenGateRow)
	}
}

// TestDokployTokenIsolationStaticAnalyzerDetectsRegressions is the
// self-check for the matchers above. The acceptance criterion "tests
// fail when the control is removed" is the load-bearing one: each
// known-bad synthetic snippet must produce hits, and the known-good
// snippet must produce zero hits. This guards against the analyser
// silently going lenient.
func TestDokployTokenIsolationStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("findForbiddenDokployTokenSurface", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical handler that uses only the value enum is accepted",
				source: `package httpapi
import "github.com/JuribaDev/yalla/internal/controlplane/dokploy"
func kindOf(s string) dokploy.ServiceType {
	switch s {
	case "application":
		return dokploy.ServiceApplication
	case "database":
		return dokploy.ServiceDatabase
	case "compose":
		return dokploy.ServiceCompose
	}
	return dokploy.ServiceType(s)
}`,
				wantHits: 0,
			},
			{
				name: "handler that references *dokploy.Client is rejected",
				source: `package httpapi
import "github.com/JuribaDev/yalla/internal/controlplane/dokploy"
type handler struct { client *dokploy.Client }`,
				wantHits: 1,
			},
			{
				name: "handler that calls dokploy.NewClient is rejected",
				source: `package httpapi
import "github.com/JuribaDev/yalla/internal/controlplane/dokploy"
func setup() *dokploy.Client { c, _ := dokploy.NewClient(dokploy.Config{}); return c }`,
				// dokploy.NewClient + dokploy.Client (return type) + dokploy.Config
				wantHits: 3,
			},
			{
				name: "handler that reads config.DokployToken is rejected",
				source: `package httpapi
import "github.com/JuribaDev/yalla/internal/controlplane/config"
func leak(c *config.Config) string { return c.DokployToken }`,
				wantHits: 1,
			},
			{
				name: "handler that reads config.EnvDokployToken is rejected",
				source: `package httpapi
import (
	"os"
	"github.com/JuribaDev/yalla/internal/controlplane/config"
)
func backdoor() string { return os.Getenv(config.EnvDokployToken) }`,
				wantHits: 1,
			},
			{
				name: "handler that declares AND uses a bare EnvDokployToken identifier is rejected twice",
				source: `package httpapi
import "os"
const EnvDokployToken = "YALLA_DOKPLOY_TOKEN"
func backdoor() string { return os.Getenv(EnvDokployToken) }`,
				// The declaration's Name and the usage's Ident reference are
				// both flagged — declaring a Dokploy-secret-named constant
				// inside httpapi is itself a smell, and the matcher's job is
				// to surface every appearance of the forbidden identifier.
				wantHits: 2,
			},
		}
		for _, tc := range tcs {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
				if err != nil {
					t.Fatalf("parse synthetic source: %v", err)
				}
				got := findForbiddenDokployTokenSurface(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findForbiddenDokployTokenSurface: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findClientExportedTokenField", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical unexported token field is accepted",
				source: `package dokploy
type Client struct {
	baseURL string
	token   string
}`,
				wantHits: 0,
			},
			{
				name: "exported Token field on Client is rejected",
				source: `package dokploy
type Client struct {
	BaseURL string
	Token   string
}`,
				wantHits: 1,
			},
			{
				name: "Token field on an unrelated struct is ignored",
				source: `package dokploy
type Config struct {
	BaseURL string
	Token   string
}`,
				wantHits: 0,
			},
		}
		for _, tc := range tcs {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
				if err != nil {
					t.Fatalf("parse synthetic source: %v", err)
				}
				got := findClientExportedTokenField(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findClientExportedTokenField: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findClientTokenSelectorSites", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical single Authorization header use is reported once",
				source: `package dokploy
import "net/http"
type Client struct{ token string }
func (c *Client) attempt(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
}`,
				wantHits: 1,
			},
			{
				name: "additional fmt.Errorf with c.token surfaces as a second hit",
				source: `package dokploy
import (
	"fmt"
	"net/http"
)
type Client struct{ token string }
func (c *Client) attempt(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	_ = fmt.Errorf("token %q rejected", c.token)
}`,
				wantHits: 2,
			},
			{
				name: "slog.String capture is also reported",
				source: `package dokploy
import "log/slog"
type Client struct{ token string }
func (c *Client) log() {
	slog.Default().Info("ping", slog.String("token", c.token))
}`,
				wantHits: 1,
			},
			{
				name: "constructor binding token: token is NOT counted (KeyValueExpr key, not selector)",
				source: `package dokploy
type Client struct{ token string }
func NewClient(token string) *Client {
	return &Client{token: token}
}`,
				wantHits: 0,
			},
		}
		for _, tc := range tcs {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
				if err != nil {
					t.Fatalf("parse synthetic source: %v", err)
				}
				got := findClientTokenSelectorSites(fset, file, "synthetic.go")
				if len(got) != tc.wantHits {
					t.Errorf("findClientTokenSelectorSites: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findConfigRedactedRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical redact(c.DokployToken) is accepted",
				source: `package config
type Config struct{ DokployToken string }
type RedactedConfig struct{ DokployToken string }
func (c *Config) Redacted() RedactedConfig {
	redact := func(v string) string { _ = v; return "[REDACTED]" }
	return RedactedConfig{DokployToken: redact(c.DokployToken)}
}`,
				wantHits: 0,
			},
			{
				name: "bare c.DokployToken selector in Redacted is rejected",
				source: `package config
type Config struct{ DokployToken string }
type RedactedConfig struct{ DokployToken string }
func (c *Config) Redacted() RedactedConfig {
	return RedactedConfig{DokployToken: c.DokployToken}
}`,
				wantHits: 1,
			},
			{
				name: "missing DokployToken field in the literal is rejected",
				source: `package config
type Config struct{ DokployToken string }
type RedactedConfig struct{ DokployBaseURL string }
func (c *Config) Redacted() RedactedConfig {
	return RedactedConfig{DokployBaseURL: "x"}
}`,
				wantHits: 1,
			},
			{
				name: "missing Redacted method is rejected",
				source: `package config
type Config struct{ DokployToken string }
type RedactedConfig struct{ DokployToken string }
func (c *Config) NotRedacted() RedactedConfig { return RedactedConfig{} }`,
				wantHits: 1,
			},
		}
		for _, tc := range tcs {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
				if err != nil {
					t.Fatalf("parse synthetic source: %v", err)
				}
				got := findConfigRedactedRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findConfigRedactedRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findConfigLogValueRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical c.Redacted() usage is accepted",
				source: `package config
import "log/slog"
type Config struct{ DokployToken string }
type RedactedConfig struct{ DokployToken string }
func (c *Config) Redacted() RedactedConfig { return RedactedConfig{} }
func (c *Config) LogValue() slog.Value {
	r := c.Redacted()
	return slog.StringValue(r.DokployToken)
}`,
				wantHits: 0,
			},
			{
				name: "LogValue that skips Redacted is rejected",
				source: `package config
import "log/slog"
type Config struct{ DokployToken string }
type RedactedConfig struct{ DokployToken string }
func (c *Config) Redacted() RedactedConfig { return RedactedConfig{} }
func (c *Config) LogValue() slog.Value {
	return slog.StringValue("nope")
}`,
				wantHits: 1,
			},
			{
				name: "LogValue that references c.DokployToken directly is rejected",
				source: `package config
import "log/slog"
type Config struct{ DokployToken string }
type RedactedConfig struct{ DokployToken string }
func (c *Config) Redacted() RedactedConfig { return RedactedConfig{} }
func (c *Config) LogValue() slog.Value {
	r := c.Redacted()
	_ = r
	return slog.StringValue(c.DokployToken)
}`,
				wantHits: 1,
			},
			{
				name: "missing LogValue method is rejected",
				source: `package config
type Config struct{ DokployToken string }
type RedactedConfig struct{ DokployToken string }
func (c *Config) Redacted() RedactedConfig { return RedactedConfig{} }`,
				wantHits: 1,
			},
		}
		for _, tc := range tcs {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
				if err != nil {
					t.Fatalf("parse synthetic source: %v", err)
				}
				got := findConfigLogValueRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findConfigLogValueRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})
}

// findForbiddenDokployTokenSurface walks the AST of a customer-facing
// production file and returns one diagnostic per occurrence of a
// forbidden Dokploy-client selector or a forbidden Dokploy-token
// config reference. The scan covers both the package-qualified
// (`dokploy.Client`, `config.DokployToken`) and bare-identifier
// (`EnvDokployToken`) variants so a future dot-import or same-package
// stunt cannot smuggle the secret reference in unflagged.
func findForbiddenDokployTokenSurface(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, kind, detail string) {
		out = append(out, kind+" "+detail+" at "+pos.String()+
			". The Yalla customer-facing HTTP surface MUST NOT touch the Dokploy bearer token: no construction of dokploy.Client, no read of config.DokployToken, no reference to EnvDokployToken. Handlers integrate with Dokploy through typed ports whose runtime lives in workers and the reconciler. "+
			"See internal/release/dokploy_token_isolation_static_test.go (BE-0361) and SECURITY.md \"Dokploy Token Isolation\" for the threat model.")
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if node.Sel == nil {
				return true
			}
			// Match the bearer-token field by its trailing selector name
			// (the most reliable signal — there is exactly one field named
			// `DokployToken` in this codebase, and it is the secret).
			// Return false to suppress descent into the inner Ident so
			// the diagnostic is counted exactly once.
			if _, bad := forbiddenDokployFieldSelectorNames[node.Sel.Name]; bad {
				emit(fset.Position(node.Pos()), "forbidden Dokploy-token field selector",
					exprText(node.X)+"."+node.Sel.Name)
				return false
			}
			pkg, ok := node.X.(*ast.Ident)
			if !ok {
				return true
			}
			qualified := pkg.Name + "." + node.Sel.Name
			if _, bad := forbiddenDokployClientSelectors[qualified]; bad {
				emit(fset.Position(node.Pos()), "forbidden Dokploy-client selector", qualified)
				return false
			}
			if node.Sel.Name == forbiddenDokployConfigEnvIdent {
				emit(fset.Position(node.Pos()), "forbidden Dokploy env-var selector", qualified)
				return false
			}
		case *ast.Ident:
			if node.Name == forbiddenDokployConfigEnvIdent {
				emit(fset.Position(node.Pos()), "forbidden Dokploy env-var identifier", node.Name)
			}
		}
		return true
	})
	sort.Strings(out)
	return out
}

// findClientExportedTokenField walks the AST of client.go and reports
// any `Client` struct field whose name begins with an uppercase rune
// and whose lowercased name is "token". Only the `Client` struct is
// inspected — the `Config` struct legitimately exports a `Token`
// field because callers must populate it before constructing the
// client; the matcher does not flag that variant.
func findClientExportedTokenField(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, detail string) {
		out = append(out, "exported Client.token-shaped field "+detail+" at "+pos.String()+
			". The privileged Dokploy bearer token MUST remain in the unexported `token` field of *Client; an exported field would let any caller read the secret via a selector. "+
			"See internal/release/dokploy_token_isolation_static_test.go (BE-0361) and SECURITY.md \"Dokploy Token Isolation\" for the threat model.")
	}
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name == nil || ts.Name.Name != "Client" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}
		for _, f := range st.Fields.List {
			for _, name := range f.Names {
				if name == nil {
					continue
				}
				if !ast.IsExported(name.Name) {
					continue
				}
				if strings.EqualFold(name.Name, "token") {
					emit(fset.Position(name.Pos()), strconv.Quote(name.Name))
				}
			}
		}
		return true
	})
	sort.Strings(out)
	return out
}

// findClientTokenSelectorSites walks the AST of a production Dokploy
// package file and returns the file:line:col of every
// `<receiver>.token` SelectorExpr (NOT a KeyValueExpr key, which is
// the constructor's `token: token` binding). The caller asserts the
// across-package count is exactly 1 and pins the single site to
// `client.go`. The matcher uses Sel.Name string equality; type
// information is unavailable at parse time but the `Client` struct is
// the only production type in this package that owns a lowercase
// `token` field, so any further `.token` selector against any
// receiver in this package is by construction a regression.
func findClientTokenSelectorSites(fset *token.FileSet, file *ast.File, rel string) []string {
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			return true
		}
		if sel.Sel.Name != "token" {
			return true
		}
		pos := fset.Position(sel.Pos())
		out = append(out, filepath.ToSlash(rel)+":"+strconv.Itoa(pos.Line)+":"+strconv.Itoa(pos.Column))
		return true
	})
	sort.Strings(out)
	return out
}

// findConfigRedactedRegressions walks the AST of config.go and reports
// three orthogonal regressions on the `(*Config).Redacted()` method:
//
//  1. The method does not exist at all (renamed, deleted) — every
//     downstream operator-visible projection consumes Redacted().
//  2. The method's returned RedactedConfig composite literal omits a
//     `DokployToken` key — a downstream projection that copies the
//     literal would silently surface the empty string instead of the
//     redaction sentinel.
//  3. The method's `DokployToken` field value is NOT a call to a
//     redact helper — bare `c.DokployToken` would surface the
//     plaintext token in every operator-visible projection.
func findConfigRedactedRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, kind, detail string) {
		out = append(out, kind+" "+detail+" at "+pos.String()+
			". (*Config).Redacted() MUST stamp DokployToken through the local `redact(...)` closure; the returned RedactedConfig is consumed by /version, by LogValue, and by String(), so a bare c.DokployToken would leak the bearer into every operator surface. "+
			"See internal/release/dokploy_token_isolation_static_test.go (BE-0361) and SECURITY.md \"Dokploy Token Isolation\" for the threat model.")
	}
	method := findMethodOnReceiver(file, "Config", "Redacted")
	if method == nil {
		emit(fset.Position(file.Pos()), "missing required method", "(*Config).Redacted()")
		sort.Strings(out)
		return out
	}
	// Find the returned RedactedConfig composite literal's DokployToken
	// field. The Redacted method returns one literal directly; if a
	// future refactor splits the construction across helpers, the
	// matcher's "find any composite literal containing DokployToken"
	// pass still locates it.
	var dokployValue ast.Expr
	var dokployFieldPos token.Pos
	foundField := false
	ast.Inspect(method.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "DokployToken" {
				continue
			}
			foundField = true
			dokployValue = kv.Value
			dokployFieldPos = kv.Pos()
		}
		return true
	})
	if !foundField {
		emit(fset.Position(method.Body.Pos()), "Redacted return literal omits required field", "DokployToken")
		sort.Strings(out)
		return out
	}
	call, ok := dokployValue.(*ast.CallExpr)
	if !ok {
		emit(fset.Position(dokployFieldPos), "DokployToken field MUST be stamped through a redact() call; got non-call expression", "")
		sort.Strings(out)
		return out
	}
	fnIdent, ok := call.Fun.(*ast.Ident)
	if !ok || fnIdent.Name != "redact" {
		emit(fset.Position(dokployFieldPos), "DokployToken field MUST be stamped through the local redact() closure; got call to", exprText(call.Fun))
	}
	sort.Strings(out)
	return out
}

// findConfigLogValueRegressions walks the AST of config.go and reports
// two orthogonal regressions on the `(*Config).LogValue()` method:
//
//  1. The method does not exist or does not call `c.Redacted()` — a
//     stray `slog.Any("config", c)` capture would walk the raw Config
//     and surface the bearer.
//  2. The method body references `c.DokployToken` directly — only
//     `r.DokployToken` (the post-Redacted value) is permitted.
func findConfigLogValueRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, kind, detail string) {
		out = append(out, kind+" "+detail+" at "+pos.String()+
			". (*Config).LogValue() MUST consult c.Redacted() first and MUST NOT touch c.DokployToken directly; the redaction seam is the only thing standing between an accidental slog capture and the bearer landing in the structured log. "+
			"See internal/release/dokploy_token_isolation_static_test.go (BE-0361) and SECURITY.md \"Dokploy Token Isolation\" for the threat model.")
	}
	method := findMethodOnReceiver(file, "Config", "LogValue")
	if method == nil {
		emit(fset.Position(file.Pos()), "missing required method", "(*Config).LogValue()")
		sort.Strings(out)
		return out
	}
	seenRedactedCall := false
	ast.Inspect(method.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "c" && sel.Sel != nil && sel.Sel.Name == "Redacted" {
					seenRedactedCall = true
				}
			}
		case *ast.SelectorExpr:
			ident, ok := node.X.(*ast.Ident)
			if !ok || ident.Name != "c" || node.Sel == nil {
				return true
			}
			if node.Sel.Name == "DokployToken" {
				emit(fset.Position(node.Pos()), "forbidden bare reference to", "c.DokployToken (must be r.DokployToken after c.Redacted())")
			}
		}
		return true
	})
	if !seenRedactedCall {
		emit(fset.Position(method.Body.Pos()), "missing required call to", "c.Redacted()")
	}
	sort.Strings(out)
	return out
}

// findMethodOnReceiver returns the FuncDecl for the named method on
// the named receiver type (matched against both value and pointer
// receivers), or nil if no such method exists in the file.
func findMethodOnReceiver(file *ast.File, recvTypeName, methodName string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name == nil || fn.Name.Name != methodName {
			continue
		}
		if len(fn.Recv.List) == 0 {
			continue
		}
		recvType := fn.Recv.List[0].Type
		if star, ok := recvType.(*ast.StarExpr); ok {
			recvType = star.X
		}
		ident, ok := recvType.(*ast.Ident)
		if !ok || ident.Name != recvTypeName {
			continue
		}
		return fn
	}
	return nil
}

// exprText renders an expression as a best-effort string for
// diagnostic messages. The matcher only uses it on call-target
// expressions where the caller already knows the shape is not the
// expected redact identifier, so a short rendering is enough.
func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if x, ok := v.X.(*ast.Ident); ok && v.Sel != nil {
			return x.Name + "." + v.Sel.Name
		}
		if v.Sel != nil {
			return "<expr>." + v.Sel.Name
		}
	}
	return "<expr>"
}

// dokployTokenHTTPAPIProductionFiles returns the relative paths of
// every non-test `.go` file under `internal/controlplane/httpapi`.
// The list is sorted so diagnostics are deterministic. Test files
// (`*_test.go`) are deliberately skipped — a future runtime test may
// legitimately import dokploy.Client to exercise an integration path
// without the gate flagging it.
func dokployTokenHTTPAPIProductionFiles(t *testing.T, root string) []string {
	t.Helper()
	dirAbs := filepath.Join(root, dokployTokenHTTPAPIDir)
	entries, err := os.ReadDir(dirAbs)
	if err != nil {
		t.Fatalf("read dir %s: %v", dokployTokenHTTPAPIDir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dokployTokenHTTPAPIDir, name))
	}
	sort.Strings(files)
	return files
}

// dokployTokenPackageProductionFiles returns the relative paths of
// every non-test `.go` file directly under
// `internal/controlplane/dokploy`. The `dokployfake/` subdirectory is
// deliberately excluded — the fake server stores its own `Token` for
// the in-test bearer check and is not part of the privileged token
// flow. The list is sorted so diagnostics are deterministic.
func dokployTokenPackageProductionFiles(t *testing.T, root string) []string {
	t.Helper()
	dirAbs := filepath.Join(root, dokployTokenPackageDir)
	entries, err := os.ReadDir(dirAbs)
	if err != nil {
		t.Fatalf("read dir %s: %v", dokployTokenPackageDir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(dokployTokenPackageDir, name))
	}
	sort.Strings(files)
	return files
}
