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

// BE-0357: Security verification — admin endpoint isolation.
//
// Threat model.
//
//  1. The Yalla control-plane API binary (cmd/yalla-api) exposes a small,
//     deliberate set of operator-visible HTTP routes: GET /healthz, GET
//     /readyz, GET /healthz/backup, GET /version, and GET /openapi.json,
//     plus the customer-facing /v1/* surface. The Go standard library
//     ships two side-effecting packages whose blank-import alone wires a
//     parallel "/debug/*" surface onto the global default mux:
//     `net/http/pprof` registers `/debug/pprof/{,profile,heap,goroutine,
//     trace,symbol,cmdline,…}`; `expvar` registers `/debug/vars`. The
//     `golang.org/x/net/trace` package similarly registers
//     `/debug/requests` and `/debug/events`. None of these surfaces are
//     authenticated. A pprof handler reachable by an unauthenticated
//     attacker is a goroutine-profile, heap-allocation, command-line,
//     and live-CPU-profile leak; `/debug/vars` exposes every registered
//     `expvar.Var` (often including build flags, command-line arguments,
//     and process counters). The matcher rejects ANY import of those
//     packages from the API binary or from `internal/controlplane/httpapi`
//     production code so an inadvertent `_ "net/http/pprof"` cannot
//     smuggle the surface back in.
//
//  2. Even with no pprof/expvar import, a hostile or careless contributor
//     could attach the API server to `http.DefaultServeMux` by leaving
//     `http.Server.Handler` nil — the standard library's documented
//     fallback. Any package imported transitively by the binary that
//     calls `http.Handle("/debug/…", …)` on the default mux would then
//     leak its surface through the API listener. The API binary's
//     `http.Server` composite literal MUST therefore set `Handler`
//     explicitly, and `httpapi.NewHandler` MUST construct a private
//     `http.NewServeMux()` rather than reach for `http.DefaultServeMux`.
//     The matcher pins both shapes.
//
//  3. No production source file in `cmd/yalla-api` or
//     `internal/controlplane/httpapi` may name a `/debug/*` path literal,
//     reference a `pprof.*` selector, reference an `expvar.*` selector,
//     or reference `http.DefaultServeMux`. The file-wide literal pass is
//     a belt-and-braces guard for the import pass: a regression that
//     side-steps the blank-import scan by registering the routes through
//     a different package (a vendored fork, a hand-rolled equivalent)
//     would still leave the debug path literal in source. The selector
//     pass rejects `pprof.Index`, `expvar.Handler`, and similar even if
//     the import alias is renamed.
//
//  4. The runtime evidence half is implicit: every unmatched route — in
//     particular every `/debug/*` request that might slip past the static
//     gate — is intercepted by `notFoundRecorder` in
//     `internal/controlplane/httpapi/server.go` and returned as the
//     stable `yalla.error.v1` envelope with code `E_NOT_FOUND`. The
//     telemetry.RequestLogging middleware logs the rejected request,
//     redacted, so an attempt to probe a debug surface lands as a
//     deterministic operator-visible 404 in the audit-quality request
//     log. The static gate ensures we never register the surface in the
//     first place; `notFoundRecorder` is the defence-in-depth wall.
//
//  5. The operator-facing contract is part of the public security
//     posture. SECURITY.md MUST document (a) the closed forbidden-import
//     set, (b) the private-mux requirement, and (c) the absent
//     `/debug/*` surface so an operator scanning the deployment for
//     debug endpoints learns we deliberately do not ship any. The
//     matcher pins the heading and the canonical substrings; a silent
//     removal of either is a regression on equal footing with a code
//     change.
//
// The single-test-file variant of the BE-0344 two-test pattern (BE-0353,
// BE-0354, BE-0355, BE-0356). The "runtime" half is implicit: the
// `notFoundRecorder` envelope IS the runtime path for any debug-shaped
// request that reaches the listener, and there is no application-code
// call site that could carry a parallel runtime gate (a Go test cannot
// prove a binary deployed somewhere else has not been rebuilt with a
// rogue `_ "net/http/pprof"`). The
// TestAdminEndpointIsolationStaticAnalyzerDetectsRegressions self-check
// feeds synthetic known-bad and known-good fixtures through every
// matcher so over- and under-tightening of the analyser are both caught.

// adminAPIMainPath is the relative path of the API entry binary. A
// future entry binary that bypasses these gates would be a regression
// worth catching at review time.
const adminAPIMainPath = "cmd/yalla-api/main.go"

// adminHTTPAPIServerPath is the relative path of the file that owns
// the `NewHandler` constructor and the private `http.NewServeMux()`
// call. Pinned by path so a future split or rename forces an explicit
// update of this test.
const adminHTTPAPIServerPath = "internal/controlplane/httpapi/server.go"

// adminHTTPAPIDir is the relative directory whose non-test `.go`
// files are scanned for forbidden imports and forbidden literals. The
// scan is bounded to production sources — `_test.go` fixtures are
// allowed to mention the forbidden surfaces (a future story may add a
// regression test that asserts `/debug/pprof` returns 404), so they
// are skipped.
const adminHTTPAPIDir = "internal/controlplane/httpapi"

// adminSecurityDocPath is the relative path of the operator-facing
// security posture document. The test pins both the dedicated section
// heading and the verification-gates table row so a silent doc
// deletion is caught alongside a silent code regression.
const adminSecurityDocPath = "SECURITY.md"

// adminHTTPServerTypeSelector is the `pkg.Name` form of the in-process
// HTTP server type whose composite literal MUST carry a non-nil
// `Handler` field. The matcher targets only this selector so unrelated
// struct literals in main.go (config, runtime metadata, …) are not
// scanned.
const adminHTTPServerTypeSelector = "http.Server"

// adminHandlerField is the `http.Server` field whose ABSENCE in the
// composite literal causes the server to fall back to
// `http.DefaultServeMux`. The matcher rejects a literal that omits
// it; defining `Handler` explicitly is the only way the binary can
// avoid serving anything a third-party import registered on the
// default mux.
const adminHandlerField = "Handler"

// adminNewServeMuxSelector is the call expression that constructs a
// private mux. `httpapi.NewHandler` MUST call this and bind the
// result to a local variable; using `http.DefaultServeMux` instead
// would re-introduce the default-mux exposure the API binary
// disclaims at construction time.
const adminNewServeMuxSelector = "http.NewServeMux"

// adminDefaultServeMuxIdentifier is the standard-library identifier
// the file MUST NOT reference anywhere. The package-qualified form
// `http.DefaultServeMux` is the only shape stdlib offers; the
// selector pass catches it regardless of receiver alias.
const adminDefaultServeMuxIdentifier = "DefaultServeMux"

// forbiddenAdminImports enumerates the Go package paths whose mere
// blank import attaches a debug surface to `http.DefaultServeMux`.
// The set is closed: a future trace/profiling import wants explicit
// review before it ships.
//
//   - `net/http/pprof` registers `/debug/pprof/*` (Index, Cmdline,
//     Profile, Symbol, Trace, plus per-profile handlers for
//     goroutine, heap, allocs, threadcreate, block, mutex, …).
//   - `expvar` registers `/debug/vars`. Any package can publish
//     a variable through `expvar.Publish`; the route serves them
//     all as JSON, including the default `cmdline` and `memstats`.
//   - `golang.org/x/net/trace` registers `/debug/requests` and
//     `/debug/events`. The package is not in the standard library
//     but is a frequent transitive of gRPC and similar stacks.
var forbiddenAdminImports = map[string]struct{}{
	"net/http/pprof":         {},
	"expvar":                 {},
	"golang.org/x/net/trace": {},
}

// forbiddenAdminSelectorPackages enumerates the package qualifiers
// whose USE in production sources signals a debug surface even if a
// future contributor managed to import them under a different name
// (`import foo "net/http/pprof"`). The matcher flags every
// SelectorExpr whose root identifier is in this set.
var forbiddenAdminSelectorPackages = map[string]struct{}{
	"pprof":  {},
	"expvar": {},
}

// forbiddenAdminLiterals enumerates the string substrings that have
// no legitimate place in `cmd/yalla-api` or
// `internal/controlplane/httpapi` production sources. A regression
// that registers `/debug/pprof` through a hand-rolled handler instead
// of the stdlib package would still leave the path literal in source
// and the file-wide pass would catch it. The list is curated to the
// concrete debug paths plus the default-mux identifier so unrelated
// uses of "debug" (e.g. log levels) are not affected.
var forbiddenAdminLiterals = []string{
	"/debug/pprof",
	"/debug/vars",
	"/debug/requests",
	"/debug/events",
	"http.DefaultServeMux",
}

// requiredAdminSecurityHeading is the literal Markdown heading that
// must appear in SECURITY.md to document this story's posture. The
// exact heading is part of the public contract — operators and
// downstream auditors deep-link to it — so changes are deliberate.
const requiredAdminSecurityHeading = "## Admin Endpoint Isolation"

// requiredAdminSecuritySubstrings is the closed set of literal
// substrings SECURITY.md MUST contain to satisfy the documentation
// half of the gate. Each captures a different load-bearing fact:
//   - the forbidden imports are named so an operator scanning the
//     dependency graph knows what is intentionally absent,
//   - `http.NewServeMux` so the private-mux contract is explicit,
//   - the `/debug/` prefix so an operator scanning the running
//     deployment for debug routes learns we ship none,
//   - the test file path itself so the gate is self-locating.
var requiredAdminSecuritySubstrings = []string{
	"net/http/pprof",
	"expvar",
	"http.NewServeMux",
	"/debug/",
	"admin_endpoint_isolation_static_test.go",
}

// requiredAdminGateRow is the literal substring of the row that MUST
// appear in SECURITY.md's Required Verification Gates table. The
// substring is the gate name plus the `-run` selector; a contributor
// who renames the test functions must update both.
const requiredAdminGateRow = "Admin endpoint isolation"

// TestAdminEndpointIsolationNoForbiddenImports proves that neither
// the API entry binary nor any production source file under
// `internal/controlplane/httpapi` imports a package whose blank
// import would side-effect-register a debug surface on
// `http.DefaultServeMux`. The scan covers every non-test `.go` file
// recursively under the httpapi directory plus the API main.go.
func TestAdminEndpointIsolationNoForbiddenImports(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	files := adminProductionFiles(t, root)
	fset := token.NewFileSet()
	for _, rel := range files {
		path := filepath.Join(root, rel)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		for _, v := range findForbiddenAdminImports(fset, file) {
			t.Error(v)
		}
	}
}

// TestAdminEndpointIsolationAPIHandlerNotDefault proves that the
// API binary's `http.Server` composite literal sets `Handler`
// explicitly. A nil `Handler` field falls back to
// `http.DefaultServeMux`, and any debug surface registered on the
// default mux by any imported package — directly or transitively —
// would leak through the API listener.
func TestAdminEndpointIsolationAPIHandlerNotDefault(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, adminAPIMainPath)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", adminAPIMainPath, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", adminAPIMainPath, err)
	}
	for _, v := range findAdminHandlerRegressions(fset, file) {
		t.Error(v)
	}
}

// TestAdminEndpointIsolationServerUsesPrivateMux proves that
// `httpapi.NewHandler` constructs its mux via `http.NewServeMux()`
// and never reaches for `http.DefaultServeMux`. The private-mux
// contract is what severs the API listener from any default-mux
// registrations made elsewhere in the binary.
func TestAdminEndpointIsolationServerUsesPrivateMux(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, adminHTTPAPIServerPath)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", adminHTTPAPIServerPath, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", adminHTTPAPIServerPath, err)
	}
	for _, v := range findAdminPrivateMuxRegressions(fset, file) {
		t.Error(v)
	}
}

// TestAdminEndpointIsolationNoDebugLiterals proves that no production
// source file under `cmd/yalla-api` or
// `internal/controlplane/httpapi` carries a `/debug/*` path literal,
// references a `pprof.*` selector, references an `expvar.*` selector,
// or references `http.DefaultServeMux`. The file-wide pass is
// belt-and-braces for the import scan: a regression that side-steps
// the import scan by registering routes through a vendored fork or a
// hand-rolled equivalent would still leave the path literal in
// source, and the selector pass catches a forbidden package even
// under a renamed import alias.
func TestAdminEndpointIsolationNoDebugLiterals(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	files := adminProductionFiles(t, root)
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
		for _, v := range findAdminDebugLiteralRegressions(fset, file) {
			t.Error(v)
		}
	}
}

// TestAdminEndpointIsolationSecurityDocumented proves that
// SECURITY.md documents the operator-facing admin-endpoint-isolation
// contract. The pinned heading and required substrings are part of
// the public security posture; a silent removal is a regression on
// equal footing with a code change.
func TestAdminEndpointIsolationSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, adminSecurityDocPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", adminSecurityDocPath, err)
	}
	doc := string(b)
	if !strings.Contains(doc, requiredAdminSecurityHeading) {
		t.Errorf("%s: missing required heading %q; "+
			"the public security posture for admin endpoint isolation must stay documented.",
			adminSecurityDocPath, requiredAdminSecurityHeading)
	}
	for _, want := range requiredAdminSecuritySubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; "+
				"the documented contract MUST name every load-bearing fact so operators and auditors do not have to read the test file.",
				adminSecurityDocPath, want, requiredAdminSecurityHeading)
		}
	}
	if !strings.Contains(doc, requiredAdminGateRow) {
		t.Errorf("%s: missing verification-gates table row containing %q; "+
			"every security-verification story must surface as a row operators and reviewers can see at a glance.",
			adminSecurityDocPath, requiredAdminGateRow)
	}
}

// TestAdminEndpointIsolationStaticAnalyzerDetectsRegressions is the
// self-check for the matchers above. The acceptance criterion "tests
// fail when the control is removed" is the load-bearing one: each
// known-bad synthetic snippet must produce hits, and the known-good
// snippet must produce zero hits. This guards against the analyser
// silently going lenient.
func TestAdminEndpointIsolationStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()
	t.Run("findForbiddenAdminImports", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical imports are accepted",
				source: `package httpapi
import (
	"net/http"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
)
func nothing() {}`,
				wantHits: 0,
			},
			{
				name: "blank import of net/http/pprof is rejected",
				source: `package main
import (
	"net/http"
	_ "net/http/pprof"
)
func main() { _ = http.ListenAndServe(":6060", nil) }`,
				wantHits: 1,
			},
			{
				name: "named import of net/http/pprof is also rejected",
				source: `package main
import (
	"net/http"
	pprof "net/http/pprof"
)
func main() { _ = pprof.Handler }`,
				wantHits: 1,
			},
			{
				name: "blank import of expvar is rejected",
				source: `package main
import (
	"net/http"
	_ "expvar"
)
func main() { _ = http.ListenAndServe(":6060", nil) }`,
				wantHits: 1,
			},
			{
				name: "blank import of golang.org/x/net/trace is rejected",
				source: `package main
import (
	"net/http"
	_ "golang.org/x/net/trace"
)
func main() { _ = http.ListenAndServe(":6060", nil) }`,
				wantHits: 1,
			},
			{
				name: "multiple forbidden imports are all reported",
				source: `package main
import (
	_ "expvar"
	_ "net/http/pprof"
	_ "golang.org/x/net/trace"
)
func main() {}`,
				wantHits: 3,
			},
		}
		for _, tc := range tcs {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ImportsOnly)
				if err != nil {
					t.Fatalf("parse synthetic source: %v", err)
				}
				got := findForbiddenAdminImports(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findForbiddenAdminImports: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findAdminHandlerRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "http.Server with explicit Handler is accepted",
				source: `package main
import "net/http"
func main() {
	srv := &http.Server{
		Addr:    ":8080",
		Handler: http.NewServeMux(),
	}
	_ = srv.ListenAndServe()
}`,
				wantHits: 0,
			},
			{
				name: "http.Server with omitted Handler is rejected (DefaultServeMux fallback)",
				source: `package main
import "net/http"
func main() {
	srv := &http.Server{Addr: ":8080"}
	_ = srv.ListenAndServe()
}`,
				wantHits: 1,
			},
			{
				name: "http.Server with explicit nil Handler is rejected",
				source: `package main
import "net/http"
func main() {
	srv := &http.Server{
		Addr:    ":8080",
		Handler: nil,
	}
	_ = srv.ListenAndServe()
}`,
				wantHits: 1,
			},
			{
				name: "unrelated struct literals are not scanned",
				source: `package main
import "net/http"
type cfg struct{ Addr string }
func main() {
	_ = cfg{Addr: ":8080"}
	srv := &http.Server{Addr: ":8080", Handler: http.NewServeMux()}
	_ = srv
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
				got := findAdminHandlerRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findAdminHandlerRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findAdminPrivateMuxRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical NewHandler builds a private mux",
				source: `package httpapi
import "net/http"
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	return mux
}`,
				wantHits: 0,
			},
			{
				name: "NewHandler that omits http.NewServeMux is rejected",
				source: `package httpapi
import "net/http"
func NewHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
}`,
				wantHits: 1,
			},
			{
				name: "any reference to http.DefaultServeMux is rejected",
				source: `package httpapi
import "net/http"
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	http.DefaultServeMux.Handle("/leaked", mux)
	return mux
}`,
				wantHits: 1,
			},
			{
				name: "returning http.DefaultServeMux instead of a private mux is doubly rejected",
				source: `package httpapi
import "net/http"
func NewHandler() http.Handler {
	return http.DefaultServeMux
}`,
				// no http.NewServeMux call (1) + DefaultServeMux reference (1)
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
				got := findAdminPrivateMuxRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findAdminPrivateMuxRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findAdminDebugLiteralRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical production source is accepted",
				source: `package httpapi
import "net/http"
func register(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/v1/services", func(w http.ResponseWriter, r *http.Request) {})
}`,
				wantHits: 0,
			},
			{
				name: "/debug/pprof literal is rejected",
				source: `package httpapi
import "net/http"
func register(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", func(w http.ResponseWriter, r *http.Request) {})
}`,
				wantHits: 1,
			},
			{
				name: "/debug/vars literal is rejected",
				source: `package httpapi
import "net/http"
func register(mux *http.ServeMux) {
	mux.HandleFunc("/debug/vars", func(w http.ResponseWriter, r *http.Request) {})
}`,
				wantHits: 1,
			},
			{
				name: "pprof selector is rejected even without an import",
				source: `package httpapi
import (
	"net/http"
	rogue "net/http/pprof"
)
func register(mux *http.ServeMux) {
	mux.HandleFunc("/profiles", rogue.Index)
	_ = pprof.Index
}`,
				// /debug/* not present (0) + rogue.Index is not flagged because root is `rogue`
				// + pprof.Index selector hit (1) - undeclared `pprof` ident, parser still produces selector.
				wantHits: 1,
			},
			{
				name: "expvar selector is rejected",
				source: `package httpapi
import "net/http"
func register(mux *http.ServeMux) {
	_ = mux
	_ = expvar.Handler
}`,
				wantHits: 1,
			},
			{
				name: "DefaultServeMux literal in a string is also rejected",
				source: `package httpapi
import "net/http"
func note() string {
	_ = http.NewServeMux()
	return "http.DefaultServeMux is forbidden but the literal mention is too"
}`,
				wantHits: 1,
			},
			{
				name: "multiple debug regressions are all reported",
				source: `package httpapi
import "net/http"
func register(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/vars", expvar.Handler)
}`,
				// /debug/pprof literal (1) + /debug/vars literal (1) +
				// pprof.Index selector (1) + expvar.Handler selector (1)
				wantHits: 4,
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
				got := findAdminDebugLiteralRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findAdminDebugLiteralRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})
}

// findForbiddenAdminImports walks the AST of a production Go file
// and returns one diagnostic per forbidden import path. Both blank
// imports (`_ "net/http/pprof"`) and named imports
// (`pprof "net/http/pprof"`) match — the import side-effect fires
// regardless of the local alias.
func findForbiddenAdminImports(fset *token.FileSet, file *ast.File) []string {
	var out []string
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if _, bad := forbiddenAdminImports[path]; bad {
			out = append(out,
				"forbidden admin-surface import "+strconv.Quote(path)+" at "+fset.Position(imp.Pos()).String()+
					". The Yalla control-plane API binary does NOT expose any /debug/* surface; importing this package side-effect-registers debug routes on http.DefaultServeMux and a regression that re-introduces it is rejected at build time. "+
					"See internal/release/admin_endpoint_isolation_static_test.go (BE-0357) and SECURITY.md \"Admin Endpoint Isolation\" for the threat model.")
		}
	}
	sort.Strings(out)
	return out
}

// findAdminHandlerRegressions walks the AST of cmd/yalla-api/main.go
// and rejects any `http.Server` composite literal that does not set
// `Handler` to a non-nil value. The matcher uses the package-qualified
// type selector `http.Server`, so unrelated structs in main.go are
// not scanned. An explicit `Handler: nil` is treated as a regression
// because it is functionally equivalent to omitting the field — both
// fall back to `http.DefaultServeMux`.
func findAdminHandlerRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, kind, detail string) {
		out = append(out, kind+" "+detail+" at "+pos.String()+
			". The Yalla API binary's http.Server MUST set Handler explicitly to a private handler — a nil Handler falls back to http.DefaultServeMux, which would leak any /debug/* route a transitive import registered. "+
			"See internal/release/admin_endpoint_isolation_static_test.go (BE-0357) and SECURITY.md \"Admin Endpoint Isolation\" for the threat model.")
	}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || !isAdminHTTPServerCompositeLit(lit) {
			return true
		}
		litPos := fset.Position(lit.Pos())
		var handler ast.Expr
		seen := false
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			if key.Name == adminHandlerField {
				seen = true
				handler = kv.Value
				break
			}
		}
		if !seen {
			emit(litPos, "http.Server literal omits required field", adminHandlerField)
			return true
		}
		if ident, ok := handler.(*ast.Ident); ok && ident.Name == "nil" {
			emit(fset.Position(handler.Pos()), "http.Server literal sets Handler to", "nil (falls back to http.DefaultServeMux)")
		}
		return true
	})
	sort.Strings(out)
	return out
}

// findAdminPrivateMuxRegressions walks the AST of
// internal/controlplane/httpapi/server.go and reports two orthogonal
// regressions:
//
//  1. The file does not contain a call to `http.NewServeMux()`. The
//     gate cannot prove the handler builds a private mux if no such
//     call appears in source.
//  2. The file references `http.DefaultServeMux` anywhere — a
//     selector call, a passed argument, or a string mention. The
//     default mux must not appear in the customer-facing handler.
func findAdminPrivateMuxRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, kind, detail string) {
		out = append(out, kind+" "+detail+" at "+pos.String()+
			". The Yalla control-plane handler MUST construct a private http.NewServeMux() and MUST NOT reference http.DefaultServeMux; the private mux severs the API listener from any default-mux registrations made elsewhere in the binary. "+
			"See internal/release/admin_endpoint_isolation_static_test.go (BE-0357) and SECURITY.md \"Admin Endpoint Isolation\" for the threat model.")
	}
	seenNewServeMux := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok {
					if pkg.Name+"."+sel.Sel.Name == adminNewServeMuxSelector {
						seenNewServeMux = true
					}
				}
			}
		case *ast.SelectorExpr:
			if node.Sel != nil && node.Sel.Name == adminDefaultServeMuxIdentifier {
				emit(fset.Position(node.Pos()), "forbidden reference to", "http."+adminDefaultServeMuxIdentifier)
			}
		}
		return true
	})
	if !seenNewServeMux {
		emit(fset.Position(file.Pos()), "missing required call to", adminNewServeMuxSelector+"()")
	}
	sort.Strings(out)
	return out
}

// findAdminDebugLiteralRegressions walks the AST of a production Go
// file and reports two orthogonal regressions:
//
//  1. Any string literal whose value contains a member of
//     `forbiddenAdminLiterals`. The match is case-sensitive: the
//     stdlib path literals are case-sensitive at the HTTP layer, so
//     a regression that registers them under unusual casing would
//     not match the real route, but we still flag exact-case hits.
//  2. Any SelectorExpr whose root identifier is in
//     `forbiddenAdminSelectorPackages`. This catches `pprof.Index`
//     and `expvar.Handler` even when the import has been renamed
//     (`import foo "net/http/pprof"; foo.Index` would NOT match —
//     that variant is the rare false-negative — but the unaliased
//     form is what virtually every example online uses, so the
//     scan still adds value).
func findAdminDebugLiteralRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, kind, detail string) {
		out = append(out, kind+" "+detail+" at "+pos.String()+
			". The Yalla control-plane API and HTTP layer do NOT expose any /debug/* surface, do NOT reference pprof or expvar, and do NOT touch http.DefaultServeMux. "+
			"See internal/release/admin_endpoint_isolation_static_test.go (BE-0357) and SECURITY.md \"Admin Endpoint Isolation\" for the threat model.")
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(node.Value)
			if err != nil {
				return true
			}
			for _, forbidden := range forbiddenAdminLiterals {
				if strings.Contains(value, forbidden) {
					emit(fset.Position(node.Pos()), "forbidden debug-surface literal", strconv.Quote(forbidden))
					break
				}
			}
		case *ast.SelectorExpr:
			pkg, ok := node.X.(*ast.Ident)
			if !ok {
				return true
			}
			if _, bad := forbiddenAdminSelectorPackages[pkg.Name]; bad {
				emit(fset.Position(node.Pos()), "forbidden selector",
					pkg.Name+"."+selectorName(node))
			}
		}
		return true
	})
	sort.Strings(out)
	return out
}

// selectorName extracts the trailing identifier from a SelectorExpr
// for diagnostic messages, defaulting to the empty string when the
// Sel field is nil (which should not occur for parsed source but
// keeps the matcher panic-free under fuzzed input).
func selectorName(sel *ast.SelectorExpr) string {
	if sel == nil || sel.Sel == nil {
		return ""
	}
	return sel.Sel.Name
}

// isAdminHTTPServerCompositeLit reports whether a composite literal's
// declared type names `http.Server` (a `&http.Server{...}` is parsed
// as a UnaryExpr wrapping a CompositeLit; this helper inspects only
// the inner literal's Type, so the matcher does not need to special-
// case the address-of). The check is structural — package selector
// `http` + selector name `Server` — to avoid false positives on
// unrelated structs in the same file.
func isAdminHTTPServerCompositeLit(node *ast.CompositeLit) bool {
	sel, ok := node.Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name+"."+sel.Sel.Name == adminHTTPServerTypeSelector
}

// adminProductionFiles returns the relative paths of every
// production (non-test) `.go` file the admin-endpoint-isolation gate
// scans: cmd/yalla-api/main.go plus every `.go` file under
// internal/controlplane/httpapi that does NOT end in `_test.go`.
// The list is sorted so failures are deterministic.
func adminProductionFiles(t *testing.T, root string) []string {
	t.Helper()
	files := []string{adminAPIMainPath}
	httpapiAbs := filepath.Join(root, adminHTTPAPIDir)
	entries, err := os.ReadDir(httpapiAbs)
	if err != nil {
		t.Fatalf("read dir %s: %v", adminHTTPAPIDir, err)
	}
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
		files = append(files, filepath.Join(adminHTTPAPIDir, name))
	}
	sort.Strings(files)
	return files
}
