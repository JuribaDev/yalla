package httpapi

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// CORS policy — static-analysis defense (BE-0347).
//
// Threat model: the Yalla control-plane API is consumed by non-browser
// callers (CLI, agents, CI) authenticated by Bearer tokens or session
// cookies. A browser script loaded from an attacker-controlled origin
// must NOT be able to read API responses or perform credentialed
// cross-origin requests against the API — the same-origin policy is the
// load-bearing browser-side defense. The control is therefore "no
// production code path in the httpapi package emits any
// `Access-Control-*` response header, under any request shape, on any
// route." A response with no `Access-Control-Allow-Origin` header makes
// the browser refuse to read the body for any cross-origin call; a
// response with no `Access-Control-Allow-Origin` AND no
// `Access-Control-Allow-Methods`/`-Headers` makes the browser refuse the
// preflight, so the unsafe request never reaches the server at all.
// Yalla intentionally has no allowlisted browser origin today: the few
// admin tools that need browser access live on the same origin behind
// the same auth surface, and a future browser allowlist will be wired
// through one explicit middleware seam — never per-handler.
//
// These tests are the regression backstop. They run without a database
// and fail at build time for any change that introduces a CORS response
// header into the package — a misconfigured proxy header passthrough, a
// well-meaning "browser-friendly" middleware, or a per-handler approval
// shortcut. The companion runtime test, `cors_test.go`, exercises the
// same invariant end-to-end through `NewHandler` against a production
// route set and an attacker-style preflight request.

// TestCORSHeadersAreNotEmittedByProductionCode walks every non-test .go
// file in the httpapi package and rejects any string literal whose value
// names a CORS response or request header — every IANA-registered CORS
// header (and the broader `Access-Control-*` family) starts with the
// case-insensitive `Access-Control-` prefix, so a prefix match is both
// necessary and sufficient to catch the entire surface. Test fixtures
// containing these literals live in `_test.go` files and are filtered
// out before the scan; only production code is checked, so the analyzer
// stays silent on the self-check fixtures below.
func TestCORSHeadersAreNotEmittedByProductionCode(t *testing.T) {
	t.Parallel()
	for _, path := range nonTestHTTPAPISourceFiles(t) {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			fset, file := mustParseHTTPAPIFile(t, path)
			for _, v := range findCORSHeaderLiterals(fset, file) {
				t.Error(v)
			}
		})
	}
}

// TestCORSStaticAnalyzerDetectsRegressions is the self-check for the
// static analyzer above. The acceptance criterion "tests fail when the
// control is removed" is the load-bearing one for this story: a future
// change that adds `w.Header().Set("Access-Control-Allow-Origin", ...)`
// to a handler or middleware must visibly fail a test. Here we
// synthesise a handful of known-bad source snippets — each of the seven
// IANA `Access-Control-*` headers used as a `Set` key, a header assigned
// via `Header()[name] = ...`, and a constant declaration that names the
// header — and assert the analyzer reports each one. The known-good
// snippets confirm the analyzer does not flag innocuous occurrences:
// `Content-Type`, `Authorization`, a comment that mentions CORS in
// prose, and an `Origin` request-side header read (the request-side
// `Origin` header is reflected, not emitted, so it does not weaken the
// browser defense — but the analyzer still must not fire on it because
// reading is allowed). If the analyzer is ever weakened, the regression
// detector itself fails to fail and this test catches it.
//
// We parse from a string rather than from disk so the bad code never
// lives in the package as a real source file (which would itself fail
// the production scan above).
func TestCORSStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		source   string
		wantHits int
	}{
		{
			name: "Access-Control-Allow-Origin as a Header().Set key is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}`,
			wantHits: 1,
		},
		{
			name: "Access-Control-Allow-Methods as a Header().Set key is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
}`,
			wantHits: 1,
		},
		{
			name: "Access-Control-Allow-Headers as a Header().Set key is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Headers", "Authorization")
}`,
			wantHits: 1,
		},
		{
			name: "Access-Control-Allow-Credentials as a Header().Set key is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}`,
			wantHits: 1,
		},
		{
			name: "Access-Control-Expose-Headers as a Header().Set key is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Expose-Headers", "X-Request-Id")
}`,
			wantHits: 1,
		},
		{
			name: "Access-Control-Max-Age as a Header().Set key is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Max-Age", "600")
}`,
			wantHits: 1,
		},
		{
			name: "Access-Control-Request-Method (request-side) literal is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Access-Control-Request-Method") != "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
}`,
			wantHits: 2,
		},
		{
			name: "lower-case access-control-allow-origin is rejected (case-insensitive)",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("access-control-allow-origin", "*")
}`,
			wantHits: 1,
		},
		{
			name: "Header()[key] = ... map assignment with a CORS literal is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header()["Access-Control-Allow-Origin"] = []string{"https://app.example"}
}`,
			wantHits: 1,
		},
		{
			name: "a const declaration that names a CORS header is rejected",
			source: `package badhandler
const corsAllowOrigin = "Access-Control-Allow-Origin"`,
			wantHits: 1,
		},
		{
			name: "Header().Add is also rejected (Add is structurally the same surface as Set)",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
}`,
			wantHits: 1,
		},
		{
			name: "Content-Type as a Header().Set key is allowed (not CORS)",
			source: `package goodhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
}`,
			wantHits: 0,
		},
		{
			name: "Authorization request-header read is allowed (not CORS)",
			source: `package goodhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	_ = r.Header.Get("Authorization")
}`,
			wantHits: 0,
		},
		{
			name: "Origin request-header read is allowed (request-side, not CORS-Approval)",
			source: `package goodhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	_ = r.Header.Get("Origin")
}`,
			wantHits: 0,
		},
		{
			name: "a comment that mentions CORS in prose is allowed",
			source: `package goodhandler
// This package deliberately does NOT emit Access-Control-* headers.
// See AGENTS.md "CORS stance".
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
}`,
			wantHits: 0,
		},
		{
			name: "ETag as a Header().Set key is allowed (not CORS)",
			source: `package goodhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("ETag", "\"1\"")
}`,
			wantHits: 0,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
			if err != nil {
				t.Fatalf("parse synthetic source: %v", err)
			}
			got := findCORSHeaderLiterals(fset, file)
			if len(got) != tc.wantHits {
				t.Errorf("findCORSHeaderLiterals: got %d hits, want %d. Hits:\n  %s",
					len(got), tc.wantHits, strings.Join(got, "\n  "))
			}
		})
	}
}

// corsHeaderLiteralPrefix is the case-insensitive prefix that names every
// IANA-registered CORS request and response header. The Fetch standard
// defines exactly seven such headers, all sharing this prefix:
//
//	Access-Control-Allow-Credentials
//	Access-Control-Allow-Headers
//	Access-Control-Allow-Methods
//	Access-Control-Allow-Origin
//	Access-Control-Expose-Headers
//	Access-Control-Max-Age
//	Access-Control-Request-Headers
//	Access-Control-Request-Method
//
// A prefix match catches the entire surface — including any future
// vendor extension under the same namespace — with one rule. The
// `Origin` request header is deliberately NOT part of this set: it is
// read-side (a browser reflects the calling page's origin into it on
// every cross-origin request) and reading it does not weaken the
// browser-side defense. Emitting an `Origin` header in a response
// would be unusual but is not a CORS-policy regression — see
// `AGENTS.md` "CORS stance" for the full rationale.
const corsHeaderLiteralPrefix = "access-control-"

// findCORSHeaderLiterals walks file's AST and returns one diagnostic per
// string literal whose unquoted value starts (case-insensitive) with
// `Access-Control-`. The analyzer is intentionally structural: it does
// not try to classify literals by syntactic role (header key vs.
// arbitrary string) because every appearance of a CORS header name in a
// production source file is a regression — there is no legitimate
// production use of these literals in this package. A test file that
// asserts the absence of these headers does need to name them, which
// is why this analyzer is scoped to non-test files by its caller.
//
// An empty return means the file is clean. Diagnostics are sorted so the
// output is deterministic across parallel parses.
func findCORSHeaderLiterals(fset *token.FileSet, file *ast.File) []string {
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if !strings.HasPrefix(strings.ToLower(value), corsHeaderLiteralPrefix) {
			return true
		}
		position := fset.Position(lit.Pos())
		out = append(out, fmt.Sprintf(
			"%s:%d: CORS header literal %q is forbidden in production code. "+
				"The Yalla control-plane API is a non-browser surface and "+
				"deliberately does NOT emit Access-Control-* headers. See "+
				"AGENTS.md \"CORS stance\" for the threat model. If a future "+
				"browser surface is required, wire ONE explicit middleware "+
				"seam, never a per-handler approval.",
			position.Filename, position.Line, value))
		return true
	})
	sort.Strings(out)
	return out
}
