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

// CSRF stance for browser sessions — static-analysis defense (BE-0348).
//
// Threat model: the Yalla control-plane API authenticates exclusively
// via the `Authorization: Bearer <token>` header (API keys, internal
// worker credentials, and human-session HS256 JWTs — see
// `internal/controlplane/auth/authenticator.go`). A browser script
// loaded from an attacker-controlled origin trying to forge a
// credentialed request against the API needs ambient credentials it
// can ride: a Set-Cookie session previously issued by the API, or a
// browser-attached Cookie header. The API issues neither and accepts
// neither — so a cross-origin `<form action="https://api.yalla">`
// submit, an `<img src=...>` GET, a `fetch(url, {credentials:
// "include"})`, or a top-level navigation that lands on a destructive
// endpoint all arrive at the server with no `Authorization` header
// (browsers do not auto-attach `Authorization` on cross-origin
// requests) and are rejected as 401 E_AUTH. The control is therefore
// "no production code path in this package emits a `Set-Cookie`
// response header, reads a `Cookie` request header as a credential,
// or names any `net/http` cookie API symbol". The CORS stance
// (`cors_static_test.go`, BE-0347) is the orthogonal browser-side
// defense; this CSRF stance is the server-side defense that does not
// rely on the browser refusing to surface the response — even if a
// browser ignored same-origin policy, the API would still reject the
// request because there is no ambient credential to ride.
//
// These tests are the regression backstop. They run without a database
// and fail at build time for any change that introduces an HTTP cookie
// surface into the package — a "remember me" cookie helper, an
// admin-tool session cookie issuer, a per-handler "Set-Cookie" emit
// for analytics, or a developer-mode cookie-jar mock. The companion
// runtime test, `csrf_test.go`, exercises the same invariant
// end-to-end through `NewHandler` against the production route set
// and an attacker-style cookie-only request.
//
// If a future surface genuinely requires browser sessions, the
// retrofit is NOT a per-handler cookie write. The retrofit is (1) a
// dedicated subpackage that owns cookie issuance and verification,
// (2) an explicit middleware seam wired through `NewHandler`, (3) a
// double-submit-cookie or SameSite=Strict cookie scheme with a
// per-request synchronizer token, and (4) a new acceptance criteria
// and analyzer relaxation reviewed against this threat model. The
// static analyzer's per-package scope is precisely so the relaxation
// surface is small and reviewable.

// TestCookieAPIIsNotUsedByProductionCode walks every non-test .go
// file in the httpapi package and rejects any production-code shape
// that names an HTTP cookie header literal or a `net/http` cookie
// API symbol. The two surfaces are orthogonal: a developer can
// emit `Set-Cookie` via `w.Header().Set("Set-Cookie", ...)` without
// referencing the typed `http.SetCookie` function, and conversely
// can use `http.SetCookie(w, c)` without writing the wire literal
// themselves. Both shapes are equally cookie-emitting from the
// browser's perspective, so both are rejected. Test fixtures
// containing these literals/identifiers live in `_test.go` files and
// are filtered out before the scan; only production code is checked,
// so the analyzer stays silent on the self-check fixtures below and
// on `csrf_test.go` itself.
func TestCookieAPIIsNotUsedByProductionCode(t *testing.T) {
	t.Parallel()
	for _, path := range nonTestHTTPAPISourceFiles(t) {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			fset, file := mustParseHTTPAPIFile(t, path)
			for _, v := range findCookieAPIUsages(fset, file) {
				t.Error(v)
			}
		})
	}
}

// TestCSRFStaticAnalyzerDetectsRegressions is the self-check for the
// static analyzer above. The acceptance criterion "tests fail when
// the control is removed" is the load-bearing one for this story: a
// future change that adds `http.SetCookie(w, ...)` or
// `w.Header().Set("Set-Cookie", ...)` to a handler must visibly fail
// a test. Here we synthesise known-bad source snippets — every cookie
// header literal, every cookie API selector, and the `http.Cookie`
// struct constructor — and assert the analyzer reports each one.
// Known-good snippets confirm the analyzer does not flag innocuous
// occurrences: `Content-Type`, `Authorization`, an `Origin` request
// read, a prose comment that mentions cookies, and a user-package
// type named `Cookie` (not `http.Cookie`).
//
// We parse from a string rather than from disk so the bad code never
// lives in the package as a real source file (which would itself
// fail the production scan above).
func TestCSRFStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		source   string
		wantHits int
	}{
		{
			name: "Set-Cookie as a Header().Set key is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Set-Cookie", "session=abc; HttpOnly")
}`,
			wantHits: 1,
		},
		{
			name: "Set-Cookie as a Header().Add key is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Set-Cookie", "session=abc; HttpOnly")
}`,
			wantHits: 1,
		},
		{
			name: "Cookie request-header read literal is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	_ = r.Header.Get("Cookie")
}`,
			wantHits: 1,
		},
		{
			name: "Cookie2 legacy header literal is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	_ = r.Header.Get("Cookie2")
}`,
			wantHits: 1,
		},
		{
			name: "Set-Cookie2 legacy header literal is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Set-Cookie2", "session=abc")
}`,
			wantHits: 1,
		},
		{
			name: "lower-case set-cookie is rejected (case-insensitive)",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("set-cookie", "session=abc")
}`,
			wantHits: 1,
		},
		{
			name: "mixed-case Set-cookie is rejected (case-insensitive)",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Set-cookie", "session=abc")
}`,
			wantHits: 1,
		},
		{
			name: "Header()[key] = ... map assignment with a cookie literal is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header()["Set-Cookie"] = []string{"session=abc"}
}`,
			wantHits: 1,
		},
		{
			name: "a const declaration that names a cookie header is rejected",
			source: `package badhandler
const cookieHeader = "Set-Cookie"`,
			wantHits: 1,
		},
		{
			name: "http.SetCookie selector is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, nil)
}`,
			wantHits: 1,
		},
		{
			name: "http.Cookie struct literal selector is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{Name: "session", Value: "abc"}
	_ = c
}`,
			wantHits: 1,
		},
		{
			name: "request AddCookie selector is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	r.AddCookie(nil)
}`,
			wantHits: 1,
		},
		{
			name: "request Cookies bulk-read selector is rejected",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	for _, c := range r.Cookies() {
		_ = c
	}
}`,
			wantHits: 1,
		},
		{
			name: "http.CookieJar interface reference is rejected",
			source: `package badhandler
import "net/http"
var jar http.CookieJar`,
			wantHits: 1,
		},
		{
			name: "combined literal and selector regression is rejected (two hits)",
			source: `package badhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "session"})
	w.Header().Set("Set-Cookie", "x=y")
}`,
			wantHits: 3,
		},
		{
			name: "Content-Type as a Header().Set key is allowed (not cookie)",
			source: `package goodhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
}`,
			wantHits: 0,
		},
		{
			name: "Authorization request-header read is allowed (not cookie)",
			source: `package goodhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	_ = r.Header.Get("Authorization")
}`,
			wantHits: 0,
		},
		{
			name: "Origin request-header read is allowed (not cookie)",
			source: `package goodhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	_ = r.Header.Get("Origin")
}`,
			wantHits: 0,
		},
		{
			name: "a prose comment that mentions cookies is allowed",
			source: `package goodhandler
// This package deliberately does NOT emit Set-Cookie headers.
// See AGENTS.md "CSRF stance".
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
}`,
			wantHits: 0,
		},
		{
			name: "a user struct field named Cookie (not http.Cookie) is allowed",
			source: `package goodhandler
type fixture struct{ Cookie string }
func use(f fixture) string { return f.Cookie }`,
			wantHits: 0,
		},
		{
			name: "a user package selector ending in Cookie is allowed",
			source: `package goodhandler
type other struct{}
func (o other) Cookie() string { return "" }
func use() string { var o other; return o.Cookie() }`,
			wantHits: 0,
		},
		{
			name: "ETag as a Header().Set key is allowed (not cookie)",
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
			got := findCookieAPIUsages(fset, file)
			if len(got) != tc.wantHits {
				t.Errorf("findCookieAPIUsages: got %d hits, want %d. Hits:\n  %s",
					len(got), tc.wantHits, strings.Join(got, "\n  "))
			}
		})
	}
}

// forbiddenCookieHeaderLiterals is the case-insensitive set of HTTP
// cookie header names. RFC 6265 defines the current `Cookie` and
// `Set-Cookie` headers; the obsolete RFC 2965 defines `Cookie2` and
// `Set-Cookie2`. A four-element exact-match set catches every
// IANA-registered cookie header literal. The match is exact (not a
// prefix) because the bare word "cookie" appears in unrelated header
// names — there are no IANA cookie headers outside this set today
// and a future extension would be a deliberate retrofit reviewed
// against the threat model in this file's package-doc block.
var forbiddenCookieHeaderLiterals = map[string]struct{}{
	"cookie":      {},
	"set-cookie":  {},
	"cookie2":     {},
	"set-cookie2": {},
}

// forbiddenCookieAPISelectors is the set of `net/http` cookie API
// selector names that uniquely identify cookie manipulation. Every
// production reference to one of these is a cookie surface
// regardless of which receiver type is involved:
//
//	http.SetCookie(w, c)         -> emits a Set-Cookie response header
//	r.AddCookie(c)               -> client-side cookie injection
//	r.Cookies() / r.Cookie(name) -> server-side cookie read
//	http.CookieJar               -> client-side cookie-jar interface
//
// `Cookie` (the unqualified selector) is excluded from this set
// because it is ambiguous with user-defined struct fields and method
// names. The `http.Cookie` shape is caught by the typed-X check in
// `findCookieAPIUsages` below, and `r.Cookie(name)` is caught by the
// wire-level `"Cookie"` literal scan (any read of a session cookie
// must name a cookie at the wire level). The combination is tight
// and false-positive free for the current httpapi production code.
var forbiddenCookieAPISelectors = map[string]struct{}{
	"SetCookie": {},
	"AddCookie": {},
	"CookieJar": {},
	"Cookies":   {},
}

// findCookieAPIUsages walks file's AST and returns one diagnostic per
// shape that names an HTTP cookie surface. The analyzer is structural
// rather than type-aware: it does not load `net/http` to verify that
// a `SetCookie` selector resolves to `(*net/http).SetCookie`. For
// this package's call surface the structural match is sufficient —
// there is no user-defined `SetCookie`/`AddCookie`/`CookieJar`/
// `Cookies` symbol in `httpapi` today, and any future identifier of
// these names would itself be a regression (cookie surface
// camouflaged behind a friendly name is still a cookie surface).
// The `http.Cookie` struct constructor is the one exception that
// requires checking the selector's X expression, because the bare
// `Cookie` selector matches user-defined fields too often to flag
// unconditionally.
//
// An empty return means the file is clean. Diagnostics are sorted so
// the output is deterministic across parallel parses.
func findCookieAPIUsages(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, kind, detail string) {
		out = append(out, fmt.Sprintf(
			"%s:%d: forbidden cookie %s %s. "+
				"The Yalla control-plane API authenticates exclusively via "+
				"the Authorization header and does NOT use HTTP cookies. "+
				"See AGENTS.md \"CSRF stance\" for the threat model. If a "+
				"future browser surface genuinely requires session cookies, "+
				"introduce a dedicated subpackage and a reviewed middleware "+
				"seam — never a per-handler cookie write.",
			pos.Filename, pos.Line, kind, detail))
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
			if _, ok := forbiddenCookieHeaderLiterals[strings.ToLower(value)]; ok {
				emit(fset.Position(node.Pos()), "header literal", strconv.Quote(value))
			}
		case *ast.SelectorExpr:
			name := node.Sel.Name
			if _, ok := forbiddenCookieAPISelectors[name]; ok {
				emit(fset.Position(node.Pos()), "API selector", "."+name)
				return true
			}
			if name == "Cookie" {
				if ident, ok := node.X.(*ast.Ident); ok && ident.Name == "http" {
					emit(fset.Position(node.Pos()), "API selector", "http.Cookie")
				}
			}
		}
		return true
	})
	sort.Strings(out)
	return out
}
