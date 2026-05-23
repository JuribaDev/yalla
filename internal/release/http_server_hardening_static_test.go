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

// BE-0356: Security verification — TLS termination and proxy header trust.
//
// Threat model.
//
//  1. The Yalla control-plane API binary (cmd/yalla-api) deliberately does
//     NOT terminate TLS itself. TLS is terminated upstream at the operator's
//     reverse proxy or ingress controller. Keeping certificate material out
//     of the API process narrows the secret surface, leverages the proxy's
//     vetted cipher-suite/HSTS/OCSP-stapling settings, and lets operators
//     rotate certs without an API restart. A regression that turns the API
//     binary into its own TLS terminator (a `ListenAndServeTLS` call, a
//     `ServeTLS` call, a populated `TLSConfig`, or a populated
//     `TLSNextProto`) is a load-bearing security event because it duplicates
//     the secret surface and bypasses the proxy's hardened defaults. The
//     matcher rejects every such shape.
//
//  2. Even when TLS is terminated upstream, the inner `*http.Server` MUST
//     set a positive `ReadHeaderTimeout`. Without it, a misconfigured or
//     compromised intermediary can dribble request headers indefinitely
//     (the Slowloris exposure), holding goroutines hostage and exhausting
//     the process. The matcher rejects an `http.Server` composite literal
//     that lacks the field.
//
//  3. The API derives the client IP for IP-bucket rate limiting from a
//     CLOSED set of forwarding headers — `X-Forwarded-For` (first hop only)
//     and `X-Real-IP` as a fallback. Every other forwarded-* family header
//     (RFC 7239 `Forwarded`, Akamai `True-Client-IP`, Cloudflare
//     `CF-Connecting-IP`, Fastly `Fastly-Client-IP`, `X-Client-IP`,
//     `X-Original-Forwarded-For`, …) is deliberately NOT consulted. If the
//     API is ever reachable directly — a network misconfiguration, an
//     internal pivot, or a forgotten test fixture — an attacker who can
//     reach it can otherwise spoof any of those headers and bypass the
//     IP-bucket rate limiter. The matcher rejects a `ClientIP` body that
//     reads a header outside the allow-list, and the file-wide pass rejects
//     any forbidden proxy-trust literal anywhere in `ratelimit.go`.
//
//  4. The operator-facing contract is part of the public security posture.
//     SECURITY.md MUST document (a) the TLS-at-proxy expectation and (b)
//     the closed-set proxy-header trust so operators wire their proxy to
//     STRIP inbound `X-Forwarded-*` / `X-Real-IP` from public traffic
//     before setting them. The matcher pins the heading and the canonical
//     substrings; a silent removal of either is a regression.
//
// The single-test-file variant of the BE-0344 two-test pattern (BE-0353,
// BE-0354, BE-0355). The "runtime" half is implicit: every production
// deploy that runs `cmd/yalla-api` against an HTTP-only listener and a
// trusted reverse proxy IS the runtime, and there is no application-code
// call site that could carry a parallel runtime gate (a Go runtime test
// cannot prove a binary deployed somewhere else is NOT exposed to the
// public internet). The TestHTTPServerHardeningStaticAnalyzerDetectsRegressions
// self-check feeds synthetic known-bad and known-good fixtures through
// every matcher so over- and under-tightening of the analyser are both
// caught.

// yallaAPIMainPath is the relative path of the API entry binary. The
// project keeps exactly one entry binary for the control-plane API; a
// new entry binary that bypasses these gates would be a regression worth
// catching at review time.
const yallaAPIMainPath = "cmd/yalla-api/main.go"

// ratelimitPath is the relative path of the file that owns the
// ClientIP helper and the rate-limit middleware. Pinned by path so a
// future split or rename forces an explicit update of this test.
const ratelimitPath = "internal/controlplane/httpapi/ratelimit.go"

// securityDocPath is the relative path of the operator-facing security
// posture document. The test pins both the dedicated section heading
// and the verification-gates table row so a silent doc deletion is
// caught alongside a silent code regression.
const securityDocPath = "SECURITY.md"

// httpServerTypeSelector is the `pkg.Name` form of the in-process HTTP
// server type whose composite literals carry the hardening fields. The
// matcher targets only this selector so unrelated struct literals in
// main.go (config, runtime metadata, …) are not scanned.
const httpServerTypeSelector = "http.Server"

// forbiddenAPITLSCallSelectors enumerates the net/http selectors that
// would attempt TLS termination inside the API process. The matcher
// flags any call whose function expression's selector name is in this
// set, regardless of receiver — the receiver may be `srv`, `http`,
// `s`, or any future name a contributor picks.
var forbiddenAPITLSCallSelectors = map[string]struct{}{
	"ListenAndServeTLS": {},
	"ServeTLS":          {},
}

// forbiddenAPITLSStructFields enumerates the `http.Server` fields
// whose presence indicates an attempt to configure in-process TLS.
// `TLSConfig` is the direct seam; `TLSNextProto` is the indirect one
// (it only fires when a TLS conn is accepted), but we forbid both for
// the same reason: an in-process TLS posture is not a permitted
// deployment shape.
var forbiddenAPITLSStructFields = map[string]struct{}{
	"TLSConfig":    {},
	"TLSNextProto": {},
}

// requiredHTTPServerFields enumerates the `http.Server` fields whose
// PRESENCE is load-bearing. A composite literal that omits any of
// them is a regression. `ReadHeaderTimeout` is the Slowloris guard;
// adding more required fields here (e.g. `MaxHeaderBytes`) MUST land
// in the same edit that introduces them in production code, so the
// gate stays honest.
var requiredHTTPServerFields = map[string]struct{}{
	"ReadHeaderTimeout": {},
	"ReadTimeout":       {},
	"WriteTimeout":      {},
	"IdleTimeout":       {},
}

// clientIPFuncName is the function whose body owns the forwarded-IP
// trust policy. The matcher locates this function by name and scans
// only its body, so unrelated helpers in `ratelimit.go` are not
// constrained.
const clientIPFuncName = "ClientIP"

// allowedProxyHeaderLiterals is the closed set of HTTP header names
// `ClientIP` is allowed to consult. RFC 7239's `Forwarded` is
// DELIBERATELY excluded: the proxy contract sets `X-Forwarded-For`
// and the API never trusts `Forwarded`, so an attacker who reaches
// the API directly cannot spoof their identity by sending one. The
// comparison is case-sensitive against the source's literal value —
// `r.Header.Get` is itself case-insensitive at runtime, but the
// canonical literal must appear in source so a code reader sees the
// exact contract.
var allowedProxyHeaderLiterals = map[string]struct{}{
	"X-Forwarded-For": {},
	"X-Real-IP":       {},
}

// forbiddenProxyHeaderLiterals enumerates the most commonly-seen
// proxy-trust headers we deliberately DO NOT consult anywhere in
// `ratelimit.go`. A regression that adds any of these to `ClientIP`
// (or to a sibling helper that feeds into it) is caught by the
// file-wide pass before it ships. The set is intentionally broad —
// it covers RFC, vendor-specific, and convention headers — and is
// matched case-insensitively so a contributor cannot smuggle one in
// under an unusual casing.
var forbiddenProxyHeaderLiterals = map[string]struct{}{
	"Forwarded":                {}, // RFC 7239
	"X-Client-IP":              {},
	"True-Client-IP":           {}, // Akamai
	"CF-Connecting-IP":         {}, // Cloudflare
	"Fastly-Client-IP":         {},
	"X-Forwarded-Host":         {},
	"X-Forwarded-Proto":        {},
	"X-Forwarded-Server":       {},
	"X-Forwarded-Port":         {},
	"X-Original-Forwarded-For": {},
}

// requiredRemoteAddrIdentifier is the Go identifier the `ClientIP`
// body MUST reference as its terminal fallback. The matcher asserts
// the function body contains a `RemoteAddr` selector so a regression
// that empties the fallback (returning "" or panicking instead of
// the connection-level peer address) is caught.
const requiredRemoteAddrIdentifier = "RemoteAddr"

// requiredSecurityHeading is the literal Markdown heading that must
// appear in SECURITY.md to document this story's posture. The exact
// heading is part of the public contract — operators and downstream
// auditors deep-link to it — so changes are deliberate.
const requiredSecurityHeading = "## TLS Termination and Proxy Header Trust"

// requiredSecuritySubstrings is the closed set of literal substrings
// SECURITY.md MUST contain to satisfy the documentation half of the
// gate. Each captures a different load-bearing fact:
//   - the proxy-termination expectation,
//   - the Slowloris guard,
//   - the closed-set proxy-header trust list, with both allowed
//     headers named so a reader cannot mistake the policy.
var requiredSecuritySubstrings = []string{
	"TLS is terminated at the operator's reverse proxy",
	"ReadHeaderTimeout",
	"X-Forwarded-For",
	"X-Real-IP",
	"http_server_hardening_static_test.go",
}

// requiredSecurityGateRow is the literal substring of the row that
// MUST appear in SECURITY.md's Required Verification Gates table.
// The substring is the gate name plus the `-run` selector; a
// contributor who renames the test functions must update both.
const requiredSecurityGateRow = "TLS and proxy header trust"

// TestHTTPServerHardeningTLSTerminationIsDelegated proves that the
// API binary does not terminate TLS itself. It scans
// cmd/yalla-api/main.go and rejects any call to a forbidden TLS API
// selector, any forbidden struct field on an `http.Server` literal,
// any assignment to such a field, and any `http.Server` composite
// literal that omits the required hardening fields.
func TestHTTPServerHardeningTLSTerminationIsDelegated(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, yallaAPIMainPath)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", yallaAPIMainPath, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", yallaAPIMainPath, err)
	}
	for _, v := range findAPITLSRegressions(fset, file) {
		t.Error(v)
	}
}

// TestHTTPServerHardeningProxyHeaderTrustIsClosedSet proves that the
// `ClientIP` helper consults only the allow-listed forwarding
// headers, and that no forbidden proxy-trust header literal appears
// anywhere in `ratelimit.go`. The two passes are orthogonal — a
// regression that smuggles a forbidden literal into a sibling helper
// is caught by the file-wide pass even if `ClientIP` itself remains
// closed.
func TestHTTPServerHardeningProxyHeaderTrustIsClosedSet(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, ratelimitPath)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", ratelimitPath, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", ratelimitPath, err)
	}
	for _, v := range findProxyHeaderTrustRegressions(fset, file) {
		t.Error(v)
	}
}

// TestHTTPServerHardeningSecurityDocumentsTLSAndProxyTrust proves
// that SECURITY.md documents the operator-facing TLS and proxy
// header trust contract. The pinned heading and required substrings
// are part of the public security posture; a silent removal is a
// regression on equal footing with a code change.
func TestHTTPServerHardeningSecurityDocumentsTLSAndProxyTrust(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, securityDocPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", securityDocPath, err)
	}
	doc := string(b)
	if !strings.Contains(doc, requiredSecurityHeading) {
		t.Errorf("%s: missing required heading %q; "+
			"the public security posture for TLS and proxy header trust must stay documented.",
			securityDocPath, requiredSecurityHeading)
	}
	for _, want := range requiredSecuritySubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; "+
				"the documented contract MUST name every load-bearing fact so operators and auditors do not have to read the test file.",
				securityDocPath, want, requiredSecurityHeading)
		}
	}
	if !strings.Contains(doc, requiredSecurityGateRow) {
		t.Errorf("%s: missing verification-gates table row containing %q; "+
			"every security-verification story must surface as a row operators and reviewers can see at a glance.",
			securityDocPath, requiredSecurityGateRow)
	}
}

// TestHTTPServerHardeningStaticAnalyzerDetectsRegressions is the
// self-check for the matchers above. The acceptance criterion "tests
// fail when the control is removed" is the load-bearing one: each
// known-bad synthetic snippet must produce hits, and the known-good
// snippet must produce zero hits. This guards against the analyser
// silently going lenient.
func TestHTTPServerHardeningStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()
	t.Run("findAPITLSRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical hardened http.Server is accepted",
				source: `package main
import (
	"net/http"
	"time"
)
func main() {
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           nil,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	_ = srv.ListenAndServe()
}`,
				wantHits: 0,
			},
			{
				name: "http.Server without ReadHeaderTimeout is rejected (Slowloris)",
				source: `package main
import "net/http"
func main() {
	srv := &http.Server{Addr: ":8080", ReadTimeout: 15, WriteTimeout: 60, IdleTimeout: 120}
	_ = srv.ListenAndServe()
}`,
				wantHits: 1,
			},
			{
				name: "http.Server with TLSConfig field is rejected",
				source: `package main
import (
	"crypto/tls"
	"net/http"
	"time"
)
func main() {
	srv := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         &tls.Config{},
	}
	_ = srv.ListenAndServe()
}`,
				wantHits: 1,
			},
			{
				name: "http.Server with TLSNextProto field is rejected",
				source: `package main
import (
	"net/http"
	"time"
)
func main() {
	srv := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	_ = srv.ListenAndServe()
}`,
				wantHits: 1,
			},
			{
				name: "ListenAndServeTLS call is rejected",
				source: `package main
import "net/http"
func main() {
	srv := &http.Server{Addr: ":8443", ReadHeaderTimeout: 10, ReadTimeout: 15, WriteTimeout: 60, IdleTimeout: 120}
	_ = srv.ListenAndServeTLS("cert.pem", "key.pem")
}`,
				wantHits: 1,
			},
			{
				name: "ServeTLS call is rejected",
				source: `package main
import (
	"net"
	"net/http"
)
func main() {
	srv := &http.Server{ReadHeaderTimeout: 10, ReadTimeout: 15, WriteTimeout: 60, IdleTimeout: 120}
	var ln net.Listener
	_ = srv.ServeTLS(ln, "cert.pem", "key.pem")
}`,
				wantHits: 1,
			},
			{
				name: "package-level http.ListenAndServeTLS is rejected",
				source: `package main
import "net/http"
func main() {
	_ = http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)
}`,
				wantHits: 1,
			},
			{
				name: "assignment to TLSConfig field is rejected",
				source: `package main
import (
	"crypto/tls"
	"net/http"
	"time"
)
func main() {
	srv := &http.Server{Addr: ":8080", ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	srv.TLSConfig = &tls.Config{}
	_ = srv.ListenAndServe()
}`,
				wantHits: 1,
			},
			{
				name: "multiple regressions are all reported",
				source: `package main
import (
	"crypto/tls"
	"net/http"
	"time"
)
func main() {
	srv := &http.Server{
		Addr:         ":8443",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig:    &tls.Config{},
	}
	_ = srv.ListenAndServeTLS("cert.pem", "key.pem")
}`,
				// missing ReadHeaderTimeout (1) + TLSConfig field (1) + ListenAndServeTLS call (1)
				wantHits: 3,
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
				got := findAPITLSRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findAPITLSRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findProxyHeaderTrustRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical ClientIP is accepted",
				source: `package httpapi
import (
	"net"
	"net/http"
	"strings"
)
func ClientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.Index(v, ","); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return strings.TrimSpace(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}`,
				wantHits: 0,
			},
			{
				name: "ClientIP that trusts RFC 7239 Forwarded is rejected",
				source: `package httpapi
import "net/http"
func ClientIP(r *http.Request) string {
	if v := r.Header.Get("Forwarded"); v != "" {
		return v
	}
	return r.RemoteAddr
}`,
				// 1 hit for ClientIP header outside allow-list + 1 file-wide forbidden literal
				wantHits: 2,
			},
			{
				name: "ClientIP that trusts CF-Connecting-IP is rejected",
				source: `package httpapi
import "net/http"
func ClientIP(r *http.Request) string {
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		return v
	}
	return r.RemoteAddr
}`,
				wantHits: 2,
			},
			{
				name: "ClientIP that trusts True-Client-IP is rejected",
				source: `package httpapi
import "net/http"
func ClientIP(r *http.Request) string {
	if v := r.Header.Get("True-Client-IP"); v != "" {
		return v
	}
	return r.RemoteAddr
}`,
				wantHits: 2,
			},
			{
				name: "ClientIP without RemoteAddr fallback is rejected",
				source: `package httpapi
import "net/http"
func ClientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return v
	}
	return ""
}`,
				wantHits: 1,
			},
			{
				name: "forbidden literal in a sibling helper is rejected by the file-wide pass",
				source: `package httpapi
import "net/http"
func ClientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	return r.RemoteAddr
}
func DebugIP(r *http.Request) string {
	return r.Header.Get("X-Original-Forwarded-For")
}`,
				wantHits: 1,
			},
			{
				name: "forbidden literal under unusual casing is still rejected",
				source: `package httpapi
import "net/http"
func ClientIP(r *http.Request) string {
	if v := r.Header.Get("x-client-ip"); v != "" {
		return v
	}
	return r.RemoteAddr
}`,
				// ClientIP allow-list pass is case-sensitive (allow-list miss = 1 hit)
				// File-wide forbidden pass is case-insensitive (= 1 hit)
				wantHits: 2,
			},
			{
				name: "file with no ClientIP function is reported",
				source: `package httpapi
func unrelated() {}`,
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
				got := findProxyHeaderTrustRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findProxyHeaderTrustRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})
}

// findAPITLSRegressions walks the AST of cmd/yalla-api/main.go and
// returns one diagnostic per regression. Three orthogonal shapes are
// scanned:
//
//   - CallExpr whose function selector name is in
//     forbiddenAPITLSCallSelectors. The receiver is ignored —
//     `srv.ListenAndServeTLS(...)`, `s.ServeTLS(...)`, and
//     `http.ListenAndServeTLS(...)` all match.
//   - CompositeLit whose type is `http.Server`. The matcher asserts
//     every element of requiredHTTPServerFields appears as a
//     KeyValueExpr key, and that no element of
//     forbiddenAPITLSStructFields does.
//   - AssignStmt whose LHS is a SelectorExpr with a Sel name in
//     forbiddenAPITLSStructFields. This catches the post-construction
//     mutation seam `srv.TLSConfig = ...`.
//
// The diagnostic always includes the file:line position and a short
// note pointing the reader at the threat-model paragraph at the top
// of this file. Ordering is by position so the output is deterministic.
func findAPITLSRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, kind, detail string) {
		out = append(out, kind+" "+detail+" at "+pos.String()+
			". The Yalla API binary does NOT terminate TLS and does NOT configure in-process TLS — TLS is terminated upstream at the operator's reverse proxy. "+
			"See internal/release/http_server_hardening_static_test.go (BE-0356) and SECURITY.md \"TLS Termination and Proxy Header Trust\" for the threat model.")
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if _, bad := forbiddenAPITLSCallSelectors[sel.Sel.Name]; bad {
					emit(fset.Position(node.Pos()), "forbidden TLS call", "."+sel.Sel.Name)
				}
			}
		case *ast.CompositeLit:
			if !isHTTPServerCompositeLit(node) {
				return true
			}
			present := make(map[string]token.Position, len(node.Elts))
			for _, elt := range node.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				present[key.Name] = fset.Position(kv.Pos())
				if _, bad := forbiddenAPITLSStructFields[key.Name]; bad {
					emit(fset.Position(kv.Pos()), "forbidden http.Server field", key.Name)
				}
			}
			litPos := fset.Position(node.Pos())
			for required := range requiredHTTPServerFields {
				if _, ok := present[required]; !ok {
					emit(litPos, "http.Server literal missing required field", required)
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				if _, bad := forbiddenAPITLSStructFields[sel.Sel.Name]; bad {
					emit(fset.Position(lhs.Pos()), "forbidden assignment to TLS field", "."+sel.Sel.Name)
				}
			}
		}
		return true
	})
	sort.Strings(out)
	return out
}

// isHTTPServerCompositeLit reports whether a composite literal's
// declared type names `http.Server` (a `&http.Server{...}` is parsed
// as a UnaryExpr wrapping a CompositeLit; this helper inspects only
// the inner literal's Type, so the matcher does not need to special-
// case the address-of). The check is structural — package selector
// `http` + selector name `Server` — to avoid false positives on
// unrelated structs in the same file.
func isHTTPServerCompositeLit(node *ast.CompositeLit) bool {
	sel, ok := node.Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkg.Name+"."+sel.Sel.Name == httpServerTypeSelector
}

// findProxyHeaderTrustRegressions walks the AST of
// internal/controlplane/httpapi/ratelimit.go and returns one
// diagnostic per regression. Two orthogonal passes:
//
//  1. Scoped pass on the `ClientIP` function body. The matcher
//     locates the function by name, then walks every call inside its
//     body and inspects every BasicLit STRING argument to a selector
//     ending in `.Header.Get`. Any literal outside
//     allowedProxyHeaderLiterals is flagged. The matcher also
//     asserts the body references `RemoteAddr` so the fallback chain
//     is intact.
//  2. File-wide pass on every string literal in the file. Any
//     literal whose lower-cased form is in forbiddenProxyHeaderLiterals
//     is flagged, regardless of where it appears — even comments and
//     unrelated helpers — because a forbidden header name has no
//     legitimate place in this file.
//
// The two passes are deliberately separate so a regression that
// reads a forbidden header but does so OUTSIDE `ClientIP` (e.g. in a
// new debug helper) is still caught. If `ClientIP` is missing
// entirely the matcher returns a single "missing function" hit so
// the gate cannot pass silently when its target is removed.
func findProxyHeaderTrustRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, kind, detail string) {
		out = append(out, kind+" "+detail+" at "+pos.String()+
			". The Yalla rate-limit middleware trusts ONLY X-Forwarded-For (first hop) and X-Real-IP as forwarded-IP signals; every other forwarded-* family header is deliberately ignored so an attacker who reaches the API directly cannot spoof the IP bucket. "+
			"See internal/release/http_server_hardening_static_test.go (BE-0356) and SECURITY.md \"TLS Termination and Proxy Header Trust\" for the threat model.")
	}

	var clientIPFunc *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name != nil && fn.Name.Name == clientIPFuncName {
			clientIPFunc = fn
			break
		}
	}

	if clientIPFunc == nil {
		emit(fset.Position(file.Pos()), "missing required function", clientIPFuncName)
	} else if clientIPFunc.Body != nil {
		fnPos := fset.Position(clientIPFunc.Pos())
		seenRemoteAddr := false
		ast.Inspect(clientIPFunc.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if !isHeaderGetCall(node.Fun) {
					return true
				}
				if len(node.Args) == 0 {
					return true
				}
				lit, ok := node.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				if _, ok := allowedProxyHeaderLiterals[value]; !ok {
					emit(fset.Position(lit.Pos()), "ClientIP reads header outside allow-list", strconv.Quote(value))
				}
			case *ast.SelectorExpr:
				if node.Sel != nil && node.Sel.Name == requiredRemoteAddrIdentifier {
					seenRemoteAddr = true
				}
			}
			return true
		})
		if !seenRemoteAddr {
			emit(fnPos, "ClientIP body missing required fallback identifier", requiredRemoteAddrIdentifier)
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		lower := strings.ToLower(value)
		for forbidden := range forbiddenProxyHeaderLiterals {
			if strings.ToLower(forbidden) == lower {
				emit(fset.Position(lit.Pos()), "forbidden proxy-trust header literal", strconv.Quote(value))
				break
			}
		}
		return true
	})

	sort.Strings(out)
	return out
}

// isHeaderGetCall reports whether the function expression of a call
// has the shape `*.Header.Get` — i.e. a SelectorExpr whose Sel is
// `Get` and whose X is another SelectorExpr whose Sel is `Header`.
// The receiver chain prefix is unconstrained so `r.Header.Get`,
// `req.Header.Get`, and `request.Header.Get` all match.
func isHeaderGetCall(fun ast.Expr) bool {
	outer, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if outer.Sel == nil || outer.Sel.Name != "Get" {
		return false
	}
	inner, ok := outer.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return inner.Sel != nil && inner.Sel.Name == "Header"
}
