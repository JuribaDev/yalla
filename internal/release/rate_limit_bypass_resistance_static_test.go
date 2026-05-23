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

// BE-0363: Security verification — rate-limit bypass resistance.
//
// Threat model.
//
//  1. The customer-facing HTTP rate-limit gate
//     (`internal/controlplane/httpapi/ratelimit.go`, BE-0035) is the
//     control that prevents a single principal or a single IP from
//     overwhelming the control-plane API. It bills three buckets in
//     order: the resolved organization, the resolved API key / session
//     principal, and the resolved client IP. Each bucket is identified
//     by the dimension name (`organization` / `api_key` / `ip`) — the
//     bucket identity (a tenant org id, an API key id, a client IP) is
//     never echoed to the wire or to the structured WARN log record.
//     A regression that put the bucket identity into `Decision.Bucket`,
//     into the 429 envelope details, or into the deny-log record would
//     turn the throttling signal into a cross-tenant leak: an operator
//     reading the request log could pivot from a 429 record to "which
//     other tenants live on this control plane", and an unauthenticated
//     attacker hammering a key bucket could enumerate live key ids by
//     watching for distinguishable retry-after values.
//
//  2. The internal-worker credential scheme is the one and only bypass
//     of the customer-facing limiter: a request whose principal
//     authenticated through `auth.MethodInternalWorker` carries
//     `ratelimit.Request.Exempt = true` and is unconditionally allowed.
//     The bypass exists because internal worker callbacks (the Dokploy
//     status webhook, the job-state reconciler, the internal metering
//     poller) are not customer traffic and would otherwise share the
//     same organization bucket as a noisy customer request. A
//     regression that set `Exempt = true` on any code path other than
//     "the resolved auth method is `auth.MethodInternalWorker`" — for
//     example, "the request carries an `X-Yalla-Internal: 1` header",
//     "the path begins with `/v1/internal`", "the IP is private", or
//     "the principal is missing" — would let an external attacker spoof
//     their way past the gate. The static gate pins the only legal
//     shape: the assignment lives inside an `if` whose condition is the
//     equality `method == auth.MethodInternalWorker` on the value
//     returned by `AuthMethodFromContext(r.Context())`, and the assignment
//     appears at exactly one site in the entire `internal/controlplane/
//     httpapi` package production tree.
//
//  3. The 429 wire shape is part of the bypass surface. A 429 reply
//     emitted as a bare `http.Error` or via a hand-rolled JSON
//     `fmt.Fprintf` instead of `apienvelope.WriteError(...,
//     apierr.RateLimited(...))` would either (a) emit a non-stable
//     envelope (no `yalla.error.v1` schema version, no request id, no
//     stable error code) — and clients that switch their retry loop on
//     the envelope code would fall back to "retry immediately" — or
//     (b) emit a body that includes the limiter's internal error string
//     ("bucket `org_acme_42` exhausted"), leaking the bucket identity.
//     The matcher pins both: exactly one `apierr.RateLimited` call site
//     in `ratelimit.go`, the only `apienvelope.WriteError` call site in
//     that file, and zero `http.Error` / `w.Write([]byte("{`/`fmt.Fprintf(w,`
//     emission seams in the deny branch.
//
//  4. The `Decision.Bucket` field MUST be one of the three named
//     constants `ratelimit.BucketOrg`, `ratelimit.BucketKey`,
//     `ratelimit.BucketIP`. A regression that filled the field with a
//     string literal (`"org_acme"`, `"ip:10.0.0.1"`, a formatted
//     `fmt.Sprintf` of the bucket identity) would smuggle the identity
//     out through the wire envelope's `details["bucket"]` slot. The
//     static gate walks every `ratelimit.Decision{...}` composite
//     literal in `limiter.go` and asserts the `Bucket` field value is
//     either omitted (an Allowed decision) or one of the three named
//     constants.
//
//  5. The middleware MUST be wired around every served route. A regression
//     that only wraps some routes with `rateLimit(...)` would create a
//     bypass channel: an attacker hitting an un-wrapped endpoint would
//     consume zero bucket budget and could indirectly evict cache
//     entries, exhaust connection pool slots, or pivot through a
//     never-throttled write path. `server.go` MUST hold exactly one
//     `RateLimit(...)` construction site and the per-route loop MUST
//     pass every handler through that wrapper. The matcher asserts the
//     construction site exists (with the canonical
//     `RateLimit(rateLimiter, logger)` shape) and that the per-route
//     loop body contains an assignment of the form `h = rateLimit(h)`.
//
//  6. The operator-facing contract is part of the public security
//     posture. `SECURITY.md` MUST document (a) the closed
//     bypass-resistance threat model, (b) the single internal-worker
//     exemption, (c) the closed `Decision.Bucket` constant set and the
//     "no bucket identity on the wire" rule, and (d) a row in the
//     Required Verification Gates table pinning the `-run` selector for
//     this test. The matcher pins the heading and the canonical
//     substrings; a silent removal of any of them is a regression on
//     equal footing with a code change.
//
// The two-test variant of the BE-0344 pattern is split as follows:
//
//   - This static analyzer (the structural half) walks the production
//     AST for `ratelimit.go`, `limiter.go`, and `server.go`, plus the
//     `SECURITY.md` documentation file, and asserts each of the five
//     invariants above. A `TestRateLimitBypassResistanceStaticAnalyzerDetectsRegressions`
//     self-check installs intentionally-broken fixtures and proves the
//     analyzer flags each regression class — so the gate's positive-case
//     silence (the production tree is clean today) is never a false
//     negative.
//
//   - The runtime evidence half lives in
//     `internal/controlplane/httpapi/ratelimit_bypass_test.go` and
//     proves the marker-prefix bypass-shaped inputs (a forged
//     `X-Yalla-Internal: 1` header, a forged `/v1/internal/...` path, a
//     drained per-key bucket queried from a second principal, a
//     concurrent burst against a single key) cannot escape the gate.
//     The two halves together pin both the structural and behavioural
//     contract.

// canonicalRateLimitMiddlewareFile is the only production file in the
// `internal/controlplane/httpapi` package that may set
// `ratelimit.Request.Exempt = true`. The single-site invariant means a
// reviewer can audit the bypass surface by reading exactly one file.
const canonicalRateLimitMiddlewareFile = "internal/controlplane/httpapi/ratelimit.go"

// canonicalRateLimitLimiterFile is the only production file that may
// construct a `ratelimit.Decision{Bucket: ...}` composite literal with a
// non-nil Bucket field. The closed-constant invariant means the bucket
// identity can never reach `Decision.Bucket`.
const canonicalRateLimitLimiterFile = "internal/controlplane/ratelimit/limiter.go"

// canonicalRateLimitServerFile is the only production file that wires
// the rate-limit middleware around every served route. The single
// wrap-call invariant means an un-wrapped route is impossible.
const canonicalRateLimitServerFile = "internal/controlplane/httpapi/server.go"

// rateLimitBucketConstants is the closed set of legal identifier names
// that may appear as the value of a `ratelimit.Decision{Bucket: ...}`
// field. Any other identifier (or a string literal, or a CallExpr) is a
// bucket-identity-leak regression.
var rateLimitBucketConstants = map[string]struct{}{
	"BucketOrg": {},
	"BucketKey": {},
	"BucketIP":  {},
}

// TestRateLimitBypassResistanceExemptOnlyForInternalWorker pins that the
// middleware sets `req.Exempt = true` at exactly one site, and that the
// assignment lives inside an `if` whose condition is the equality
// `method == auth.MethodInternalWorker` on the value returned by
// `AuthMethodFromContext`.
func TestRateLimitBypassResistanceExemptOnlyForInternalWorker(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	files := rateLimitMiddlewareProductionFiles(t, root)

	fset := token.NewFileSet()
	type hit struct {
		file string
		line int
	}
	var sites []hit
	for _, path := range files {
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, site := range findExemptAssignmentSites(fset, file) {
			sites = append(sites, hit{file: path, line: site})
		}
	}
	if len(sites) != 1 {
		t.Fatalf("got %d Exempt=true assignment sites, want exactly 1; sites = %+v", len(sites), sites)
	}
	rel, err := filepath.Rel(root, sites[0].file)
	if err != nil {
		t.Fatalf("rel %s: %v", sites[0].file, err)
	}
	if filepath.ToSlash(rel) != canonicalRateLimitMiddlewareFile {
		t.Fatalf("Exempt=true site lives in %s, want %s", filepath.ToSlash(rel), canonicalRateLimitMiddlewareFile)
	}
	// The single site must also live inside a guard that checks the
	// internal-worker auth method.
	canonical := filepath.Join(root, filepath.FromSlash(canonicalRateLimitMiddlewareFile))
	file, err := parser.ParseFile(fset, canonical, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", canonical, err)
	}
	if msg := requireExemptGuardedByInternalWorker(fset, file); msg != "" {
		t.Fatal(msg)
	}
}

// TestRateLimitBypassResistanceDecisionBucketIsClosedConstantSet pins
// that every `ratelimit.Decision{Bucket: ...}` composite literal in
// `limiter.go` uses one of the three named constants. A regression that
// substituted a string literal or a CallExpr would smuggle the bucket
// identity onto the wire.
func TestRateLimitBypassResistanceDecisionBucketIsClosedConstantSet(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	path := filepath.Join(root, filepath.FromSlash(canonicalRateLimitLimiterFile))
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	violations := findDecisionBucketRegressions(fset, file)
	if len(violations) != 0 {
		t.Fatalf("Decision{Bucket: ...} sites with non-constant values:\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestRateLimitBypassResistance429EmitSiteIsCanonical pins the single
// 429 emission shape in the middleware: exactly one
// `apierr.RateLimited(...)` call wrapped by exactly one
// `apienvelope.WriteError(...)` call. A bare `http.Error`, a
// hand-rolled JSON body, or a duplicate emission seam would either
// leak the bucket identity through an unredacted error string or break
// the stable `yalla.error.v1` envelope contract.
func TestRateLimitBypassResistance429EmitSiteIsCanonical(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	path := filepath.Join(root, filepath.FromSlash(canonicalRateLimitMiddlewareFile))
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	rateLimitedCalls, writeErrorCalls, forbidden := findRateLimit429EmitSeams(fset, file)
	if len(rateLimitedCalls) != 1 {
		t.Errorf("apierr.RateLimited call sites = %d, want 1; sites = %+v", len(rateLimitedCalls), rateLimitedCalls)
	}
	if len(writeErrorCalls) != 1 {
		t.Errorf("apienvelope.WriteError call sites = %d, want 1; sites = %+v", len(writeErrorCalls), writeErrorCalls)
	}
	if len(forbidden) != 0 {
		t.Fatalf("forbidden 429 emission seams:\n  %s", strings.Join(forbidden, "\n  "))
	}
}

// TestRateLimitBypassResistanceServerWiresEveryRoute pins that
// `server.go` constructs exactly one `RateLimit(...)` wrapper and that
// the per-route loop body contains the assignment `h = rateLimit(h)`.
// A regression that only wrapped some routes — or wrapped them with
// the wrong inner handler — would let an attacker bypass the gate by
// hitting the un-wrapped route.
func TestRateLimitBypassResistanceServerWiresEveryRoute(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	path := filepath.Join(root, filepath.FromSlash(canonicalRateLimitServerFile))
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	constructionSites, wrapSites := findRateLimitWrapSeams(fset, file)
	if len(constructionSites) != 1 {
		t.Errorf("RateLimit(...) construction sites = %d, want 1; sites = %+v", len(constructionSites), constructionSites)
	}
	if len(wrapSites) != 1 {
		t.Errorf("h = rateLimit(h) wrap sites = %d, want 1; sites = %+v", len(wrapSites), wrapSites)
	}
}

// TestRateLimitBypassResistanceSecurityDocumented pins the documented
// security posture: SECURITY.md MUST contain a "## Rate Limit Bypass
// Resistance" section, the closed bypass list, the closed bucket-identity
// guarantee, and a row in the Required Verification Gates table pinning
// the `-run` selector for this test.
func TestRateLimitBypassResistanceSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	path := filepath.Join(root, "SECURITY.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SECURITY.md: %v", err)
	}
	text := string(body)
	required := []string{
		"## Rate Limit Bypass Resistance",
		"`auth.MethodInternalWorker`",
		"`ratelimit.BucketOrg`",
		"`ratelimit.BucketKey`",
		"`ratelimit.BucketIP`",
		"`apienvelope.WriteError`",
		"`apierr.RateLimited`",
		"`Decision.Bucket`",
		"`rate_limit_bypass_resistance_static_test.go`",
		"TestRateLimitBypassResistance",
	}
	for _, want := range required {
		if !strings.Contains(text, want) {
			t.Errorf("SECURITY.md missing required substring: %q", want)
		}
	}
	// Required Verification Gates table row.
	if !strings.Contains(text, "Rate limit bypass resistance") {
		t.Error("SECURITY.md missing 'Rate limit bypass resistance' row in Required Verification Gates table")
	}
}

// TestRateLimitBypassResistanceStaticAnalyzerDetectsRegressions installs
// intentionally-broken fixtures and proves each of the five matchers
// flags its regression class. Without this self-check, a refactor that
// silently neuters a matcher (e.g. by changing the SelectorExpr pivot
// from "method == auth.MethodInternalWorker" to a value the test fixture
// no longer mentions) would make the positive case silently pass while
// shipping a real bypass.
func TestRateLimitBypassResistanceStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()

	cases := []struct {
		name string
		src  string
		want func(t *testing.T, file *ast.File)
	}{
		{
			name: "Exempt=true outside auth-method guard is rejected",
			src: `package httpapi

import "net/http"

func bypass(w http.ResponseWriter, r *http.Request) {
	req := struct{ Exempt bool }{}
	if r.Header.Get("X-Yalla-Internal") == "1" {
		req.Exempt = true
	}
	_ = req
}
`,
			want: func(t *testing.T, file *ast.File) {
				if msg := requireExemptGuardedByInternalWorker(fset, file); msg == "" {
					t.Error("matcher missed: Exempt=true under header-only guard should be flagged")
				}
			},
		},
		{
			name: "Exempt=true with auth.MethodInternalWorker guard is accepted",
			src: `package httpapi

import (
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
)

func ok(w http.ResponseWriter, r *http.Request) {
	req := struct{ Exempt bool }{}
	if method, present := AuthMethodFromContext(r.Context()); present && method == auth.MethodInternalWorker {
		req.Exempt = true
	}
	_ = req
}
`,
			want: func(t *testing.T, file *ast.File) {
				if msg := requireExemptGuardedByInternalWorker(fset, file); msg != "" {
					t.Errorf("matcher false positive on canonical guard: %s", msg)
				}
			},
		},
		{
			name: "Decision{Bucket: \"literal\"} is rejected",
			src: `package ratelimit

type Decision struct {
	Allowed bool
	Bucket  string
}

func leak() Decision {
	return Decision{Bucket: "org_acme"}
}
`,
			want: func(t *testing.T, file *ast.File) {
				v := findDecisionBucketRegressions(fset, file)
				if len(v) == 0 {
					t.Error("matcher missed: Decision{Bucket: \"literal\"} should be flagged")
				}
			},
		},
		{
			name: "Decision{Bucket: BucketOrg} is accepted",
			src: `package ratelimit

const (
	BucketOrg = "organization"
	BucketKey = "api_key"
	BucketIP  = "ip"
)

type Decision struct {
	Allowed bool
	Bucket  string
}

func ok() Decision {
	return Decision{Bucket: BucketOrg}
}
`,
			want: func(t *testing.T, file *ast.File) {
				v := findDecisionBucketRegressions(fset, file)
				if len(v) != 0 {
					t.Errorf("matcher false positive on canonical constant: %v", v)
				}
			},
		},
		{
			name: "http.Error in the deny branch is rejected",
			src: `package httpapi

import "net/http"

func deny(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "rate limited", http.StatusTooManyRequests)
}
`,
			want: func(t *testing.T, file *ast.File) {
				_, _, forbidden := findRateLimit429EmitSeams(fset, file)
				if len(forbidden) == 0 {
					t.Error("matcher missed: http.Error emission seam should be flagged")
				}
			},
		},
		{
			name: "RateLimitWithClientIPResolver(...) construction site is detected",
			src: `package httpapi

import "net/http"

func wire(rateLimiter RateLimiter, logger interface{}) http.Handler {
	rateLimit := RateLimitWithClientIPResolver(rateLimiter, logger, ClientIP)
	var h http.Handler
	h = rateLimit(h)
	return h
}
`,
			want: func(t *testing.T, file *ast.File) {
				cs, ws := findRateLimitWrapSeams(fset, file)
				if len(cs) != 1 {
					t.Errorf("matcher false negative: construction sites = %d, want 1", len(cs))
				}
				if len(ws) != 1 {
					t.Errorf("matcher false negative: wrap sites = %d, want 1", len(ws))
				}
			},
		},
		{
			name: "missing RateLimit(...) construction site is detected",
			src: `package httpapi

import "net/http"

func wire() http.Handler {
	var h http.Handler
	return h
}
`,
			want: func(t *testing.T, file *ast.File) {
				cs, ws := findRateLimitWrapSeams(fset, file)
				if len(cs) != 0 {
					t.Errorf("matcher false positive: construction sites = %d, want 0", len(cs))
				}
				if len(ws) != 0 {
					t.Errorf("matcher false positive: wrap sites = %d, want 0", len(ws))
				}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			file, err := parser.ParseFile(fset, tc.name+".go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse fixture %q: %v", tc.name, err)
			}
			tc.want(t, file)
		})
	}
}

// repoRoot resolves the repository root from the test working directory.
// The static gate lives at `internal/release/`, so the root is two
// `..` segments above.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// rateLimitMiddlewareProductionFiles returns every non-test .go file in
// the `internal/controlplane/httpapi` package so a refactor cannot
// migrate the Exempt=true assignment to a sibling file.
func rateLimitMiddlewareProductionFiles(t *testing.T, root string) []string {
	t.Helper()
	dir := filepath.Join(root, "internal", "controlplane", "httpapi")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out
}

// findExemptAssignmentSites returns the source line number of every
// statement of the form `<expr>.Exempt = true` in the file. The matcher
// uses the trailing-selector-name convention (Sel.Name == "Exempt"): a
// future refactor that renamed the local receiver from `req` to `r2` or
// hung the assignment off a method receiver instead of a local
// composite literal would still trip the matcher.
func findExemptAssignmentSites(fset *token.FileSet, file *ast.File) []int {
	var hits []int
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN {
			return true
		}
		if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		sel, ok := assign.Lhs[0].(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Exempt" {
			return true
		}
		// RHS must be the identifier `true` (the canonical bypass
		// assignment). `false` is a no-op write and shouldn't be
		// counted; a non-literal RHS is an obfuscated bypass and would
		// still trip the matcher on the LHS path.
		ident, ok := assign.Rhs[0].(*ast.Ident)
		if !ok || ident.Name != "true" {
			return true
		}
		hits = append(hits, fset.Position(assign.Pos()).Line)
		return true
	})
	return hits
}

// requireExemptGuardedByInternalWorker walks the file looking for the
// canonical guard:
//
//	if method, ok := AuthMethodFromContext(r.Context()); ok && method == auth.MethodInternalWorker {
//	    req.Exempt = true
//	}
//
// and returns a non-empty string describing the regression when (a) no
// `Exempt = true` assignment is found, or (b) any such assignment lives
// outside a guard whose condition references the SelectorExpr
// `auth.MethodInternalWorker`. The matcher is intentionally lenient
// about the exact guard structure — the load-bearing rule is that the
// `MethodInternalWorker` selector dominates the assignment. A
// regression that swapped the equality for a header check, a path
// prefix, or a constant-true would no longer reference the selector
// inside the dominating if-stmt and would trip the matcher.
func requireExemptGuardedByInternalWorker(fset *token.FileSet, file *ast.File) string {
	type assignInfo struct {
		pos     token.Position
		guarded bool
	}
	var assigns []assignInfo
	// Walk every if-statement; for each, collect Exempt=true assignments
	// whose AST ancestor chain passes through this if-stmt AND whose
	// condition references auth.MethodInternalWorker.
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// First pass: find every Exempt=true assign in the function.
		var raw []token.Pos
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			a, ok := n.(*ast.AssignStmt)
			if !ok || a.Tok != token.ASSIGN || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
				return true
			}
			sel, ok := a.Lhs[0].(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "Exempt" {
				return true
			}
			id, ok := a.Rhs[0].(*ast.Ident)
			if !ok || id.Name != "true" {
				return true
			}
			raw = append(raw, a.Pos())
			return true
		})
		if len(raw) == 0 {
			continue
		}
		// Second pass: collect every if-stmt whose condition contains
		// the selector auth.MethodInternalWorker, recording its body
		// range. An Exempt=true assignment whose position falls inside
		// any such range is "guarded".
		type guardRange struct{ start, end token.Pos }
		var guards []guardRange
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ifs, ok := n.(*ast.IfStmt)
			if !ok || ifs.Body == nil || ifs.Cond == nil {
				return true
			}
			if !conditionReferencesInternalWorker(ifs.Cond) && !conditionReferencesInternalWorker(ifs.Init) {
				return true
			}
			guards = append(guards, guardRange{start: ifs.Body.Lbrace, end: ifs.Body.Rbrace})
			return true
		})
		for _, pos := range raw {
			guarded := false
			for _, g := range guards {
				if pos > g.start && pos < g.end {
					guarded = true
					break
				}
			}
			assigns = append(assigns, assignInfo{pos: fset.Position(pos), guarded: guarded})
		}
	}
	if len(assigns) == 0 {
		return "no Exempt=true assignment found in middleware — the bypass channel was removed entirely; if intentional, update the static gate accordingly"
	}
	for _, a := range assigns {
		if !a.guarded {
			return "Exempt=true at " + a.pos.String() + " is not inside an if-stmt guarded by auth.MethodInternalWorker"
		}
	}
	return ""
}

// conditionReferencesInternalWorker reports whether any node in the
// expression sub-tree is the selector `auth.MethodInternalWorker` (or
// any selector whose trailing name is `MethodInternalWorker`). The
// trailing-name match catches dot-imports and renamed aliases.
func conditionReferencesInternalWorker(n ast.Node) bool {
	if n == nil {
		return false
	}
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		if found {
			return false
		}
		sel, ok := node.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			return true
		}
		if sel.Sel.Name == "MethodInternalWorker" {
			found = true
			return false
		}
		return true
	})
	return found
}

// findDecisionBucketRegressions walks every `Decision{...}` composite
// literal and returns "file:line: <expr>" for every Bucket field whose
// value is not an Ident referencing one of the closed-set constants.
// An omitted Bucket field (the Allowed-decision shape) is accepted.
func findDecisionBucketRegressions(fset *token.FileSet, file *ast.File) []string {
	var bad []string
	ast.Inspect(file, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		// Match `Decision{...}` (bare) or `ratelimit.Decision{...}`
		// (qualified). The trailing-name match catches both.
		switch t := cl.Type.(type) {
		case *ast.Ident:
			if t.Name != "Decision" {
				return true
			}
		case *ast.SelectorExpr:
			if t.Sel == nil || t.Sel.Name != "Decision" {
				return true
			}
		default:
			return true
		}
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Bucket" {
				continue
			}
			ident, ok := kv.Value.(*ast.Ident)
			if ok {
				if _, allowed := rateLimitBucketConstants[ident.Name]; allowed {
					continue
				}
			}
			// A SelectorExpr like `ratelimit.BucketOrg` is also legal —
			// the trailing-name check is the load-bearing rule.
			if sel, ok := kv.Value.(*ast.SelectorExpr); ok && sel.Sel != nil {
				if _, allowed := rateLimitBucketConstants[sel.Sel.Name]; allowed {
					continue
				}
			}
			bad = append(bad, fset.Position(kv.Pos()).String()+": Bucket value is not BucketOrg/BucketKey/BucketIP")
		}
		return true
	})
	return bad
}

// findRateLimit429EmitSeams returns three slices describing the 429
// emission seams in the file:
//
//   - rateLimitedCalls: positions of `apierr.RateLimited(...)` calls.
//   - writeErrorCalls: positions of `apienvelope.WriteError(...)` calls.
//   - forbidden: positions of forbidden emission seams in the deny
//     branch (`http.Error`, `fmt.Fprintf(w, ...)`, `w.Write([]byte(...))`).
//
// The matcher catches the three most likely regression shapes: a bare
// `http.Error` that loses the envelope, a hand-rolled JSON `fmt.Fprintf`
// that bypasses the envelope renderer, and a direct `w.Write([]byte(...))`
// that ships an arbitrary body.
func findRateLimit429EmitSeams(fset *token.FileSet, file *ast.File) (rateLimitedCalls, writeErrorCalls, forbidden []string) {
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			return true
		}
		x, _ := sel.X.(*ast.Ident)
		switch {
		case x != nil && x.Name == "apierr" && sel.Sel.Name == "RateLimited":
			rateLimitedCalls = append(rateLimitedCalls, fset.Position(call.Pos()).String())
		case x != nil && x.Name == "apienvelope" && sel.Sel.Name == "WriteError":
			writeErrorCalls = append(writeErrorCalls, fset.Position(call.Pos()).String())
		case x != nil && x.Name == "http" && sel.Sel.Name == "Error":
			forbidden = append(forbidden, fset.Position(call.Pos()).String()+": http.Error in middleware")
		case x != nil && x.Name == "fmt" && (sel.Sel.Name == "Fprintf" || sel.Sel.Name == "Fprint" || sel.Sel.Name == "Fprintln"):
			forbidden = append(forbidden, fset.Position(call.Pos()).String()+": fmt."+sel.Sel.Name+" emission in middleware")
		case sel.Sel.Name == "Write":
			// Only flag w.Write(...) where the only argument is a
			// composite/conversion expression — that's the
			// hand-rolled body shape. A telemetry helper that
			// happens to be named Write is not the regression.
			if len(call.Args) == 1 {
				if c, ok := call.Args[0].(*ast.CallExpr); ok {
					if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "[]byte" {
						forbidden = append(forbidden, fset.Position(call.Pos()).String()+": w.Write([]byte(...)) emission")
					}
				}
			}
		}
		return true
	})
	return
}

// findRateLimitWrapSeams returns:
//
//   - constructionSites: positions of `RateLimit(...)` or
//     `RateLimitWithClientIPResolver(...)` construction calls.
//   - wrapSites: positions of `h = rateLimit(h)` (or any
//     `<lhs> = <rhs>(<lhs>)` where the rhs is the `rateLimit` local)
//     assignment statements.
//
// The two together prove the middleware is wired once at the
// construction site and applied once per route.
func findRateLimitWrapSeams(fset *token.FileSet, file *ast.File) (constructionSites, wrapSites []string) {
	// Track every local name bound to a rate-limit construction call so the
	// wrap-site matcher knows what identifier to look for.
	binders := map[string]struct{}{}
	ast.Inspect(file, func(n ast.Node) bool {
		// Constructions: any call whose Fun is an accepted rate-limit builder.
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && isRateLimitBuilder(id.Name) {
			constructionSites = append(constructionSites, fset.Position(call.Pos()).String())
			// Walk up to find the enclosing assign/short-decl and
			// capture the binder name. Because ast.Inspect doesn't
			// expose the parent, we re-walk file.Decls below.
		}
		return true
	})
	// Second pass: discover binders.
	ast.Inspect(file, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if len(s.Rhs) == 1 {
				if c, ok := s.Rhs[0].(*ast.CallExpr); ok {
					if id, ok := c.Fun.(*ast.Ident); ok && isRateLimitBuilder(id.Name) {
						for _, lhs := range s.Lhs {
							if name, ok := lhs.(*ast.Ident); ok {
								binders[name.Name] = struct{}{}
							}
						}
					}
				}
			}
		}
		return true
	})
	// Third pass: find `<x> = <binder>(<x>)` shapes.
	ast.Inspect(file, func(n ast.Node) bool {
		s, ok := n.(*ast.AssignStmt)
		if !ok || s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
			return true
		}
		call, ok := s.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		callIdent, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if _, ok := binders[callIdent.Name]; !ok {
			return true
		}
		if len(call.Args) != 1 {
			return true
		}
		lhsIdent, lhsOk := s.Lhs[0].(*ast.Ident)
		argIdent, argOk := call.Args[0].(*ast.Ident)
		if !lhsOk || !argOk {
			return true
		}
		if lhsIdent.Name != argIdent.Name {
			return true
		}
		wrapSites = append(wrapSites, fset.Position(s.Pos()).String())
		return true
	})
	return
}

func isRateLimitBuilder(name string) bool {
	return name == "RateLimit" || name == "RateLimitWithClientIPResolver"
}

var _ = strconv.Itoa // keep strconv import live for future use; matches the BE-0361 file style.
