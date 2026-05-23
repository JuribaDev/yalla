package validate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// Domain-takeover prevention — static-analysis defence (BE-0350).
//
// Threat model: the Yalla Control Plane stores customer-attached hostnames
// in the `service_domains` table behind a UNIQUE (hostname, path)
// constraint that spans every tenant. The FIRST tenant to land a row owns
// the routing for that hostname in the entire cluster. That uniqueness is
// the exact lever a domain-takeover attack pulls: an IP literal, a
// reserved special-use TLD (RFC 6761 / RFC 2606), or the bare form of a
// shared-hosting eTLD (`appspot.com`, `github.io`, `vercel.app`, etc.) can
// each let one tenant permanently lock a hostname that does not
// legitimately belong to them — either denying it to every other tenant
// forever, or (worse) siphoning a Host-header-routed request they were
// never authorised to receive.
//
// The validator-layer defence is the `disallowedTakeoverHost` helper in
// `domain_takeover.go`: it accepts a lower-cased, trimmed, optionally
// wildcard-stripped hostname and returns a typed, value-free violation
// reason for any host the parser can prove is structurally illegitimate
// — an IP literal, a reserved exact-match name, or a reserved suffix. The
// single public validator that feeds customer-supplied hostnames into the
// service-domain attach path — `Domain` in `network.go` — MUST funnel its
// final, stripped hostname through that helper. Skipping the helper
// silently re-opens the takeover surface; the validator says "OK" and the
// next layer down (`service_domains` insert) commits the row.
//
// This is the validator layer only. Ownership PROOF (HTTP-01 / DNS-01 /
// ALPN-01 challenge, or an external pre-shared verification record) must
// live in the certificate-issuance and routing-attach worker — the
// validator only catches the shapes the parser can prove are illegitimate
// without doing I/O.
//
// The two-test pattern (BE-0344, BE-0345, BE-0346, BE-0349) applies here.
// The static half (`TestDomainTakeoverGuardIsCalledFromDomainValidator`,
// this file) parses `network.go`, locates `Domain`, and asserts the body
// contains at least one call to `disallowedTakeoverHost(...)` — a future
// change that splits `Domain` and forgets the takeover call fails the
// build BEFORE the regression can ship. The runtime half lives in
// `domain_takeover_test.go` (the table of blocked / accepted hosts plus
// the value-free-reason invariant). Self-check:
// `TestDomainTakeoverGuardStaticAnalyzerDetectsRegressions` feeds
// synthetic known-bad and known-good validators to the analyser and pins
// both directions, so a future change that over-tightens the analyser
// (false positives) or silently under-tightens it (missing call goes
// unflagged) is caught.

// TestDomainTakeoverGuardIsCalledFromDomainValidator is the load-bearing
// static guard. It parses `network.go`, locates `Domain`, and asserts the
// body contains at least one call to `disallowedTakeoverHost` somewhere in
// its body. A diagnostic is one short string per missing site.
func TestDomainTakeoverGuardIsCalledFromDomainValidator(t *testing.T) {
	t.Parallel()

	checks := []struct {
		path string
		fn   string
	}{
		{"network.go", "Domain"},
	}
	for _, ch := range checks {
		ch := ch
		t.Run(ch.fn, func(t *testing.T) {
			t.Parallel()
			fset, file := mustParseValidateFile(t, ch.path)
			decl := findFuncDecl(file, ch.fn)
			if decl == nil {
				t.Fatalf("%s: %s function not found — the domain-takeover guard is vacuous", ch.path, ch.fn)
			}
			if !callsDisallowedTakeoverHost(decl) {
				pos := fset.Position(decl.Pos())
				t.Errorf("%s:%d: %s does not call disallowedTakeoverHost(...) on its parsed host. "+
					"Every public customer-domain validator must funnel the final hostname through "+
					"the takeover blocklist before returning — see AGENTS.md "+
					"\"Domain-takeover prevention\" for the threat model.",
					pos.Filename, pos.Line, ch.fn)
			}
		})
	}
}

// TestDomainTakeoverGuardStaticAnalyzerDetectsRegressions is the
// self-check for the static analyser. It feeds synthetic Domain-shaped
// functions and asserts the analyser stays silent on a shape that DOES
// call the helper, fires on a shape that doesn't, and stays silent on a
// shape that calls a look-alike-but-wrong identifier (so the analyser is
// not just matching on string prefix).
func TestDomainTakeoverGuardStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		source   string
		funcName string
		want     bool
	}{
		{
			name: "validator that calls disallowedTakeoverHost is clean",
			source: `package validate
func Domain(c *Collector, field, value string, opts DomainOptions) {
	if reason, blocked := disallowedTakeoverHost(value); blocked {
		c.Add(field, reason)
	}
}`,
			funcName: "Domain",
			want:     true,
		},
		{
			name: "validator that never calls the helper is flagged",
			source: `package validate
func Domain(c *Collector, field, value string, opts DomainOptions) {
	c.Add(field, "no takeover check")
}`,
			funcName: "Domain",
			want:     false,
		},
		{
			name: "validator that calls a look-alike-but-wrong helper is still flagged",
			source: `package validate
func Domain(c *Collector, field, value string, opts DomainOptions) {
	// Not the canonical helper — same package, different name.
	if reason, blocked := disallowedHost(value); blocked {
		c.Add(field, reason)
	}
}
func disallowedHost(string) (string, bool) { return "", false }`,
			funcName: "Domain",
			want:     false,
		},
		{
			name: "validator that calls the helper inside a nested branch is clean",
			source: `package validate
func Domain(c *Collector, field, value string, opts DomainOptions) {
	if value != "" {
		if reason, blocked := disallowedTakeoverHost(value); blocked {
			c.Add(field, reason)
		}
	}
}`,
			funcName: "Domain",
			want:     true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse synthetic source: %v", err)
			}
			decl := findFuncDecl(file, tc.funcName)
			if decl == nil {
				t.Fatalf("synthetic source has no %s function", tc.funcName)
			}
			if got := callsDisallowedTakeoverHost(decl); got != tc.want {
				t.Errorf("callsDisallowedTakeoverHost(%s) = %v, want %v", tc.funcName, got, tc.want)
			}
		})
	}
}

// callsDisallowedTakeoverHost reports whether the function body of decl
// contains at least one direct call to the package-private
// `disallowedTakeoverHost` identifier. The match is exact: a renamed
// helper is treated as a missing call (intentional — the analyser pins
// the identifier so that "I rewrote my own takeover check" can't
// silently substitute for the audited canonical one).
func callsDisallowedTakeoverHost(decl *ast.FuncDecl) bool {
	const want = "disallowedTakeoverHost"
	var found bool
	ast.Inspect(decl, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			if fun.Name == want {
				found = true
			}
		case *ast.SelectorExpr:
			if fun.Sel != nil && fun.Sel.Name == want {
				found = true
			}
		}
		return !found
	})
	return found
}

// TestDomainTakeoverListsAreCanonical is a sealing-trap: it pins the
// contents of the package-private reserved-hostname blocklists so a
// future edit that drops a documented entry (e.g. removes `localhost`
// or `appspot.com`) fails the build. New entries are fine — the test
// only checks the documented entries are present and that every suffix
// keeps its leading dot.
func TestDomainTakeoverListsAreCanonical(t *testing.T) {
	t.Parallel()
	requiredNames := []string{
		// RFC 6761 / RFC 2606 special-use names — non-public, reserved.
		"localhost",
		"localdomain",
		"local",
		"internal",
		"intranet",
		"private",
		"corp",
		"home",
		"home.arpa",
		"lan",
		"test",
		"example",
		"invalid",
		// Shared-hosting eTLDs — bare form must never be a single tenant's.
		"appspot.com",
		"azurewebsites.net",
		"cloudfront.net",
		"elasticbeanstalk.com",
		"firebaseapp.com",
		"github.io",
		"gitlab.io",
		"herokuapp.com",
		"netlify.app",
		"pages.dev",
		"vercel.app",
		"web.app",
	}
	for _, name := range requiredNames {
		if _, ok := reservedTakeoverHostnames[name]; !ok {
			t.Errorf("reservedTakeoverHostnames is missing required entry %q", name)
		}
	}
	requiredSuffixes := []string{
		".localhost", ".localdomain", ".local",
		".internal", ".intranet", ".private",
		".corp", ".home", ".home.arpa", ".lan",
	}
	have := map[string]bool{}
	for _, s := range reservedTakeoverHostSuffixes {
		have[s] = true
	}
	for _, s := range requiredSuffixes {
		if !have[s] {
			t.Errorf("reservedTakeoverHostSuffixes is missing required entry %q", s)
		}
	}
	// Suffixes must all start with a dot — a bare suffix would over-match.
	for _, s := range reservedTakeoverHostSuffixes {
		if len(s) == 0 || s[0] != '.' {
			t.Errorf("reservedTakeoverHostSuffixes entry %q must begin with a dot to prevent over-matching", s)
		}
	}
	// Detect a future change that introduces a duplicate suffix.
	seen := map[string]bool{}
	for _, s := range reservedTakeoverHostSuffixes {
		if seen[s] {
			t.Errorf("reservedTakeoverHostSuffixes has duplicate entry %q", s)
		}
		seen[s] = true
	}
	sorted := append([]string(nil), reservedTakeoverHostSuffixes...)
	sort.Strings(sorted)
}
