package validate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// SSRF host blocklist — static-analysis defense (BE-0349).
//
// Threat model: the Yalla Control Plane accepts customer-supplied URLs
// (Git repository URL on a service's build settings; deploy and
// notification webhook URLs on a service's lifecycle hooks) which a
// downstream worker later dereferences without an authenticated identity
// of its own. If those URLs were allowed to point at the loopback
// interface, a link-local cloud-metadata service (the canonical AWS/GCP
// 169.254.169.254 endpoint, the ECS 169.254.170.2 endpoint, the
// `metadata.google.internal` hostname), an RFC1918 private network, or a
// `localhost`/`.internal`/`.local` pseudo-hostname, a tenant could coerce
// the platform into fetching internal credentials, probing intra-cluster
// services, or pivoting to other tenants' workloads.
//
// The validator-layer defence is the `disallowedSSRFHost` helper in
// `ssrf.go`: it inspects the parsed host of a URL and returns a typed,
// value-free violation reason for any host the parser can prove is
// internal — an IP literal in a forbidden range, a known
// non-routable hostname, or a non-routable suffix. The two public
// validators that feed customer-supplied URLs into worker call paths —
// `URL` (notifications and webhooks) and `GitRepoURL` (build repository)
// — MUST funnel their parsed host through that helper. Skipping the
// helper from either site silently re-opens the SSRF surface; the
// validator says "OK" and the worker is left holding the bag.
//
// This is the validator layer only. A second layer of defence must live
// in the HTTP client / git client used by the worker (re-validating the
// resolved IP at fetch time to catch DNS-rebinding attacks where a
// public name resolves to a private IP). The validator catches every
// shape the parser can see without resolving DNS; the runtime catches
// the rest.
//
// The two-test pattern (BE-0344, BE-0345, BE-0346) applies here. The
// static half (`TestSSRFGuardIsCalledFromURLValidators`, this file)
// parses `network.go` and `refs.go`, locates `URL` and `GitRepoURL`,
// and asserts each body contains at least one call to
// `disallowedSSRFHost(...)` — a future change that splits one of these
// validators and forgets the SSRF call fails the build BEFORE the
// regression can ship. The runtime half lives in `ssrf_test.go` (the
// table of blocked / allowed hosts plus the value-free-reason
// invariant). Self-check:
// `TestSSRFGuardStaticAnalyzerDetectsRegressions` feeds synthetic
// known-bad and known-good validators to the analyser and pins both
// directions, so a future change that over-tightens the analyser (false
// positives) or silently under-tightens it (missing call goes
// unflagged) is caught.

// TestSSRFGuardIsCalledFromURLValidators is the load-bearing static
// guard. It parses the two files that own the URL-shaped validators and
// asserts each of those validators calls `disallowedSSRFHost` somewhere
// in its body. A diagnostic is one short string per missing site.
func TestSSRFGuardIsCalledFromURLValidators(t *testing.T) {
	t.Parallel()

	checks := []struct {
		path string
		fn   string
	}{
		{"network.go", "URL"},
		{"refs.go", "GitRepoURL"},
	}
	for _, ch := range checks {
		ch := ch
		t.Run(ch.fn, func(t *testing.T) {
			t.Parallel()
			fset, file := mustParseValidateFile(t, ch.path)
			decl := findFuncDecl(file, ch.fn)
			if decl == nil {
				t.Fatalf("%s: %s function not found — the SSRF guard is vacuous", ch.path, ch.fn)
			}
			if !callsDisallowedSSRFHost(decl) {
				pos := fset.Position(decl.Pos())
				t.Errorf("%s:%d: %s does not call disallowedSSRFHost(...) on its parsed host. "+
					"Every public URL-shaped validator must funnel the parsed host through "+
					"the SSRF blocklist before returning — see AGENTS.md "+
					"\"SSRF protection for webhooks and Git URLs\" for the threat model.",
					pos.Filename, pos.Line, ch.fn)
			}
		})
	}
}

// TestSSRFGuardStaticAnalyzerDetectsRegressions is the self-check for the
// static analyser. It feeds synthetic URL-validator-shaped functions and
// asserts the analyser stays silent on a shape that DOES call the helper,
// fires on a shape that doesn't, and stays silent on a shape that calls a
// look-alike-but-wrong identifier (so the analyser is not just matching
// on string prefix).
func TestSSRFGuardStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		source   string
		funcName string
		want     bool
	}{
		{
			name: "validator that calls disallowedSSRFHost is clean",
			source: `package validate
func URL(c *Collector, field, value string) {
	if reason, blocked := disallowedSSRFHost(value); blocked {
		c.Add(field, reason)
	}
}`,
			funcName: "URL",
			want:     true,
		},
		{
			name: "validator that never calls the helper is flagged",
			source: `package validate
func URL(c *Collector, field, value string) {
	c.Add(field, "no ssrf check")
}`,
			funcName: "URL",
			want:     false,
		},
		{
			name: "validator that calls a look-alike-but-wrong helper is still flagged",
			source: `package validate
func URL(c *Collector, field, value string) {
	// Not the canonical helper — same package, different name.
	if reason, blocked := disallowedHost(value); blocked {
		c.Add(field, reason)
	}
}
func disallowedHost(string) (string, bool) { return "", false }`,
			funcName: "URL",
			want:     false,
		},
		{
			name: "validator that calls the helper inside a nested branch is clean",
			source: `package validate
func GitRepoURL(c *Collector, field, value string) {
	if value != "" {
		if reason, blocked := disallowedSSRFHost(value); blocked {
			c.Add(field, reason)
		}
	}
}`,
			funcName: "GitRepoURL",
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
			if got := callsDisallowedSSRFHost(decl); got != tc.want {
				t.Errorf("callsDisallowedSSRFHost(%s) = %v, want %v", tc.funcName, got, tc.want)
			}
		})
	}
}

// callsDisallowedSSRFHost reports whether the function body of decl
// contains at least one direct call to the package-private
// `disallowedSSRFHost` identifier. The match is exact: a renamed helper
// is treated as a missing call (intentional — the analyser pins the
// identifier so that "I rewrote my own SSRF check" can't silently
// substitute for the audited canonical one).
func callsDisallowedSSRFHost(decl *ast.FuncDecl) bool {
	const want = "disallowedSSRFHost"
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

// TestSSRFHostnameListsAreCanonical is a sealing-trap: it pins the
// contents of the package-private hostname blocklists so a future
// edit that drops a documented entry (e.g. removes `localhost` or
// `metadata.google.internal`) fails the build. New entries are fine —
// the test only checks the documented entries are present.
func TestSSRFHostnameListsAreCanonical(t *testing.T) {
	t.Parallel()
	requiredNames := []string{
		"localhost",
		"ip6-localhost",
		"ip6-loopback",
		"metadata",
		"metadata.google.internal",
		"metadata.aws.internal",
		"169.254.169.254",
	}
	for _, name := range requiredNames {
		if _, ok := forbiddenSSRFHostnames[name]; !ok {
			t.Errorf("forbiddenSSRFHostnames is missing required entry %q", name)
		}
	}
	requiredSuffixes := []string{".localhost", ".internal", ".local", ".localdomain"}
	have := map[string]bool{}
	for _, s := range forbiddenSSRFHostSuffixes {
		have[s] = true
	}
	for _, s := range requiredSuffixes {
		if !have[s] {
			t.Errorf("forbiddenSSRFHostSuffixes is missing required entry %q", s)
		}
	}
	// Suffixes must all start with a dot — a bare suffix would over-match.
	for _, s := range forbiddenSSRFHostSuffixes {
		if len(s) == 0 || s[0] != '.' {
			t.Errorf("forbiddenSSRFHostSuffixes entry %q must begin with a dot to prevent over-matching", s)
		}
	}
	// Stable order helps debug a regression diff — sort and compare against
	// itself to detect a future change that introduces a duplicate.
	seen := map[string]bool{}
	for _, s := range forbiddenSSRFHostSuffixes {
		if seen[s] {
			t.Errorf("forbiddenSSRFHostSuffixes has duplicate entry %q", s)
		}
		seen[s] = true
	}
	sorted := append([]string(nil), forbiddenSSRFHostSuffixes...)
	sort.Strings(sorted)
}
