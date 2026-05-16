package validate_test

import (
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// Domain-takeover prevention — runtime tests (BE-0350).
//
// Companion to the static analyser in `domain_takeover_static_test.go`.
// The static half asserts that `Domain` syntactically calls the
// `disallowedTakeoverHost` helper; this half drives `Domain` with
// concrete attacker-shaped hostnames and proves the helper actually
// rejects the threat-modelled hosts, accepts legitimately-registered
// public hostnames, and never echoes the submitted value (no host
// bleeds back into the FieldViolation reason — a sensitive internal
// label name pasted into the wrong field must not leak through the
// rejection error).
//
// All assertions live in this `_test` package — the runtime tests use
// only the public API surface so the threat model is enforced from the
// caller's point of view, the same way every other handler does.

// blockedDomainHosts is the canonical regression list for
// `validate.Domain`. Each entry is a hostname that the takeover guard
// MUST reject; the categories span every IP-literal form, every
// reserved exact-match name (RFC 6761 / RFC 2606), every shared-hosting
// eTLD, and every reserved suffix. A future change that drops any
// category from `disallowedTakeoverHost` fails the matching subtest by
// name.
// Notes on test-case selection: only hostnames that survive `Domain`'s
// existing FQDN / label-shape checks reach `disallowedTakeoverHost`. A
// single-label hostname (`localhost`, `local`, `lan`, `test`, …) is
// already rejected by the "must be a fully-qualified domain name with at
// least two labels" check BEFORE the takeover guard fires, and an IPv6
// literal (with or without brackets) reduces to a single label after the
// dot-split so it is rejected at the same earlier layer. Those forms are
// still pinned in the `reservedTakeoverHostnames` map (a future change
// that loosens Domain's FQDN check, or a different caller that bypasses
// it, must still trip the takeover guard) — see
// `TestDomainTakeoverListsAreCanonical` — but the runtime regression
// table below restricts itself to inputs that actually pass through the
// helper today, so a missing call site is caught by a failing subtest
// rather than a silently-skipped one.
var blockedDomainHosts = []struct {
	name string
	host string
}{
	// IPv4 literals (dotted four-label form passes the FQDN/label checks).
	{"ipv4 public literal", "1.2.3.4"},
	{"ipv4 loopback literal", "127.0.0.1"},
	{"ipv4 dns literal", "8.8.8.8"},
	{"ipv4 private literal", "192.168.1.1"},
	// Multi-label reserved exact-match (RFC 6761): `home.arpa` is the
	// only special-use name that is multi-label on its own.
	{"reserved home.arpa", "home.arpa"},
	// Reserved suffixes — sub-labels that fall under a reserved namespace.
	// RFC 2606 documentation-only suffixes (`.test`, `.example`, `.invalid`)
	// are intentionally NOT in this list — see the doc on
	// `reservedTakeoverHostSuffixes` for why.
	{".local suffix mDNS", "printer.local"},
	{".internal suffix", "consul.service.internal"},
	{".corp suffix", "intranet.corp"},
	{".home suffix", "router.home"},
	{".home.arpa suffix", "edge.home.arpa"},
	{".lan suffix", "server.lan"},
	{".private suffix", "store.private"},
	{".localhost suffix", "api.localhost"},
	{".localdomain suffix", "host.localdomain"},
	// Shared-hosting eTLDs — bare form is not a single tenant's to claim.
	{"appspot.com bare", "appspot.com"},
	{"azurewebsites.net bare", "azurewebsites.net"},
	{"cloudfront.net bare", "cloudfront.net"},
	{"elasticbeanstalk.com bare", "elasticbeanstalk.com"},
	{"firebaseapp.com bare", "firebaseapp.com"},
	{"github.io bare", "github.io"},
	{"gitlab.io bare", "gitlab.io"},
	{"herokuapp.com bare", "herokuapp.com"},
	{"netlify.app bare", "netlify.app"},
	{"pages.dev bare", "pages.dev"},
	{"vercel.app bare", "vercel.app"},
	{"web.app bare", "web.app"},
}

// publicDomainHosts is the regression-positive list — fully-qualified,
// publicly-registrable hostnames that the takeover guard MUST accept.
// Without these the analyser could be satisfied by a no-op that
// rejected every host, so the runtime test keeps both directions
// honest. Each host is a legitimate registrable form (a customer's own
// subdomain under a shared-hosting eTLD is also fine — only the bare
// suffix is reserved).
var publicDomainHosts = []string{
	"example.com",
	"api.example.com",
	"deep.sub.example.com",
	"acme-corp.io",
	"my-org.dev",
	// Registrable sub-tenants under a shared-hosting eTLD are fine —
	// only the bare suffix is reserved.
	"myapp.appspot.com",
	"acme.github.io",
	"my-thing.vercel.app",
	"static.pages.dev",
	// Public DNS hosting with a TLD that includes a reserved label as a
	// substring but is NOT the reserved label (over-match defence).
	"flocal.example.com",
	"public-internal-services.example.com",
}

// canonicalTakeoverReasons is the closed set of classification strings
// `disallowedTakeoverHost` is allowed to emit. The "value-free" runtime
// invariant is that any rejection reason MUST be a member of this set
// — that is strictly stronger than a substring check, because "the
// reason doesn't contain my host" is a false guarantee when the reason
// legitimately contains words like "domain" or "namespace" as part of
// the documented category text. The set is small and curated; a future
// change that introduces a new classification must add the literal to
// this slice (and to the AGENTS.md doc) so the closure is auditable.
var canonicalTakeoverReasons = []string{
	"must not be an IP address literal — register a hostname instead",
	"must not be a reserved or shared-hosting domain",
	"must not target a reserved or internal-use namespace",
}

func isCanonicalTakeoverReason(s string) bool {
	for _, r := range canonicalTakeoverReasons {
		if s == r {
			return true
		}
	}
	return false
}

func TestDomainRejectsTakeoverTargets(t *testing.T) {
	t.Parallel()
	for _, tt := range blockedDomainHosts {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fields, err := fieldsOf(t, func(c *validate.Collector) {
				validate.Domain(c, "service.hostname", tt.host, validate.DomainOptions{})
			})
			if err == nil {
				t.Fatalf("Domain(%q) was accepted — takeover guard did not fire", tt.host)
			}
			reason, ok := fields["service.hostname"]
			if !ok {
				t.Fatalf("Domain rejection did not record a violation under service.hostname: %v", fields)
			}
			if !isCanonicalTakeoverReason(reason) {
				t.Fatalf("Domain rejection for %q produced a non-canonical takeover reason: %q", tt.host, reason)
			}
		})
	}
}

func TestDomainAcceptsPublicHosts(t *testing.T) {
	t.Parallel()
	for _, host := range publicDomainHosts {
		host := host
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			c := validate.New()
			validate.Domain(c, "service.hostname", host, validate.DomainOptions{})
			if err := c.Err(); err != nil {
				t.Fatalf("Domain(%q) was rejected as if reserved: %v", host, err)
			}
		})
	}
}

func TestDomainRejectsTakeoverTargetsForWildcard(t *testing.T) {
	t.Parallel()
	// Even with wildcards enabled, the takeover guard MUST reject the
	// wildcard form of every reserved exact-match name and every
	// shared-hosting eTLD — a wildcard makes the takeover STRICTLY
	// worse (the bare suffix locks one routing entry; a wildcard locks
	// every sub-tenant of that suffix). Wildcard forms of single-label
	// reserved names are tested as the suffix-match path inside
	// `disallowedTakeoverHost` (`*.local` strips to `local`, then the
	// suffix-match-on-the-final-`v` rule short-circuits via the
	// exact-name set BEFORE the suffix walk).
	wildcardHosts := []string{
		"*.appspot.com",
		"*.github.io",
		"*.vercel.app",
		"*.home.arpa",
	}
	for _, host := range wildcardHosts {
		host := host
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			fields, err := fieldsOf(t, func(c *validate.Collector) {
				validate.Domain(c, "service.hostname", host, validate.DomainOptions{AllowWildcard: true})
			})
			if err == nil {
				t.Fatalf("Domain(%q) was accepted with wildcards enabled — takeover guard did not fire", host)
			}
			reason, ok := fields["service.hostname"]
			if !ok {
				t.Fatalf("Domain rejection did not record a violation under service.hostname: %v", fields)
			}
			if !isCanonicalTakeoverReason(reason) {
				t.Fatalf("Domain wildcard rejection for %q produced a non-canonical reason: %q", host, reason)
			}
		})
	}
}

// TestDomainTakeoverReasonsAreValueFree is the redaction backstop: it
// drives every blocked host through `Domain` and asserts the resulting
// reason is one of the canonical classification strings AND does not
// contain the submitted host as a substring. A regression that quotes
// the host (e.g. via fmt.Sprintf("... %q ...", host)) would fail this
// test without depending on a specific category.
//
// A planted secret canary is included in the input via a sub-label that
// would only ever appear in the reason if a regression interpolated the
// submitted value; the canary is chosen to NOT collide with any word
// in the canonical reasons, so a reason containing it is an
// unambiguous regression.
func TestDomainTakeoverReasonsAreValueFree(t *testing.T) {
	t.Parallel()
	const canary = "takeover-redact-canary-7f3c2a1e-do-not-echo"
	// Drive a hostname that is GUARANTEED to trigger the takeover guard
	// (suffix-match `.internal` or `.local`) AND that embeds the canary
	// as a sub-label — the canary becomes part of the rejected hostname
	// and a reason containing it proves the validator leaked the value.
	hosts := []string{
		canary + ".local",
		canary + ".internal",
		"deep." + canary + ".lan",
	}
	for _, host := range hosts {
		host := host
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			fields, err := fieldsOf(t, func(c *validate.Collector) {
				validate.Domain(c, "service.hostname", host, validate.DomainOptions{})
			})
			if err == nil {
				t.Fatalf("Domain(%q) was accepted — takeover guard did not fire", host)
			}
			reason := fields["service.hostname"]
			if !isCanonicalTakeoverReason(reason) {
				t.Fatalf("Domain rejection for %q produced a non-canonical reason: %q", host, reason)
			}
			if strings.Contains(reason, canary) {
				t.Fatalf("Domain reason leaked the submitted hostname: %q", reason)
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("Domain error wrapper leaked the submitted hostname: %v", err)
			}
		})
	}
}

// TestDomainTakeoverEmptyHostKeepsExistingDiagnostic pins the
// order-of-precedence: `Domain("")` returns the existing
// "must not be blank" diagnostic, not a takeover diagnostic. The
// takeover helper is well-behaved on the degenerate empty-string host
// and returns false, so the surface error stays the existing
// presence-check one.
func TestDomainTakeoverEmptyHostKeepsExistingDiagnostic(t *testing.T) {
	t.Parallel()
	fields, err := fieldsOf(t, func(c *validate.Collector) {
		validate.Domain(c, "service.hostname", "", validate.DomainOptions{})
	})
	if err == nil {
		t.Fatalf("Domain with empty host was accepted")
	}
	reason := fields["service.hostname"]
	if reason != "must not be blank" {
		t.Fatalf("empty host produced an unexpected reason: %q", reason)
	}
	if isCanonicalTakeoverReason(reason) {
		t.Fatalf("empty host must not trip the takeover guard: %q", reason)
	}
}
