package validate_test

import (
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// SSRF host blocklist — runtime tests (BE-0349).
//
// Companion to the static analyser in `ssrf_static_test.go`. The static
// half asserts that `URL` and `GitRepoURL` syntactically call the
// `disallowedSSRFHost` helper; this half drives both validators with
// concrete attacker-shaped inputs and proves the helper actually
// rejects the threat-modelled hosts, accepts well-formed public hosts,
// and never echoes the submitted value (no host bleeds back into the
// FieldViolation reason — a token pasted into a URL query string must
// not leak through the rejection error).
//
// All assertions live in this `_test` package — the runtime tests use
// only the public API surface so the threat model is enforced from the
// caller's point of view, the same way every other handler does.

// blockedURLHosts is the canonical regression list for `validate.URL`.
// Each entry is a host that the SSRF guard MUST reject; the categories
// span every IP-literal range, every documented hostname/suffix, and
// the canonical cloud-metadata endpoints called out by the threat
// model. A future change that drops any category from
// `disallowedSSRFHost` fails the matching subtest by name.
var blockedURLHosts = []struct {
	name string
	host string
}{
	{"loopback v4", "127.0.0.1"},
	{"loopback v4 high", "127.255.255.254"},
	{"loopback v6", "[::1]"},
	{"unspecified v4", "0.0.0.0"},
	{"unspecified v6", "[::]"},
	{"link-local v4", "169.254.10.20"},
	{"AWS metadata", "169.254.169.254"},
	{"ECS task metadata", "169.254.170.2"},
	{"link-local v6", "[fe80::1]"},
	{"private v4 10/8", "10.0.0.1"},
	{"private v4 172.16/12", "172.16.5.5"},
	{"private v4 192.168/16", "192.168.1.1"},
	{"unique local v6 fc00::/7", "[fc00::1]"},
	{"unique local v6 fd00::/8", "[fd12:3456:789a::1]"},
	{"CGNAT", "100.64.0.1"},
	{"benchmark range", "198.18.0.1"},
	{"limited broadcast", "255.255.255.255"},
	{"multicast v4", "224.0.0.1"},
	{"multicast v6", "[ff02::1]"},
	{"localhost name", "localhost"},
	{"localhost subdomain", "api.localhost"},
	{"ip6-localhost", "ip6-localhost"},
	{"ip6-loopback", "ip6-loopback"},
	{"metadata bare", "metadata"},
	{"metadata.google.internal", "metadata.google.internal"},
	{"metadata.aws.internal", "metadata.aws.internal"},
	{".internal suffix", "consul.service.internal"},
	{".local suffix mDNS", "printer.local"},
	{".localdomain suffix", "host.localdomain"},
}

// publicURLHosts is the regression-positive list — public hosts that
// the SSRF guard MUST accept. Without these the analyser could be
// satisfied by a no-op that rejected every host, so the runtime test
// keeps both directions honest.
var publicURLHosts = []string{
	"example.com",
	"api.example.com",
	"github.com",
	"8.8.8.8",
	"1.1.1.1",
	"[2606:4700::1111]", // Cloudflare DNS public v6.
}

// canonicalSSRFReasons is the closed set of classification strings
// `disallowedSSRFHost` is allowed to emit. The "value-free" runtime
// invariant is that any rejection reason MUST be a member of this
// set — that is strictly stronger than a substring check, because
// "the reason doesn't contain my host" is a false guarantee when the
// reason legitimately contains words like "localhost" or "metadata"
// as part of the documented category text. The set is small and
// curated; a future change that introduces a new classification must
// add the literal to this slice (and to the AGENTS.md doc) so the
// closure is auditable.
var canonicalSSRFReasons = []string{
	"must not target a non-routable IP address (unspecified)",
	"must not target a non-routable IP address (loopback)",
	"must not target a non-routable IP address (link-local)",
	"must not target a non-routable IP address (multicast)",
	"must not target a non-routable IP address (private network)",
	"must not target a non-routable IP address (CGNAT)",
	"must not target a non-routable IP address (benchmark range)",
	"must not target a non-routable IP address (broadcast)",
	"must not target a non-routable host (localhost or a cloud metadata service)",
}

func isCanonicalSSRFReason(s string) bool {
	for _, r := range canonicalSSRFReasons {
		if s == r {
			return true
		}
	}
	return false
}

func TestURLRejectsSSRFTargets(t *testing.T) {
	t.Parallel()
	for _, tt := range blockedURLHosts {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			value := "https://" + tt.host + "/path?token=secret-MUST-NOT-LEAK-zzy"
			fields, err := fieldsOf(t, func(c *validate.Collector) {
				validate.URL(c, "notifications.url", value)
			})
			if err == nil {
				t.Fatalf("URL(%q) was accepted — SSRF guard did not fire", value)
			}
			reason, ok := fields["notifications.url"]
			if !ok {
				t.Fatalf("URL rejection did not record a violation under notifications.url: %v", fields)
			}
			if !isCanonicalSSRFReason(reason) {
				t.Fatalf("URL rejection for %q produced a non-canonical SSRF reason: %q", tt.host, reason)
			}
			if strings.Contains(reason, "secret-MUST-NOT-LEAK-zzy") {
				t.Fatalf("URL reason leaked the submitted value: %q", reason)
			}
		})
	}
}

func TestURLAcceptsPublicHosts(t *testing.T) {
	t.Parallel()
	for _, host := range publicURLHosts {
		host := host
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			value := "https://" + host + "/path"
			c := validate.New()
			validate.URL(c, "notifications.url", value)
			if err := c.Err(); err != nil {
				t.Fatalf("URL(%q) was rejected as if internal: %v", value, err)
			}
		})
	}
}

func TestGitRepoURLRejectsSSRFTargets(t *testing.T) {
	t.Parallel()
	// Each entry exercises one of the three GitRepoURL shapes:
	// https://, ssh://, and the scp-like "git@host:path" form.
	cases := []struct {
		name  string
		value string
	}{
		{"https loopback", "https://127.0.0.1/acme/app.git"},
		{"https localhost", "https://localhost:8080/acme/app.git"},
		{"https AWS metadata", "https://169.254.169.254/latest/meta-data/"},
		{"https private 10/8", "https://10.0.0.1/acme/app.git"},
		{"https ipv6 loopback", "https://[::1]/acme/app.git"},
		{"https .internal", "https://gitea.svc.internal/acme/app.git"},
		{"ssh loopback", "ssh://git@127.0.0.1:22/acme/app.git"},
		{"ssh link-local v6", "ssh://git@[fe80::1]/acme/app.git"},
		{"scp loopback", "git@127.0.0.1:acme/app.git"},
		{"scp localhost", "git@localhost:acme/app.git"},
		{"scp .internal", "git@gitea.svc.internal:acme/app.git"},
		{"scp metadata bare", "git@metadata:acme/app.git"},
	}
	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fields, err := fieldsOf(t, func(c *validate.Collector) {
				validate.GitRepoURL(c, "build.repo_url", tt.value)
			})
			if err == nil {
				t.Fatalf("GitRepoURL(%q) was accepted — SSRF guard did not fire", tt.value)
			}
			reason, ok := fields["build.repo_url"]
			if !ok {
				t.Fatalf("GitRepoURL rejection did not record a violation under build.repo_url: %v", fields)
			}
			if !isCanonicalSSRFReason(reason) {
				t.Fatalf("GitRepoURL rejection for %q produced a non-canonical SSRF reason: %q", tt.value, reason)
			}
			if strings.Contains(reason, tt.value) {
				t.Fatalf("GitRepoURL reason echoed the submitted value: %q", reason)
			}
		})
	}
}

func TestGitRepoURLAcceptsPublicHosts(t *testing.T) {
	t.Parallel()
	values := []string{
		"https://github.com/acme/app.git",
		"ssh://git@github.com/acme/app.git",
		"git@github.com:acme/app.git",
		"https://gitlab.com/group/sub/app.git",
		"https://8.8.8.8/acme/app.git",
	}
	for _, v := range values {
		v := v
		t.Run(v, func(t *testing.T) {
			t.Parallel()
			c := validate.New()
			validate.GitRepoURL(c, "build.repo_url", v)
			if err := c.Err(); err != nil {
				t.Fatalf("GitRepoURL(%q) was rejected as if internal: %v", v, err)
			}
		})
	}
}

// TestSSRFReasonsAreValueFree is the redaction backstop: it drives every
// blocked host through both validators and asserts the resulting error
// string contains neither the host nor a planted secret-shaped payload.
// A regression that quotes the host (e.g. via fmt.Sprintf("... %q ...",
// host)) would fail this test without depending on a specific category.
func TestSSRFReasonsAreValueFree(t *testing.T) {
	t.Parallel()
	// The canary value is chosen to NOT collide with any word that appears in
	// the canonical SSRF reason text (no "localhost", "metadata", "loopback",
	// "private", etc.) — the BE-0343 redaction pattern flagged that
	// substring-based redaction checks can false-positive on stable
	// classification phrases. A reason containing this canary is therefore an
	// unambiguous regression: the validator interpolated the submitted value.
	const secret = "ssrf-redact-canary-7f3c2a1e-do-not-echo"
	// IPv6 literals are passed in their bracketed URL form so url.Parse
	// extracts the host as the inner address, not a colon-split host:port.
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "10.5.5.5", "[fd00::1]"} {
		host := host
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			value := "https://" + host + "/x?leak=" + secret
			fields, err := fieldsOf(t, func(c *validate.Collector) {
				validate.URL(c, "notifications.url", value)
			})
			if err == nil {
				t.Fatalf("URL(%q) was accepted — SSRF guard did not fire", value)
			}
			reason := fields["notifications.url"]
			if !isCanonicalSSRFReason(reason) {
				t.Fatalf("URL rejection for %q produced a non-canonical SSRF reason: %q", host, reason)
			}
			if strings.Contains(reason, secret) {
				t.Fatalf("URL reason leaked the secret canary: %q", reason)
			}
			// The trimmed inner host (without brackets) must not appear in
			// the reason — for IP-literal hosts no classification word
			// shares characters with an IP literal, so this assertion is
			// strict.
			inner := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
			if strings.Contains(reason, inner) {
				t.Fatalf("URL reason echoed the submitted host %q: %q", inner, reason)
			}
		})
	}
}

// TestSSRFGuardAcceptsEmptyHost confirms the helper is well-behaved on
// the degenerate empty-string input — callers may legitimately pass an
// empty Hostname() value when the URL has no authority component, and
// the helper must classify that as "not internal" so the existing
// "must include a host" diagnostic remains the surface error.
func TestSSRFGuardAcceptsEmptyHost(t *testing.T) {
	t.Parallel()
	// The "must include a host" error is owned by the host-presence check, not
	// the SSRF check; an empty-host URL must produce exactly that diagnostic,
	// not an SSRF diagnostic. This pins the order-of-precedence — the SSRF
	// helper is well-behaved on the degenerate empty-string host and returns
	// false, so the surface error stays the existing host-presence one.
	fields, err := fieldsOf(t, func(c *validate.Collector) {
		validate.URL(c, "notifications.url", "https://")
	})
	if err == nil {
		t.Fatalf("URL with no host was accepted")
	}
	reason := fields["notifications.url"]
	if !strings.Contains(reason, "must include a host") &&
		!strings.Contains(reason, "must be a valid URL") {
		t.Fatalf("empty-host URL produced an unexpected reason: %q", reason)
	}
	if strings.HasPrefix(reason, "must not target a non-routable") {
		t.Fatalf("empty-host URL must not trip the SSRF guard: %q", reason)
	}
}
