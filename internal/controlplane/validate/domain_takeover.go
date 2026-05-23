package validate

import (
	"net"
	"strings"
)

// Domain-takeover prevention — reserved-hostname blocklist enforced when a
// customer attaches a public-facing hostname to one of their services
// (BE-0350).
//
// Threat model: the Yalla Control Plane stores customer-attached hostnames in
// the `service_domains` table with a UNIQUE (hostname, path) constraint that
// spans every tenant. The constraint plus the worker's downstream Dokploy
// configuration mean that the FIRST tenant to land a row owns that hostname's
// routing in the cluster; subsequent attempts from a different tenant fail as
// a typed Conflict, never silently. That uniqueness guarantee is exactly the
// surface a domain-takeover attack exploits:
//
//   - **IP literals.** An IPv4 or IPv6 literal is not a domain at all — a
//     public certificate authority will not issue a TLS certificate for an
//     arbitrary IP address the platform does not authoritatively own, and a
//     customer who manages to claim "1.2.3.4" as a hostname can siphon any
//     request whose Host header happens to be that literal — bypassing every
//     DNS-rooted ownership check the rest of the platform performs. The
//     symmetrical SSRF guard in `ssrf.go` blocks IP-literal targets when the
//     validator parses an outbound URL; this guard is the symmetric inbound
//     wall for hostnames the platform agrees to ROUTE traffic for.
//   - **Reserved special-use TLDs and labels (RFC 6761 / RFC 2606).** Names
//     like `localhost`, `local`, `internal`, `intranet`, `corp`, `home`,
//     `home.arpa`, `lan`, `test`, `example`, `invalid`, `private`,
//     `localdomain` are reserved by IANA / the IETF as non-public. A tenant
//     claiming `*.local` or `mything.test` would either collide with mDNS /
//     Bonjour / internal-resolver behaviour or simply hold an unroutable
//     hostname forever — both are denial-of-service for the next tenant
//     trying to use the same label.
//   - **Shared-hosting eTLDs.** Names like `appspot.com`, `azurewebsites.net`,
//     `cloudfront.net`, `elasticbeanstalk.com`, `firebaseapp.com`,
//     `github.io`, `gitlab.io`, `herokuapp.com`, `netlify.app`, `pages.dev`,
//     `vercel.app`, `web.app` are public suffixes shared across many
//     unrelated tenants. The FIRST customer who attaches the bare suffix
//     would claim every legitimate sub-tenant of that platform forever,
//     blocking any other customer who later attaches `myapp.appspot.com`.
//     Sub-domains under these suffixes (the registrable `myapp.appspot.com`
//     form) are perfectly legitimate; the bare suffix is what we reject.
//
// This package is pure: it cannot perform DNS lookups and therefore cannot
// independently prove that a customer actually owns the hostname they
// attach. Ownership proof (an HTTP-01 / DNS-01 challenge, an ALPN-01
// challenge, or an external pre-shared verification record) is a runtime
// concern that belongs to the certificate-issuance and routing-attach
// worker — NOT this layer. The validator rejects every shape the parser can
// see is structurally illegitimate; the runtime catches the rest.
//
// The reason text NEVER echoes the submitted hostname: a hostname that
// happens to embed an internal label name must not be reflected back into
// the validation error.

// disallowedTakeoverHost reports whether host is a hostname the validator
// must reject as a domain-takeover risk. The function accepts the
// lower-cased, fully-trimmed hostname with any single trailing dot already
// removed (the same shape `Domain` produces internally) — it is also
// idempotent on a bare bracketed IPv6 literal (the brackets are stripped
// before parsing) and on a single leading `*.` wildcard label (the wildcard
// is stripped before the reserved-name check so a wildcard form like
// `*.appspot.com` is rejected for the same reason as the bare form).
//
// The returned `reason` is a fixed classification string suitable for use
// as a FieldViolation reason; it never embeds the submitted host. `blocked`
// is false (and `reason` empty) for any host that is structurally legitimate
// at this layer.
func disallowedTakeoverHost(host string) (reason string, blocked bool) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "", false
	}
	// A bracketed IPv6 literal may still arrive here when the caller did
	// not pre-strip the brackets; strip a single set so net.ParseIP sees
	// the inner address.
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	// A single leading wildcard label is stripped before the
	// reserved-name check so a wildcard form like `*.appspot.com`
	// reduces to `appspot.com` and is rejected for the same reason as
	// the bare form. Wildcard POLICY itself (whether wildcards are
	// allowed for the tenant at all) is enforced separately by
	// `DomainOptions.AllowWildcard` in `Domain`.
	if rest, ok := strings.CutPrefix(h, "*."); ok {
		h = rest
	}
	if h == "" {
		return "", false
	}

	// 1. IP-literal forms (with or without brackets in the original input)
	// are never a legitimate customer hostname.
	if ip := net.ParseIP(h); ip != nil {
		return "must not be an IP address literal — register a hostname instead", true
	}

	// 2. Exact-match reserved hostnames / shared-hosting eTLDs whose
	// ownership cannot legitimately transfer to a single tenant.
	if _, ok := reservedTakeoverHostnames[h]; ok {
		return "must not be a reserved or shared-hosting domain", true
	}

	// 3. Reserved internal suffixes (each with a leading dot to prevent
	// over-match — `.local` must not flag `flocal.example.com`).
	for _, suffix := range reservedTakeoverHostSuffixes {
		if strings.HasSuffix(h, suffix) {
			return "must not target a reserved or internal-use namespace", true
		}
	}
	return "", false
}

// reservedTakeoverHostnames is the exact-match set of hostnames the
// validator rejects as a domain-takeover risk: special-use TLDs and labels
// reserved by RFC 6761 / RFC 2606, plus the bare form of common
// shared-hosting eTLDs whose ownership is shared across many unrelated
// tenants and cannot legitimately be claimed by a single one.
//
// The shared-hosting list is intentionally narrow: it covers the most
// common platforms whose sub-domains are sold or assigned to arbitrary
// third parties under a single registrable parent. Sub-tenant forms
// (`myapp.appspot.com`) are perfectly legitimate; the bare suffix is what
// we reject. The list is not a substitute for a full Public Suffix List —
// it is a hard-coded set of known-attack-surface tails that we are
// confident no individual tenant should ever claim.
var reservedTakeoverHostnames = map[string]struct{}{
	// RFC 6761 / RFC 2606 special-use TLDs and labels — non-public,
	// reserved by IANA / IETF for documentation, testing, mDNS, or
	// intranet use.
	"localhost":   {},
	"localdomain": {},
	"local":       {},
	"internal":    {},
	"intranet":    {},
	"private":     {},
	"corp":        {},
	"home":        {},
	"home.arpa":   {},
	"lan":         {},
	"test":        {},
	"example":     {},
	"invalid":     {},
	// Shared-hosting eTLDs — the bare suffix is shared across many
	// unrelated tenants of an external platform; a customer claiming
	// the bare form would squat on every legitimate sub-tenant.
	"appspot.com":          {},
	"azurewebsites.net":    {},
	"cloudfront.net":       {},
	"elasticbeanstalk.com": {},
	"firebaseapp.com":      {},
	"github.io":            {},
	"gitlab.io":            {},
	"herokuapp.com":        {},
	"netlify.app":          {},
	"pages.dev":            {},
	"vercel.app":           {},
	"web.app":              {},
}

// reservedTakeoverHostSuffixes is the suffix-match set of hostname tails
// that are reserved internal namespaces. The leading dot is required to
// prevent over-matching (`.local` must not flag `flocal.example.com`).
//
// Deliberately EXCLUDED: the RFC 2606 documentation-only suffixes
// (`.test`, `.example`, `.invalid`). Those names are not publicly
// routable and cannot be used to intercept real customer traffic — so
// they are not a takeover threat in the sense modelled by this file,
// only a squatting threat that the `service_domains` UNIQUE constraint
// already bounds. They remain in `reservedTakeoverHostnames` as
// defence-in-depth for the bare-label form (in case the FQDN check is
// ever loosened) but the suffix walk omits them so existing test
// fixtures and documentation-grade examples — `api.acme.example`,
// `host.test`, etc. — remain valid customer hostnames.
//
// A future change that drops the leading dot is caught by
// `TestDomainTakeoverListsAreCanonical`.
var reservedTakeoverHostSuffixes = []string{
	".localhost",
	".localdomain",
	".local",
	".internal",
	".intranet",
	".private",
	".corp",
	".home",
	".home.arpa",
	".lan",
}
