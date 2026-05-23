package validate

import (
	"net"
	"net/url"
	"strings"
)

// SSRF host blocklist — server-side request forgery defence at the validation
// layer (BE-0349).
//
// Threat model: the Yalla Control Plane accepts customer-supplied URLs (Git
// repository URL, deploy/notification webhook URL) that downstream code paths
// later dereference — the build worker clones the repo URL, the notification
// dispatcher posts to the webhook URL. If those URLs were allowed to point at
// internal addresses, a tenant could coerce the platform into making
// unauthenticated requests to:
//
//   - the loopback interface, where unauthenticated admin/debug surfaces of
//     Yalla, Dokploy, or sidecar processes commonly live;
//   - link-local addresses, in particular the cloud metadata services at
//     169.254.169.254 (AWS, GCP, Azure, OpenStack), 169.254.170.2 (ECS task
//     metadata) and metadata.{google,aws}.internal hostnames that hand out
//     short-lived workload credentials over plain HTTP;
//   - RFC1918 / CGNAT / unique-local IPv6 ranges, where intra-cluster control
//     planes (Dokploy itself, Postgres, Redis, internal HTTP services) listen
//     without internet-facing auth;
//   - unspecified / multicast / broadcast addresses, which are not valid
//     external destinations and almost always indicate a host that resolves
//     locally;
//   - non-routable pseudo-hostnames (`localhost`, `.internal`, `.local`) that
//     a downstream resolver would map onto one of the above.
//
// This package is pure: it cannot perform DNS lookups and therefore cannot
// catch a DNS-rebinding attack where a public name resolves to a private IP
// at fetch time. That second layer of defence must live in the actual HTTP
// client / git client used by the worker (the runtime must re-validate the
// resolved address before connecting). The validator layer rejects everything
// the parser can see is internal — the union of (a) IP-literal hosts in the
// forbidden ranges below and (b) a small closed set of hostname/suffix
// patterns that are by definition not externally routable.
//
// The reason text NEVER echoes the submitted value: a webhook URL that
// happens to contain a query-string secret must not be reflected back into
// the validation error.

// disallowedSSRFHost reports whether host is a host the validator must reject
// at parse time as an SSRF target. It accepts either the bare host (no port,
// no brackets) from a URL — e.g. `u.Hostname()` for an `https://` form — or
// the bare host extracted from the scp-like `git@host:path` form. The function
// is allocation-light and side-effect free: it performs no DNS lookups and
// does not mutate any package-level state.
//
// The returned `reason` is a fixed classification string suitable for use as
// a FieldViolation reason; it never embeds the submitted host. `blocked` is
// false (and `reason` empty) for any host the parser cannot prove is
// internal — those hosts pass this layer and must be re-validated at fetch
// time against the resolved IP address.
func disallowedSSRFHost(host string) (reason string, blocked bool) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "", false
	}
	// A bracketed IPv6 literal may still arrive here when the caller
	// extracted the host from a non-URL form; strip a single set of
	// surrounding brackets so net.ParseIP sees the inner address.
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	h = strings.ToLower(h)

	// IP-literal forms are checked first: an IP literal cannot be made safe by
	// a downstream resolver, so a private/loopback/link-local literal is
	// unconditionally rejected.
	if ip := net.ParseIP(h); ip != nil {
		if r, ok := ipReason(ip); ok {
			return r, true
		}
		return "", false
	}

	// Hostname forms are checked against a small closed set of names and
	// suffixes that are by definition not externally routable. The list is
	// intentionally tight — the goal is to reject names a downstream DNS
	// resolver would map onto a private/loopback address, not to police
	// externally registered domains.
	if _, ok := forbiddenSSRFHostnames[h]; ok {
		return "must not target a non-routable host (localhost or a cloud metadata service)", true
	}
	for _, suffix := range forbiddenSSRFHostSuffixes {
		if strings.HasSuffix(h, suffix) {
			return "must not target a non-routable host (localhost or a cloud metadata service)", true
		}
	}
	return "", false
}

// ipReason returns a fixed classification reason for an IP literal that falls
// in one of the SSRF-forbidden ranges, or the zero value when the address is
// not known-internal. The reason text is value-free: callers can safely
// surface it through a FieldViolation without leaking the submitted host.
func ipReason(ip net.IP) (string, bool) {
	switch {
	case ip.IsUnspecified():
		// 0.0.0.0 / :: — never a valid external destination.
		return "must not target a non-routable IP address (unspecified)", true
	case ip.IsLoopback():
		// 127.0.0.0/8, ::1 — the local host's services.
		return "must not target a non-routable IP address (loopback)", true
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		// 169.254.0.0/16 (incl. 169.254.169.254 cloud metadata) and fe80::/10.
		return "must not target a non-routable IP address (link-local)", true
	case ip.IsMulticast():
		// 224.0.0.0/4 and ff00::/8 — not a unicast destination.
		return "must not target a non-routable IP address (multicast)", true
	case ip.IsPrivate():
		// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7.
		return "must not target a non-routable IP address (private network)", true
	}
	// IPv4 ranges Go's stdlib does not classify as "private" but which are
	// equally not external destinations: 100.64.0.0/10 (CGNAT, RFC6598) and
	// 198.18.0.0/15 (RFC2544 benchmarking). 169.254.0.0/16 is already covered
	// by IsLinkLocalUnicast above.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return "must not target a non-routable IP address (CGNAT)", true
		}
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return "must not target a non-routable IP address (benchmark range)", true
		}
		// 255.255.255.255 limited broadcast — not unicast.
		if v4.Equal(net.IPv4bcast) {
			return "must not target a non-routable IP address (broadcast)", true
		}
	}
	return "", false
}

// forbiddenSSRFHostnames is the exact-match set of hostnames the validator
// rejects without doing DNS. It covers the small surface of names whose
// canonical resolution lands on a loopback or cloud-metadata address.
var forbiddenSSRFHostnames = map[string]struct{}{
	"localhost":                {},
	"ip6-localhost":            {},
	"ip6-loopback":             {},
	"metadata":                 {},
	"metadata.google.internal": {},
	"metadata.aws.internal":    {},
	"169.254.169.254":          {}, // belt-and-braces: also caught by ipReason.
}

// forbiddenSSRFHostSuffixes is the suffix-match set of hostname tails that
// are by definition not externally routable. The leading dot is required to
// prevent over-matching (`.local` must not flag `flocal.example.com`).
var forbiddenSSRFHostSuffixes = []string{
	".localhost",
	".internal", // covers metadata.google.internal, *.internal mDNS-adjacent.
	".local",    // covers mDNS / Bonjour names.
	".localdomain",
}

// urlHost extracts a comparable host string from a parsed URL. It strips the
// IPv6 bracket form and returns the host without port, lower-cased. An empty
// return signals that the URL had no host component.
func urlHost(u *url.URL) string {
	h := strings.ToLower(strings.TrimSpace(u.Hostname()))
	return h
}
