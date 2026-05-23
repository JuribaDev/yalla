package validate

import (
	"net/url"
	"strings"
)

// URL validates that value is an absolute http or https URL safe to store as
// part of a service's desired state. It rejects non-http schemes, missing
// hosts, embedded credentials (a userinfo component, which would smuggle a
// secret into stored state), and over-long inputs. The reason never echoes the
// submitted URL, so a credential pasted into the wrong field cannot leak
// through the validation error.
func URL(c *Collector, field, value string) {
	v := strings.TrimSpace(value)
	if v == "" {
		c.Add(field, "must not be blank")
		return
	}
	if len(v) > MaxURLLen {
		c.Addf(field, "must be at most %d characters", MaxURLLen)
		return
	}
	if containsControl(v) {
		c.Add(field, "must not contain control characters")
		return
	}
	u, err := url.Parse(v)
	if err != nil {
		c.Add(field, "must be a valid URL")
		return
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		c.Add(field, "must use the http or https scheme")
	}
	if u.Host == "" {
		c.Add(field, "must include a host")
	}
	if u.User != nil {
		c.Add(field, "must not embed credentials (a user:password@ component)")
	}
	if reason, blocked := disallowedSSRFHost(urlHost(u)); blocked {
		c.Add(field, reason)
	}
}

// DomainOptions tunes Domain validation with rules that depend on per-tenant
// policy. The validate package does not resolve these itself: the caller sets
// them from the organization's feature flags and quota before calling.
type DomainOptions struct {
	// AllowWildcard permits a single leading "*." wildcard label. The caller
	// sets it true only after confirming both that the organization's wildcard
	// domain feature flag is enabled AND that wildcard-domain quota is
	// available; a wildcard host with AllowWildcard false is rejected.
	AllowWildcard bool
}

// Domain validates a fully-qualified hostname for a customer domain. It
// lower-cases and trims a single optional trailing dot, requires at least two
// labels, and validates each label as a DNS label (1-63 characters of
// [a-z0-9-], no leading or trailing hyphen). A leading "*." wildcard label is
// rejected unless opts.AllowWildcard is set.
func Domain(c *Collector, field, value string, opts DomainOptions) {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		c.Add(field, "must not be blank")
		return
	}
	if containsControl(v) {
		c.Add(field, "must not contain control characters")
		return
	}
	// A single trailing dot is the absolute-FQDN form; accept and drop it.
	v = strings.TrimSuffix(v, ".")
	if len(v) > MaxHostnameLen {
		c.Addf(field, "must be at most %d characters", MaxHostnameLen)
		return
	}

	wildcard := false
	if rest, ok := strings.CutPrefix(v, "*."); ok {
		wildcard = true
		if !opts.AllowWildcard {
			c.Add(field, "wildcard domains are not enabled for this organization")
		}
		v = rest
	}
	if strings.Contains(v, "*") {
		c.Add(field, "may only contain a wildcard as a single leading \"*.\" label")
		return
	}

	labels := strings.Split(v, ".")
	if len(labels) < 2 {
		c.Add(field, "must be a fully-qualified domain name with at least two labels")
		return
	}
	// A wildcard host needs a base domain in addition to the "*" label that
	// was already stripped, so it still needs at least two remaining labels.
	if wildcard && len(labels) < 2 {
		c.Add(field, "wildcard domains must include a base domain")
		return
	}
	for _, label := range labels {
		if !validDNSLabel(label) {
			c.Add(field, "each label must be 1-63 characters of [a-z0-9-] without a leading or trailing hyphen")
			return
		}
	}
	// Domain-takeover prevention (BE-0350): reject hostnames that are
	// structurally illegitimate as a customer-attached service domain —
	// IP-literal forms that survive the FQDN/label checks (dotted IPv4),
	// reserved special-use TLDs / labels (RFC 6761 / RFC 2606), and
	// shared-hosting eTLDs whose ownership cannot legitimately transfer
	// to a single tenant. See domain_takeover.go for the threat model.
	if reason, blocked := disallowedTakeoverHost(v); blocked {
		c.Add(field, reason)
	}
}

// validDNSLabel reports whether label is a valid single DNS label: 1..
// MaxHostLabelLen characters of [a-z0-9-] that neither starts nor ends with a
// hyphen. The caller lower-cases the input first.
func validDNSLabel(label string) bool {
	n := len(label)
	if n < 1 || n > MaxHostLabelLen {
		return false
	}
	if label[0] == '-' || label[n-1] == '-' {
		return false
	}
	for i := 0; i < n; i++ {
		ch := label[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
			continue
		}
		return false
	}
	return true
}
