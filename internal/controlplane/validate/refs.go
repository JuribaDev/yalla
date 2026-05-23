package validate

import (
	"net/url"
	"regexp"
	"strings"
)

// gitCommitPattern matches an abbreviated or full Git commit SHA: 7 to 40
// hexadecimal characters.
var gitCommitPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

// imageTagPattern matches a container image tag per the Docker reference
// grammar: an alphanumeric or underscore start, then up to 127 characters of
// [A-Za-z0-9_.-].
var imageTagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// imageDigestPattern matches a content-addressable image digest such as
// "sha256:" followed by 32 or more lowercase hex characters.
var imageDigestPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[0-9a-f]{32,}$`)

// imageNamePattern matches a single image name component (registry host or
// repository path segment) per the Docker reference grammar.
var imageNamePattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*$`)

// GitRepoURL validates a Git repository URL safe to store as part of a
// service's build settings. It accepts the https/ssh/git URL forms and the
// scp-like "git@host:path" form, and rejects embedded credentials (a
// user:password@ component) so a token pasted into the repo field cannot leak
// into stored desired state. The reason never echoes the submitted URL.
func GitRepoURL(c *Collector, field, value string) {
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
	// scp-like syntax: "git@host:owner/repo.git" — no scheme, has "@" before
	// the first "/" and a ":" separating host from path.
	if !strings.Contains(v, "://") {
		userhost, path, ok := strings.Cut(v, ":")
		if !ok || path == "" {
			c.Add(field, "must be an https, ssh, or git@host:path repository URL")
			return
		}
		user, host, hasUser := strings.Cut(userhost, "@")
		if !hasUser || host == "" || user == "" {
			c.Add(field, "must be an https, ssh, or git@host:path repository URL")
			return
		}
		if strings.Contains(user, ":") {
			c.Add(field, "must not embed credentials (a user:password@ component)")
		}
		if reason, blocked := disallowedSSRFHost(host); blocked {
			c.Add(field, reason)
		}
		return
	}
	u, err := url.Parse(v)
	if err != nil {
		c.Add(field, "must be a valid repository URL")
		return
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "http", "ssh", "git":
	default:
		c.Add(field, "must use the https, ssh, or git scheme")
	}
	if u.Host == "" {
		c.Add(field, "must include a host")
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			c.Add(field, "must not embed credentials (a user:password@ component)")
		}
	}
	if reason, blocked := disallowedSSRFHost(urlHost(u)); blocked {
		c.Add(field, reason)
	}
}

// GitBranch validates a Git branch or tag reference using a simplified subset
// of git's check-ref-format rules: non-empty, within MaxGitRefLen, no control
// characters, none of the characters git forbids (space ~^:?*[\), no ".."
// sequence, no leading/trailing/double slash, no leading "-", no "@{", and not
// ending in "/", "." or ".lock".
func GitBranch(c *Collector, field, value string) {
	v := strings.TrimSpace(value)
	if v == "" {
		c.Add(field, "must not be blank")
		return
	}
	if len(v) > MaxGitRefLen {
		c.Addf(field, "must be at most %d characters", MaxGitRefLen)
		return
	}
	if containsControl(v) {
		c.Add(field, "must not contain control characters")
		return
	}
	if strings.ContainsAny(v, " ~^:?*[\\") {
		c.Add(field, "must not contain whitespace or any of the characters ~^:?*[\\")
		return
	}
	switch {
	case strings.Contains(v, ".."),
		strings.Contains(v, "//"),
		strings.Contains(v, "@{"),
		strings.HasPrefix(v, "/"), strings.HasSuffix(v, "/"),
		strings.HasPrefix(v, "-"),
		strings.HasSuffix(v, "."), strings.HasSuffix(v, ".lock"):
		c.Add(field, "must be a well-formed Git reference name")
	}
}

// GitCommit validates an abbreviated or full Git commit SHA: 7 to 40
// hexadecimal characters.
func GitCommit(c *Collector, field, value string) {
	v := strings.TrimSpace(value)
	if v == "" {
		c.Add(field, "must not be blank")
		return
	}
	if !gitCommitPattern.MatchString(v) {
		c.Add(field, "must be a 7-40 character hexadecimal Git commit SHA")
	}
}

// ImageRef validates a container image reference of the form
// "[registry[:port]/]repository[:tag][@digest]" per a pragmatic subset of the
// Docker reference grammar. It rejects path traversal segments, uppercase
// repository components, malformed tags or digests, and over-long inputs.
func ImageRef(c *Collector, field, value string) {
	v := strings.TrimSpace(value)
	if v == "" {
		c.Add(field, "must not be blank")
		return
	}
	if len(v) > MaxImageRefLen {
		c.Addf(field, "must be at most %d characters", MaxImageRefLen)
		return
	}
	if containsControl(v) {
		c.Add(field, "must not contain control characters")
		return
	}

	// Split off an optional "@digest" suffix.
	name := v
	if at := strings.LastIndexByte(v, '@'); at >= 0 {
		digest := v[at+1:]
		name = v[:at]
		if !imageDigestPattern.MatchString(digest) {
			c.Add(field, "has a malformed image digest")
		}
	}

	// Split off an optional ":tag" suffix. A colon is only a tag separator
	// when it appears after the last "/": before that it is a registry port.
	if colon := strings.LastIndexByte(name, ':'); colon >= 0 && colon > strings.LastIndexByte(name, '/') {
		tag := name[colon+1:]
		name = name[:colon]
		if !imageTagPattern.MatchString(tag) {
			c.Add(field, "has a malformed image tag")
		}
	}

	if name == "" {
		c.Add(field, "must include a repository name")
		return
	}
	components := strings.Split(name, "/")
	for _, comp := range components {
		if comp == ".." || comp == "." || comp == "" {
			c.Add(field, "must not contain empty or path traversal (\"..\") components")
			return
		}
	}
	// The first component may be a registry host (it contains a "." or ":" or
	// is exactly "localhost"); validate it loosely, validate the rest strictly.
	for i, comp := range components {
		if i == 0 && (strings.ContainsAny(comp, ".:") || comp == "localhost") {
			continue
		}
		if !imageNamePattern.MatchString(comp) {
			c.Add(field, "repository components must be lowercase alphanumeric, optionally separated by [._-]")
			return
		}
	}
}
