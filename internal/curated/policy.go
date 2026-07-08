// Package curated defines the policy that turns raw Dokploy OpenAPI
// operations into stable, agent-friendly yalla commands.
//
// The package is intentionally narrow. It does not register Cobra
// commands itself; later stories wire the actual command tree. What
// this package does is:
//
//  1. Codify the public naming rules — domains, verb style, no clever
//     short aliases — so curated commands stay predictable across
//     yalla versions.
//  2. Provide a [Command] descriptor that maps every curated command
//     to one or more OpenAPI operationIds and validates the mapping.
//  3. Provide a [Registry] that aggregates the curated descriptors and
//     can be projected into the manifest payload (see
//     internal/cli.manifestCuratedCommand).
//
// Raw API coverage (`yalla api call <operationId>`,
// `yalla schema get <operationId>`) remains available for every
// operation. Curated commands are an additional, opinionated surface;
// they never remove or shadow the raw access path.
package curated

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Domain is one of yalla's curated grouping namespaces. Curated
// commands always start with `yalla <domain> <verb> ...`. The domain
// list is intentionally closed so the public CLI surface cannot grow
// new top-level groups by accident.
type Domain string

const (
	// DomainProject groups commands operating on Dokploy projects (the
	// top-level grouping of applications/composes/databases).
	DomainProject Domain = "project"
	// DomainApp groups Dokploy "application" commands — single-image
	// services, deploys, lifecycle.
	DomainApp Domain = "app"
	// DomainCompose groups Dokploy compose-stack commands.
	DomainCompose Domain = "compose"
	// DomainDatabase groups managed-database commands across the
	// supported engines (postgres, mysql, mariadb, mongo, redis).
	DomainDatabase Domain = "database"
	// DomainServer groups Dokploy server / cluster commands.
	DomainServer Domain = "server"
	// DomainSettings groups Dokploy instance settings, certificates,
	// notifications, and other tenant-level configuration.
	DomainSettings Domain = "settings"
	// DomainProvider groups external provider integrations (git
	// providers, container registries, AI providers).
	DomainProvider Domain = "provider"
)

// Domains returns the canonical, alphabetically-sorted set of curated
// domains. Adding or removing a domain is a public-API change.
func Domains() []Domain {
	return []Domain{
		DomainApp,
		DomainCompose,
		DomainDatabase,
		DomainProject,
		DomainProvider,
		DomainServer,
		DomainSettings,
	}
}

// IsDomain reports whether s is one of the canonical curated domains.
func IsDomain(s string) bool {
	for _, d := range Domains() {
		if string(d) == s {
			return true
		}
	}
	return false
}

// PreferredVerbs is the recommended verb vocabulary for curated
// commands. Future curated commands SHOULD prefer these full English
// verbs over clever short aliases. The list is documented for human
// reference; [Command.Validate] enforces the deny-list of known-bad
// short aliases (see [BannedVerbAliases]) rather than a positive
// whitelist so genuinely new verbs (e.g. `deploy`, `redeploy`,
// `rollback`) are not blocked by an outdated list.
var PreferredVerbs = []string{
	"create",
	"delete",
	"deploy",
	"get",
	"list",
	"list-files",
	"logs",
	"redeploy",
	"register",
	"rollback",
	"run",
	"set",
	"start",
	"stop",
	"update",
}

// BannedVerbAliases enumerates the short aliases curated commands MUST
// NOT use. The rationale (per US-0012) is "Use clear names. Do not
// optimize for clever short aliases."
//
// Each entry maps the banned alias to the recommended replacement so
// validation errors can hint the right verb without callers needing
// out-of-band documentation.
var BannedVerbAliases = map[string]string{
	"ls":   "list",
	"rm":   "delete",
	"del":  "delete",
	"new":  "create",
	"show": "get",
	"info": "get",
	"edit": "update",
	"mod":  "update",
	"push": "deploy",
	"up":   "deploy",
	"down": "stop",
	"tail": "logs",
}

// nameRE is the canonical token shape for both domain and verb
// segments: lowercase ASCII, optional hyphenated continuation. The
// pattern matches kebab-case identifiers but never CamelCase or
// snake_case. Path segments are also constrained to this shape.
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// Command describes one curated command and the OpenAPI operationIds
// it is allowed to invoke. A curated command is always rooted at
// `yalla <domain> <verb> [more]` — the [Path] field is the full,
// space-separated invocation including the leading `yalla` token.
type Command struct {
	// Path is the full invocation, e.g. "yalla app deploy". Each
	// segment must match the curated naming rules. The first segment
	// is always "yalla", the second is the [Domain], and the third is
	// the canonical verb. Additional segments are allowed for
	// sub-grouped commands (e.g. "yalla provider git list").
	Path string

	// Domain is the top-level grouping namespace.
	Domain Domain

	// Verb is the canonical action verb (the third path segment when
	// the command is a direct child of the domain group). For deeper
	// nestings (e.g. "yalla provider git list"), Verb is the trailing
	// segment of Path.
	Verb string

	// Summary is a short, human-readable description (sentence case,
	// no trailing period). It mirrors the Cobra `Short` field.
	Summary string

	// OperationIDs lists the OpenAPI operationIds this curated command
	// dispatches to. At least one is required. Operationals are not
	// required to be unique across curated commands — the same
	// operation can be reached through multiple curated entry points
	// (e.g. `app deploy` and `app redeploy` may both invoke
	// `application-deploy` with different inputs).
	OperationIDs []string

	// HumanExample is the human-mode invocation snippet shown in
	// `--help`. It MUST start with `yalla ` (no `--json`).
	HumanExample string

	// JSONExample is the agent-mode invocation snippet shown in
	// `--help`. It MUST contain `--json` so agents discover the
	// machine-readable form from the command's own help output.
	JSONExample string
}

// Validate checks the command against the curated policy. The first
// violation encountered is returned; the caller is expected to fix
// problems sequentially during development. Validation is purely
// structural — it does not look up operationIds against a live
// registry. Use [Registry.VerifyAgainstSpec] for that.
func (c Command) Validate() error {
	if c.Path == "" {
		return fmt.Errorf("curated: Path is required")
	}
	segments := strings.Split(c.Path, " ")
	if len(segments) < 3 {
		return fmt.Errorf("curated: Path %q must have at least three segments (yalla <domain> <verb>)", c.Path)
	}
	if segments[0] != "yalla" {
		return fmt.Errorf("curated: Path %q must start with %q", c.Path, "yalla")
	}
	if !IsDomain(segments[1]) {
		return fmt.Errorf("curated: Path %q has unknown domain %q (allowed: %v)", c.Path, segments[1], Domains())
	}
	if string(c.Domain) != segments[1] {
		return fmt.Errorf("curated: Path %q domain segment %q does not match Domain field %q", c.Path, segments[1], c.Domain)
	}
	for _, seg := range segments[1:] {
		if !nameRE.MatchString(seg) {
			return fmt.Errorf("curated: Path segment %q is not a kebab-case identifier", seg)
		}
	}
	last := segments[len(segments)-1]
	if c.Verb == "" {
		return fmt.Errorf("curated: Verb is required")
	}
	if c.Verb != last {
		return fmt.Errorf("curated: Verb %q does not match trailing path segment %q", c.Verb, last)
	}
	if rep, banned := BannedVerbAliases[c.Verb]; banned {
		return fmt.Errorf("curated: Verb %q is a banned short alias; use %q instead", c.Verb, rep)
	}
	if len(c.OperationIDs) == 0 {
		return fmt.Errorf("curated: %q has no OperationIDs (raw API coverage is independent; curated commands must still declare what they call)", c.Path)
	}
	seen := make(map[string]struct{}, len(c.OperationIDs))
	for _, id := range c.OperationIDs {
		if id == "" {
			return fmt.Errorf("curated: %q has an empty OperationID entry", c.Path)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("curated: %q lists OperationID %q twice", c.Path, id)
		}
		seen[id] = struct{}{}
	}
	if c.Summary == "" {
		return fmt.Errorf("curated: %q is missing a Summary", c.Path)
	}
	if strings.HasSuffix(c.Summary, ".") {
		return fmt.Errorf("curated: %q Summary must not end with a period", c.Path)
	}
	if err := validateExample(c.Path, "HumanExample", c.HumanExample, false); err != nil {
		return err
	}
	if err := validateExample(c.Path, "JSONExample", c.JSONExample, true); err != nil {
		return err
	}
	return nil
}

// validateExample enforces the help-text contract: every curated
// command must ship one human-mode and one agent-mode example so the
// CLI's --help output documents both audiences.
func validateExample(path, field, example string, requireJSON bool) error {
	if example == "" {
		return fmt.Errorf("curated: %q is missing %s", path, field)
	}
	trim := strings.TrimSpace(example)
	if !strings.HasPrefix(trim, "yalla ") {
		return fmt.Errorf("curated: %q %s must start with %q (got %q)", path, field, "yalla ", trim)
	}
	hasJSON := strings.Contains(example, "--json")
	switch {
	case requireJSON && !hasJSON:
		return fmt.Errorf("curated: %q JSONExample must contain --json", path)
	case !requireJSON && hasJSON:
		return fmt.Errorf("curated: %q HumanExample must not contain --json (use JSONExample for that)", path)
	}
	return nil
}

// SortCommands sorts a slice of curated commands by Path so manifest
// output, docs generation, and registry walks all see the same order.
// The function mutates the input slice in place.
func SortCommands(cmds []Command) {
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].Path < cmds[j].Path })
}
