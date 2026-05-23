package variables

import (
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/output"
)

// Source identifies which level of the hierarchy contributed a variable
// in the effective Resolved set. The string values are stable wire
// identifiers (mirrored by dokploy.VariableSource) so downstream
// consumers can re-emit them losslessly without an enum mapping.
type Source string

const (
	// SourceOrganization is the lowest-precedence scope.
	SourceOrganization Source = "organization"
	// SourceProject overrides organization-level variables.
	SourceProject Source = "project"
	// SourceEnvironment overrides project-level variables.
	SourceEnvironment Source = "environment"
	// SourceService is the highest-precedence scope.
	SourceService Source = "service"
)

// envVarName matches a POSIX-shell environment variable name. The
// resolver enforces this shape so a malformed name (a name with a
// space, a dash, or a leading digit) is rejected as customer input
// rather than smuggled through the renderer and ultimately rejected
// by Dokploy with a less actionable error.
var envVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ScopedVariable is one variable as fed to the resolver. It carries the
// at-rest seal tuple from its source-of-truth row plus an opaque
// ResourceID for explain output. The resolver does not depend on the
// store package: the caller is responsible for converting store types
// (OrganizationVariable, ProjectVariable, EnvironmentVariable,
// ServiceVariable) into this scope-agnostic shape.
//
// For non-secret rows: only Key and Value are read; the SecretProvider /
// SecretKeyID / SecretCiphertext columns are ignored even when populated.
//
// For secret rows: Value is ignored and the plaintext is recovered
// through Resolver.provider.Open(SecretCiphertext, SecretKeyID). A
// secret row whose SecretProvider does not match the resolver's
// provider id surfaces as apierr.SecretDecryption wrapping
// secrets.ErrUnsupportedProvider rather than as a customer input error.
type ScopedVariable struct {
	// ResourceID is the source-of-truth row id (e.g.
	// organization_variables.id). It is preserved on the Rendered and
	// Contribution outputs so an operator can locate the exact row that
	// contributed an effective value. The resolver never echoes
	// ResourceID into an error message or violation field path.
	ResourceID string
	// Key is the environment variable name. It is trimmed and must
	// match a POSIX-shell environment variable name
	// ([A-Za-z_][A-Za-z0-9_]*).
	Key string
	// Value is the plaintext value for non-secret rows. It is carried
	// verbatim (not trimmed) so a row containing legitimate trailing
	// whitespace round-trips losslessly.
	Value string
	// IsSecret marks the row as carrying a secret value protected at
	// rest by the encryption seam. The resolver Opens this row exactly
	// once during the merge pass.
	IsSecret bool
	// SecretProvider is the wire identifier of the secrets.Provider
	// that sealed this row. The resolver compares it against its
	// provider's ProviderID and surfaces a mismatch as
	// secrets.ErrUnsupportedProvider wrapped in apierr.Internal.
	SecretProvider string
	// SecretKeyID is the wire identifier of the key inside the provider
	// that sealed this row. It is passed verbatim to provider.Open.
	SecretKeyID string
	// SecretCiphertext is the opaque sealed blob produced by the
	// provider. The resolver never logs it.
	SecretCiphertext []byte
}

// LogValue redacts the variable's plaintext and ciphertext at the slog
// boundary so a stray log record that captures a ScopedVariable cannot
// leak either the literal value or the sealed bytes. The non-secret
// identifiers (ResourceID, Key, IsSecret flag, provider/key wire ids)
// remain visible so an operator can still trace the row.
func (v ScopedVariable) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("resource_id", v.ResourceID),
		slog.String("key", v.Key),
		slog.String("value", output.Sentinel),
		slog.Bool("is_secret", v.IsSecret),
		slog.String("secret_provider", v.SecretProvider),
		slog.String("secret_key_id", v.SecretKeyID),
	)
}

// ResolveInput collects the per-scope variable sets the resolver
// merges. Each slice is treated as the authoritative set for that
// scope: the caller is expected to have fetched it in a single
// short-lived read transaction (the per-scope Reader adapters in
// internal/controlplane/store do this) and the resolver does not
// re-read or re-validate persistence-level invariants (uniqueness
// within a scope is enforced again as a defence-in-depth check, but
// the database constraint is the source of truth).
type ResolveInput struct {
	OrganizationVariables []ScopedVariable
	ProjectVariables      []ScopedVariable
	EnvironmentVariables  []ScopedVariable
	ServiceVariables      []ScopedVariable
}

// Options tunes resolver behavior. The zero value is the safe default:
// every secret downgrade is rejected.
type Options struct {
	// AllowSecretDowngrade lets a non-secret variable at a higher scope
	// override a secret variable of the same name at a lower scope.
	// The default behavior (false) rejects such overrides as
	// apierr.InvalidInput with a stable field path so the customer can
	// either mark the higher-scope value as a secret or opt in
	// explicitly. The opt-in is a deliberate, audited admin action —
	// callers wiring this flag MUST emit an audit event recording the
	// override.
	AllowSecretDowngrade bool
}

// Rendered is one effective variable after merging. The Source and
// SourceID fields identify the winning scope; the full override chain
// is recorded separately on Resolved.Contributions.
type Rendered struct {
	// Key is the validated POSIX-shell variable name.
	Key string
	// Value is the plaintext effective value. For secret rows it is
	// the plaintext recovered through secrets.Provider.Open. Callers
	// surfacing this struct on a customer-facing wire MUST redact via
	// Explain.
	Value string
	// IsSecret reports whether the winning row was marked as secret.
	IsSecret bool
	// Source is the scope that contributed the winning value.
	Source Source
	// SourceID is the source-of-truth row id at the winning scope.
	SourceID string
}

// LogValue redacts Rendered.Value at the slog boundary so a panic
// stack trace, an accidental debug log, or a structured-log capture
// of the struct cannot leak the plaintext. The Source / SourceID /
// IsSecret legs remain visible for operator diagnostics.
func (r Rendered) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("key", r.Key),
		slog.String("value", output.Sentinel),
		slog.Bool("is_secret", r.IsSecret),
		slog.String("source", string(r.Source)),
		slog.String("source_id", r.SourceID),
	)
}

// Contribution records one (scope, source_id, is_secret) tuple in a
// key's override chain. Contribution carries no plaintext: it is safe
// to surface on a customer-facing wire and in audit metadata as-is.
type Contribution struct {
	Source   Source `json:"source"`
	SourceID string `json:"source_id,omitempty"`
	IsSecret bool   `json:"is_secret"`
}

// Resolved is the fully-merged variable set plus the per-key override
// chain. Variables is sorted by Key for determinism so two callers
// observing the same Resolved value produce byte-identical output.
type Resolved struct {
	// Variables is the effective variable set, sorted ascending by Key.
	Variables []Rendered
	// Contributions maps a variable key to the chain of scopes that
	// contributed a value for it, in ascending precedence order. The
	// last entry in the chain is the winning Rendered row.
	Contributions map[string][]Contribution
}

// LogValue redacts the entire Resolved set at the slog boundary. A
// debug log line that captures a Resolved value sees only the count
// and the redaction sentinel; the per-key plaintext values are
// structurally inaccessible.
func (r Resolved) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("count", len(r.Variables)),
		slog.String("values", output.Sentinel),
	)
}

// ExplainedVariable is one entry in a customer-facing explain
// projection. Value is always output.Sentinel; the override chain is
// preserved so an operator can audit which scope contributed a value
// without seeing the plaintext.
type ExplainedVariable struct {
	Key      string         `json:"key"`
	Value    string         `json:"value"`
	IsSecret bool           `json:"is_secret"`
	Source   Source         `json:"source"`
	SourceID string         `json:"source_id,omitempty"`
	Sources  []Contribution `json:"contributions"`
}

// Explained is the redacted projection of a Resolved set suitable for
// customer-facing JSON envelopes, audit metadata, and operator
// diagnostics. It carries no plaintext values.
type Explained struct {
	Variables []ExplainedVariable `json:"variables"`
}

// Explain returns the redacted projection of r. Every value becomes
// output.Sentinel; the override chains, source scopes, and source row
// ids are preserved.
func (r Resolved) Explain() Explained {
	out := Explained{Variables: make([]ExplainedVariable, 0, len(r.Variables))}
	for _, v := range r.Variables {
		out.Variables = append(out.Variables, ExplainedVariable{
			Key:      v.Key,
			Value:    output.Sentinel,
			IsSecret: v.IsSecret,
			Source:   v.Source,
			SourceID: v.SourceID,
			Sources:  append([]Contribution(nil), r.Contributions[v.Key]...),
		})
	}
	return out
}

// Resolver merges variables across the four hierarchy scopes using the
// Dokploy-compatible precedence service > environment > project >
// organization, Opens sealed values through a secrets.Provider, and
// records per-key provenance for explain output. A Resolver is
// stateless and safe for concurrent use.
type Resolver struct {
	provider secrets.Provider
}

// NewResolver builds a Resolver that decrypts sealed rows through
// provider. The constructor returns an error for a nil provider so a
// misconfigured resolver fails at construction rather than on its first
// Resolve call. The provider's ProviderID must be non-empty (the
// secrets package reserves the empty string as a wiring error) and
// every sealed row passed to Resolve must have been sealed by a
// provider with the same wire identifier.
func NewResolver(p secrets.Provider) (*Resolver, error) {
	if p == nil {
		return nil, errors.New("variables: nil secrets provider")
	}
	if strings.TrimSpace(p.ProviderID()) == "" {
		return nil, errors.New("variables: secrets provider has an empty provider id")
	}
	return &Resolver{provider: p}, nil
}

// Resolve merges in's per-scope variables under the precedence service
// > environment > project > organization, Opens sealed values through
// the resolver's provider, and returns the effective set plus the
// per-key Contribution chain.
//
// Customer-input failures (invalid name, duplicate within a scope,
// secret downgrade without Options.AllowSecretDowngrade) are collected
// as apierr.FieldViolation values and returned as a single
// apierr.InvalidInput. Server-side failures (unable to Open a sealed
// row because the provider id mismatches, the key id is unknown, or
// the ciphertext fails authentication) surface as apierr.SecretDecryption with
// a wrapped cause for server-side logging — never as a customer-input
// violation, and never echoing the plaintext or ciphertext.
func (r *Resolver) Resolve(in ResolveInput, opts Options) (Resolved, error) {
	if r == nil || r.provider == nil {
		return Resolved{}, apierr.Internal(errors.New("variables: Resolve called on a misconfigured resolver"))
	}

	type slot struct {
		rendered      Rendered
		contributions []Contribution
	}

	state := make(map[string]*slot)
	violations := make([]apierr.FieldViolation, 0)

	levels := []struct {
		src  Source
		vars []ScopedVariable
	}{
		{SourceOrganization, in.OrganizationVariables},
		{SourceProject, in.ProjectVariables},
		{SourceEnvironment, in.EnvironmentVariables},
		{SourceService, in.ServiceVariables},
	}

	for _, lvl := range levels {
		seen := make(map[string]struct{}, len(lvl.vars))
		for i, raw := range lvl.vars {
			name := strings.TrimSpace(raw.Key)
			path := fmt.Sprintf("%s.variables[%d].key", lvl.src, i)
			if !envVarName.MatchString(name) {
				violations = append(violations, apierr.FieldViolation{
					Field:  path,
					Reason: "must be a valid environment variable name",
				})
				continue
			}
			if _, dup := seen[name]; dup {
				violations = append(violations, apierr.FieldViolation{
					Field:  path,
					Reason: "duplicate variable name within this scope",
				})
				continue
			}
			seen[name] = struct{}{}

			existing := state[name]
			if existing != nil && existing.rendered.IsSecret && !raw.IsSecret && !opts.AllowSecretDowngrade {
				violations = append(violations, apierr.FieldViolation{
					Field:  path,
					Reason: "non-secret variable overrides a secret variable at a lower scope; set allow_secret_downgrade to opt in",
				})
				continue
			}

			plaintext, openErr := r.materialise(raw)
			if openErr != nil {
				return Resolved{}, apierr.SecretDecryption(openErr)
			}

			contrib := Contribution{
				Source:   lvl.src,
				SourceID: raw.ResourceID,
				IsSecret: raw.IsSecret,
			}
			rendered := Rendered{
				Key:      name,
				Value:    plaintext,
				IsSecret: raw.IsSecret,
				Source:   lvl.src,
				SourceID: raw.ResourceID,
			}
			if existing == nil {
				state[name] = &slot{
					rendered:      rendered,
					contributions: []Contribution{contrib},
				}
			} else {
				existing.rendered = rendered
				existing.contributions = append(existing.contributions, contrib)
			}
		}
	}

	if len(violations) > 0 {
		return Resolved{}, apierr.InvalidInput(violations...)
	}

	keys := make([]string, 0, len(state))
	for k := range state {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	variables := make([]Rendered, 0, len(keys))
	contributions := make(map[string][]Contribution, len(keys))
	for _, k := range keys {
		s := state[k]
		variables = append(variables, s.rendered)
		contributions[k] = s.contributions
	}
	return Resolved{Variables: variables, Contributions: contributions}, nil
}

// materialise returns the plaintext value of v. For a non-secret row
// it returns Value verbatim; for a secret row it Opens the sealed
// blob through r.provider after verifying the provider id matches.
// A mismatch surfaces as secrets.ErrUnsupportedProvider with a
// non-value-bearing wrapping cause so the operator can identify which
// provider id was expected vs. observed; neither id is secret material.
func (r *Resolver) materialise(v ScopedVariable) (string, error) {
	if !v.IsSecret {
		return v.Value, nil
	}
	if v.SecretProvider != r.provider.ProviderID() {
		return "", fmt.Errorf("variables: cannot open ciphertext sealed by provider %q with provider %q: %w",
			v.SecretProvider, r.provider.ProviderID(), secrets.ErrUnsupportedProvider)
	}
	plaintext, err := r.provider.Open(v.SecretCiphertext, v.SecretKeyID)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
