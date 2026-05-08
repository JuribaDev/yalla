package curated

import (
	"fmt"
	"sync"
)

// OperationLookup is the minimal shape [Registry.VerifyAgainstSpec]
// needs to confirm every curated mapping resolves to a real OpenAPI
// operation. The full *api.Registry satisfies it; tests can pass a
// hand-rolled fake without dragging the OpenAPI machinery in.
type OperationLookup interface {
	// Has reports whether the supplied operationId resolves in the
	// underlying OpenAPI spec.
	Has(operationID string) bool
}

// Registry aggregates curated [Command] descriptors. Construct one
// with [NewRegistry]; the package-level default is reachable via
// [Default]. The zero Registry is empty but usable.
type Registry struct {
	commands []Command
}

// NewRegistry builds a registry from the supplied commands. Each
// command is validated against the policy and the slice is checked
// for duplicate paths. Sorting is stable and by Path. Returning an
// error rather than panicking keeps the constructor usable from
// tests, but production callers (e.g. [Default]) treat any error as
// programmer-fatal.
func NewRegistry(cmds ...Command) (*Registry, error) {
	out := make([]Command, 0, len(cmds))
	seen := make(map[string]struct{}, len(cmds))
	for _, c := range cmds {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if _, dup := seen[c.Path]; dup {
			return nil, fmt.Errorf("curated: duplicate command path %q", c.Path)
		}
		seen[c.Path] = struct{}{}
		out = append(out, c)
	}
	SortCommands(out)
	return &Registry{commands: out}, nil
}

// Commands returns the curated commands in deterministic Path order.
// The returned slice is a defensive copy; mutations on the caller
// side do not bleed back into the registry.
func (r *Registry) Commands() []Command {
	if r == nil {
		return nil
	}
	out := make([]Command, len(r.commands))
	copy(out, r.commands)
	return out
}

// Len reports the number of curated commands in the registry. A nil
// receiver is treated as empty so callers can write
// `curated.Default().Len()` without a guard.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.commands)
}

// ByDomain returns all curated commands attached to the supplied
// domain in Path order. Unknown domains return an empty slice.
func (r *Registry) ByDomain(d Domain) []Command {
	if r == nil {
		return nil
	}
	out := make([]Command, 0)
	for _, c := range r.commands {
		if c.Domain == d {
			out = append(out, c)
		}
	}
	return out
}

// VerifyAgainstSpec walks every curated command and asserts every
// declared OperationID resolves in lookup. The first missing ID is
// returned with the curated command's Path so a stale registry fails
// loudly rather than at command-invocation time.
func (r *Registry) VerifyAgainstSpec(lookup OperationLookup) error {
	if r == nil {
		return nil
	}
	if lookup == nil {
		return fmt.Errorf("curated: VerifyAgainstSpec requires a non-nil OperationLookup")
	}
	for _, c := range r.commands {
		for _, id := range c.OperationIDs {
			if !lookup.Has(id) {
				return fmt.Errorf("curated: command %q references unknown operationId %q", c.Path, id)
			}
		}
	}
	return nil
}

var (
	defaultOnce sync.Once
	defaultReg  *Registry
)

// Default returns the package-level curated registry. The default is
// intentionally empty for the policy-foundation story (US-0012); each
// curated-command story (US-001x and onward) appends its descriptor
// to defaultCommands and the manifest picks it up automatically.
//
// Callers MUST treat the returned registry as read-only.
func Default() *Registry {
	defaultOnce.Do(func() {
		reg, err := NewRegistry(defaultCommands...)
		if err != nil {
			// A bad default is a programmer error caught by tests in
			// this package; surfacing it here keeps the cli/manifest
			// layer free of error handling for the static set.
			panic(fmt.Errorf("curated: default registry invalid: %w", err))
		}
		defaultReg = reg
	})
	return defaultReg
}

// defaultCommands is the package-private static list of curated
// commands wired into the binary. US-0012 establishes the registry
// shape; future curated-command stories append their descriptors
// here. Keep entries grouped by Domain and alphabetised by Path.
var defaultCommands = []Command{}
