// Package variables resolves a single service's effective environment-
// variable set by merging the four hierarchy scopes (organization,
// project, environment, service) under the Dokploy-compatible precedence
// service > environment > project > organization.
//
// The resolver is pure: it performs no I/O. The caller is responsible
// for fetching each scope's variables in a single short-lived read
// transaction (typically through the per-scope Reader adapters in
// internal/controlplane/store) and for converting the at-rest source-of-
// truth rows into the package-local ScopedVariable shape. Keeping the
// resolver scope-agnostic means it can be exercised in unit tests with
// hand-built fixtures and reused by callers that fetch variables from a
// non-store source (for example a future cache or an admin export tool)
// without changing the merge contract.
//
// Sealed secret values are opened through a secrets.Provider passed at
// construction. The resolver Opens a sealed row exactly once, on the
// pass that visits its scope; a row whose ciphertext fails authentication
// is surfaced as apierr.Internal (a server-side classification) with a
// wrapped cause for diagnostics, never as a customer-facing validation
// failure. A row whose SecretProvider id does not match the resolver's
// provider id surfaces as apierr.Internal wrapping secrets.ErrUnsupportedProvider.
//
// The resolver enforces three correctness invariants:
//
//  1. Names match a POSIX-shell environment variable name
//     ([A-Za-z_][A-Za-z0-9_]*); the rejection is a single
//     apierr.FieldViolation with a stable, indexed field path that
//     never echoes the rejected value.
//  2. A scope cannot define the same variable twice. A duplicate within
//     one scope is a single FieldViolation; later scopes still get to
//     contribute the same name (overrides are the entire point).
//  3. A non-secret value at a higher scope cannot override a secret at
//     a lower scope unless Options.AllowSecretDowngrade is explicitly
//     set. The default behavior is the safe one: a downgrade is a
//     FieldViolation that surfaces as apierr.InvalidInput rather than a
//     silent leak of the lower-scope secret as a plaintext non-secret.
//     A secret value at a higher scope overriding a non-secret at a
//     lower scope is always allowed; that direction strengthens the
//     posture rather than weakening it.
//
// The Resolved view is the internal-only consumer surface: it carries
// verbatim plaintext values and per-key Contribution chains so the
// caller (the Dokploy renderer worker, future variable-explain admin
// endpoint) can take action on the effective set. The Explain view is
// the customer-facing projection of the same data with every value
// redacted to output.Sentinel; it is safe to surface in JSON envelopes,
// logs, audit metadata, and test output. Resolved and Rendered also
// implement slog.LogValuer to redact values at the slog boundary as a
// second line of defence against accidental capture of the struct in a
// debug log line.
package variables
