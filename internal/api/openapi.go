// Package api owns the runtime OpenAPI operation registry for Dokploy.
//
// The registry is the source of truth for every yalla command that touches
// the upstream API: the raw `yalla api call` executor, the `yalla schema`
// commands, the `yalla manifest` documentation, and the agent-facing
// JSON envelopes that describe the API surface.
//
// The registry is built once at process start by parsing an embedded copy
// of Dokploy's OpenAPI 3.1 document. Embedding the spec keeps the binary
// hermetic — distribution targets (Homebrew, npm wrapper, Scoop, WinGet,
// install script) ship a single binary with zero runtime file dependencies.
//
// The embedded document is pinned by SHA-256 in EmbeddedSpecSHA256. Any
// drift from the upstream spec is caught by registry_test.go before it can
// land on a release branch.
package api

import (
	_ "embed"
)

// EmbeddedSpec is the verbatim Dokploy OpenAPI 3.1 document, embedded at
// build time. The bytes are the canonical input for Load() and are also
// returned by `yalla manifest --raw` (US-0007) so agents can fetch the full
// spec without a network round trip.
//
//go:embed data/openapi.json
var EmbeddedSpec []byte

// EmbeddedSpecSHA256 is the SHA-256 hex digest of EmbeddedSpec. It is the
// public version handle of the registry: bumping the spec is a public-API
// change and must be reflected in this constant, in ralph/prd.json's
// sourceApi.sha256 field, and in the registry test that locks the digest.
const EmbeddedSpecSHA256 = "09999cf46fa7504ca2bc7539d8b1e6817da3d612964a5f83fe404dd32c56c7c7"
