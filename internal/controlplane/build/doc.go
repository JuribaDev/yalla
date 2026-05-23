// Package build verifies properties of the operations artefacts that wrap the
// backend binaries — Dockerfiles, container manifests, deploy scripts — so
// that a regression in one of those artefacts surfaces as a failing
// `go test ./...` run rather than as a production incident.
//
// The package contains no production code; its tests read the repo-tracked
// artefacts at the repository root and assert the properties an operations
// audit would check (multi-stage builds, non-root runtime users, no baked
// secrets, port hints that match the configured production defaults, …).
// Concrete artefact docs live next to the artefacts themselves; this package
// is purely the verification surface.
package build
