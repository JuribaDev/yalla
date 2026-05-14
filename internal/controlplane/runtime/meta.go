package runtime

import "sync"

// APISchemaVersion is the stable version of the Yalla Control Plane API
// contract. Endpoint paths, methods, request/response schemas, and error
// codes are versioned under it, so agents and CI can pin to a known contract.
// It is deliberately distinct from BuildInfo.Version, which identifies the
// build artifact, not the contract. The /version endpoint reports both.
const APISchemaVersion = "yalla.api.v1"

// MigrationVersionUnknown is the migration version reported before the
// process has connected to Postgres and resolved the applied schema version.
const MigrationVersionUnknown = "unknown"

// MetaReporter exposes dynamic process metadata that is not known at build
// time and only becomes available once startup completes — principally the
// applied database migration version. The HTTP API's /version handler
// depends on this interface. A nil MetaReporter is treated as "unknown",
// which suits tests and processes with no persistence layer wired yet.
type MetaReporter interface {
	// MigrationVersion returns the applied database migration version, or
	// MigrationVersionUnknown before the process has resolved it.
	MigrationVersion() string
}

// Meta is the concurrency-safe MetaReporter the backend binaries populate as
// their startup checks complete. It is safe for concurrent use: the HTTP
// /version handler reads it while the startup goroutine sets it.
//
// A freshly constructed Meta reports MigrationVersionUnknown until
// SetMigrationVersion records the value the persistence layer resolved.
type Meta struct {
	mu               sync.RWMutex
	migrationVersion string
}

// NewMeta returns a Meta with an unresolved migration version.
func NewMeta() *Meta { return &Meta{} }

// SetMigrationVersion records the applied database migration version. The
// startup goroutine calls it once the persistence layer reports the version.
func (m *Meta) SetMigrationVersion(version string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.migrationVersion = version
}

// MigrationVersion returns the applied database migration version, or
// MigrationVersionUnknown if it has not been resolved yet.
func (m *Meta) MigrationVersion() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.migrationVersion == "" {
		return MigrationVersionUnknown
	}
	return m.migrationVersion
}
