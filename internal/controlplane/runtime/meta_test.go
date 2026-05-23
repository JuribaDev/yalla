package runtime

import (
	"sync"
	"testing"
)

func TestMetaMigrationVersionDefaultsToUnknown(t *testing.T) {
	t.Parallel()

	m := NewMeta()
	if got := m.MigrationVersion(); got != MigrationVersionUnknown {
		t.Errorf("fresh Meta MigrationVersion() = %q, want %q", got, MigrationVersionUnknown)
	}
}

func TestMetaSetMigrationVersion(t *testing.T) {
	t.Parallel()

	m := NewMeta()
	m.SetMigrationVersion("0007")
	if got := m.MigrationVersion(); got != "0007" {
		t.Errorf("MigrationVersion() = %q, want 0007", got)
	}

	// An explicit empty string resets to the unknown sentinel rather than
	// reporting a blank version on the wire.
	m.SetMigrationVersion("")
	if got := m.MigrationVersion(); got != MigrationVersionUnknown {
		t.Errorf("MigrationVersion() after empty set = %q, want %q", got, MigrationVersionUnknown)
	}
}

// TestMetaConcurrentAccess proves Meta is safe for concurrent use: the
// /version handler reads it while a startup goroutine sets it.
func TestMetaConcurrentAccess(t *testing.T) {
	t.Parallel()

	m := NewMeta()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); m.SetMigrationVersion("0042") }()
		go func() { defer wg.Done(); _ = m.MigrationVersion() }()
	}
	wg.Wait()

	if got := m.MigrationVersion(); got != "0042" {
		t.Errorf("MigrationVersion() = %q, want 0042", got)
	}
}

func TestAPISchemaVersionIsStable(t *testing.T) {
	t.Parallel()

	// The API schema version is a public compatibility contract. Pin it so an
	// accidental change is caught here.
	if APISchemaVersion != "yalla.api.v1" {
		t.Errorf("APISchemaVersion = %q, want yalla.api.v1", APISchemaVersion)
	}
}

// TestMetaSatisfiesMetaReporter is a compile-time guard that *Meta implements
// the MetaReporter interface the HTTP API depends on.
func TestMetaSatisfiesMetaReporter(t *testing.T) {
	t.Parallel()

	var _ MetaReporter = NewMeta()
}
