// Package runtime contains process-level metadata shared by backend binaries.
package runtime

// BuildInfo is the build-time identity shared by the control-plane API and
// worker binaries.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// Normalized returns non-empty values for process and health responses.
func (b BuildInfo) Normalized() BuildInfo {
	if b.Version == "" {
		b.Version = "0.0.0-dev"
	}
	if b.Commit == "" {
		b.Commit = "unknown"
	}
	if b.Date == "" {
		b.Date = "unknown"
	}
	return b
}
