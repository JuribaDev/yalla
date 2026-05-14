package validate

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// ResourceRequest is a customer-requested compute allocation for a service. A
// zero field means "unset — inherit the deterministic default later"; the
// renderer fills zero fields, so validation only rejects values that are
// negative or above the hard ceiling.
type ResourceRequest struct {
	// CPUMillis is the CPU limit in millicores (1000 = one core).
	CPUMillis int
	// MemoryMiB is the memory limit in mebibytes.
	MemoryMiB int
	// Replicas is the desired replica count.
	Replicas int
}

// Resources validates a requested compute allocation. Each dimension is
// reported under its own dotted sub-path (field+".cpu_millis", etc.) so a
// caller can tell exactly which size was rejected. Negative values and values
// above the hard ceiling are rejected; zero is accepted as "unset".
func Resources(c *Collector, field string, r ResourceRequest) {
	boundedSize(c, field+".cpu_millis", r.CPUMillis, MaxCPUMillis)
	boundedSize(c, field+".memory_mib", r.MemoryMiB, MaxMemoryMiB)
	boundedSize(c, field+".replicas", r.Replicas, MaxReplicas)
}

// boundedSize records a violation when v is negative or above max. Zero is
// always accepted: it is the "unset, inherit a default" sentinel.
func boundedSize(c *Collector, field string, v, max int) {
	switch {
	case v < 0:
		c.Add(field, "must not be negative")
	case v > max:
		c.Addf(field, "must be at most %d", max)
	}
}

// EnvVar is one environment variable submitted on a request. Secret marks the
// value as sensitive. Neither a secret nor a non-secret value is ever echoed
// in a violation reason — validate never echoes submitted values — but Secret
// still matters: it selects the larger length ceiling and routes the variable
// into the field path's "secret" segment so a caller can tell which kind of
// variable failed without inspecting the value.
type EnvVar struct {
	// Name is the environment variable name. It must match a POSIX shell
	// environment variable name ([A-Za-z_][A-Za-z0-9_]*).
	Name string
	// Value is the variable's value. It is validated but never echoed.
	Value string
	// Secret marks the value as sensitive.
	Secret bool
}

// EnvVars validates a list of environment variables, separating secret from
// non-secret entries. Names must be POSIX shell environment variable names and
// must be unique across the whole list (a name appearing as both a secret and
// a plain variable is a conflict). Values must be valid UTF-8 free of NUL
// bytes and within the length ceiling for their kind (MaxSecretValueLen for
// secrets, MaxEnvVarValueLen otherwise).
//
// Violations are reported under "<field>.secret[<i>]" for secret entries and
// "<field>[<i>]" for non-secret entries, so the field path alone tells a
// caller whether a secret or a plain variable was rejected — without the
// reason ever carrying the value.
func EnvVars(c *Collector, field string, vars []EnvVar) {
	seen := make(map[string]struct{}, len(vars))
	for i, v := range vars {
		path := envVarPath(field, i, v.Secret)
		name := strings.TrimSpace(v.Name)
		if !validEnvVarName(name) {
			c.Add(path+".name", "must be a POSIX environment variable name ([A-Za-z_][A-Za-z0-9_]*)")
		} else if len(name) > MaxEnvVarNameLen {
			c.Addf(path+".name", "must be at most %d characters", MaxEnvVarNameLen)
		} else {
			if _, dup := seen[name]; dup {
				c.Add(path+".name", "duplicates another environment variable name")
			}
			seen[name] = struct{}{}
		}

		max := MaxEnvVarValueLen
		if v.Secret {
			max = MaxSecretValueLen
		}
		if !utf8.ValidString(v.Value) {
			c.Add(path+".value", "must be valid UTF-8")
		} else if strings.ContainsRune(v.Value, 0) {
			c.Add(path+".value", "must not contain NUL bytes")
		} else if len(v.Value) > max {
			c.Addf(path+".value", "must be at most %d bytes", max)
		}
	}
}

// envVarPath builds the dotted field path for the i-th environment variable,
// routing secret entries through a distinct ".secret" segment.
func envVarPath(field string, i int, secret bool) string {
	if secret {
		return fmt.Sprintf("%s.secret[%d]", field, i)
	}
	return fmt.Sprintf("%s[%d]", field, i)
}

// validEnvVarName reports whether name is a POSIX shell environment variable
// name: a non-empty string of [A-Za-z0-9_] that does not start with a digit.
func validEnvVarName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch == '_':
			// always allowed
		case ch >= '0' && ch <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
