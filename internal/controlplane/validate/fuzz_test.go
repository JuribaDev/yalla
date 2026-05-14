package validate_test

import (
	stderrors "errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/validate"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// fuzzSeeds are inputs every string-validator fuzz target is seeded with: the
// hostile shapes called out by the BE-0036 acceptance criteria — long
// strings, invalid UTF-8, path traversal attempts — plus assorted control
// characters and Unicode tricks.
var fuzzSeeds = []string{
	"", " ", "ok", "Valid Name",
	strings.Repeat("a", 5000),                     // long string
	"bad\xff\xfeutf8", "\xc3\x28", "\xed\xa0\x80", // invalid UTF-8
	"../../etc/passwd", "..\\..\\windows", "a/../../b", // path traversal
	"nul\x00byte", "tab\there", "new\nline", "ret\rurn",
	"*.example.com", "a.*.b.com", "UPPER.CASE.COM",
	"git@host:path", "https://u:p@host/x", "{\"x\":", "<<garbage>>",
	"café-déjà", "🚀", "\u200bzero-width",
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// FuzzName asserts Name never panics and only ever accepts a value that is
// non-empty after trimming, valid UTF-8, free of control characters, and
// within the rune-count bound.
func FuzzName(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		c := validate.New()
		validate.Name(c, "name", input)
		if !c.OK() {
			return
		}
		v := strings.TrimSpace(input)
		if v == "" {
			t.Fatalf("Name accepted a blank value %q", input)
		}
		if !utf8.ValidString(v) {
			t.Fatalf("Name accepted invalid UTF-8 %q", input)
		}
		if utf8.RuneCountInString(v) > validate.MaxNameLen {
			t.Fatalf("Name accepted an over-long value (%d runes)", utf8.RuneCountInString(v))
		}
		if hasControl(v) {
			t.Fatalf("Name accepted a control character in %q", input)
		}
	})
}

// FuzzPath asserts Path never panics and never accepts a value that could
// escape the repository root: absolute paths, backslashes, NUL bytes, and
// ".." traversal segments must all be rejected.
func FuzzPath(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		c := validate.New()
		validate.Path(c, "path", input)
		if !c.OK() {
			return
		}
		v := strings.TrimSpace(input)
		if v == "" {
			t.Fatalf("Path accepted a blank value")
		}
		if !utf8.ValidString(v) {
			t.Fatalf("Path accepted invalid UTF-8 %q", input)
		}
		if len(v) > validate.MaxPathLen {
			t.Fatalf("Path accepted an over-long value")
		}
		if strings.ContainsRune(v, 0) {
			t.Fatalf("Path accepted a NUL byte")
		}
		if strings.ContainsRune(v, '\\') {
			t.Fatalf("Path accepted a backslash %q", input)
		}
		if strings.HasPrefix(v, "/") {
			t.Fatalf("Path accepted an absolute path %q", input)
		}
		for _, seg := range strings.Split(v, "/") {
			if seg == ".." {
				t.Fatalf("Path accepted a traversal segment in %q", input)
			}
		}
		if hasControl(v) {
			t.Fatalf("Path accepted a control character in %q", input)
		}
	})
}

// FuzzDomain asserts Domain never panics and, with wildcards disabled, only
// accepts a fully-qualified hostname of two or more valid DNS labels.
func FuzzDomain(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		c := validate.New()
		validate.Domain(c, "host", input, validate.DomainOptions{AllowWildcard: false})
		if !c.OK() {
			return
		}
		v := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(input)), ".")
		if v == "" || len(v) > validate.MaxHostnameLen {
			t.Fatalf("Domain accepted an out-of-range host %q", input)
		}
		if strings.Contains(v, "*") {
			t.Fatalf("Domain accepted a wildcard with wildcards disabled: %q", input)
		}
		if hasControl(v) {
			t.Fatalf("Domain accepted a control character in %q", input)
		}
		labels := strings.Split(v, ".")
		if len(labels) < 2 {
			t.Fatalf("Domain accepted a non-FQDN %q", input)
		}
		for _, label := range labels {
			n := len(label)
			if n < 1 || n > validate.MaxHostLabelLen || label[0] == '-' || label[n-1] == '-' {
				t.Fatalf("Domain accepted an invalid label in %q", input)
			}
			for i := 0; i < n; i++ {
				ch := label[i]
				if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
					t.Fatalf("Domain accepted an invalid label character in %q", input)
				}
			}
		}
	})
}

// FuzzEnvVarName asserts EnvVars never panics on an arbitrary variable name
// and only accepts POSIX shell environment variable names.
func FuzzEnvVarName(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		c := validate.New()
		validate.EnvVars(c, "env", []validate.EnvVar{{Name: name, Value: "value", Secret: false}})
		if !c.OK() {
			return
		}
		v := strings.TrimSpace(name)
		if v == "" || len(v) > validate.MaxEnvVarNameLen {
			t.Fatalf("EnvVars accepted an out-of-range name %q", name)
		}
		for i := 0; i < len(v); i++ {
			ch := v[i]
			ok := ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9' && i > 0)
			if !ok {
				t.Fatalf("EnvVars accepted an invalid name character in %q", name)
			}
		}
	})
}

// FuzzEnvVarValue asserts EnvVars never panics on an arbitrary value and never
// echoes that value into the resulting error.
func FuzzEnvVarValue(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		c := validate.New()
		validate.EnvVars(c, "env", []validate.EnvVar{{Name: "FUZZ_VALUE", Value: value, Secret: true}})
		if err := c.Err(); err != nil && len(value) >= 8 && utf8.ValidString(value) && !strings.ContainsRune(value, 0) {
			// A within-bounds, well-formed value should never have produced a
			// violation; if it did, the value must still not be echoed.
			if strings.Contains(err.Error(), value) {
				t.Fatalf("EnvVars echoed the submitted value into the error")
			}
		}
	})
}

// FuzzDecodeJSON asserts DecodeJSON never panics on arbitrary bytes — covering
// malformed JSON, truncated bodies, and binary garbage — and that any failure
// is a typed E_INVALID_INPUT error.
func FuzzDecodeJSON(f *testing.F) {
	for _, s := range []string{
		``, `{}`, `{"name":"ok"}`, `{"name":`, `[1,2,3]`, `null`,
		`{"name":"ok"}{"x":1}`, "\x00\x01\x02", `{"name":"` + strings.Repeat("x", 9000) + `"}`,
		`<<garbage>>`, `{"unknown":1}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var into struct {
			Name string `json:"name"`
		}
		err := validate.DecodeJSON(strings.NewReader(string(body)), &into, 4096)
		if err == nil {
			return
		}
		var ye *yerr.Error
		if !stderrors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
			t.Fatalf("DecodeJSON returned a non-E_INVALID_INPUT error: %v", err)
		}
	})
}

// FuzzImageRef asserts ImageRef never panics and never accepts a reference
// with control characters, path traversal components, or an over-long value.
func FuzzImageRef(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Add("nginx:latest")
	f.Add("ghcr.io/acme/app@sha256:" + strings.Repeat("a", 64))
	f.Fuzz(func(t *testing.T, input string) {
		c := validate.New()
		validate.ImageRef(c, "image", input)
		if !c.OK() {
			return
		}
		v := strings.TrimSpace(input)
		if v == "" || len(v) > validate.MaxImageRefLen || hasControl(v) {
			t.Fatalf("ImageRef accepted an out-of-range or control-bearing value %q", input)
		}
		for _, comp := range strings.Split(v, "/") {
			if comp == ".." {
				t.Fatalf("ImageRef accepted a traversal component in %q", input)
			}
		}
	})
}

// FuzzGitBranch asserts GitBranch never panics and never accepts a reference
// with control characters, a ".." sequence, or an over-long value.
func FuzzGitBranch(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		c := validate.New()
		validate.GitBranch(c, "branch", input)
		if !c.OK() {
			return
		}
		v := strings.TrimSpace(input)
		if v == "" || len(v) > validate.MaxGitRefLen || hasControl(v) || strings.Contains(v, "..") {
			t.Fatalf("GitBranch accepted a malformed reference %q", input)
		}
	})
}
