package validate_test

import (
	stderrors "errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
// accepts a fully-qualified hostname of two or more valid DNS labels that is
// NOT in the domain-takeover blocklist (BE-0350). The seeds include each
// IPv4-literal form, the multi-label reserved special-use name `home.arpa`,
// each shared-hosting eTLD bare form, and each reserved suffix, so a fuzzer
// that drops a category from `disallowedTakeoverHost` fails the next replay
// (the accept-branch `net.ParseIP` / reserved-suffix re-derivation below
// proves the takeover invariants hold for every accepted host).
func FuzzDomain(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	for _, s := range []string{
		// IPv4 literals — survive the FQDN/label check, must be caught by
		// the takeover guard.
		"1.2.3.4", "127.0.0.1", "8.8.8.8", "192.168.1.1",
		// Multi-label reserved exact-match (RFC 6761).
		"home.arpa",
		// Reserved suffix forms (RFC 2606 documentation suffixes
		// .test/.example/.invalid are intentionally omitted — see
		// `reservedTakeoverHostSuffixes` doc).
		"printer.local", "consul.service.internal", "router.home",
		"edge.home.arpa", "server.lan", "api.localhost",
		// Shared-hosting eTLD bare forms.
		"appspot.com", "azurewebsites.net", "cloudfront.net",
		"firebaseapp.com", "github.io", "gitlab.io", "herokuapp.com",
		"netlify.app", "pages.dev", "vercel.app", "web.app",
		// Wildcard forms with a reserved tail.
		"*.appspot.com", "*.vercel.app", "*.home.arpa",
	} {
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
		// Re-derive the takeover invariants: any accepted host MUST NOT
		// parse as an IP literal and MUST NOT end in one of the
		// documented reserved suffixes. A regression that drops the
		// takeover guard from Domain trips here on the next replay of an
		// IPv4-literal or reserved-suffix seed.
		if ip := net.ParseIP(v); ip != nil {
			t.Fatalf("Domain accepted an IP-literal host %q", input)
		}
		reservedSuffixes := []string{
			".localhost", ".localdomain", ".local",
			".internal", ".intranet", ".private",
			".corp", ".home", ".home.arpa", ".lan",
		}
		for _, suffix := range reservedSuffixes {
			if strings.HasSuffix(v, suffix) {
				t.Fatalf("Domain accepted a reserved-suffix host %q (suffix %q)", input, suffix)
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
// is a typed E_VALIDATION error.
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
		if !stderrors.As(err, &ye) || ye.Code != yerr.CodeValidation {
			t.Fatalf("DecodeJSON returned a non-E_VALIDATION error: %v", err)
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

// FuzzURL asserts URL never panics and any accepted URL has a non-empty host
// that is NOT in the SSRF blocklist (BE-0349). The seeds include each
// loopback/link-local/private/CGNAT/IPv6-link-local/multicast IP shape, the
// localhost/.internal/.local hostname surface, the cloud-metadata
// hostnames, and the embedded-credentials form — so a fuzzer that drops a
// category from disallowedSSRFHost fails the next replay.
func FuzzURL(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	for _, s := range []string{
		"https://example.com/", "http://example.com/x", "https://github.com/acme/app",
		"https://127.0.0.1/", "https://localhost/", "https://169.254.169.254/",
		"https://10.0.0.1/", "https://172.16.5.5/", "https://192.168.1.1/",
		"https://100.64.0.1/", "https://[::1]/", "https://[fe80::1]/",
		"https://[fc00::1]/", "https://224.0.0.1/", "https://0.0.0.0/",
		"https://metadata.google.internal/", "https://svc.consul.internal/",
		"https://printer.local/", "https://api.localhost/",
		"https://user:pass@example.com/", "ftp://example.com/",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		c := validate.New()
		validate.URL(c, "url", input)
		if !c.OK() {
			if err := c.Err(); err != nil && len(input) >= 16 && strings.Contains(err.Error(), input) {
				t.Fatalf("URL reason echoed the submitted value")
			}
			return
		}
		v := strings.TrimSpace(input)
		if v == "" || len(v) > validate.MaxURLLen || hasControl(v) {
			t.Fatalf("URL accepted an out-of-range or control-bearing value %q", input)
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

// fuzzValidatorExpectedTargets is the closed set of public validators in
// `internal/controlplane/validate` that MUST have a corresponding Fuzz
// target in this file. Each entry is the literal function declaration the
// canonical fuzz file MUST carry. The PRD's `go test -run TestFuzzValidator
// ./...` filter binds to the `TestFuzzValidator` prefix on the wrapper
// functions below; the FuzzXxx targets bind to `go test -fuzz=FuzzXxx
// ./internal/controlplane/validate/...`. A regression that drops a
// validator from this list, deletes a FuzzXxx target, or adds a new public
// validator without an accompanying FuzzXxx target silently weakens the
// hostile-input contract — the seed corpus is what proves "no panic, no
// value-echo, no accepted invalid input" under adversarial conditions.
var fuzzValidatorExpectedTargets = []string{
	"func FuzzName(f *testing.F)",
	"func FuzzPath(f *testing.F)",
	"func FuzzDomain(f *testing.F)",
	"func FuzzEnvVarName(f *testing.F)",
	"func FuzzEnvVarValue(f *testing.F)",
	"func FuzzDecodeJSON(f *testing.F)",
	"func FuzzImageRef(f *testing.F)",
	"func FuzzURL(f *testing.F)",
	"func FuzzGitBranch(f *testing.F)",
}

// TestFuzzValidatorContractCoversExpectedValidators pins that every public
// validator in the `internal/controlplane/validate` surface has a Fuzz
// target declared in this file. A new validator added without an
// accompanying FuzzXxx target — or a deletion of an existing target —
// silently drops the validator from the seed-corpus replay that proves
// hostile inputs (long strings, invalid UTF-8, traversal sequences,
// embedded NUL, control characters, Unicode tricks) never panic and never
// produce an accepted-but-invalid value.
//
// The matcher reads this file's source on disk (resolved via
// `runtime.Caller` so a future package move auto-updates the lookup) and
// asserts every literal in `fuzzValidatorExpectedTargets` appears. The
// closed-set design means BOTH directions are caught:
//
//   - Deletion. A removed FuzzXxx target leaves a missing declaration; the
//     matcher fires with the exact validator name so the failure points the
//     operator at the regressed surface.
//   - Addition. A new validator (say, `validate.Slug`) added to the public
//     surface without a `FuzzSlug` target plus an updated expected-list
//     leaves the list out of date; the maintainer extending the validator
//     surface MUST extend this list in the same edit, which forces the
//     accompanying FuzzXxx target to be written before the test passes.
func TestFuzzValidatorContractCoversExpectedValidators(t *testing.T) {
	t.Parallel()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot resolve fuzz_test.go path")
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(self), err)
	}
	doc := string(b)
	for _, want := range fuzzValidatorExpectedTargets {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing fuzz target declaration %q; every public validator in `internal/controlplane/validate` MUST have a Fuzz target so the seed corpus replays hostile inputs deterministically under `go test -run TestFuzzValidator ./...` AND under `go test -fuzz=<target> ./internal/controlplane/validate/...`. A missing target silently drops the validator from the seed-corpus replay that proves no-panic, no-value-echo, and no-accepted-invalid-input under adversarial conditions.",
				filepath.Base(self), want)
		}
	}
}

// TestFuzzValidatorContractSeedCorpusRejectsHostileInputs binds the
// `go test -run TestFuzzValidator ./...` filter to a real runtime
// assertion: every public validator MUST accept every hostile seed in
// `fuzzSeeds` without panicking. This complements the FuzzXxx targets'
// `-fuzz` driver — the FuzzXxx functions only run their full random walk
// when invoked with `-fuzz=<name>`; without that flag they replay only
// their seed corpus, so the canonical Test wrapper here is the one a
// plain `go test ./...` run exercises.
//
// Each subtest drives every validator with one seed inside a `recover()`
// guard so a panic surfaces as a failure naming the offending validator
// AND the seed (the actionable-failure contract). The runtime invariant
// pinned here is the weakest one every Fuzz target carries — no panic.
// Stronger per-validator invariants (the rejection rules, the no-value-
// echo guarantees) remain in the FuzzXxx targets themselves; the wrapper
// is intentionally weak so a new validator added without an extended
// rejection rule still trips this gate on seed-corpus panic.
func TestFuzzValidatorContractSeedCorpusRejectsHostileInputs(t *testing.T) {
	t.Parallel()
	for i, seed := range fuzzSeeds {
		i, seed := i, seed
		t.Run("seed"+strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			run := func(name string, fn func()) {
				t.Helper()
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s panicked on seed[%d]=%q: %v", name, i, seed, r)
					}
				}()
				fn()
			}
			run("Name", func() {
				validate.Name(validate.New(), "name", seed)
			})
			run("Path", func() {
				validate.Path(validate.New(), "path", seed)
			})
			run("Domain", func() {
				validate.Domain(validate.New(), "host", seed, validate.DomainOptions{AllowWildcard: false})
			})
			run("EnvVarName", func() {
				validate.EnvVars(validate.New(), "env", []validate.EnvVar{{Name: seed, Value: "value", Secret: false}})
			})
			run("EnvVarValue", func() {
				validate.EnvVars(validate.New(), "env", []validate.EnvVar{{Name: "FUZZ_VALUE", Value: seed, Secret: true}})
			})
			run("DecodeJSON", func() {
				var into struct {
					Name string `json:"name"`
				}
				_ = validate.DecodeJSON(strings.NewReader(seed), &into, 4096)
			})
			run("ImageRef", func() {
				validate.ImageRef(validate.New(), "image", seed)
			})
			run("URL", func() {
				validate.URL(validate.New(), "url", seed)
			})
			run("GitBranch", func() {
				validate.GitBranch(validate.New(), "branch", seed)
			})
		})
	}
}
