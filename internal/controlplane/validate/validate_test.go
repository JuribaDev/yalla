package validate_test

import (
	"bytes"
	stderrors "errors"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// fieldsOf runs fn against a fresh Collector and returns the set of violated
// field paths plus the joined reasons, so a test can assert on field paths
// without depending on violation ordering.
func fieldsOf(t *testing.T, fn func(c *validate.Collector)) (fields map[string]string, err error) {
	t.Helper()
	c := validate.New()
	fn(c)
	err = c.Err()
	fields = map[string]string{}
	for _, v := range c.Violations() {
		fields[v.Field] = v.Reason
	}
	return fields, err
}

// assertInvalidInput asserts err is a catalogued E_INVALID_INPUT error whose
// recovered violations match the expected field paths exactly.
func assertInvalidInput(t *testing.T, err error, wantFields ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	var ye *yerr.Error
	if !stderrors.As(err, &ye) {
		t.Fatalf("expected *yerr.Error, got %T", err)
	}
	if ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("expected code %s, got %s", yerr.CodeInvalidInput, ye.Code)
	}
	violations, ok := apierr.ViolationsOf(err)
	if !ok {
		t.Fatalf("expected recoverable field violations, got none")
	}
	got := map[string]struct{}{}
	for _, v := range violations {
		got[v.Field] = struct{}{}
	}
	if len(got) != len(wantFields) {
		t.Fatalf("got fields %v, want %v", got, wantFields)
	}
	for _, f := range wantFields {
		if _, ok := got[f]; !ok {
			t.Fatalf("missing expected field %q in %v", f, got)
		}
	}
}

func TestCollector(t *testing.T) {
	t.Parallel()

	c := validate.New()
	if !c.OK() || c.Err() != nil {
		t.Fatalf("fresh collector must be OK with a nil error")
	}
	c.Add("  ", "  ") // blank/blank pair is dropped
	if !c.OK() {
		t.Fatalf("blank violation must be dropped")
	}
	c.Add("field.one", "must not be blank")
	c.Addf("field.two", "must be at most %d", 5)
	if c.OK() {
		t.Fatalf("collector with violations must not be OK")
	}
	assertInvalidInput(t, c.Err(), "field.one", "field.two")

	// Violations returns an independent copy.
	got := c.Violations()
	got[0].Field = "mutated"
	if c.Violations()[0].Field == "mutated" {
		t.Fatalf("Violations must return a copy")
	}
}

func TestName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		ok    bool
	}{
		{"valid", "My Service", true},
		{"trims", "  trimmed  ", true},
		{"blank", "   ", false},
		{"too long", strings.Repeat("x", validate.MaxNameLen+1), false},
		{"control char", "bad\tname", false},
		{"newline", "bad\nname", false},
		{"invalid utf8", "bad\xff\xfename", false},
		{"unicode ok", "café déjà ✨", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fields, err := fieldsOf(t, func(c *validate.Collector) {
				validate.Name(c, "metadata.name", tt.value)
			})
			if tt.ok {
				if err != nil {
					t.Fatalf("Name(%q) = %v, want nil", tt.value, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Name(%q) = nil, want error", tt.value)
			}
			if _, ok := fields["metadata.name"]; !ok {
				t.Fatalf("expected violation on metadata.name, got %v", fields)
			}
			// The submitted value must never be echoed in the reason.
			if strings.Contains(fields["metadata.name"], strings.TrimSpace(tt.value)) && strings.TrimSpace(tt.value) != "" {
				t.Fatalf("reason echoed the submitted value: %q", fields["metadata.name"])
			}
		})
	}
}

func TestSlug(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		value string
		ok    bool
	}{
		{"my-service", true},
		{"svc1", true},
		{"-bad", false},
		{"bad-", false},
		{"a--b", false},
		{"UPPER", false},
		{"", false},
		{strings.Repeat("a", domain.MaxSlugLen+1), false},
	} {
		fields, err := fieldsOf(t, func(c *validate.Collector) {
			validate.Slug(c, "slug", tt.value)
		})
		if tt.ok != (err == nil) {
			t.Fatalf("Slug(%q): ok=%v err=%v", tt.value, tt.ok, err)
		}
		if !tt.ok {
			if r := fields["slug"]; strings.Contains(r, tt.value) && tt.value != "" {
				t.Fatalf("Slug reason echoed value: %q", r)
			}
		}
	}
}

func TestID(t *testing.T) {
	t.Parallel()
	projectID := domain.MustNewID(domain.KindProject)
	orgID := domain.MustNewID(domain.KindOrganization)

	for _, tt := range []struct {
		name  string
		value string
		want  domain.Kind
		ok    bool
	}{
		{"valid project", string(projectID), domain.KindProject, true},
		{"wrong kind", string(orgID), domain.KindProject, false},
		{"malformed", "not-an-id", domain.KindProject, false},
		{"empty", "", domain.KindProject, false},
		{"non-crockford suffix", "proj_llllllllllllllllllllllllll", domain.KindProject, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fields, err := fieldsOf(t, func(c *validate.Collector) {
				validate.ID(c, "project_id", tt.value, tt.want)
			})
			if tt.ok != (err == nil) {
				t.Fatalf("ID(%q) ok=%v err=%v", tt.value, tt.ok, err)
			}
			if !tt.ok {
				if r := fields["project_id"]; strings.Contains(r, tt.value) && tt.value != "" {
					t.Fatalf("ID reason echoed the submitted id: %q", r)
				}
			}
		})
	}
}

func TestPath(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		value string
		ok    bool
	}{
		{"Dockerfile", true},
		{"build/Dockerfile", true},
		{"./app/Dockerfile", true},
		{"", false},
		{"/etc/passwd", false},
		{"../../etc/passwd", false},
		{"build/../../secret", false},
		{"bad\\path", false},
		{"nul\x00byte", false},
		{strings.Repeat("a/", validate.MaxPathLen), false},
	} {
		_, err := fieldsOf(t, func(c *validate.Collector) {
			validate.Path(c, "build.dockerfile_path", tt.value)
		})
		if tt.ok != (err == nil) {
			t.Fatalf("Path(%q) ok=%v err=%v", tt.value, tt.ok, err)
		}
	}
}

func TestURL(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		value string
		ok    bool
	}{
		{"https://example.com/hook", true},
		{"http://example.com", true},
		{"ftp://example.com", false},
		{"https://", false},
		{"not a url", false},
		{"https://user:secret-pass@example.com", false},
		{"", false},
		{"https://example.com/" + strings.Repeat("a", validate.MaxURLLen), false},
	} {
		fields, err := fieldsOf(t, func(c *validate.Collector) {
			validate.URL(c, "notifications.url", tt.value)
		})
		if tt.ok != (err == nil) {
			t.Fatalf("URL(%q) ok=%v err=%v", tt.value, tt.ok, err)
		}
		if strings.Contains(fields["notifications.url"], "secret-pass") {
			t.Fatalf("URL reason leaked embedded credential")
		}
	}
}

func TestDomain(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		value   string
		allowWC bool
		ok      bool
	}{
		{"simple", "app.example.com", false, true},
		{"trailing dot", "app.example.com.", false, true},
		{"uppercase normalised", "APP.Example.COM", false, true},
		{"single label", "localhost", false, false},
		{"wildcard denied", "*.example.com", false, false},
		{"wildcard allowed", "*.example.com", true, true},
		{"interior wildcard", "a.*.example.com", true, false},
		{"bad label", "-bad.example.com", false, false},
		{"empty", "", false, false},
		{"too long", strings.Repeat("a.", 130) + "com", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := fieldsOf(t, func(c *validate.Collector) {
				validate.Domain(c, "domain.host", tt.value, validate.DomainOptions{AllowWildcard: tt.allowWC})
			})
			if tt.ok != (err == nil) {
				t.Fatalf("Domain(%q, allowWC=%v) ok=%v err=%v", tt.value, tt.allowWC, tt.ok, err)
			}
		})
	}
}

func TestResources(t *testing.T) {
	t.Parallel()
	// Zero is "unset" and accepted.
	if _, err := fieldsOf(t, func(c *validate.Collector) {
		validate.Resources(c, "resources", validate.ResourceRequest{})
	}); err != nil {
		t.Fatalf("zero ResourceRequest must be accepted: %v", err)
	}
	if _, err := fieldsOf(t, func(c *validate.Collector) {
		validate.Resources(c, "resources", validate.ResourceRequest{CPUMillis: 2000, MemoryMiB: 512, Replicas: 3})
	}); err != nil {
		t.Fatalf("valid ResourceRequest must be accepted: %v", err)
	}
	_, err := fieldsOf(t, func(c *validate.Collector) {
		validate.Resources(c, "resources", validate.ResourceRequest{
			CPUMillis: -1,
			MemoryMiB: validate.MaxMemoryMiB + 1,
			Replicas:  validate.MaxReplicas + 1,
		})
	})
	assertInvalidInput(t, err, "resources.cpu_millis", "resources.memory_mib", "resources.replicas")
}

func TestEnvVarsSeparatesSecretAndNonSecret(t *testing.T) {
	t.Parallel()
	vars := []validate.EnvVar{
		{Name: "1BAD", Value: "ok", Secret: false},             // [0]: invalid plain name
		{Name: "API_TOKEN", Value: "tok_LEAKME", Secret: true}, // [1]: valid secret
		{Name: "API_TOKEN", Value: "dup", Secret: false},       // [2]: duplicate of [1]
	}
	fields, err := fieldsOf(t, func(c *validate.Collector) {
		validate.EnvVars(c, "env", vars)
	})
	if err == nil {
		t.Fatalf("expected violations")
	}
	if _, ok := fields["env[0].name"]; !ok {
		t.Fatalf("expected non-secret entry under env[0].name, got %v", fields)
	}
	if _, ok := fields["env[2].name"]; !ok {
		t.Fatalf("expected duplicate non-secret entry under env[2].name, got %v", fields)
	}
	// The valid secret at index 1 must report no violation, proving secret and
	// non-secret entries are validated independently.
	for f := range fields {
		if strings.HasPrefix(f, "env.secret[1]") {
			t.Fatalf("valid secret env var must not produce a violation: %v", fields)
		}
	}
}

func TestEnvVarsNeverEchoesValues(t *testing.T) {
	t.Parallel()
	const secret = "tok_SUPER_SECRET_VALUE"
	vars := []validate.EnvVar{
		{Name: "GOOD_NAME", Value: secret + "\xff", Secret: true},      // invalid UTF-8 value
		{Name: "OTHER", Value: secret + "\x00trailing", Secret: false}, // NUL byte value
	}
	c := validate.New()
	validate.EnvVars(c, "env", vars)
	err := c.Err()
	if err == nil {
		t.Fatalf("expected violations for malformed values")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error string leaked the submitted value")
	}
	violations, _ := apierr.ViolationsOf(err)
	for _, v := range violations {
		if strings.Contains(v.Field, secret) || strings.Contains(v.Reason, secret) {
			t.Fatalf("violation leaked the submitted value: %+v", v)
		}
	}
	// The secret entry must route through the ".secret" path segment.
	foundSecretPath := false
	for _, v := range violations {
		if strings.Contains(v.Field, "env.secret[0]") {
			foundSecretPath = true
		}
	}
	if !foundSecretPath {
		t.Fatalf("secret env var violation must use the .secret path segment: %+v", violations)
	}
}

func TestGitRepoURL(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		value string
		ok    bool
	}{
		{"https://github.com/acme/app.git", true},
		{"ssh://git@github.com/acme/app.git", true},
		{"git@github.com:acme/app.git", true},
		{"https://x-access-token:ghp_secret@github.com/acme/app.git", false},
		{"ftp://github.com/acme/app.git", false},
		{"git@github.com", false},
		{"", false},
	} {
		fields, err := fieldsOf(t, func(c *validate.Collector) {
			validate.GitRepoURL(c, "build.repo_url", tt.value)
		})
		if tt.ok != (err == nil) {
			t.Fatalf("GitRepoURL(%q) ok=%v err=%v", tt.value, tt.ok, err)
		}
		if strings.Contains(fields["build.repo_url"], "ghp_secret") {
			t.Fatalf("GitRepoURL reason leaked an embedded token")
		}
	}
}

func TestGitBranchAndCommit(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		value string
		ok    bool
	}{
		{"main", true},
		{"feature/login", true},
		{"release-1.2.3", true},
		{"bad..branch", false},
		{"-leading", false},
		{"trailing/", false},
		{"with space", false},
		{"ends.lock", false},
		{"", false},
	} {
		_, err := fieldsOf(t, func(c *validate.Collector) {
			validate.GitBranch(c, "build.branch", tt.value)
		})
		if tt.ok != (err == nil) {
			t.Fatalf("GitBranch(%q) ok=%v err=%v", tt.value, tt.ok, err)
		}
	}
	for _, tt := range []struct {
		value string
		ok    bool
	}{
		{"a1b2c3d", true},
		{"0123456789abcdef0123456789abcdef01234567", true},
		{"short", false},
		{"nothex!", false},
		{"", false},
	} {
		_, err := fieldsOf(t, func(c *validate.Collector) {
			validate.GitCommit(c, "build.commit", tt.value)
		})
		if tt.ok != (err == nil) {
			t.Fatalf("GitCommit(%q) ok=%v err=%v", tt.value, tt.ok, err)
		}
	}
}

func TestImageRef(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		value string
		ok    bool
	}{
		{"nginx", true},
		{"nginx:1.27", true},
		{"library/nginx:latest", true},
		{"ghcr.io/acme/app:v1.2.3", true},
		{"registry.local:5000/acme/app:tag", true},
		{"acme/app@sha256:" + strings.Repeat("a", 64), true},
		{"acme/../app", false},
		{"ACME/App", false},
		{"acme/app:Bad Tag", false},
		{"acme/app@sha256:nothex", false},
		{"", false},
	} {
		_, err := fieldsOf(t, func(c *validate.Collector) {
			validate.ImageRef(c, "build.image", tt.value)
		})
		if tt.ok != (err == nil) {
			t.Fatalf("ImageRef(%q) ok=%v err=%v", tt.value, tt.ok, err)
		}
	}
}

func TestDecodeJSON(t *testing.T) {
	t.Parallel()
	type payload struct {
		Name string `json:"name"`
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		var p payload
		if err := validate.DecodeJSON(strings.NewReader(`{"name":"ok"}`), &p, 0); err != nil {
			t.Fatalf("DecodeJSON valid body: %v", err)
		}
		if p.Name != "ok" {
			t.Fatalf("decoded %q, want ok", p.Name)
		}
	})

	for _, tt := range []struct {
		name string
		body string
		max  int64
	}{
		{"malformed json", `{"name": `, 0},
		{"not json", `<<<garbage>>>`, 0},
		{"empty body", ``, 0},
		{"unknown field", `{"name":"ok","extra":1}`, 0},
		{"trailing data", `{"name":"ok"}{"name":"two"}`, 0},
		{"wrong type", `{"name":123}`, 0},
		{"too large", `{"name":"` + strings.Repeat("x", 100) + `"}`, 16},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var p payload
			err := validate.DecodeJSON(strings.NewReader(tt.body), &p, tt.max)
			if err == nil {
				t.Fatalf("DecodeJSON(%q) = nil, want error", tt.body)
			}
			var ye *yerr.Error
			if !stderrors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
				t.Fatalf("DecodeJSON(%q) = %v, want E_INVALID_INPUT", tt.body, err)
			}
			// The body must never appear in the error.
			if strings.Contains(err.Error(), "garbage") {
				t.Fatalf("decode error leaked the request body: %v", err)
			}
		})
	}

	t.Run("secret in malformed body is not echoed", func(t *testing.T) {
		t.Parallel()
		const secret = "tok_SHOULD_NOT_LEAK"
		var p payload
		body := bytes.NewBufferString(`{"name":"` + secret + `",,,`)
		err := validate.DecodeJSON(body, &p, 0)
		if err == nil {
			t.Fatalf("expected a decode error")
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("decode error leaked a secret from the body: %v", err)
		}
	})
}
