package output

import (
	"strings"
	"testing"
)

func TestNewRedactor_DropsEmptyAndShortSecrets(t *testing.T) {
	t.Parallel()
	r := NewRedactor("", " ", "abc", "valid-secret-token")
	in := "abc valid-secret-token"
	got := r.Redact(in)
	// "abc" is below minRedactableLen and must NOT be rewritten.
	if !strings.Contains(got, "abc ") {
		t.Errorf("short token should not be redacted; got %q", got)
	}
	if strings.Contains(got, "valid-secret-token") {
		t.Errorf("long token should be redacted; got %q", got)
	}
	if !strings.Contains(got, Sentinel) {
		t.Errorf("expected Sentinel in output; got %q", got)
	}
}

func TestRedactor_DeduplicatesSecrets(t *testing.T) {
	t.Parallel()
	r := NewRedactor("supersecret", "supersecret", "supersecret")
	got := r.Redact("supersecret in the middle")
	if strings.Count(got, Sentinel) != 1 {
		t.Errorf("expected single redaction, got %q", got)
	}
}

func TestRedactor_AuthorizationHeaderScrubbed(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	in := "GET /v1/x HTTP/1.1\r\nAuthorization: Bearer abcdef.ghijkl.mnop\r\nHost: example.com"
	got := r.Redact(in)
	if strings.Contains(got, "abcdef") {
		t.Errorf("Bearer token leaked: %q", got)
	}
	if !strings.Contains(got, "Authorization: "+Sentinel) {
		t.Errorf("expected Authorization header to be scrubbed; got %q", got)
	}
	if !strings.Contains(got, "Host: example.com") {
		t.Errorf("non-secret headers should pass through; got %q", got)
	}
}

func TestRedactor_XApiKeyAndXAuthTokenHeaders(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	cases := []string{
		"X-API-Key: keykeykeykey",
		"x-api-key: keykeykeykey",
		"X-Auth-Token: tttttttttttt",
	}
	for _, in := range cases {
		got := r.Redact(in)
		if strings.Contains(got, "keykey") || strings.Contains(got, "tttt") {
			t.Errorf("secret header value leaked: %q", got)
		}
		if !strings.Contains(got, Sentinel) {
			t.Errorf("expected sentinel in %q", got)
		}
	}
}

func TestRedactor_QueryStringTokens(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	cases := []string{
		"https://api.example.com/v1?token=abcdef1234",
		"https://api.example.com/v1?api_key=abcdef1234&page=2",
		"https://api.example.com/v1?access_token=abcdef1234",
		"https://api.example.com/v1?x-auth-token=abcdef1234",
	}
	for _, in := range cases {
		got := r.Redact(in)
		if strings.Contains(got, "abcdef1234") {
			t.Errorf("token leaked from query: in=%q got=%q", in, got)
		}
		if !strings.Contains(got, Sentinel) {
			t.Errorf("expected sentinel; got %q", got)
		}
	}
}

func TestRedactor_PreservesNonSecretQueryParams(t *testing.T) {
	t.Parallel()
	r := NewRedactor()
	in := "https://api.example.com/v1?page=2&q=hello"
	got := r.Redact(in)
	if got != in {
		t.Errorf("non-secret query mutated: %q -> %q", in, got)
	}
}

func TestRedactor_ExplicitSecretPriority(t *testing.T) {
	t.Parallel()
	r := NewRedactor("user-token-value")
	in := "logged in with user-token-value, retrying"
	got := r.Redact(in)
	if strings.Contains(got, "user-token-value") {
		t.Errorf("explicit secret leaked: %q", got)
	}
}

func TestRedactor_Idempotent(t *testing.T) {
	t.Parallel()
	r := NewRedactor("supersecret")
	in := "Authorization: Bearer xyzxyzxyz, supersecret tail"
	once := r.Redact(in)
	twice := r.Redact(once)
	if once != twice {
		t.Errorf("redact not idempotent: once=%q twice=%q", once, twice)
	}
}

func TestRedactor_EmptyStringPassthrough(t *testing.T) {
	t.Parallel()
	r := NewRedactor("anything")
	if got := r.Redact(""); got != "" {
		t.Errorf("empty input mutated to %q", got)
	}
}
