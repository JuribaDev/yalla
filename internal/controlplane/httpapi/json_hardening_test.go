package httpapi

import (
	stderrors "errors"
	"net/http"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
)

// JSON parser hardening — runtime defense (BE-0346).
//
// These integration-style handler tests prove the hardenings configured on
// `validate.DecodeJSON` (the canonical JSON body decoder) hold end-to-end
// through `NewHandler` against a real production handler chain — auth
// middleware, the route table, the strict JSON decoder — without spinning
// up Postgres. They drive `POST /v1/organizations` because that handler is
// the simplest well-covered mutating endpoint that decodes a JSON body; the
// same decoder is wired identically on every other mutating route, so the
// hardenings proven here are the hardenings every mutating route inherits.
// The companion static analyser in
// `internal/controlplane/validate/json_static_test.go` is the regression
// backstop and rejects any future change that removes the decoder
// hardenings at the source.
//
// Every test below pins TWO properties:
//
//  1. A specific hardening fires: an unknown field is rejected, trailing
//     data is rejected, a wrong-typed field is rejected, malformed JSON is
//     rejected, a truncated body is rejected.
//
//  2. The rejection NEVER echoes the submitted body. A secret pasted into a
//     bad payload must not leak back through a decode error. Each test
//     plants a distinctive sentinel token in the offending body shape and
//     asserts the sentinel does not appear anywhere in the error envelope
//     — message, field, or otherwise.

// TestJSONHardeningUnknownFieldIsRejected proves the
// `DisallowUnknownFields()` hardening fires end-to-end. A body that
// includes an extra key the schema does not declare is a stable 400
// `E_INVALID_INPUT` with the canonical "contains an unknown field" message
// — and the unknown key's NAME is not echoed back. encoding/json's raw
// error message embeds the key (`json: unknown field "<name>"`); the
// hardening explicitly catches that case in `decodeError` and rewrites it
// to a fixed-string message, so a typo of `password_hash` does not leak
// through.
func TestJSONHardeningUnknownFieldIsRejected(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called when the body has an unknown field"),
	}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	const sentinel = "tok_unknown_field_should_not_leak"
	body := `{"slug":"acme","display_name":"Acme","` + sentinel + `":"x"}`
	rec := postOrganizations(handler, "a-valid-session-token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_INVALID_INPUT")
	const wantMsg = "contains an unknown field"
	if !strings.Contains(env.Error.Message, wantMsg) {
		t.Errorf("error.message = %q, want substring %q", env.Error.Message, wantMsg)
	}
	if strings.Contains(rec.Body.String(), sentinel) {
		t.Errorf("response body echoes the unknown field name %q — schema-leak surface", sentinel)
	}
}

// TestJSONHardeningTrailingDataIsRejected proves the `dec.More()`
// trailing-data hardening fires end-to-end. A body that concatenates two
// JSON values (`{"a":1}{"b":2}`) is a stable 400 `E_INVALID_INPUT` with the
// canonical "must contain a single JSON value" message. Without this
// check, a proxy or WAF could observe the first value while the API acts
// on the second — JSON smuggling. The orchestrator must NOT be reached.
func TestJSONHardeningTrailingDataIsRejected(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called when the body has trailing data"),
	}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	const sentinel = "tok_trailing_value_should_not_leak"
	body := `{"slug":"acme","display_name":"Acme"}{"slug":"` + sentinel + `","display_name":"Other"}`
	rec := postOrganizations(handler, "a-valid-session-token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_INVALID_INPUT")
	const wantMsg = "must contain a single JSON value"
	if !strings.Contains(env.Error.Message, wantMsg) {
		t.Errorf("error.message = %q, want substring %q", env.Error.Message, wantMsg)
	}
	if strings.Contains(rec.Body.String(), sentinel) {
		t.Errorf("response body echoes the trailing-value sentinel %q — body-echo surface", sentinel)
	}
}

// TestJSONHardeningMalformedJSONIsRejected proves the syntax-error
// hardening fires end-to-end. A body that is structurally invalid JSON is
// a stable 400 `E_INVALID_INPUT` with the canonical "not valid JSON"
// message — the rewritten, fixed-string variant that does NOT include
// `encoding/json`'s parser-position diagnostics (which can quote the
// offending byte). A secret pasted into the broken JSON must not appear in
// the response.
func TestJSONHardeningMalformedJSONIsRejected(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called for a malformed body"),
	}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	const sentinel = "tok_malformed_body_should_not_leak"
	body := `{"slug":"` + sentinel + `","display_name":` // unterminated value: malformed
	rec := postOrganizations(handler, "a-valid-session-token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_INVALID_INPUT")
	// Either the syntax-error branch or the truncation branch is acceptable
	// — the unterminated body can race either path depending on the read
	// pattern. Both branches use a fixed-string message that excludes the
	// submitted bytes.
	wantSyntax := strings.Contains(env.Error.Message, "not valid JSON")
	wantTruncated := strings.Contains(env.Error.Message, "truncated or not valid JSON")
	if !wantSyntax && !wantTruncated {
		t.Errorf("error.message = %q, want one of %q or %q",
			env.Error.Message, "not valid JSON", "truncated or not valid JSON")
	}
	if strings.Contains(rec.Body.String(), sentinel) {
		t.Errorf("response body echoes the malformed-payload sentinel %q — body-echo surface", sentinel)
	}
}

// TestJSONHardeningWrongTypeIsRejected proves the
// `json.UnmarshalTypeError` hardening fires end-to-end. A body that gives
// a declared field the wrong JSON type (a number where a string is
// expected) is a stable 400 `E_INVALID_INPUT` with a field-level violation
// — and the offending VALUE is never echoed. encoding/json's raw type
// error embeds the value; the hardening's `apierr.InvalidInput` path
// emits only the field name and the classification "has the wrong JSON
// type".
func TestJSONHardeningWrongTypeIsRejected(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called for a wrong-typed body"),
	}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	// The numeric sentinel is what would leak through a verbose
	// encoding/json type error. It must not appear in the response.
	const sentinel = "424242424242"
	body := `{"slug":"acme","display_name":` + sentinel + `}`
	rec := postOrganizations(handler, "a-valid-session-token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_INVALID_INPUT")
	if strings.Contains(rec.Body.String(), sentinel) {
		t.Errorf("response body echoes the wrong-typed value %q — value-leak surface", sentinel)
	}
	// The classification must surface in some form so the caller can
	// remediate. We accept either the field-violation message or the
	// fallback "wrong JSON type" string — both come from the hardening's
	// dedicated UnmarshalTypeError branch.
	gotFieldClass := strings.Contains(env.Error.Message, "wrong JSON type") ||
		strings.Contains(rec.Body.String(), "wrong JSON type") ||
		strings.Contains(rec.Body.String(), "validation failed")
	if !gotFieldClass {
		t.Errorf("error envelope %q does not surface the type-classification hardening", rec.Body.String())
	}
}

// TestJSONHardeningHardeningsDoNotBypassAuth proves the middleware chain
// order: auth runs BEFORE body decode, so a body that would otherwise trip
// any hardening returns 401 `E_AUTH` for an unauthenticated caller, never
// a 400. A handler that decoded first would let an attacker probe the
// hardenings (timing, internal field names through unknown-field errors)
// without a valid credential — a reconnaissance vector. The same
// invariant is asserted for body size in `body_size_test.go`; the JSON
// hardenings inherit it because both run in the same decode step, after
// the same auth middleware.
func TestJSONHardeningHardeningsDoNotBypassAuth(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called for an unauthenticated request"),
	}
	handler := createOrganizationHandlerFor(auth.Identity{}, nil, creator)

	// Unknown-field body — would be a 400 for an authenticated caller.
	body := `{"slug":"acme","display_name":"Acme","internal_admin_flag":true}`
	rec := postOrganizations(handler, "", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTHENTICATION_REQUIRED")
	if strings.Contains(env.Error.Message, "internal_admin_flag") {
		t.Errorf("auth-failure response echoes the unknown field name — pre-auth schema leak")
	}
}
