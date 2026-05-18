package httpapi

import (
	stderrors "errors"
	"net/http"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// Request body size limits — runtime defense (BE-0345).
//
// These integration-style handler tests prove the body-size cap holds
// end-to-end through `NewHandler` against a real production handler chain
// — auth middleware, the route table, the strict JSON decoder, the
// orchestrator port — without spinning up Postgres. They drive
// `POST /v1/organizations` because that handler is the simplest
// well-covered mutating endpoint in the package: it requires a session
// principal, decodes a JSON body, and renders the canonical
// `yalla.output.v1` success envelope; the same body decoder
// (`validate.DecodeJSON`) is wired identically on every other mutating
// route, so the cap proven here is the cap every mutating route inherits.
// The companion static test in `body_size_static_test.go` is the
// regression backstop and rejects any future handler that touches
// `r.Body` outside the size-bounded shapes.

// TestRequestBodyLimitOversizedBodyIsRejected proves the load-bearing
// validation contract: a JSON body whose length exceeds
// `validate.DefaultMaxBodyBytes` (1 MiB) is a stable 400 `E_INVALID_INPUT`
// with the canonical "exceeds the maximum allowed size" message, the
// `yalla.error.v1` envelope, and a non-empty `request_id`. The
// orchestrator never runs — the creator is wired to fail loudly if the
// handler reaches it. This is the acceptance criterion "Add unit or
// integration tests that fail when the control is removed": disable the
// `errBodyTooLarge` path in `validate.DecodeJSON` and this test goes red.
func TestRequestBodyLimitOversizedBodyIsRejected(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called when the body exceeds the cap"),
	}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	// Build a payload whose total wire length is one byte over the
	// `DefaultMaxBodyBytes` cap. The padding is large but inert: pure
	// ASCII alphanumerics, no JSON-significant characters, so the decoder
	// would treat it as a regular string value were it not over-cap.
	// `DefaultMaxBodyBytes` is `1 << 20` (1 MiB) — `strings.Repeat`
	// allocates the padding once; the runtime is well under a second.
	pad := strings.Repeat("x", int(validate.DefaultMaxBodyBytes))
	body := `{"slug":"acme","display_name":"` + pad + `"}`
	if int64(len(body)) <= validate.DefaultMaxBodyBytes {
		t.Fatalf("test fixture is at-or-under cap (len=%d, cap=%d); a regression in DefaultMaxBodyBytes invalidates this test", len(body), validate.DefaultMaxBodyBytes)
	}

	rec := postOrganizations(handler, "a-valid-session-token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_INVALID_INPUT")
	const wantMsg = "exceeds the maximum allowed size"
	if !strings.Contains(env.Error.Message, wantMsg) {
		t.Errorf("error.message = %q, want substring %q", env.Error.Message, wantMsg)
	}
	// Redaction backstop: the rejection message must NOT echo the
	// submitted body (a token pasted into a malformed body cannot leak
	// through a decode error). The padding character `x` is benign on its
	// own, but a long run of it in the response would indicate the body
	// was reflected; a stray slug or display_name fragment likewise. The
	// canonical fixed-string message keeps this trivially true.
	if strings.Contains(env.Error.Message, pad[:64]) {
		t.Errorf("error.message echoes the submitted body — secret leak surface")
	}
	if strings.Contains(env.Error.Message, "acme") {
		t.Errorf("error.message echoes a submitted JSON field value")
	}
}

// TestRequestBodyLimitValidBodyIsAccepted is the symmetric positive test:
// a valid in-cap body decodes normally, the orchestrator is called, and
// the handler renders the stable 201 success envelope. Without this
// counter-test a regression that over-tightens the cap (e.g. drops it to
// zero) would pass `TestRequestBodyLimitOversizedBodyIsRejected` but
// silently break every legitimate write.
func TestRequestBodyLimitValidBodyIsAccepted(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{org: store.Organization{
		ID:          "org_acme",
		Slug:        "acme",
		DisplayName: "Acme",
	}}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	body := `{"slug":"acme","display_name":"Acme"}`
	if int64(len(body)) >= validate.DefaultMaxBodyBytes {
		t.Fatalf("test fixture is over cap (len=%d, cap=%d); fixture drift", len(body), validate.DefaultMaxBodyBytes)
	}

	rec := postOrganizations(handler, "a-valid-session-token", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	decodeCreateOrganization(t, rec)
}

// TestRequestBodyLimitDoesNotBypassAuth proves the middleware chain order
// is correct: auth runs BEFORE body decode, so an oversized body from an
// unauthenticated caller is a stable 401 `E_AUTH`, never a 400. A handler
// that decoded first would let an attacker probe the cap (timing or
// memory pressure) without a valid credential.
func TestRequestBodyLimitDoesNotBypassAuth(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called for an unauthenticated request"),
	}
	handler := createOrganizationHandlerFor(auth.Identity{}, nil, creator)

	pad := strings.Repeat("x", int(validate.DefaultMaxBodyBytes))
	body := `{"slug":"acme","display_name":"` + pad + `"}`

	rec := postOrganizations(handler, "", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTHENTICATION_REQUIRED")
}

// TestRequestBodyLimitMissingBodyIsValidationError proves a request with
// an empty body is a stable 400 `E_INVALID_INPUT` with the canonical
// "must not be empty" message, the symmetric lower-edge of the body-size
// contract. A handler that silently accepted an empty body would skip the
// orchestrator's input validation entirely. This is the "not-found"-style
// rejection on the input side: nothing to decode.
func TestRequestBodyLimitMissingBodyIsValidationError(t *testing.T) {
	t.Parallel()

	creator := fakeOrganizationCreator{
		err: stderrors.New("creator must not be called when the body is empty"),
	}
	handler := createOrganizationHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postOrganizations(handler, "a-valid-session-token", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_INVALID_INPUT")
	const wantMsg = "must not be empty"
	if !strings.Contains(env.Error.Message, wantMsg) {
		t.Errorf("error.message = %q, want substring %q", env.Error.Message, wantMsg)
	}
}
