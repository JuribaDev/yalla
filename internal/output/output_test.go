package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func newRendererForTest(jsonMode bool, secrets ...string) (*Renderer, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	r := New(&out, &errOut, jsonMode, NewRedactor(secrets...))
	return r, &out, &errOut
}

func TestRenderer_Data_JSONEnvelopeOnStdout(t *testing.T) {
	t.Parallel()
	r, out, errOut := newRendererForTest(true)
	type Payload struct {
		Name string `json:"name"`
	}
	if err := r.Data(Payload{Name: "yalla"}); err != nil {
		t.Fatalf("Data: %v", err)
	}
	if errOut.Len() != 0 {
		t.Errorf("stderr should be empty; got %q", errOut.String())
	}
	var env successEnvelope
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v; raw=%q", err, out.String())
	}
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if !strings.HasSuffix(out.String(), "\n") {
		t.Errorf("expected trailing newline from json.Encoder; got %q", out.String())
	}
}

func TestRenderer_Data_NoOpInHumanMode(t *testing.T) {
	t.Parallel()
	r, out, _ := newRendererForTest(false)
	if err := r.Data(map[string]any{"k": "v"}); err != nil {
		t.Fatalf("Data: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("stdout should be empty in human mode; got %q", out.String())
	}
}

func TestRenderer_Human_NoOpInJSONMode(t *testing.T) {
	t.Parallel()
	r, out, _ := newRendererForTest(true)
	r.Human("hello world")
	if out.Len() != 0 {
		t.Errorf("Human must not write in JSON mode; got %q", out.String())
	}
}

func TestRenderer_Human_RedactsAndWritesToStdoutInHumanMode(t *testing.T) {
	t.Parallel()
	r, out, errOut := newRendererForTest(false, "supersecret")
	r.Human("loaded with supersecret value")
	if errOut.Len() != 0 {
		t.Errorf("stderr should be empty; got %q", errOut.String())
	}
	if strings.Contains(out.String(), "supersecret") {
		t.Errorf("secret leaked: %q", out.String())
	}
	if !strings.Contains(out.String(), Sentinel) {
		t.Errorf("expected sentinel; got %q", out.String())
	}
}

func TestRenderer_Logf_AlwaysToStderrWithRedaction(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range []bool{false, true} {
		r, out, errOut := newRendererForTest(jsonMode, "supersecret")
		r.Logf("connecting with %s", "supersecret")
		if out.Len() != 0 {
			t.Errorf("Logf leaked into stdout (json=%v): %q", jsonMode, out.String())
		}
		if !strings.Contains(errOut.String(), Sentinel) {
			t.Errorf("Logf did not redact (json=%v): %q", jsonMode, errOut.String())
		}
		if strings.Contains(errOut.String(), "supersecret") {
			t.Errorf("Logf leaked secret (json=%v): %q", jsonMode, errOut.String())
		}
	}
}

func TestRenderer_Error_HumanFormat(t *testing.T) {
	t.Parallel()
	r, out, errOut := newRendererForTest(false)
	e := yerr.New(yerr.CodeNotFound, "project foo not found").WithHint("run `yalla project list`")
	if err := r.Error(e); err != nil {
		t.Fatalf("Error: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("stdout should be empty when rendering error; got %q", out.String())
	}
	got := errOut.String()
	for _, want := range []string{"Error [E_NOT_FOUND]", "project foo not found", "hint: run `yalla project list`"} {
		if !strings.Contains(got, want) {
			t.Errorf("stderr missing %q; got %q", want, got)
		}
	}
}

func TestRenderer_Error_JSONEnvelope(t *testing.T) {
	t.Parallel()
	r, out, errOut := newRendererForTest(true)
	e := yerr.New(yerr.CodeAuth, "invalid token").WithHint("set DOKPLOY_TOKEN")
	if err := r.Error(e); err != nil {
		t.Fatalf("Error: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("stdout must be empty for JSON errors; got %q", out.String())
	}
	var env errorEnvelope
	if err := json.Unmarshal(errOut.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v; raw=%q", err, errOut.String())
	}
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	if env.Error.Code != "E_AUTH" {
		t.Errorf("code = %q, want E_AUTH", env.Error.Code)
	}
	if env.Error.Message != "invalid token" {
		t.Errorf("message = %q", env.Error.Message)
	}
	if env.Error.Hint != "set DOKPLOY_TOKEN" {
		t.Errorf("hint = %q", env.Error.Hint)
	}
}

func TestRenderer_Error_HintOmittedWhenEmpty(t *testing.T) {
	t.Parallel()
	r, _, errOut := newRendererForTest(true)
	e := yerr.New(yerr.CodeInternal, "boom")
	if err := r.Error(e); err != nil {
		t.Fatalf("Error: %v", err)
	}
	if strings.Contains(errOut.String(), "hint") {
		t.Errorf("hint must be omitted when empty; got %q", errOut.String())
	}
}

func TestRenderer_Error_DefaultsCodeWhenMissing(t *testing.T) {
	t.Parallel()
	r, _, errOut := newRendererForTest(true)
	e := &yerr.Error{Message: "no code"}
	if err := r.Error(e); err != nil {
		t.Fatalf("Error: %v", err)
	}
	if !strings.Contains(errOut.String(), "E_INTERNAL") {
		t.Errorf("expected fallback code E_INTERNAL; got %q", errOut.String())
	}
}

func TestRenderer_Error_RedactsSecretsInMessageAndHint(t *testing.T) {
	t.Parallel()
	r, _, errOut := newRendererForTest(true, "supersecret")
	e := yerr.New(yerr.CodeAuth, "auth failed for supersecret").
		WithHint("rotate supersecret and retry")
	if err := r.Error(e); err != nil {
		t.Fatalf("Error: %v", err)
	}
	if strings.Contains(errOut.String(), "supersecret") {
		t.Errorf("secret leaked into JSON error: %q", errOut.String())
	}
}

func TestRenderer_Error_NilNoOp(t *testing.T) {
	t.Parallel()
	r, out, errOut := newRendererForTest(true)
	if err := r.Error(nil); err != nil {
		t.Fatalf("Error(nil): %v", err)
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Errorf("Error(nil) wrote bytes: stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

func TestRenderer_Raw_PassesThroughBytes(t *testing.T) {
	t.Parallel()
	r, out, _ := newRendererForTest(false)
	payload := []byte{0x01, 0x02, 0x03, 0xff}
	if _, err := r.Raw(payload); err != nil {
		t.Fatalf("Raw: %v", err)
	}
	if !bytes.Equal(out.Bytes(), payload) {
		t.Errorf("Raw mutated payload: got %v want %v", out.Bytes(), payload)
	}
}

func TestRenderer_AccessorsExposeStreams(t *testing.T) {
	t.Parallel()
	r, out, errOut := newRendererForTest(true)
	if r.Out() != out {
		t.Error("Out() did not return the configured writer")
	}
	if r.ErrOut() != errOut {
		t.Error("ErrOut() did not return the configured writer")
	}
	if !r.JSON() {
		t.Error("JSON() = false, want true")
	}
	if r.Redactor() == nil {
		t.Error("Redactor() returned nil")
	}
}

func TestRenderer_NilRedactorIsTolerated(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	r := New(&out, &errOut, false, nil)
	r.Human("plain") // must not panic
	if !strings.Contains(out.String(), "plain") {
		t.Errorf("Human did not write: %q", out.String())
	}
}

func TestSuccessSchemaIsStable(t *testing.T) {
	t.Parallel()
	if SuccessSchema != "yalla.output.v1" {
		t.Errorf("SuccessSchema = %q, want yalla.output.v1", SuccessSchema)
	}
}
