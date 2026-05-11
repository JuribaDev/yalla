package cli

// Focused tests for the multipart/form-data path of `yalla api call`.
// They live in their own file so the (already large) api_call_cmd_test.go
// stays focused on the JSON / generic-executor flows and so a multipart
// regression is easy to git-grep for.
//
// Wire-level invariants under test:
//   - The CLI emits a real multipart envelope (parses with mime/multipart).
//   - The server sees the right form fields and the right file bytes.
//   - The Content-Type header carries a boundary parameter.
//   - --dry-run uses a deterministic boundary and substitutes a redaction
//     sentinel for file bytes (no token, no Authorization, no file
//     content ever leaks into stdout/stderr).
//   - Missing-file / wrong-shape inputs return stable CodeInvalidInput.
//   - JSON endpoints keep producing application/json bodies (regression).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
	"github.com/JuribaDev/yalla/internal/config"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// readMultipartFromServer is a thin helper used by every multipart test
// here: it parses the Content-Type, walks the parts, and returns the
// observed scalar fields, file bytes, and per-file Content-Type headers
// so each test can focus on the wire assertion it actually cares about.
func readMultipartFromServer(t *testing.T, r *http.Request) (fields map[string]string, files map[string][]byte, fileCT map[string]string, boundary string) {
	t.Helper()
	fields = map[string]string{}
	files = map[string][]byte{}
	fileCT = map[string]string{}
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		t.Errorf("server ParseMediaType: %v", err)
		return
	}
	boundary = params["boundary"]
	if boundary == "" {
		t.Errorf("server saw Content-Type without boundary: %q", r.Header.Get("Content-Type"))
		return
	}
	mr := multipart.NewReader(r.Body, boundary)
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("server NextPart: %v", err)
			return
		}
		b, err := io.ReadAll(p)
		if err != nil {
			t.Errorf("server ReadAll: %v", err)
			return
		}
		if p.FileName() != "" {
			files[p.FormName()] = b
			fileCT[p.FormName()] = p.Header.Get("Content-Type")
		} else {
			fields[p.FormName()] = string(b)
		}
	}
	return
}

func TestAPICall_Multipart_Success(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "dist.zip")
	zipBytes := []byte("PK\x03\x04--fake-zip-content--")
	if err := os.WriteFile(tmpFile, zipBytes, 0o600); err != nil {
		t.Fatalf("seed zip: %v", err)
	}

	var (
		seenMethod      string
		seenPath        string
		seenContentType string
		seenFields      map[string]string
		seenFiles       map[string][]byte
		seenFileCT      map[string]string
	)
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		seenContentType = r.Header.Get("Content-Type")
		seenFields, seenFiles, seenFileCT, _ = readMultipartFromServer(t, r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	inputPath := filepath.Join(t.TempDir(), "input.json")
	inputJSON := fmt.Sprintf(`{
        "body":  {"applicationId": "app-1", "dropBuildPath": "build/output"},
        "files": {"zip": {"path": %q, "filename": "dist.zip", "content_type": "application/zip"}}
    }`, tmpFile)
	if err := os.WriteFile(inputPath, []byte(inputJSON), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "application-dropDeployment", "--input", inputPath)
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode; got %q", stderr)
	}
	if seenMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", seenMethod)
	}
	if wantPath := coverageWirePath("/drop-deployment"); seenPath != wantPath {
		t.Errorf("path = %q, want %q", seenPath, wantPath)
	}
	if !strings.HasPrefix(seenContentType, "multipart/form-data; boundary=") {
		t.Errorf("Content-Type = %q, want multipart/form-data with boundary", seenContentType)
	}
	if seenFields["applicationId"] != "app-1" {
		t.Errorf("applicationId = %q", seenFields["applicationId"])
	}
	if seenFields["dropBuildPath"] != "build/output" {
		t.Errorf("dropBuildPath = %q", seenFields["dropBuildPath"])
	}
	if !bytes.Equal(seenFiles["zip"], zipBytes) {
		t.Errorf("zip bytes mismatch:\n got=%q\nwant=%q", seenFiles["zip"], zipBytes)
	}
	if seenFileCT["zip"] != "application/zip" {
		t.Errorf("zip part Content-Type = %q", seenFileCT["zip"])
	}
	if !strings.Contains(stdout, `"operation_id":"application-dropDeployment"`) {
		t.Errorf("stdout missing operation_id; got %q", stdout)
	}
}

func TestAPICall_Multipart_AcceptsBareStringFileValue(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(tmpFile, []byte("hello-bare"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var (
		seenFiles  map[string][]byte
		seenFileCT map[string]string
	)
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, seenFiles, seenFileCT, _ = readMultipartFromServer(t, r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	inputPath := filepath.Join(t.TempDir(), "input.json")
	body := fmt.Sprintf(`{"files":{"zip":%q}}`, tmpFile)
	if err := os.WriteFile(inputPath, []byte(body), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	_, stderr, err := runRootArgs(t, "--json", "api", "call", "application-dropDeployment", "--input", inputPath)
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if string(seenFiles["zip"]) != "hello-bare" {
		t.Errorf("seenFiles[zip] = %q, want hello-bare", seenFiles["zip"])
	}
	// Filename defaults to basename of the path; Content-Type defaults
	// to application/octet-stream when not overridden.
	if seenFileCT["zip"] != "application/octet-stream" {
		t.Errorf("seenFileCT[zip] = %q, want application/octet-stream", seenFileCT["zip"])
	}
}

func TestAPICall_Multipart_DryRun_RedactsFileAndToken(t *testing.T) {
	const secretToken = "supersecret-bearer-value"
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, secretToken)

	tmpFile := filepath.Join(t.TempDir(), "secret.zip")
	secretBytes := []byte("FILE-SECRET-CONTENT-DO-NOT-LEAK\x00\x01")
	if err := os.WriteFile(tmpFile, secretBytes, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	inputPath := filepath.Join(t.TempDir(), "input.json")
	inputJSON := fmt.Sprintf(`{
        "body":  {"applicationId": "abc", "dropBuildPath": "build/output"},
        "files": {"zip": %q}
    }`, tmpFile)
	if err := os.WriteFile(inputPath, []byte(inputJSON), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "application-dropDeployment",
		"--input", inputPath, "--dry-run")
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty; got %q", stderr)
	}
	combined := stdout + stderr
	if strings.Contains(combined, secretToken) {
		t.Errorf("token leaked into dry-run output: %q", combined)
	}
	if strings.Contains(combined, "FILE-SECRET-CONTENT-DO-NOT-LEAK") {
		t.Errorf("file content leaked into dry-run output: %q", combined)
	}

	var env struct {
		Data apiCallDryRunDoc `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode: %v; raw=%q", err, stdout)
	}
	wantCT := "multipart/form-data; boundary=" + api.DefaultDryRunMultipartBoundary
	if env.Data.ContentType != wantCT {
		t.Errorf("dry-run Content-Type = %q, want %q", env.Data.ContentType, wantCT)
	}
	// Non-JSON body lands in body_text, not body.
	if len(env.Data.Body) != 0 {
		t.Errorf("body should be empty for multipart dry-run; got %q", string(env.Data.Body))
	}
	if env.Data.BodyText == "" {
		t.Errorf("body_text should carry the multipart envelope; got empty")
	}
	if !strings.Contains(env.Data.BodyText, output.Sentinel) {
		t.Errorf("body_text should include redaction sentinel; got %q", env.Data.BodyText)
	}
	if !strings.Contains(env.Data.BodyText, `name="applicationId"`) {
		t.Errorf("body_text should include scalar form field name; got %q", env.Data.BodyText)
	}
	if !strings.Contains(env.Data.BodyText, api.DefaultDryRunMultipartBoundary) {
		t.Errorf("body_text should include dry-run boundary; got %q", env.Data.BodyText)
	}

	// The Authorization / X-API-Key header in the dry-run envelope is
	// redacted via the existing scheme-aware code path. Sanity-check it
	// still works under the multipart code path.
	apiKey := env.Data.Headers[http.CanonicalHeaderKey(api.DefaultAPIKeyHeader)]
	if len(apiKey) != 1 || !strings.Contains(apiKey[0], output.Sentinel) {
		t.Errorf("api-key header should be redacted; got %v", apiKey)
	}
}

func TestAPICall_Multipart_MissingFile_Error(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")

	inputPath := filepath.Join(t.TempDir(), "input.json")
	inputJSON := `{"body":{"applicationId":"abc"},"files":{"zip":"/definitely/does/not/exist.zip"}}`
	if err := os.WriteFile(inputPath, []byte(inputJSON), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "application-dropDeployment", "--input", inputPath)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty on error; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeInvalidInput)) {
		t.Errorf("expected %s in stderr; got %q", yerr.CodeInvalidInput, stderr)
	}
}

func TestAPICall_Multipart_EmptyFilePath_Error(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")

	inputPath := filepath.Join(t.TempDir(), "input.json")
	inputJSON := `{"body":{"applicationId":"abc"},"files":{"zip":{"filename":"x.zip"}}}`
	if err := os.WriteFile(inputPath, []byte(inputJSON), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	_, stderr, err := runRootArgs(t, "--json", "api", "call", "application-dropDeployment", "--input", inputPath)
	if err == nil {
		t.Fatal("expected error for empty file path")
	}
	if !strings.Contains(stderr, string(yerr.CodeInvalidInput)) {
		t.Errorf("expected %s in stderr; got %q", yerr.CodeInvalidInput, stderr)
	}
}

func TestAPICall_Multipart_FilesForJSONOperation_Error(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")

	tmp := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	inputPath := filepath.Join(t.TempDir(), "input.json")
	body := fmt.Sprintf(`{"body":{"applicationId":"abc"},"files":{"zip":%q}}`, tmp)
	if err := os.WriteFile(inputPath, []byte(body), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	stdout, stderr, err := runRootArgs(t, "--json", "api", "call", "application-deploy", "--input", inputPath)
	if err == nil {
		t.Fatal("expected error when supplying files to a JSON operation")
	}
	if stdout != "" {
		t.Errorf("stdout should be empty on error; got %q", stdout)
	}
	if !strings.Contains(stderr, string(yerr.CodeInvalidInput)) {
		t.Errorf("expected %s in stderr; got %q", yerr.CodeInvalidInput, stderr)
	}
}

func TestAPICall_Multipart_RejectsUnknownFileField(t *testing.T) {
	t.Setenv(config.EnvBaseURL, "https://dokploy.example.com")
	t.Setenv(config.EnvToken, "test-token-value")

	inputPath := filepath.Join(t.TempDir(), "input.json")
	inputJSON := `{"files":{"zip":{"path":"/tmp/x","not_a_field":1}}}`
	if err := os.WriteFile(inputPath, []byte(inputJSON), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	_, stderr, err := runRootArgs(t, "--json", "api", "call", "application-dropDeployment", "--input", inputPath)
	if err == nil {
		t.Fatal("expected error for unknown field in files map")
	}
	if !strings.Contains(stderr, string(yerr.CodeInvalidInput)) {
		t.Errorf("expected %s in stderr; got %q", yerr.CodeInvalidInput, stderr)
	}
}

func TestAPICall_JSON_StillUsesApplicationJSON(t *testing.T) {
	// Regression guard: a non-multipart operation must keep producing
	// application/json on the wire after the multipart wiring lands.
	var (
		seenCT   string
		seenBody []byte
	)
	setupAPICallServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenCT = r.Header.Get("Content-Type")
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	inputPath := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(inputPath, []byte(`{"body":{"applicationId":"abc"}}`), 0o600); err != nil {
		t.Fatalf("seed input: %v", err)
	}

	_, stderr, err := runRootArgs(t, "--json", "api", "call", "application-deploy", "--input", inputPath)
	if err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, stderr)
	}
	if !strings.HasPrefix(seenCT, api.ContentTypeJSON) {
		t.Errorf("Content-Type = %q, want application/json prefix", seenCT)
	}
	if !bytes.Equal(seenBody, []byte(`{"applicationId":"abc"}`)) {
		t.Errorf("body = %q, want %q", seenBody, `{"applicationId":"abc"}`)
	}
}

func TestAPICallFile_UnmarshalJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    apiCallFile
		wantErr bool
	}{
		{
			name: "bare string is path",
			in:   `"/abs/path/file.zip"`,
			want: apiCallFile{Path: "/abs/path/file.zip"},
		},
		{
			name: "object full",
			in:   `{"path":"/a","filename":"b","content_type":"application/zip"}`,
			want: apiCallFile{Path: "/a", Filename: "b", ContentType: "application/zip"},
		},
		{
			name:    "object unknown field",
			in:      `{"path":"/a","sneaky":1}`,
			wantErr: true,
		},
		{
			name: "null is no-op",
			in:   `null`,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got apiCallFile
			err := json.Unmarshal([]byte(tc.in), &got)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error; got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
