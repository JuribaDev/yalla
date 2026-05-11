package api_test

// Focused unit tests for the multipart/form-data encoder. They verify the
// invariants the CLI relies on (parses back through mime/multipart, fields
// + file parts present, Content-Type carries a usable boundary) and the
// determinism the dry-run renderer depends on (stable ordering, supplied
// boundary applied verbatim).

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/api"
)

func TestBuildMultipart_EncodesFieldsAndFile(t *testing.T) {
	t.Parallel()

	fields := []api.MultipartField{
		{Name: "applicationId", Value: "app-123"},
		{Name: "dropBuildPath", Value: "build/out"},
	}
	files := []api.MultipartFile{
		{
			FieldName:   "zip",
			Filename:    "dist.zip",
			ContentType: "application/zip",
			Content:     []byte("zip-content-bytes\x00\x01\x02"),
		},
	}

	body, ct, err := api.BuildMultipart(fields, files, "fixed-boundary-test")
	if err != nil {
		t.Fatalf("BuildMultipart: %v", err)
	}

	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("ParseMediaType(%q): %v", ct, err)
	}
	if mediaType != api.ContentTypeMultipartForm {
		t.Errorf("media type = %q, want %q", mediaType, api.ContentTypeMultipartForm)
	}
	if params["boundary"] != "fixed-boundary-test" {
		t.Errorf("boundary param = %q, want fixed-boundary-test", params["boundary"])
	}

	seenFields := map[string]string{}
	seenFiles := map[string][]byte{}
	seenCT := map[string]string{}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		b, err := io.ReadAll(p)
		if err != nil {
			t.Fatalf("ReadAll part %q: %v", p.FormName(), err)
		}
		if p.FileName() != "" {
			seenFiles[p.FormName()] = b
			seenCT[p.FormName()] = p.Header.Get("Content-Type")
		} else {
			seenFields[p.FormName()] = string(b)
		}
	}

	if seenFields["applicationId"] != "app-123" {
		t.Errorf("applicationId = %q", seenFields["applicationId"])
	}
	if seenFields["dropBuildPath"] != "build/out" {
		t.Errorf("dropBuildPath = %q", seenFields["dropBuildPath"])
	}
	if got, want := seenFiles["zip"], []byte("zip-content-bytes\x00\x01\x02"); !bytes.Equal(got, want) {
		t.Errorf("zip content mismatch:\n got=%q\nwant=%q", got, want)
	}
	if seenCT["zip"] != "application/zip" {
		t.Errorf("zip Content-Type = %q, want application/zip", seenCT["zip"])
	}
}

func TestBuildMultipart_RandomBoundaryUnique(t *testing.T) {
	t.Parallel()
	// Two calls with the same input but no caller-supplied boundary must
	// produce different envelopes — that is the property the live wire
	// relies on to avoid a collision between parallel uploads.
	body1, ct1, err := api.BuildMultipart([]api.MultipartField{{Name: "a", Value: "1"}}, nil, "")
	if err != nil {
		t.Fatalf("call 1: %v", err)
	}
	body2, ct2, err := api.BuildMultipart([]api.MultipartField{{Name: "a", Value: "1"}}, nil, "")
	if err != nil {
		t.Fatalf("call 2: %v", err)
	}
	if ct1 == ct2 {
		t.Errorf("random boundary should differ between calls; got %q twice", ct1)
	}
	if bytes.Equal(body1, body2) {
		t.Errorf("bodies should differ when boundaries differ")
	}
	_, params1, err := mime.ParseMediaType(ct1)
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	if params1["boundary"] == "" || !strings.Contains(string(body1), params1["boundary"]) {
		t.Errorf("body does not contain boundary from Content-Type: ct=%q", ct1)
	}
}

func TestBuildMultipart_FileContentTypeDefaults(t *testing.T) {
	t.Parallel()
	body, ct, err := api.BuildMultipart(nil, []api.MultipartFile{
		{FieldName: "zip", Content: []byte("a")},
	}, "fixed")
	if err != nil {
		t.Fatalf("BuildMultipart: %v", err)
	}
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	p, err := mr.NextPart()
	if err != nil {
		t.Fatalf("NextPart: %v", err)
	}
	if got := p.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("file Content-Type = %q, want application/octet-stream", got)
	}
	// Filename defaults to FieldName when Filename is empty.
	if got := p.FileName(); got != "zip" {
		t.Errorf("file Filename = %q, want zip", got)
	}
}

func TestBuildMultipart_DeterministicOrder(t *testing.T) {
	t.Parallel()
	body1, _, err := api.BuildMultipart([]api.MultipartField{
		{Name: "b", Value: "2"},
		{Name: "a", Value: "1"},
	}, nil, "fixed")
	if err != nil {
		t.Fatalf("call 1: %v", err)
	}
	body2, _, err := api.BuildMultipart([]api.MultipartField{
		{Name: "a", Value: "1"},
		{Name: "b", Value: "2"},
	}, nil, "fixed")
	if err != nil {
		t.Fatalf("call 2: %v", err)
	}
	if !bytes.Equal(body1, body2) {
		t.Errorf("part order should be deterministic regardless of input order")
	}
	// Lexicographic order: name="a" appears before name="b".
	idxA := strings.Index(string(body1), `name="a"`)
	idxB := strings.Index(string(body1), `name="b"`)
	if idxA < 0 || idxB < 0 || idxA > idxB {
		t.Errorf("expected name=\"a\" before name=\"b\"; got idxA=%d idxB=%d body=%q", idxA, idxB, body1)
	}
}

func TestBuildMultipart_RejectsEmptyAndDuplicateNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		fields []api.MultipartField
		files  []api.MultipartFile
	}{
		{
			name:   "empty scalar name",
			fields: []api.MultipartField{{Name: " ", Value: "v"}},
		},
		{
			name:  "empty file name",
			files: []api.MultipartFile{{FieldName: "", Content: []byte("x")}},
		},
		{
			name: "duplicate names across scalar+file",
			fields: []api.MultipartField{
				{Name: "zip", Value: "scalar"},
			},
			files: []api.MultipartFile{
				{FieldName: "zip", Content: []byte("file")},
			},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := api.BuildMultipart(tc.fields, tc.files, "fixed"); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestBuildMultipart_InvalidBoundaryErrors(t *testing.T) {
	t.Parallel()
	// mime/multipart rejects boundaries with disallowed characters
	// (whitespace, control bytes). Surface the error verbatim.
	if _, _, err := api.BuildMultipart(nil, nil, "bad\nboundary"); err == nil {
		t.Fatalf("expected error for invalid boundary")
	}
}

func TestBuildMultipart_DryRunBoundaryHonoured(t *testing.T) {
	t.Parallel()
	body, ct, err := api.BuildMultipart(
		[]api.MultipartField{{Name: "applicationId", Value: "abc"}},
		[]api.MultipartFile{{FieldName: "zip", Content: []byte("payload")}},
		api.DefaultDryRunMultipartBoundary,
	)
	if err != nil {
		t.Fatalf("BuildMultipart: %v", err)
	}
	wantCT := "multipart/form-data; boundary=" + api.DefaultDryRunMultipartBoundary
	if ct != wantCT {
		t.Errorf("Content-Type = %q, want %q", ct, wantCT)
	}
	if !strings.Contains(string(body), api.DefaultDryRunMultipartBoundary) {
		t.Errorf("body missing dry-run boundary literal")
	}
}

func TestIsMultipartFormData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want bool
	}{
		{"multipart/form-data", true},
		{"Multipart/Form-Data", true},
		{"multipart/form-data; charset=utf-8", true},
		{"  multipart/form-data  ", true},
		{"application/json", false},
		{"", false},
		{"multipart/mixed", false},
		{"text/plain; boundary=x", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := api.IsMultipartFormData(tc.in); got != tc.want {
				t.Errorf("IsMultipartFormData(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
