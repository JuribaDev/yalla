package api

// multipart/form-data request encoding for the few Dokploy operations
// that ship a binary payload (today the single `application-dropDeployment`
// endpoint). The encoder lives in the api package so it can be reused by
// future curated commands without re-implementing the wire shape, but it
// has no dependency on the CLI layer — callers supply scalar fields and
// already-read file bytes and receive the body + Content-Type that go
// straight into [Request.Body] / [Request.ContentType].
//
// Determinism: the encoder writes parts in lexicographic order by field
// name and accepts a caller-supplied boundary, so the exact same input
// produces the exact same bytes. That is what makes `yalla api call
// application-dropDeployment --dry-run` byte-stable across runs (the CLI
// passes [DefaultDryRunMultipartBoundary]) and what makes the unit tests
// here assert literal expected bodies without a custom matcher.

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"sort"
	"strings"
)

// ContentTypeMultipartForm is the canonical media type literal Dokploy
// declares under requestBody.content for the file-upload operation. The
// registry preserves it verbatim; the CLI's request builder branches on
// [IsMultipartFormData] to decide whether to actually encode a multipart
// envelope (this package's [BuildMultipart]) or pass the body bytes
// through as application/json.
const ContentTypeMultipartForm = "multipart/form-data"

// DefaultDryRunMultipartBoundary is the deterministic boundary the CLI
// uses when rendering `yalla api call --dry-run` output for a multipart
// operation. Exported as a constant so tests can assert the dry-run wire
// shape without duplicating the literal.
const DefaultDryRunMultipartBoundary = "yalla-dryrun-boundary"

// defaultFileContentType is the per-part Content-Type substituted when a
// [MultipartFile] leaves ContentType empty. Mirrors curl's behaviour for
// `-F field=@file` — application/octet-stream is the safe default so an
// intermediary cannot mislabel a binary as text.
const defaultFileContentType = "application/octet-stream"

// MultipartField is a scalar form field part. Each MultipartField becomes a
// `Content-Disposition: form-data; name="<Name>"` part with Value as the
// body. Numbers, booleans, or JSON-encoded sub-objects must be flattened
// to a string by the caller before being passed in.
type MultipartField struct {
	Name  string
	Value string
}

// MultipartFile is a single file upload part. The CLI populates Content
// with the real file bytes for a live request and with a redacted
// placeholder for --dry-run; the encoder itself is agnostic to which case
// it is in.
//
// Filename ends up in the Content-Disposition `filename=` attribute; an
// empty value falls back to FieldName so the part still has a stable
// identifier on the wire. ContentType becomes the per-part Content-Type
// header; an empty value defaults to application/octet-stream.
type MultipartFile struct {
	FieldName   string
	Filename    string
	ContentType string
	Content     []byte
}

// IsMultipartFormData reports whether ct is the multipart/form-data media
// type, ignoring case and any parameters. The OpenAPI spec stores the
// bare literal `multipart/form-data` under requestBody.content, but
// stripping parameters keeps us safe against a future spec drop that
// attaches a charset.
func IsMultipartFormData(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == ContentTypeMultipartForm
}

// BuildMultipart encodes fields + files into a multipart/form-data body
// and returns the body bytes plus the full Content-Type header value
// (including the boundary parameter).
//
// boundary controls the part separator:
//   - empty   → mime/multipart picks a random boundary (live wire).
//   - non-empty → the value is set verbatim via
//     [multipart.Writer.SetBoundary] (used by --dry-run and tests for
//     determinism). multipart's own validation surfaces invalid
//     boundaries as a typed error.
//
// Parts are written in stable, lexicographic order (by Name / FieldName)
// so the output is byte-deterministic for a given boundary. Empty field
// names or duplicate names across the (scalar, file) namespaces surface
// as typed errors before any bytes are written; the CLI translates them
// into CodeInvalidInput.
func BuildMultipart(fields []MultipartField, files []MultipartFile, boundary string) ([]byte, string, error) {
	for i, f := range fields {
		if strings.TrimSpace(f.Name) == "" {
			return nil, "", fmt.Errorf("multipart field[%d]: empty name", i)
		}
	}
	for i, f := range files {
		if strings.TrimSpace(f.FieldName) == "" {
			return nil, "", fmt.Errorf("multipart file[%d]: empty field name", i)
		}
	}

	// Single ordering pass: scalars and files share a namespace because
	// an upstream server cannot tell them apart by position on the wire,
	// and the OpenAPI multipart schema declares both kinds under one
	// `properties` map.
	type part struct {
		name string
		fld  *MultipartField
		file *MultipartFile
	}
	parts := make([]part, 0, len(fields)+len(files))
	for i := range fields {
		parts = append(parts, part{name: fields[i].Name, fld: &fields[i]})
	}
	for i := range files {
		parts = append(parts, part{name: files[i].FieldName, file: &files[i]})
	}
	sort.SliceStable(parts, func(i, j int) bool { return parts[i].name < parts[j].name })

	// Detect collisions: a scalar field and a file with the same name
	// would yield two parts with identical `name="..."` headers. The wire
	// permits this but it is almost always a fixture mistake.
	for i := 1; i < len(parts); i++ {
		if parts[i].name == parts[i-1].name {
			return nil, "", fmt.Errorf("multipart: duplicate field name %q", parts[i].name)
		}
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if boundary != "" {
		if err := w.SetBoundary(boundary); err != nil {
			return nil, "", fmt.Errorf("multipart: set boundary: %w", err)
		}
	}

	for _, p := range parts {
		switch {
		case p.fld != nil:
			fw, err := w.CreateFormField(p.fld.Name)
			if err != nil {
				return nil, "", fmt.Errorf("multipart: create field %q: %w", p.fld.Name, err)
			}
			if _, err := io.WriteString(fw, p.fld.Value); err != nil {
				return nil, "", fmt.Errorf("multipart: write field %q: %w", p.fld.Name, err)
			}
		case p.file != nil:
			filename := p.file.Filename
			if filename == "" {
				filename = p.file.FieldName
			}
			ct := strings.TrimSpace(p.file.ContentType)
			if ct == "" {
				ct = defaultFileContentType
			}
			fh := make(textproto.MIMEHeader, 2)
			fh.Set("Content-Disposition",
				fmt.Sprintf(`form-data; name=%q; filename=%q`, p.file.FieldName, filename))
			fh.Set("Content-Type", ct)
			pw, err := w.CreatePart(fh)
			if err != nil {
				return nil, "", fmt.Errorf("multipart: create file part %q: %w", p.file.FieldName, err)
			}
			if _, err := pw.Write(p.file.Content); err != nil {
				return nil, "", fmt.Errorf("multipart: write file part %q: %w", p.file.FieldName, err)
			}
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("multipart: close: %w", err)
	}

	return buf.Bytes(), w.FormDataContentType(), nil
}
