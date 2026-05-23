package store

import (
	"context"
	"reflect"
	"strings"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// White-box unit tests for the audit repository's pure decision logic — the
// decision verdict set, id minting, metadata (un)marshalling, and the
// constructor guards on Append. They need no database, so they run on every
// `go test ./...` regardless of whether Postgres is available.

func TestAuditDecisionValid(t *testing.T) {
	t.Parallel()

	for _, d := range []AuditDecision{AuditDecisionAllowed, AuditDecisionDenied} {
		if !d.Valid() {
			t.Errorf("AuditDecision(%q).Valid() = false, want true", d)
		}
		if d.String() != string(d) {
			t.Errorf("AuditDecision(%q).String() = %q, want %q", d, d.String(), string(d))
		}
	}
	for _, d := range []AuditDecision{"", "ALLOWED", "allow", "denied ", "unknown"} {
		if d.Valid() {
			t.Errorf("AuditDecision(%q).Valid() = true, want false", d)
		}
	}
}

func TestNewAuditID(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		id, err := newAuditID()
		if err != nil {
			t.Fatalf("newAuditID: %v", err)
		}
		if !strings.HasPrefix(id, "aud_") {
			t.Fatalf("newAuditID() = %q, want an aud_ prefix", id)
		}
		// "aud_" + 16 bytes hex-encoded = 4 + 32.
		if len(id) != 36 {
			t.Fatalf("newAuditID() length = %d, want 36 (%q)", len(id), id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("newAuditID() produced a duplicate id %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestMarshalAuditMetadataEmpty(t *testing.T) {
	t.Parallel()

	for name, in := range map[string]map[string]string{
		"nil":   nil,
		"empty": {},
	} {
		b, err := marshalAuditMetadata(in)
		if err != nil {
			t.Fatalf("marshalAuditMetadata(%s): %v", name, err)
		}
		if string(b) != "{}" {
			t.Errorf("marshalAuditMetadata(%s) = %q, want %q", name, b, "{}")
		}
	}
}

func TestAuditMetadataRoundTrip(t *testing.T) {
	t.Parallel()

	want := map[string]string{"field": "replicas", "from": "1", "to": "3"}
	b, err := marshalAuditMetadata(want)
	if err != nil {
		t.Fatalf("marshalAuditMetadata: %v", err)
	}
	got, err := unmarshalAuditMetadata(b)
	if err != nil {
		t.Fatalf("unmarshalAuditMetadata: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip = %v, want %v", got, want)
	}
}

func TestUnmarshalAuditMetadataEmptyYieldsNil(t *testing.T) {
	t.Parallel()

	for name, in := range map[string][]byte{
		"nil bytes":    nil,
		"empty bytes":  {},
		"empty object": []byte("{}"),
	} {
		got, err := unmarshalAuditMetadata(in)
		if err != nil {
			t.Fatalf("unmarshalAuditMetadata(%s): %v", name, err)
		}
		if got != nil {
			t.Errorf("unmarshalAuditMetadata(%s) = %v, want nil", name, got)
		}
	}
}

func TestAuditRepositoryAppendNilTransaction(t *testing.T) {
	t.Parallel()

	repo := NewAuditRepository()
	_, err := repo.Append(context.Background(), nil, AuditEvent{Decision: AuditDecisionAllowed})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Append(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

func TestAuditRepositoryAppendInvalidDecision(t *testing.T) {
	t.Parallel()

	repo := NewAuditRepository()
	// A non-nil *Tx is not required: the invalid-decision guard runs before the
	// transaction is ever touched. Pass a zero-value *Tx to prove that.
	_, err := repo.Append(context.Background(), &Tx{}, AuditEvent{Decision: "bogus"})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Append(invalid decision) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
