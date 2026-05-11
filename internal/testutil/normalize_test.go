package testutil_test

import (
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/testutil"
)

func TestNormalizeRequestID(t *testing.T) {
	in := `{"request_id":"abc-123","other":"abc-123"}`
	out := testutil.NormalizeRequestID(in)
	if !strings.Contains(out, `"request_id":"[REQUEST_ID]"`) {
		t.Errorf("request_id not normalised: %s", out)
	}
	if !strings.Contains(out, `"other":"abc-123"`) {
		t.Errorf("normaliser leaked into unrelated field: %s", out)
	}
}

func TestNormalizeDuration(t *testing.T) {
	in := `{"duration_ms":47.2,"other":47}`
	out := testutil.NormalizeDuration(in)
	if !strings.Contains(out, `"duration_ms":0`) {
		t.Errorf("duration not normalised: %s", out)
	}
	if !strings.Contains(out, `"other":47`) {
		t.Errorf("duration normaliser corrupted unrelated field: %s", out)
	}
}

func TestNormalizeTimestamps(t *testing.T) {
	in := `{"started_at":"2026-05-08T01:02:03Z","note":"timestamp 2026-05-08T05:06:07.123+02:00"}`
	out := testutil.NormalizeTimestamps(in)
	if !strings.Contains(out, `"started_at":"[TIMESTAMP]"`) {
		t.Errorf("started_at not normalised: %s", out)
	}
	if strings.Contains(out, "2026-05-08T05:06:07.123+02:00") {
		t.Errorf("free-floating timestamp not normalised: %s", out)
	}
}

func TestChainNormalizers(t *testing.T) {
	in := `{"request_id":"abc","trace_id":"xyz","duration_ms":1}`
	chain := testutil.ChainNormalizers(testutil.DefaultJSONNormalizers()...)
	out := chain(in)
	for _, want := range []string{
		`"request_id":"[REQUEST_ID]"`,
		`"trace_id":"[TRACE_ID]"`,
		`"duration_ms":0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("chain missed %q in %s", want, out)
		}
	}
}
