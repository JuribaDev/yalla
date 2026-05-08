package upgrade

import "testing"

func TestParseSemVer_Roundtrip(t *testing.T) {
	cases := []struct {
		in           string
		wantMaj      uint64
		wantMin      uint64
		wantPatch    uint64
		wantPre      string
		wantParseErr bool
	}{
		{in: "0.1.0", wantMaj: 0, wantMin: 1, wantPatch: 0},
		{in: "v1.2.3", wantMaj: 1, wantMin: 2, wantPatch: 3},
		{in: "V10.20.30", wantMaj: 10, wantMin: 20, wantPatch: 30},
		{in: "0.0.0-dev", wantMaj: 0, wantMin: 0, wantPatch: 0, wantPre: "dev"},
		{in: "1.2.3-rc.1+exp.sha.5114f85", wantMaj: 1, wantMin: 2, wantPatch: 3, wantPre: "rc.1"},
		{in: "1.2", wantMaj: 1, wantMin: 2, wantPatch: 0},
		{in: "", wantParseErr: true},
		{in: "not-a-version", wantParseErr: true},
		{in: "1.2.3.4", wantParseErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseSemVer(tc.in)
			if (err != nil) != tc.wantParseErr {
				t.Fatalf("ParseSemVer(%q) err=%v, wantErr=%v", tc.in, err, tc.wantParseErr)
			}
			if tc.wantParseErr {
				return
			}
			if got.Major != tc.wantMaj || got.Minor != tc.wantMin || got.Patch != tc.wantPatch {
				t.Fatalf("ParseSemVer(%q) = %d.%d.%d, want %d.%d.%d",
					tc.in, got.Major, got.Minor, got.Patch, tc.wantMaj, tc.wantMin, tc.wantPatch)
			}
			if got.PreRelease != tc.wantPre {
				t.Errorf("ParseSemVer(%q).PreRelease = %q, want %q", tc.in, got.PreRelease, tc.wantPre)
			}
		})
	}
}

func TestCompare_Ordering(t *testing.T) {
	mustParse := func(s string) SemVer {
		v, err := ParseSemVer(s)
		if err != nil {
			t.Fatalf("ParseSemVer(%q): %v", s, err)
		}
		return v
	}

	cases := []struct {
		a, b string
		want int
	}{
		{a: "1.2.3", b: "1.2.4", want: -1},
		{a: "1.2.4", b: "1.2.3", want: 1},
		{a: "1.2.3", b: "1.2.3", want: 0},
		{a: "0.10.0", b: "0.9.99", want: 1},
		// Pre-release sorts before its release.
		{a: "1.2.3-rc.1", b: "1.2.3", want: -1},
		{a: "1.2.3", b: "1.2.3-rc.1", want: 1},
		// Identical pre-releases.
		{a: "1.2.3-rc.1", b: "1.2.3-rc.1", want: 0},
		// Numeric pre-release ordering.
		{a: "1.2.3-rc.1", b: "1.2.3-rc.2", want: -1},
		{a: "1.2.3-rc.10", b: "1.2.3-rc.2", want: 1},
		// Numeric beats alphanumeric (SemVer 2.0 §11).
		{a: "1.2.3-1", b: "1.2.3-alpha", want: -1},
		// Build metadata is ignored.
		{a: "1.2.3+exp.sha.5114f85", b: "1.2.3+ci.1", want: 0},
	}
	for _, tc := range cases {
		got := Compare(mustParse(tc.a), mustParse(tc.b))
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
