package upgrade

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeReleaseHandler returns a stub /releases/latest + /releases handler.
// Callers supply the encoded payload bytes per route so individual tests
// drive the latest-vs-prerelease branches independently.
func fakeReleaseHandler(t *testing.T, latest, all []byte) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/JuribaDev/yalla/releases/latest":
			if latest == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(latest)
		case "/repos/JuribaDev/yalla/releases":
			if all == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(all)
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestCheck_LatestStable(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"tag_name":     "v0.2.0",
		"name":         "v0.2.0",
		"prerelease":   false,
		"draft":        false,
		"html_url":     "https://github.com/JuribaDev/yalla/releases/tag/v0.2.0",
		"published_at": "2026-05-01T12:00:00Z",
		"assets": []map[string]any{
			{"name": "yalla_0.2.0_linux_amd64.tar.gz", "size": 1234, "browser_download_url": "https://example/download/yalla_0.2.0_linux_amd64.tar.gz"},
			{"name": "yalla_0.2.0_checksums.txt", "size": 256, "browser_download_url": "https://example/download/yalla_0.2.0_checksums.txt"},
		},
	})
	srv := httptest.NewServer(fakeReleaseHandler(t, body, nil))
	defer srv.Close()

	got, err := Check(t.Context(), CheckOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Version != "0.2.0" {
		t.Errorf("Version = %q, want %q", got.Version, "0.2.0")
	}
	if got.IsPreRelease {
		t.Error("IsPreRelease = true; want false on stable tag")
	}
	if len(got.Assets) != 2 {
		t.Fatalf("len(Assets) = %d, want 2", len(got.Assets))
	}
	asset, ok := got.FindAsset("yalla_0.2.0_linux_amd64.tar.gz")
	if !ok {
		t.Fatal("FindAsset returned !ok for known asset")
	}
	if asset.DownloadURL == "" {
		t.Error("Asset.DownloadURL is empty")
	}
}

func TestCheck_IncludePrereleasePicksHighest(t *testing.T) {
	all, _ := json.Marshal([]map[string]any{
		{"tag_name": "v0.2.0-rc.1", "prerelease": true, "draft": false},
		{"tag_name": "v0.1.5", "prerelease": false, "draft": false},
		{"tag_name": "v0.3.0-rc.1", "prerelease": true, "draft": false},
		{"tag_name": "v0.2.0", "prerelease": false, "draft": false},
	})
	srv := httptest.NewServer(fakeReleaseHandler(t, nil, all))
	defer srv.Close()

	got, err := Check(t.Context(), CheckOptions{BaseURL: srv.URL, IncludePrerelease: true})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Version != "0.3.0-rc.1" {
		t.Errorf("Version = %q, want %q", got.Version, "0.3.0-rc.1")
	}
	if !got.IsPreRelease {
		t.Error("IsPreRelease = false; want true on rc tag")
	}
}

func TestCheck_NotFoundIsAFriendlyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := Check(t.Context(), CheckOptions{BaseURL: srv.URL})
	if err == nil {
		t.Fatal("Check returned nil error on 404")
	}
}

func TestCheck_ContextCancelAborts(t *testing.T) {
	// httptest server that blocks until the request is canceled. The
	// test asserts that ctx.Done() unblocks the call.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := Check(ctx, CheckOptions{BaseURL: srv.URL})
	if err == nil {
		t.Fatal("Check returned nil error after context cancel")
	}
}
