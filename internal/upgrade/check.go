package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// LatestRelease summarises the GitHub release used to evaluate an
// upgrade. The struct is the JSON shape embedded in `yalla upgrade
// --check --json` so renaming a field is a public-API change.
type LatestRelease struct {
	// Tag is the raw git tag (e.g. "v0.2.0").
	Tag string `json:"tag"`

	// Version is the parsed SemVer view of Tag (without the leading
	// `v`). It is the value scripts should switch on.
	Version string `json:"version"`

	// IsPreRelease mirrors GitHub's prerelease flag.
	IsPreRelease bool `json:"is_prerelease"`

	// PublishedAt is the GitHub-recorded publish time. Zero when
	// GitHub omits the field (e.g. drafts).
	PublishedAt time.Time `json:"published_at,omitempty"`

	// HTMLURL points at the release page on github.com.
	HTMLURL string `json:"html_url,omitempty"`

	// Assets is the list of downloadable release assets (archives +
	// checksums.txt). Tests use this to verify the matching archive
	// for a target was published.
	Assets []ReleaseAsset `json:"assets"`
}

// ReleaseAsset is a single GitHub-release asset.
type ReleaseAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
	Size        int64  `json:"size"`
}

// CheckOptions configures the GitHub Releases lookup. Defaults are wired
// to the live JuribaDev/yalla repository; tests override BaseURL and
// HTTPClient to point at an httptest.Server.
type CheckOptions struct {
	// HTTPClient performs the API call. nil means "construct a client
	// with a 15s timeout".
	HTTPClient *http.Client

	// BaseURL is the GitHub API root, without trailing slash. Defaults
	// to "https://api.github.com" when empty.
	BaseURL string

	// Owner / Repo identify the GitHub project. Both default to
	// JuribaDev/yalla when empty.
	Owner string
	Repo  string

	// IncludePrerelease asks the checker to include pre-release tags
	// in the candidate set. When false (the default) the latest stable
	// release is returned, matching `yalla upgrade --check`'s safe
	// default.
	IncludePrerelease bool

	// UserAgent is sent with the API request. GitHub rejects
	// unidentified clients on some endpoints; the CLI passes
	// "yalla/<version>".
	UserAgent string
}

// DefaultOwner / DefaultRepo are the production GitHub coordinates.
// Constants live here (rather than `internal/release`) because the
// upgrade package is the only consumer that needs to talk to GitHub —
// keeping the dependency one-way avoids release-test churn when the
// upgrade flow evolves.
const (
	DefaultOwner = "JuribaDev"
	DefaultRepo  = "yalla"
)

// gitHubRelease is the raw GitHub Releases API shape we consume. Only
// the fields we use are decoded; everything else is dropped.
type gitHubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// Check fetches the latest yalla release. When IncludePrerelease is
// false the call hits `/releases/latest` (which is the safest default;
// GitHub guarantees that endpoint excludes drafts and prereleases). When
// it is true the function falls back to `/releases?per_page=20` and
// picks the highest-versioned non-draft tag.
//
// The function returns a typed error string for transport / decode
// failures; the CLI layer wraps it into a `*errors.Error` with
// `CodeNetwork` so the JSON envelope stays stable.
func Check(ctx context.Context, opts CheckOptions) (LatestRelease, error) {
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if opts.BaseURL == "" {
		opts.BaseURL = "https://api.github.com"
	}
	if opts.Owner == "" {
		opts.Owner = DefaultOwner
	}
	if opts.Repo == "" {
		opts.Repo = DefaultRepo
	}

	if !opts.IncludePrerelease {
		rel, err := fetchOne(ctx, opts, "/repos/"+opts.Owner+"/"+opts.Repo+"/releases/latest")
		if err != nil {
			return LatestRelease{}, err
		}
		return convertRelease(rel), nil
	}

	releases, err := fetchAll(ctx, opts, "/repos/"+opts.Owner+"/"+opts.Repo+"/releases")
	if err != nil {
		return LatestRelease{}, err
	}
	best, err := highest(releases, true)
	if err != nil {
		return LatestRelease{}, err
	}
	return convertRelease(best), nil
}

func fetchOne(ctx context.Context, opts CheckOptions, path string) (gitHubRelease, error) {
	body, err := getJSON(ctx, opts, path)
	if err != nil {
		return gitHubRelease{}, err
	}
	var rel gitHubRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return gitHubRelease{}, fmt.Errorf("decode release: %w", err)
	}
	return rel, nil
}

func fetchAll(ctx context.Context, opts CheckOptions, path string) ([]gitHubRelease, error) {
	body, err := getJSON(ctx, opts, path+"?per_page=20")
	if err != nil {
		return nil, err
	}
	var rels []gitHubRelease
	if err := json.Unmarshal(body, &rels); err != nil {
		return nil, fmt.Errorf("decode releases: %w", err)
	}
	return rels, nil
}

func getJSON(ctx context.Context, opts CheckOptions, path string) ([]byte, error) {
	u := strings.TrimRight(opts.BaseURL, "/") + path
	if _, err := url.Parse(u); err != nil {
		return nil, fmt.Errorf("invalid url %q: %w", u, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	} else {
		req.Header.Set("User-Agent", "yalla-upgrade")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no release published yet (HTTP 404)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github releases returned HTTP %d", resp.StatusCode)
	}
	return body, nil
}

func convertRelease(r gitHubRelease) LatestRelease {
	out := LatestRelease{
		Tag:          r.TagName,
		Version:      strings.TrimPrefix(r.TagName, "v"),
		IsPreRelease: r.Prerelease,
		PublishedAt:  r.PublishedAt,
		HTMLURL:      r.HTMLURL,
	}
	for _, a := range r.Assets {
		out.Assets = append(out.Assets, ReleaseAsset{
			Name:        a.Name,
			DownloadURL: a.BrowserDownloadURL,
			Size:        a.Size,
		})
	}
	return out
}

// highest picks the highest-versioned non-draft release from the list.
// When includePrerelease is false, prereleases are skipped. The function
// preserves GitHub's order when version parsing fails (so a typo in a
// tag does not abort the upgrade flow); only successfully-parsed tags
// participate in the SemVer comparison.
func highest(rels []gitHubRelease, includePrerelease bool) (gitHubRelease, error) {
	var (
		best   gitHubRelease
		bestV  SemVer
		hasOne bool
	)
	for _, r := range rels {
		if r.Draft {
			continue
		}
		if r.Prerelease && !includePrerelease {
			continue
		}
		v, err := ParseSemVer(r.TagName)
		if err != nil {
			continue
		}
		if !hasOne || bestV.LessThan(v) {
			best = r
			bestV = v
			hasOne = true
		}
	}
	if !hasOne {
		return gitHubRelease{}, fmt.Errorf("no compatible release found in github response")
	}
	return best, nil
}

// FindAsset returns the release asset whose name matches the supplied
// archive name (e.g. "yalla_0.2.0_linux_amd64.tar.gz"). The match is
// exact and case-insensitive — GitHub's API echoes the asset name
// verbatim from the upload, so any drift is a release-pipeline bug
// worth surfacing.
func (r LatestRelease) FindAsset(name string) (ReleaseAsset, bool) {
	want := strings.ToLower(name)
	for _, a := range r.Assets {
		if strings.ToLower(a.Name) == want {
			return a, true
		}
	}
	return ReleaseAsset{}, false
}
