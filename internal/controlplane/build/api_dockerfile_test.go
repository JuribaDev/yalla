package build_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestAPIDockerfileIsProductionGrade locks the repo-tracked production
// Dockerfile down against the most common operations-artefact regressions:
//
//   - The build is multi-stage so toolchain layers never reach the runtime
//     image (smaller attack surface, smaller image).
//   - The runtime stage runs as a non-root user (least-privilege).
//   - Every base image is pinned (no implicit :latest) so a daemon-side image
//     refresh cannot silently change what production runs.
//   - The image builds and runs the yalla-api binary specifically — not the
//     CLI or the worker, which have their own artefacts.
//   - The image declares EXPOSE 8080 to match config.ProfileProduction's
//     default API listen address. Drift here would force operators to read
//     the source code to know which port to map.
//   - No secret-bearing environment variable is pre-populated by the image.
//     A leaked image must not carry production credentials; secrets are an
//     operator-runtime concern only.
//   - No literal secret-shaped pattern (a PostgreSQL DSN, a PEM block) has
//     been pasted into the file by accident.
func TestAPIDockerfileIsProductionGrade(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	dockerfile := filepath.Join(root, "Dockerfile")
	data, err := os.ReadFile(dockerfile)
	if err != nil {
		t.Fatalf("read Dockerfile at %s: %v", dockerfile, err)
	}
	s := string(data)

	// FROM lines — multi-stage requires at least two stages. Match either
	// `FROM image` or `FROM image AS stage`, case-insensitive (Dockerfile
	// keywords are conventionally upper-case but the parser is case-blind).
	fromRe := regexp.MustCompile(`(?mi)^FROM\s+(\S+)(?:\s+AS\s+\S+)?\s*$`)
	matches := fromRe.FindAllStringSubmatch(s, -1)
	if len(matches) < 2 {
		t.Fatalf("Dockerfile must be multi-stage (>=2 FROM lines); got %d", len(matches))
	}

	for _, m := range matches {
		ref := m[1]
		// ARG-substituted references are pinned via the ARG default at the
		// top of the file; the ARG default itself is what the linter cares
		// about, and a separate test below verifies the defaults are pinned.
		if strings.Contains(ref, "${") {
			continue
		}
		if strings.HasSuffix(ref, ":latest") {
			t.Errorf("FROM %s uses :latest — pin a specific tag or digest", ref)
		}
		// Require a tag (":tag") or a digest ("@sha256:...") so the FROM is
		// not implicitly resolved to :latest by the daemon.
		if !strings.ContainsAny(ref, ":@") {
			t.Errorf("FROM %s is not pinned (no tag, no digest)", ref)
		}
	}

	// ARG defaults for image references must themselves be pinned. The
	// Dockerfile threads GO_VERSION and RUNTIME_IMAGE through ARGs; a bare
	// ARG with no default (or with :latest) would defeat the pinning above.
	argDefaultRe := regexp.MustCompile(`(?mi)^ARG\s+(GO_VERSION|RUNTIME_IMAGE)=(\S+)\s*$`)
	argDefaults := argDefaultRe.FindAllStringSubmatch(s, -1)
	if len(argDefaults) == 0 {
		t.Errorf("Dockerfile must default GO_VERSION and RUNTIME_IMAGE ARGs so the FROM stages are pinned")
	}
	for _, m := range argDefaults {
		name, def := m[1], m[2]
		if def == "latest" || strings.HasSuffix(def, ":latest") {
			t.Errorf("ARG %s defaults to %q — pin a specific tag", name, def)
		}
	}

	// USER directive must exist and must not be root. Match the singular
	// `USER` line; the docker reference allows `user:group`, `uid`, and
	// `uid:gid` so the check normalises before comparing.
	userRe := regexp.MustCompile(`(?mi)^USER\s+(\S+)\s*$`)
	userMatches := userRe.FindAllStringSubmatch(s, -1)
	if len(userMatches) == 0 {
		t.Errorf("Dockerfile must declare a USER directive (non-root runtime)")
	}
	for _, u := range userMatches {
		target := strings.ToLower(strings.TrimSpace(u[1]))
		user, _, _ := strings.Cut(target, ":")
		if user == "root" || user == "0" || user == "" {
			t.Errorf("USER %q is root — runtime must be non-root", u[1])
		}
	}

	// Reference the yalla-api binary specifically. The worker has its own
	// Dockerfile artefact (BE-0410); the CLI is shipped through release
	// pipelines, not container images.
	if !strings.Contains(s, "yalla-api") {
		t.Errorf("Dockerfile must reference the yalla-api binary")
	}
	if !strings.Contains(s, "./cmd/yalla-api") {
		t.Errorf("Dockerfile must build ./cmd/yalla-api (got no matching go build path)")
	}

	// ENTRYPOINT must point at the API binary. Match the exec form (the
	// shell form is forbidden by Dockerfile best practice).
	entrypointRe := regexp.MustCompile(`(?mi)^ENTRYPOINT\s+\[\s*"[^"]*yalla-api"\s*\]\s*$`)
	if !entrypointRe.MatchString(s) {
		t.Errorf("Dockerfile must ENTRYPOINT the yalla-api binary in exec form")
	}

	// EXPOSE 8080 — matches the production profile's default listen address
	// in internal/controlplane/config/load.go. Drift here would silently
	// break operator-side port mappings.
	exposeRe := regexp.MustCompile(`(?mi)^EXPOSE\s+8080\b`)
	if !exposeRe.MatchString(s) {
		t.Errorf("Dockerfile must EXPOSE 8080 (matches the production listen address)")
	}

	// Forbidden ENV/ARG: secret-bearing variables must never be pre-populated
	// by the image. ENV NAME=VAL or ENV NAME VAL or ARG NAME=VAL with a
	// non-empty default are all banned. The list mirrors the secret fields
	// the config package treats as never-loggable.
	forbidden := []string{
		"YALLA_DATABASE_URL",
		"YALLA_SIGNING_KEYS",
		"YALLA_DOKPLOY_TOKEN",
		"DATABASE_URL",
		"POSTGRES_PASSWORD",
	}
	for _, name := range forbidden {
		envSet := regexp.MustCompile(fmt.Sprintf(`(?mi)^ENV\s+%s\s*=`, regexp.QuoteMeta(name)))
		if envSet.MatchString(s) {
			t.Errorf("Dockerfile sets ENV %s — secrets must be supplied at runtime, not baked into the image", name)
		}
		envLegacy := regexp.MustCompile(fmt.Sprintf(`(?mi)^ENV\s+%s\s+\S`, regexp.QuoteMeta(name)))
		if envLegacy.MatchString(s) {
			t.Errorf("Dockerfile sets ENV %s (legacy form) — secrets must be supplied at runtime", name)
		}
		argSet := regexp.MustCompile(fmt.Sprintf(`(?mi)^ARG\s+%s\s*=\s*\S`, regexp.QuoteMeta(name)))
		if argSet.MatchString(s) {
			t.Errorf("Dockerfile defaults ARG %s — secrets must be supplied at runtime", name)
		}
	}

	// Literal secret-shaped patterns. None of these should ever appear in a
	// committed file; the check is defence in depth in case a developer
	// pastes a sample DSN or PEM block into a comment.
	secretPatterns := []string{
		"postgres://yalla:",
		"BEGIN PRIVATE KEY",
		"BEGIN RSA PRIVATE KEY",
		"BEGIN OPENSSH PRIVATE KEY",
	}
	for _, p := range secretPatterns {
		if strings.Contains(s, p) {
			t.Errorf("Dockerfile contains a literal secret-shaped pattern %q", p)
		}
	}

	// CGO must be disabled so the binary is statically linked and runs
	// inside the distroless static image. A missing CGO_ENABLED=0 turns into
	// a runtime "no such file or directory" the first time the container
	// starts in production.
	if !strings.Contains(s, "CGO_ENABLED=0") {
		t.Errorf("Dockerfile must build with CGO_ENABLED=0 to be runnable in the distroless static image")
	}

	// -trimpath strips local filesystem paths from the binary so a leaked
	// binary does not reveal the build host's directory layout.
	if !strings.Contains(s, "-trimpath") {
		t.Errorf("Dockerfile must build with -trimpath")
	}

	// Build metadata must be threaded through -ldflags so GET /version
	// surfaces what shipped. The three variables match the package-level
	// vars in cmd/yalla-api/main.go.
	for _, sym := range []string{"main.Version=", "main.Commit=", "main.Date="} {
		if !strings.Contains(s, sym) {
			t.Errorf("Dockerfile must inject %s via -ldflags so GET /version surfaces build identity", sym)
		}
	}
}

// TestDockerignoreCoversSensitivePaths asserts the repo-tracked .dockerignore
// at the repository root excludes the paths that must never enter the build
// context. The check is defence in depth — secrets must never be checked in —
// but a missing .dockerignore would still send the .git directory to the
// daemon on every build, bloating image-build time and leaking commit-author
// emails through inadvertently-baked artefacts.
func TestDockerignoreCoversSensitivePaths(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	path := filepath.Join(root, ".dockerignore")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read .dockerignore at %s: %v", path, err)
	}
	lines := make(map[string]struct{}, 64)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines[line] = struct{}{}
	}

	required := []string{
		".git",
		".env",
		"secrets/",
		"*.pem",
		"*.key",
	}
	for _, want := range required {
		if _, ok := lines[want]; !ok {
			t.Errorf(".dockerignore must exclude %q to keep secrets and version-control state out of the build context", want)
		}
	}
}

// repoRoot walks up from the test's working directory until it finds the
// directory containing go.mod. The Dockerfile is canonical at the repo root,
// so locating it without a hard-coded relative path keeps the test stable if
// it ever moves to a different package under internal/.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root: walked above filesystem root without finding go.mod")
		}
		dir = parent
	}
}
