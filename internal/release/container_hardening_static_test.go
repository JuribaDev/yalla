package release_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Container image hardening — static-analysis defence (BE-0355).
//
// Threat model: a leaked or compromised production container image
// for yalla-api ships materials that an attacker — internal or
// external — can pivot from. The mitigations live in the production
// `Dockerfile`, the local `docker-compose.yml`, and the public
// `SECURITY.md` posture document. Any one of them silently weakening
// is the failure mode this defence exists to catch:
//
//  1. The runtime stage MUST be a distroless `nonroot` image so the
//     final layer ships no shell, no package manager, no busybox, no
//     setuid binaries — only the API binary and a CA bundle. A swap
//     to a Debian/Alpine slim runtime would land a shell and apt/apk
//     back in the production image.
//  2. The runtime stage MUST run as `nonroot:nonroot` (UID/GID
//     65532). A regression that drops the `USER` directive falls
//     back to root in the final layer, defeating the read-only-fs +
//     dropped-capabilities posture documented in the Dockerfile and
//     in SECURITY.md.
//  3. The builder MUST produce a static binary with `CGO_ENABLED=0`,
//     `-trimpath`, and `-s -w` ldflags so (a) the binary works in
//     the distroless static image, (b) the leaked binary does not
//     reveal the build host's filesystem layout, and (c) the symbol
//     and DWARF tables are dropped. Dropping any of the three is a
//     supply-chain regression.
//  4. The Dockerfile MUST be multi-stage — a single-stage build
//     leaves the Go toolchain, package manager, source tree, and
//     `/go/pkg/mod` cache in the final image.
//  5. The Dockerfile MUST NOT use `ADD <url>` instructions — `ADD`
//     with a URL silently fetches arbitrary content at build time
//     without checksum verification and is forbidden by SECURITY.md
//     "Threat Model and Hard Rules".
//  6. The Dockerfile MUST NOT bake secret-shaped ENV values
//     (`*TOKEN`, `*PASSWORD`, `*SECRET`, `*API_KEY`, `*PRIVATE_KEY`,
//     `*SIGNING_KEY`, `*DSN`) — a leaked image must not leak
//     production credentials.
//  7. The runtime stage MUST NOT install OS packages — `apt-get`,
//     `apt install`, `yum install`, `dnf install`, and `apk add` are
//     all defeating moves for the distroless posture.
//  8. The runtime stage's `COPY --from=builder` MUST use
//     `--chown=nonroot:nonroot` so the copied binary is not owned
//     by root inside the runtime layer.
//  9. The Dockerfile MUST declare an `ENTRYPOINT` (not just `CMD`)
//     so `docker run -- some/arg` cannot replace the binary at
//     launch.
// 10. The local `docker-compose.yml` MUST pin the Postgres image to
//     a major version tag (e.g. `postgres:16`), never `postgres` or
//     `postgres:latest`, and MUST declare a `healthcheck` so the
//     integration-test harness has a deterministic readiness gate.
// 11. SECURITY.md MUST document the container hardening posture and
//     list it as a verification gate so auditors and downstream
//     redistributors can confirm the contract without reading the
//     Dockerfile.
//
// The two-test pattern (BE-0344, BE-0345, BE-0346, BE-0349, BE-0350,
// BE-0351, BE-0352, BE-0353, BE-0354) applies. The static half (this
// file) parses the Dockerfile and docker-compose.yml and asserts the
// invariants above. The "runtime" half is implicit: every CI pipeline
// and production deploy that pulls the image inherits the hardened
// posture — there is no application-code call site to drive a
// runtime contract against. The
// TestContainerHardeningStaticAnalyzerDetectsRegressions self-check
// feeds synthetic known-bad and known-good fixtures through every
// matcher so over- and under-tightening of the analyser are both
// caught — the same shape used by BE-0353 (audit tamper) and BE-0354
// (dependency scan).

// dockerfilePath is the relative path of the production container
// definition. The Dockerfile lives at the repository root by
// convention; renaming it without updating this constant is a
// regression because every CI image build, the published deployment
// runbook, and the `docker build` example inside the file itself
// reference this exact location.
const dockerfilePath = "Dockerfile"

// workerDockerfilePath is the production worker image definition.
// Keeping it separate from the API Dockerfile lets operators build,
// scan, tag, and roll the background job runner independently from
// the customer-facing listener while preserving the same hardened
// runtime posture.
const workerDockerfilePath = "Dockerfile.worker"

// dockerComposePath is the relative path of the local dependency
// stack used by integration tests (`docker compose up -d postgres`).
// CONTRIBUTING.md and the package's `internal/release/AGENTS.md`
// reference this exact path.
const dockerComposePath = "docker-compose.yml"

// requiredRuntimeBaseImage is the canonical distroless runtime base.
// The Dockerfile declares it as an ARG default; the matcher resolves
// the ARG so a regression that swaps the default to a Debian slim or
// Alpine image is caught regardless of whether the FROM line uses
// the ARG expansion or hard-codes the value.
const requiredRuntimeBaseImage = "gcr.io/distroless/static-debian12:nonroot"

// requiredNonrootUser is the canonical USER directive for the
// distroless `nonroot` image (UID 65532 / GID 65532). A bare
// `USER nonroot` (without the group) would still resolve, but the
// canonical form pinned by the Dockerfile is `nonroot:nonroot` and
// the matcher pins both halves to catch a partial regression that
// drops the group.
const requiredNonrootUser = "nonroot:nonroot"

// requiredCopyChown is the canonical `--chown=` flag for the
// runtime stage's `COPY --from=builder ...` instruction. Without
// `--chown=nonroot:nonroot` the copied binary is owned by the
// builder-image's effective user (root by default), which leaves a
// world-writable artefact under a read-only filesystem mount and
// confuses operator-side audit tooling that walks file ownership.
const requiredCopyChown = "--chown=nonroot:nonroot"

// requiredBuilderBuildFlags is the closed set of Go build knobs the
// builder stage MUST set. They are joined into a single RUN payload
// in the production Dockerfile, so the matcher scans every RUN body
// for the literal substring of each entry. The flags split as:
//
//   - `CGO_ENABLED=0` — produces a fully static binary compatible
//     with the distroless static image (the runtime carries no
//     libc). A regression to `CGO_ENABLED=1` would crash at
//     container startup with `no such file or directory` and force
//     a runtime swap to a glibc-based image.
//   - `-trimpath` — strips local filesystem paths from the binary so
//     a leaked binary does not reveal the build host's directory
//     layout.
//   - `-s -w` — drops the symbol and DWARF tables. Smaller image,
//     fewer reverse-engineering hand-holds.
var requiredBuilderBuildFlags = []string{
	"CGO_ENABLED=0",
	"-trimpath",
	"-s -w",
}

// forbiddenSecretEnvFragments is the closed set of substring patterns
// whose appearance inside an ENV key in any Dockerfile stage is
// treated as a baked-secret regression. The fragments are matched
// case-insensitively against the full key (e.g. `YALLA_DOKPLOY_TOKEN`
// matches `TOKEN`). The list is intentionally narrow — it catches the
// secret-shaped fragments the project's config layer uses, not every
// possible English word that contains "key" — so a future ENV that
// holds a non-secret hint does not false-positive. A regression that
// adds `ENV YALLA_DOKPLOY_TOKEN=...` fails here with a single
// file:line diagnostic.
var forbiddenSecretEnvFragments = []string{
	"TOKEN",
	"PASSWORD",
	"SECRET",
	"API_KEY",
	"PRIVATE_KEY",
	"SIGNING_KEY",
	"DSN",
}

// forbiddenRuntimePackageInstalls is the closed set of substrings
// whose appearance inside any RUN body of the *runtime* stage is
// treated as a regression. The distroless runtime has no package
// manager; introducing one (even just to install ca-certificates,
// which is already shipped by `static-debian12:nonroot`) defeats the
// no-shell, no-package-manager posture.
var forbiddenRuntimePackageInstalls = []string{
	"apt-get",
	"apt install",
	"yum install",
	"dnf install",
	"apk add",
	"microdnf install",
}

// dockerfileInstruction is a parsed Dockerfile instruction. The
// parser joins backslash-continuation lines so `Args` is a single
// logical string regardless of how the source spreads it across
// physical lines.
type dockerfileInstruction struct {
	Cmd  string // upper-case instruction name (FROM, RUN, COPY, USER, ENV, ENTRYPOINT, EXPOSE, LABEL, WORKDIR, CMD, ADD, ARG)
	Args string // joined arg payload
	Line int    // 1-based line number of the FIRST physical line of the instruction
}

// dockerfileStage is one `FROM ... [AS name]` block plus every
// instruction that follows up to the next FROM (or EOF).
type dockerfileStage struct {
	Base         string // ARG-expanded base image reference
	AsName       string // "" if the FROM line has no `AS <name>`
	Instructions []dockerfileInstruction
}

// dockerfileModel is the parsed structural view of a Dockerfile.
// `Args` holds ARG instructions that appear before the FIRST FROM
// (Dockerfile spec: those are "global ARGs" usable inside any FROM
// line). The matcher uses them to resolve `${RUNTIME_IMAGE}` to its
// default value when asserting the runtime base image.
type dockerfileModel struct {
	Args   map[string]string
	Stages []dockerfileStage
}

// parseDockerfile is a deliberately small Dockerfile parser scoped
// to the surface this test asserts. It (a) joins backslash-
// continuation lines into one logical instruction, (b) strips `#`
// comments and the `# syntax=` parser directive, (c) groups
// instructions under their owning FROM stage, and (d) records
// global ARG defaults so the matcher can expand `${VAR}` references
// in the runtime base image. Anything beyond that scope is opaque
// to the parser by design — the analyser is allowed to be ignorant
// of corner cases that are not part of the invariant.
func parseDockerfile(src string) dockerfileModel {
	model := dockerfileModel{Args: map[string]string{}}

	rawLines := strings.Split(src, "\n")
	type logical struct {
		text string
		line int
	}
	logicals := make([]logical, 0, len(rawLines))
	var (
		buf       strings.Builder
		startLine int
	)
	flush := func() {
		text := strings.TrimSpace(buf.String())
		if text != "" {
			logicals = append(logicals, logical{text: text, line: startLine})
		}
		buf.Reset()
		startLine = 0
	}
	for i, raw := range rawLines {
		ln := i + 1
		trimmed := strings.TrimRight(raw, " \t\r")
		// Skip pure comment / blank lines that are NOT part of a
		// continuation already in progress.
		if buf.Len() == 0 {
			s := strings.TrimSpace(trimmed)
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
		}
		// A line ending in `\` is a continuation.
		isCont := strings.HasSuffix(trimmed, "\\")
		if isCont {
			trimmed = strings.TrimSuffix(trimmed, "\\")
		}
		if buf.Len() == 0 {
			startLine = ln
		} else {
			buf.WriteByte(' ')
		}
		buf.WriteString(trimmed)
		if !isCont {
			flush()
		}
	}
	flush()

	var current *dockerfileStage // nil until the first FROM
	for _, ll := range logicals {
		text := ll.text
		sp := strings.IndexAny(text, " \t")
		if sp <= 0 {
			continue
		}
		cmd := strings.ToUpper(strings.TrimSpace(text[:sp]))
		args := strings.TrimSpace(text[sp:])
		switch cmd {
		case "FROM":
			base, asName := splitFromArgs(args)
			model.Stages = append(model.Stages, dockerfileStage{
				Base:   expandArgs(base, model.Args),
				AsName: asName,
			})
			current = &model.Stages[len(model.Stages)-1]
		case "ARG":
			if current == nil {
				name, val := splitArgDefault(args)
				if name != "" {
					model.Args[name] = val
				}
				continue
			}
			current.Instructions = append(current.Instructions, dockerfileInstruction{
				Cmd: cmd, Args: args, Line: ll.line,
			})
		default:
			if current == nil {
				continue
			}
			current.Instructions = append(current.Instructions, dockerfileInstruction{
				Cmd: cmd, Args: args, Line: ll.line,
			})
		}
	}
	return model
}

// splitFromArgs parses `FROM` arguments into (base, asName). The
// `AS <name>` clause is optional and case-insensitive.
func splitFromArgs(args string) (string, string) {
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return "", ""
	}
	base := fields[0]
	for i := 1; i+1 < len(fields); i++ {
		if strings.EqualFold(fields[i], "AS") {
			return base, fields[i+1]
		}
	}
	return base, ""
}

// splitArgDefault parses `ARG NAME=default` (or `ARG NAME` with no
// default) into (name, default). Quoting is preserved literally — the
// matcher only compares against the expanded value as the Dockerfile
// passes it through.
func splitArgDefault(args string) (string, string) {
	args = strings.TrimSpace(args)
	if args == "" {
		return "", ""
	}
	eq := strings.IndexByte(args, '=')
	if eq < 0 {
		return args, ""
	}
	return strings.TrimSpace(args[:eq]), strings.TrimSpace(args[eq+1:])
}

// argRefPattern matches `$NAME` and `${NAME}` references. The
// matcher uses it to expand the runtime base image whose Dockerfile
// declaration is `FROM ${RUNTIME_IMAGE}`.
var argRefPattern = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

// expandArgs replaces `$NAME` and `${NAME}` with the corresponding
// `args[NAME]` value. Unknown references are left untouched — the
// matcher will fail the substitution-aware assertion downstream
// rather than silently accept an opaque base reference.
func expandArgs(s string, args map[string]string) string {
	return argRefPattern.ReplaceAllStringFunc(s, func(ref string) string {
		name := strings.Trim(ref, "${}")
		if v, ok := args[name]; ok {
			return v
		}
		return ref
	})
}

// runtimeStage returns the LAST stage of the Dockerfile, which by
// convention is the runtime stage (the builder stages all carry
// `AS <name>` clauses; the final stage is unnamed). An empty model
// returns the zero stage.
func runtimeStage(model dockerfileModel) dockerfileStage {
	if len(model.Stages) == 0 {
		return dockerfileStage{}
	}
	return model.Stages[len(model.Stages)-1]
}

// builderStage returns the FIRST named stage of the Dockerfile,
// which is the builder by convention. If no stage carries an
// `AS` name the function returns the first stage so the matcher's
// downstream assertion fails with a useful diagnostic.
func builderStage(model dockerfileModel) dockerfileStage {
	for _, s := range model.Stages {
		if s.AsName != "" {
			return s
		}
	}
	if len(model.Stages) == 0 {
		return dockerfileStage{}
	}
	return model.Stages[0]
}

// stageRunPayload joins every RUN body in the stage with newlines so
// the matcher can scan for a fragment that may be spread across
// multiple RUN instructions or backslash continuations.
func stageRunPayload(s dockerfileStage) string {
	var b strings.Builder
	for _, ins := range s.Instructions {
		if ins.Cmd == "RUN" {
			b.WriteString(ins.Args)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// TestDockerfileUsesMultiStageBuild asserts the production
// Dockerfile contains AT LEAST one builder stage with an `AS` name
// AND a separate final stage. A regression that collapses the build
// into a single stage would ship the Go toolchain, module cache,
// and source tree to production.
func TestDockerfileUsesMultiStageBuild(t *testing.T) {
	t.Parallel()
	model := loadDockerfile(t)
	if err := matchMultiStageBuild(model); err != nil {
		t.Fatalf("%s: %v", dockerfilePath, err)
	}
}

// TestDockerfileRuntimeBaseImageIsDistroless asserts the runtime
// stage's FROM references the canonical distroless-static-debian12-
// nonroot image. The Dockerfile expresses this through an ARG
// default; the matcher resolves the ARG so a regression that swaps
// the default — or that hard-codes a different image — is caught
// either way.
func TestDockerfileRuntimeBaseImageIsDistroless(t *testing.T) {
	t.Parallel()
	model := loadDockerfile(t)
	if err := matchRuntimeBaseImage(model); err != nil {
		t.Fatalf("%s: %v", dockerfilePath, err)
	}
}

// TestDockerfileRuntimeStageRunsAsNonRoot asserts the runtime stage
// carries a `USER nonroot:nonroot` directive. The matcher requires
// the canonical form (user + group) to catch a partial regression
// that drops the group.
func TestDockerfileRuntimeStageRunsAsNonRoot(t *testing.T) {
	t.Parallel()
	model := loadDockerfile(t)
	if err := matchRuntimeUser(model); err != nil {
		t.Fatalf("%s: %v", dockerfilePath, err)
	}
}

// TestDockerfileBuildsStaticTrimmedBinary asserts the builder stage's
// `RUN ... go build ...` invocation carries every member of
// `requiredBuilderBuildFlags`. The matcher walks every RUN body in
// the builder stage so a flag spread across continuations or split
// into a separate RUN is still discovered.
func TestDockerfileBuildsStaticTrimmedBinary(t *testing.T) {
	t.Parallel()
	model := loadDockerfile(t)
	if err := matchBuilderBuildFlags(model); err != nil {
		t.Fatalf("%s: %v", dockerfilePath, err)
	}
}

// TestDockerfileHasEntrypoint asserts the Dockerfile declares an
// ENTRYPOINT in the runtime stage (regardless of whether CMD is also
// present). A `CMD` without `ENTRYPOINT` lets `docker run` swap the
// binary at launch.
func TestDockerfileHasEntrypoint(t *testing.T) {
	t.Parallel()
	model := loadDockerfile(t)
	if err := matchHasEntrypoint(model); err != nil {
		t.Fatalf("%s: %v", dockerfilePath, err)
	}
}

// TestDockerfileRejectsAddFromURL asserts no `ADD <url>` instruction
// appears anywhere in the Dockerfile. `ADD` with a URL fetches
// arbitrary content at build time without checksum verification.
// `ADD` with a local path is allowed but the project's convention
// is `COPY`; the matcher only flags the URL form, which is the
// supply-chain-relevant subset.
func TestDockerfileRejectsAddFromURL(t *testing.T) {
	t.Parallel()
	model := loadDockerfile(t)
	if err := matchNoAddFromURL(model); err != nil {
		t.Fatalf("%s: %v", dockerfilePath, err)
	}
}

// TestDockerfileEnvDoesNotBakeSecrets asserts no ENV instruction in
// any stage has a key that matches a `forbiddenSecretEnvFragments`
// substring. The matcher is case-insensitive — `ENV SecretToken=`
// fails just as `ENV YALLA_DOKPLOY_TOKEN=` does.
func TestDockerfileEnvDoesNotBakeSecrets(t *testing.T) {
	t.Parallel()
	model := loadDockerfile(t)
	if err := matchNoBakedSecrets(model); err != nil {
		t.Fatalf("%s: %v", dockerfilePath, err)
	}
}

// TestDockerfileRuntimeStageHasNoPackageInstall asserts no RUN body
// in the runtime stage contains a member of
// `forbiddenRuntimePackageInstalls`. The distroless runtime has no
// package manager; introducing one defeats the hardening even if
// nominally "for ca-certificates".
func TestDockerfileRuntimeStageHasNoPackageInstall(t *testing.T) {
	t.Parallel()
	model := loadDockerfile(t)
	if err := matchNoRuntimePackageInstall(model); err != nil {
		t.Fatalf("%s: %v", dockerfilePath, err)
	}
}

// TestDockerfileCopyUsesChown asserts every `COPY --from=builder ...`
// instruction in the runtime stage carries `--chown=nonroot:nonroot`.
// Without the chown flag, the copied artefact would be owned by the
// builder-image's effective user (root by default).
func TestDockerfileCopyUsesChown(t *testing.T) {
	t.Parallel()
	model := loadDockerfile(t)
	if err := matchRuntimeCopyUsesChown(model); err != nil {
		t.Fatalf("%s: %v", dockerfilePath, err)
	}
}

func TestWorkerDockerfileBuildsWorkerBinary(t *testing.T) {
	t.Parallel()
	model := loadDockerfilePath(t, workerDockerfilePath)
	if err := matchMultiStageBuild(model); err != nil {
		t.Fatalf("%s: %v", workerDockerfilePath, err)
	}
	if err := matchRuntimeBaseImage(model); err != nil {
		t.Fatalf("%s: %v", workerDockerfilePath, err)
	}
	if err := matchRuntimeUser(model); err != nil {
		t.Fatalf("%s: %v", workerDockerfilePath, err)
	}
	if err := matchBuilderBuildFlags(model); err != nil {
		t.Fatalf("%s: %v", workerDockerfilePath, err)
	}
	if err := matchNoAddFromURL(model); err != nil {
		t.Fatalf("%s: %v", workerDockerfilePath, err)
	}
	if err := matchNoBakedSecrets(model); err != nil {
		t.Fatalf("%s: %v", workerDockerfilePath, err)
	}
	if err := matchNoRuntimePackageInstall(model); err != nil {
		t.Fatalf("%s: %v", workerDockerfilePath, err)
	}
	if err := matchRuntimeCopyUsesChown(model); err != nil {
		t.Fatalf("%s: %v", workerDockerfilePath, err)
	}
	if err := matchBuildsGoPackage(model, "./cmd/yalla-worker"); err != nil {
		t.Fatalf("%s: %v", workerDockerfilePath, err)
	}
	if err := matchRuntimeCopiesArtifact(model, "/out/yalla-worker", "/usr/local/bin/yalla-worker"); err != nil {
		t.Fatalf("%s: %v", workerDockerfilePath, err)
	}
	if err := matchRuntimeEntrypoint(model, "/usr/local/bin/yalla-worker"); err != nil {
		t.Fatalf("%s: %v", workerDockerfilePath, err)
	}
}

func TestWorkerDockerfileDocumentsOperationsContract(t *testing.T) {
	t.Parallel()
	path := filepath.Join(projectRoot(t), workerDockerfilePath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", workerDockerfilePath, err)
	}
	src := string(b)
	required := []string{
		"yalla-worker production container",
		"docker build",
		"YALLA_DATABASE_URL",
		"YALLA_DOKPLOY_BASE_URL",
		"YALLA_DOKPLOY_TOKEN",
		"Health / readiness",
		"no HTTP listener",
		"structured JSON to stdout",
		"service=yalla-worker",
		"never appear in logs",
	}
	for _, want := range required {
		if !strings.Contains(src, want) {
			t.Errorf("%s: missing required operations note %q", workerDockerfilePath, want)
		}
	}
}

// TestDockerComposePostgresImageIsPinned asserts the local
// `docker-compose.yml` pins the Postgres image to a major-tag
// reference such as `postgres:16` and never `postgres`,
// `postgres:latest`, or a moving sub-major tag like `postgres:16-bookworm`
// (the matcher requires a digit-only major tag to keep the
// integration-test stack reproducible across local environments).
func TestDockerComposePostgresImageIsPinned(t *testing.T) {
	t.Parallel()
	if err := matchPostgresImagePinned(loadComposeServices(t)); err != nil {
		t.Fatalf("%s: %v", dockerComposePath, err)
	}
}

// TestDockerComposePostgresHasHealthcheck asserts the postgres
// service declares a `healthcheck` block. Integration tests in
// CONTRIBUTING.md depend on `pg_isready` returning before the
// suite connects; a regression that drops the healthcheck causes
// flaky test starts and hides connection-pool misconfigurations
// behind retries.
func TestDockerComposePostgresHasHealthcheck(t *testing.T) {
	t.Parallel()
	if err := matchPostgresHasHealthcheck(loadComposeServices(t)); err != nil {
		t.Fatalf("%s: %v", dockerComposePath, err)
	}
}

// TestSecurityPolicyDocumentsContainerHardening asserts the public
// SECURITY.md document carries the container-hardening section and
// the corresponding verification-gate row. A regression that drops
// either silently removes the human-facing posture contract.
func TestSecurityPolicyDocumentsContainerHardening(t *testing.T) {
	t.Parallel()

	path := filepath.Join(projectRoot(t), "SECURITY.md")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SECURITY.md: %v", err)
	}
	src := string(b)
	required := []string{
		"## Container Image Hardening",
		"Dockerfile.worker",
		"yalla-worker",
		"no HTTP listener",
		"distroless",
		"nonroot",
		"Multi-stage build",
		"CGO_ENABLED=0",
		"-trimpath",
		"Container image hardening",
	}
	for _, want := range required {
		if !strings.Contains(src, want) {
			t.Errorf("SECURITY.md: missing required reference %q — the published security policy no longer documents the container hardening posture", want)
		}
	}
}

// TestContainerHardeningStaticAnalyzerDetectsRegressions feeds
// synthetic known-good AND known-bad Dockerfile fixtures through
// every matcher in this file and asserts both directions. Without
// this self-check a future refactor could quietly over-accept (a
// regressed Dockerfile slips through) or quietly over-reject (the
// canonical Dockerfile shape trips the analyser). The self-check is
// the only safety net against "I weakened my own analyser without
// noticing." (Same shape as BE-0353 and BE-0354 self-checks.)
func TestContainerHardeningStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("multi-stage matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical builder + runtime",
				input:   "FROM golang:1.23-bookworm AS builder\nRUN go build\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: false,
			},
			{
				name:    "regression: single stage only",
				input:   "FROM debian:bookworm\nRUN apt-get install -y go\nRUN go build\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: two FROMs but neither has AS",
				input:   "FROM golang:1.23\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
		}
		runMatcherCases(t, cases, matchMultiStageBuild)
	})

	t.Run("runtime base image matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical distroless via ARG default",
				input:   "ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot\nFROM golang:1.23 AS builder\nRUN go build\nFROM ${RUNTIME_IMAGE}\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: false,
			},
			{
				name:    "canonical distroless inlined",
				input:   "FROM golang:1.23 AS builder\nRUN go build\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: false,
			},
			{
				name:    "regression: debian slim runtime",
				input:   "FROM golang:1.23 AS builder\nRUN go build\nFROM debian:bookworm-slim\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: distroless but not nonroot variant",
				input:   "FROM golang:1.23 AS builder\nRUN go build\nFROM gcr.io/distroless/static-debian12\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: unknown ARG default leaves placeholder",
				input:   "FROM golang:1.23 AS builder\nRUN go build\nFROM ${RUNTIME_IMAGE}\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
		}
		runMatcherCases(t, cases, matchRuntimeBaseImage)
	})

	t.Run("runtime user matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical user+group",
				input:   minimalCanonicalDockerfile(),
				wantErr: false,
			},
			{
				name:    "regression: USER directive missing",
				input:   "FROM golang:1.23 AS builder\nRUN go build\nFROM gcr.io/distroless/static-debian12:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: bare USER nonroot without group",
				input:   "FROM golang:1.23 AS builder\nRUN go build\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: USER root in runtime stage",
				input:   "FROM golang:1.23 AS builder\nRUN go build\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER root\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
		}
		runMatcherCases(t, cases, matchRuntimeUser)
	})

	t.Run("builder build-flags matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical: all three flags present in one RUN",
				input:   minimalCanonicalDockerfile(),
				wantErr: false,
			},
			{
				name:    "regression: CGO_ENABLED dropped",
				input:   "FROM golang:1.23 AS builder\nRUN go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: trimpath dropped",
				input:   "FROM golang:1.23 AS builder\nRUN CGO_ENABLED=0 go build -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: -s -w dropped",
				input:   "FROM golang:1.23 AS builder\nRUN CGO_ENABLED=0 go build -trimpath ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
		}
		runMatcherCases(t, cases, matchBuilderBuildFlags)
	})

	t.Run("entrypoint matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical exec-form ENTRYPOINT",
				input:   minimalCanonicalDockerfile(),
				wantErr: false,
			},
			{
				name:    "regression: only CMD, no ENTRYPOINT",
				input:   "FROM golang:1.23 AS builder\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nCMD [\"/x\"]\n",
				wantErr: true,
			},
		}
		runMatcherCases(t, cases, matchHasEntrypoint)
	})

	t.Run("no-ADD-from-URL matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical: no ADD instructions",
				input:   minimalCanonicalDockerfile(),
				wantErr: false,
			},
			{
				name:    "regression: ADD https URL",
				input:   "FROM golang:1.23 AS builder\nADD https://example.com/payload.tgz /tmp/payload.tgz\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: ADD http URL in runtime stage",
				input:   "FROM golang:1.23 AS builder\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nADD http://example.com/ca.crt /etc/ssl/ca.crt\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "allowed: ADD with a local relative path is not flagged",
				input:   "FROM golang:1.23 AS builder\nADD . /src\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: false,
			},
		}
		runMatcherCases(t, cases, matchNoAddFromURL)
	})

	t.Run("no-baked-secrets matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical: no secret-shaped ENV",
				input:   minimalCanonicalDockerfile(),
				wantErr: false,
			},
			{
				name:    "regression: ENV bakes a TOKEN",
				input:   "FROM golang:1.23 AS builder\nENV YALLA_DOKPLOY_TOKEN=abc123\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: ENV bakes a PASSWORD in runtime stage",
				input:   "FROM golang:1.23 AS builder\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nENV YALLA_DATABASE_PASSWORD=hunter2\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: ENV API_KEY (case-insensitive)",
				input:   "FROM golang:1.23 AS builder\nENV some_Api_Key=abc\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "allowed: benign ENV like GO_VERSION",
				input:   "FROM golang:1.23 AS builder\nENV GO_VERSION=1.23 GOOS=linux\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: false,
			},
		}
		runMatcherCases(t, cases, matchNoBakedSecrets)
	})

	t.Run("no-runtime-package-install matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical: runtime has no RUN instructions",
				input:   minimalCanonicalDockerfile(),
				wantErr: false,
			},
			{
				name:    "regression: apt-get install in runtime",
				input:   "FROM golang:1.23 AS builder\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nRUN apt-get update && apt-get install -y curl\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: apk add in runtime",
				input:   "FROM golang:1.23 AS builder\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nRUN apk add --no-cache curl\nENTRYPOINT [\"/x\"]\n",
				wantErr: true,
			},
			{
				name:    "allowed: builder stage may install packages",
				input:   "FROM golang:1.23 AS builder\nRUN apt-get update && apt-get install -y git\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nENTRYPOINT [\"/x\"]\n",
				wantErr: false,
			},
		}
		runMatcherCases(t, cases, matchNoRuntimePackageInstall)
	})

	t.Run("runtime COPY --chown matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical: COPY --from=builder --chown=nonroot:nonroot",
				input:   "FROM golang:1.23 AS builder\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" -o /out/x ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nCOPY --from=builder --chown=nonroot:nonroot /out/x /usr/local/bin/x\nENTRYPOINT [\"/usr/local/bin/x\"]\n",
				wantErr: false,
			},
			{
				name:    "regression: COPY --from=builder without --chown",
				input:   "FROM golang:1.23 AS builder\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" -o /out/x ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nCOPY --from=builder /out/x /usr/local/bin/x\nENTRYPOINT [\"/usr/local/bin/x\"]\n",
				wantErr: true,
			},
			{
				name:    "regression: --chown=root:root",
				input:   "FROM golang:1.23 AS builder\nRUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" -o /out/x ./cmd/yalla-api\nFROM gcr.io/distroless/static-debian12:nonroot\nUSER nonroot:nonroot\nCOPY --from=builder --chown=root:root /out/x /usr/local/bin/x\nENTRYPOINT [\"/usr/local/bin/x\"]\n",
				wantErr: true,
			},
			{
				name:    "allowed: no COPY --from at all (runtime stage has nothing to copy)",
				input:   minimalCanonicalDockerfile(),
				wantErr: false,
			},
		}
		runMatcherCases(t, cases, matchRuntimeCopyUsesChown)
	})

	t.Run("go package matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical: worker package built",
				input:   minimalCanonicalWorkerDockerfile(),
				wantErr: false,
			},
			{
				name:    "regression: API package built instead",
				input:   minimalCanonicalDockerfile(),
				wantErr: true,
			},
		}
		runMatcherCases(t, cases, func(model dockerfileModel) error {
			return matchBuildsGoPackage(model, "./cmd/yalla-worker")
		})
	})

	t.Run("runtime artifact matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical: worker artifact copied",
				input:   minimalCanonicalWorkerDockerfile(),
				wantErr: false,
			},
			{
				name:    "regression: wrong source artifact",
				input:   strings.ReplaceAll(minimalCanonicalWorkerDockerfile(), "/out/yalla-worker", "/out/yalla-api"),
				wantErr: true,
			},
			{
				name:    "regression: wrong destination artifact",
				input:   strings.ReplaceAll(minimalCanonicalWorkerDockerfile(), "/usr/local/bin/yalla-worker", "/usr/local/bin/yalla-api"),
				wantErr: true,
			},
		}
		runMatcherCases(t, cases, func(model dockerfileModel) error {
			return matchRuntimeCopiesArtifact(model, "/out/yalla-worker", "/usr/local/bin/yalla-worker")
		})
	})

	t.Run("runtime entrypoint target matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerCase{
			{
				name:    "canonical: worker entrypoint",
				input:   minimalCanonicalWorkerDockerfile(),
				wantErr: false,
			},
			{
				name:    "regression: API entrypoint",
				input:   strings.ReplaceAll(minimalCanonicalWorkerDockerfile(), "/usr/local/bin/yalla-worker", "/usr/local/bin/yalla-api"),
				wantErr: true,
			},
		}
		runMatcherCases(t, cases, func(model dockerfileModel) error {
			return matchRuntimeEntrypoint(model, "/usr/local/bin/yalla-worker")
		})
	})

	t.Run("postgres pinned matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerComposeCase{
			{
				name:     "canonical: postgres:16",
				services: map[string]composeService{"postgres": {Image: "postgres:16"}},
				wantErr:  false,
			},
			{
				name:     "canonical: postgres:17",
				services: map[string]composeService{"postgres": {Image: "postgres:17"}},
				wantErr:  false,
			},
			{
				name:     "regression: postgres unpinned",
				services: map[string]composeService{"postgres": {Image: "postgres"}},
				wantErr:  true,
			},
			{
				name:     "regression: postgres:latest",
				services: map[string]composeService{"postgres": {Image: "postgres:latest"}},
				wantErr:  true,
			},
			{
				name:     "regression: postgres service missing",
				services: map[string]composeService{"other": {Image: "redis:7"}},
				wantErr:  true,
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := matchPostgresImagePinned(tc.services)
				assertWantErr(t, tc.name, err, tc.wantErr)
			})
		}
	})

	t.Run("postgres healthcheck matcher", func(t *testing.T) {
		t.Parallel()
		cases := []analyzerComposeCase{
			{
				name: "canonical: pg_isready healthcheck",
				services: map[string]composeService{
					"postgres": {
						Image:       "postgres:16",
						Healthcheck: map[string]interface{}{"test": []interface{}{"CMD-SHELL", "pg_isready"}},
					},
				},
				wantErr: false,
			},
			{
				name:     "regression: postgres service has no healthcheck",
				services: map[string]composeService{"postgres": {Image: "postgres:16"}},
				wantErr:  true,
			},
			{
				name:     "regression: healthcheck present but empty",
				services: map[string]composeService{"postgres": {Image: "postgres:16", Healthcheck: map[string]interface{}{}}},
				wantErr:  true,
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := matchPostgresHasHealthcheck(tc.services)
				assertWantErr(t, tc.name, err, tc.wantErr)
			})
		}
	})
}

// analyzerCase is a Dockerfile fixture for the self-check loop.
type analyzerCase struct {
	name    string
	input   string
	wantErr bool
}

// analyzerComposeCase is a docker-compose fixture for the self-check
// loop. The compose-format matchers operate on the parsed services
// map rather than on raw YAML; pre-parsing in the test keeps the
// fixture readable without forcing the matcher to re-decode YAML
// per case.
type analyzerComposeCase struct {
	name     string
	services map[string]composeService
	wantErr  bool
}

// runMatcherCases drives a sequence of Dockerfile fixtures through
// the given matcher and asserts both directions. The helper exists
// so each matcher's self-check sub-test stays a small declarative
// table rather than a hand-rolled loop.
func runMatcherCases(t *testing.T, cases []analyzerCase, match func(dockerfileModel) error) {
	t.Helper()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := match(parseDockerfile(tc.input))
			assertWantErr(t, tc.name, err, tc.wantErr)
		})
	}
}

// assertWantErr converts a (wantErr, err) pair into a single
// targeted failure message. The shared helper keeps the self-check
// diagnostics uniform across every matcher.
func assertWantErr(t *testing.T, name string, err error, wantErr bool) {
	t.Helper()
	if wantErr && err == nil {
		t.Fatalf("synthetic %q should have failed but the analyser accepted it", name)
	}
	if !wantErr && err != nil {
		t.Fatalf("synthetic %q should have been accepted but the analyser rejected: %v", name, err)
	}
}

// minimalCanonicalDockerfile returns a stripped-down Dockerfile that
// passes every matcher in this file. The fixture is reused across
// self-check cases as the "good" baseline; a case that mutates only
// one invariant on top of this fixture isolates the regression the
// case is meant to catch.
func minimalCanonicalDockerfile() string {
	return strings.Join([]string{
		"FROM golang:1.23 AS builder",
		"RUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" -o /out/x ./cmd/yalla-api",
		"FROM gcr.io/distroless/static-debian12:nonroot",
		"USER nonroot:nonroot",
		"ENTRYPOINT [\"/x\"]",
		"",
	}, "\n")
}

func minimalCanonicalWorkerDockerfile() string {
	return strings.Join([]string{
		"FROM golang:1.23 AS builder",
		"RUN CGO_ENABLED=0 go build -trimpath -ldflags=\"-s -w\" -o /out/yalla-worker ./cmd/yalla-worker",
		"FROM gcr.io/distroless/static-debian12:nonroot",
		"USER nonroot:nonroot",
		"COPY --from=builder --chown=nonroot:nonroot /out/yalla-worker /usr/local/bin/yalla-worker",
		"ENTRYPOINT [\"/usr/local/bin/yalla-worker\"]",
		"",
	}, "\n")
}

// loadDockerfile reads and parses the production Dockerfile. A
// missing file fails the test — the container image is non-optional
// for the deployment story.
func loadDockerfile(t *testing.T) dockerfileModel {
	t.Helper()
	return loadDockerfilePath(t, dockerfilePath)
}

func loadDockerfilePath(t *testing.T, rel string) dockerfileModel {
	t.Helper()
	path := filepath.Join(projectRoot(t), rel)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return parseDockerfile(string(b))
}

// matchMultiStageBuild returns nil iff the Dockerfile carries at
// least one stage with an AS clause AND a separate final stage.
func matchMultiStageBuild(model dockerfileModel) error {
	if len(model.Stages) < 2 {
		return fmt.Errorf("Dockerfile must declare at least one builder + one runtime stage; got %d stage(s)", len(model.Stages))
	}
	named := 0
	for _, s := range model.Stages {
		if s.AsName != "" {
			named++
		}
	}
	if named == 0 {
		return fmt.Errorf("Dockerfile has %d FROM lines but none carry `AS <name>` — the build is structurally single-stage and would ship the toolchain to production", len(model.Stages))
	}
	return nil
}

// matchRuntimeBaseImage returns nil iff the runtime stage's FROM
// resolves (after ARG expansion) to `requiredRuntimeBaseImage`.
func matchRuntimeBaseImage(model dockerfileModel) error {
	rt := runtimeStage(model)
	if rt.Base == "" {
		return fmt.Errorf("runtime stage has no FROM base image")
	}
	if rt.Base != requiredRuntimeBaseImage {
		return fmt.Errorf("runtime stage base image is %q — must be %q (distroless static-debian12 nonroot)", rt.Base, requiredRuntimeBaseImage)
	}
	return nil
}

// matchRuntimeUser returns nil iff the runtime stage contains a
// `USER nonroot:nonroot` directive.
func matchRuntimeUser(model dockerfileModel) error {
	rt := runtimeStage(model)
	for _, ins := range rt.Instructions {
		if ins.Cmd != "USER" {
			continue
		}
		if strings.TrimSpace(ins.Args) == requiredNonrootUser {
			return nil
		}
		return fmt.Errorf("runtime stage USER directive is %q — must be %q", strings.TrimSpace(ins.Args), requiredNonrootUser)
	}
	return fmt.Errorf("runtime stage has no USER directive — the image would run as root")
}

// matchBuilderBuildFlags returns nil iff every member of
// `requiredBuilderBuildFlags` appears in the builder stage's joined
// RUN payload.
func matchBuilderBuildFlags(model dockerfileModel) error {
	b := builderStage(model)
	if b.AsName == "" {
		return fmt.Errorf("no builder stage found — multi-stage build is required")
	}
	payload := stageRunPayload(b)
	for _, flag := range requiredBuilderBuildFlags {
		if !strings.Contains(payload, flag) {
			return fmt.Errorf("builder stage RUN payload is missing required build flag %q — the runtime image would not get a hardened binary", flag)
		}
	}
	return nil
}

// matchHasEntrypoint returns nil iff the runtime stage declares an
// ENTRYPOINT instruction.
func matchHasEntrypoint(model dockerfileModel) error {
	rt := runtimeStage(model)
	for _, ins := range rt.Instructions {
		if ins.Cmd == "ENTRYPOINT" {
			return nil
		}
	}
	return fmt.Errorf("runtime stage has no ENTRYPOINT — `docker run` could replace the binary at launch")
}

// addURLPattern matches the URL form of an ADD instruction. The
// pattern is anchored at start-of-args and tolerates `--chown=`
// style flags between the verb and the URL.
var addURLPattern = regexp.MustCompile(`(?i)^(?:--\S+\s+)*https?://`)

// matchNoAddFromURL returns nil iff no ADD instruction in any stage
// has an http:// or https:// source.
func matchNoAddFromURL(model dockerfileModel) error {
	for stageIdx, s := range model.Stages {
		for _, ins := range s.Instructions {
			if ins.Cmd != "ADD" {
				continue
			}
			if addURLPattern.MatchString(strings.TrimSpace(ins.Args)) {
				return fmt.Errorf("stage %d (%s): ADD instruction fetches from a URL: %q — `ADD <url>` is forbidden by SECURITY.md; use a checksum-verified COPY or fetch-via-RUN with verification", stageIdx, stageLabelForError(s), ins.Args)
			}
		}
	}
	return nil
}

// matchNoBakedSecrets returns nil iff no ENV instruction in any
// stage has a key whose name contains a member of
// `forbiddenSecretEnvFragments` (case-insensitive). The matcher
// supports both ENV forms: `ENV KEY=VAL` and `ENV KEY VAL`, and the
// space-separated multi-pair form `ENV K1=V1 K2=V2`.
func matchNoBakedSecrets(model dockerfileModel) error {
	for stageIdx, s := range model.Stages {
		for _, ins := range s.Instructions {
			if ins.Cmd != "ENV" {
				continue
			}
			for _, key := range envKeys(ins.Args) {
				upper := strings.ToUpper(key)
				for _, frag := range forbiddenSecretEnvFragments {
					if strings.Contains(upper, frag) {
						return fmt.Errorf("stage %d (%s): ENV key %q matches forbidden secret-shaped fragment %q — a leaked image must not leak credentials", stageIdx, stageLabelForError(s), key, frag)
					}
				}
			}
		}
	}
	return nil
}

// envKeys returns the list of keys declared by an ENV instruction's
// argument payload. Supports both syntaxes:
//
//	ENV KEY VAL                          -> [KEY]
//	ENV K1=V1 K2=V2 K3=V3                -> [K1, K2, K3]
//
// Quoted values containing spaces are tolerated coarsely — the
// parser splits on space and treats only tokens with `=` as
// key=value pairs.
func envKeys(args string) []string {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	if !strings.Contains(args, "=") {
		// `ENV KEY VAL` form: the FIRST token is the key.
		fields := strings.Fields(args)
		if len(fields) >= 1 {
			return []string{fields[0]}
		}
		return nil
	}
	// `ENV K=V K=V` form. Split on whitespace OUTSIDE of double
	// quotes — a value may legitimately contain spaces inside
	// quotes (`ENV MSG="hello world"`).
	var (
		out     []string
		current strings.Builder
		inQuote bool
	)
	emit := func() {
		token := strings.TrimSpace(current.String())
		current.Reset()
		if token == "" {
			return
		}
		eq := strings.IndexByte(token, '=')
		if eq <= 0 {
			return
		}
		out = append(out, token[:eq])
	}
	for _, r := range args {
		switch {
		case r == '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuote:
			emit()
		default:
			current.WriteRune(r)
		}
	}
	emit()
	return out
}

// matchNoRuntimePackageInstall returns nil iff no RUN body in the
// runtime stage contains a member of
// `forbiddenRuntimePackageInstalls`.
func matchNoRuntimePackageInstall(model dockerfileModel) error {
	rt := runtimeStage(model)
	payload := stageRunPayload(rt)
	for _, frag := range forbiddenRuntimePackageInstalls {
		if strings.Contains(payload, frag) {
			return fmt.Errorf("runtime stage RUN payload contains forbidden package-install fragment %q — the distroless posture forbids a package manager in the final image", frag)
		}
	}
	return nil
}

// matchRuntimeCopyUsesChown returns nil iff every `COPY --from=...`
// in the runtime stage carries `--chown=nonroot:nonroot`. COPY
// instructions without `--from=` are allowed without the flag — they
// copy from the build context and the project does not currently
// rely on those in the runtime stage.
func matchRuntimeCopyUsesChown(model dockerfileModel) error {
	rt := runtimeStage(model)
	for _, ins := range rt.Instructions {
		if ins.Cmd != "COPY" {
			continue
		}
		args := strings.TrimSpace(ins.Args)
		if !strings.Contains(args, "--from=") {
			continue
		}
		if !strings.Contains(args, requiredCopyChown) {
			return fmt.Errorf("runtime stage COPY --from=... instruction is missing %q: %q", requiredCopyChown, args)
		}
	}
	return nil
}

func matchBuildsGoPackage(model dockerfileModel, wantPackage string) error {
	payload := stageRunPayload(builderStage(model))
	if !strings.Contains(payload, wantPackage) {
		return fmt.Errorf("builder stage RUN payload does not build %s", wantPackage)
	}
	return nil
}

func matchRuntimeCopiesArtifact(model dockerfileModel, wantSource, wantDestination string) error {
	rt := runtimeStage(model)
	for _, ins := range rt.Instructions {
		if ins.Cmd != "COPY" {
			continue
		}
		args := strings.TrimSpace(ins.Args)
		if strings.Contains(args, wantSource) && strings.Contains(args, wantDestination) {
			return nil
		}
	}
	return fmt.Errorf("runtime stage does not copy %s to %s", wantSource, wantDestination)
}

func matchRuntimeEntrypoint(model dockerfileModel, wantBinary string) error {
	rt := runtimeStage(model)
	for _, ins := range rt.Instructions {
		if ins.Cmd != "ENTRYPOINT" {
			continue
		}
		if strings.Contains(ins.Args, wantBinary) {
			return nil
		}
		return fmt.Errorf("runtime stage ENTRYPOINT is %q — must execute %s", ins.Args, wantBinary)
	}
	return fmt.Errorf("runtime stage has no ENTRYPOINT — `docker run` could replace the binary at launch")
}

// composeFile is the YAML subset the test asserts on. We model
// `services` and rely on KnownFields(false) to ignore everything
// else (volumes, networks, top-level `name`, etc.).
type composeFile struct {
	Services map[string]composeService `yaml:"services"`
}

// composeService models the service-level fields the test asserts
// on. `Healthcheck` is `interface{}` rather than a typed struct so
// that the asserter only cares whether the key is present, not
// what shape the healthcheck takes — a future migration from
// `test: ["CMD-SHELL", ...]` to a typed liveness probe should not
// require a parser change here.
type composeService struct {
	Image       string                 `yaml:"image"`
	Healthcheck map[string]interface{} `yaml:"healthcheck"`
}

// loadComposeServices reads and decodes `docker-compose.yml` and
// returns the services map. KnownFields(false) lets compose add
// top-level fields without breaking the test.
func loadComposeServices(t *testing.T) map[string]composeService {
	t.Helper()
	path := filepath.Join(projectRoot(t), dockerComposePath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", dockerComposePath, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(false)
	var cf composeFile
	if err := dec.Decode(&cf); err != nil {
		t.Fatalf("decode %s: %v", dockerComposePath, err)
	}
	return cf.Services
}

// postgresImagePinPattern matches `postgres:<digits>` and nothing
// else. A trailing variant (`-bookworm`, `-alpine`) would NOT match
// because the integration-test stack must remain reproducible across
// local environments; if the project later adopts a variant the
// pattern can widen in a single edit and the regression-fixture
// catalogue grows alongside.
var postgresImagePinPattern = regexp.MustCompile(`^postgres:\d+$`)

// matchPostgresImagePinned returns nil iff the `postgres` service's
// image matches `postgres:<digits>`.
func matchPostgresImagePinned(services map[string]composeService) error {
	svc, ok := services["postgres"]
	if !ok {
		return fmt.Errorf("services.postgres is missing — the local integration-test stack has no Postgres")
	}
	if !postgresImagePinPattern.MatchString(svc.Image) {
		return fmt.Errorf("services.postgres.image is %q — must match %q so the integration-test stack stays reproducible", svc.Image, postgresImagePinPattern.String())
	}
	return nil
}

// matchPostgresHasHealthcheck returns nil iff the `postgres` service
// declares a non-empty `healthcheck` block.
func matchPostgresHasHealthcheck(services map[string]composeService) error {
	svc, ok := services["postgres"]
	if !ok {
		return fmt.Errorf("services.postgres is missing — the local integration-test stack has no Postgres")
	}
	if len(svc.Healthcheck) == 0 {
		return fmt.Errorf("services.postgres.healthcheck is missing or empty — the integration-test harness has no deterministic readiness gate")
	}
	return nil
}

// stageLabelForError returns a short human-readable identifier for a
// stage, used in matcher diagnostics. Builder stages report their
// `AS` name; the runtime stage reports `<runtime>`.
func stageLabelForError(s dockerfileStage) string {
	if s.AsName != "" {
		return s.AsName
	}
	return "<runtime>"
}
