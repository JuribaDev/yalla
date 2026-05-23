package release_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/JuribaDev/yalla/internal/release"
)

// Canonical pair for the BE-0401 release-build verification suite.
//
// The PRD's `verificationLoop.requiredBackendCommands` declares
// `go test -run TestReleaseBuild ./...` as the load-bearing release-
// build gate. That filter binds to every test whose name starts with
// the `TestReleaseBuild` prefix. The two functions in this file are
// the closed-set members the PRD-level static defence
// (`internal/release/verification_suite_release_build_static_test.go`)
// pins:
//
//   - TestReleaseBuildCoversCallSites exercises the closed-set
//     release-derivation invariants the `internal/release` package
//     exposes to GoReleaser, the npm wrapper, the Homebrew formula,
//     and the Scoop/WinGet manifests. The release-derivation
//     functions (`Target.ArchiveExt`, `Target.BinaryName`,
//     `Target.ArchiveName`, `release.ChecksumsName`) are pure and the
//     test asserts every (OS, arch) coordinate in
//     `release.SupportedTargets` yields the documented archive
//     extension, binary name, archive name, and per-version checksum
//     file name. A regression in any of those projections — a renamed
//     target, a flipped archive extension, a dropped windows .exe
//     suffix, a checksums-template drift — fails on the offending
//     scenario name. The set of supported targets itself is part of
//     the closed-set coverage: every documented (OS, arch) pair MUST
//     appear exactly once and no off-list pair may slip in.
//
//   - TestReleaseBuildPreservesContractUnderContention fires
//     `releaseBuildWorkers * releaseBuildIterationsPerWorker`
//     goroutines that all derive the same release projections from a
//     shared `release.SupportedTargets` slice, each goroutine asserts
//     its OWN target's derivation matches the predicted archive
//     extension, binary name, archive name, and checksums name. A
//     regression that introduced shared mutable state in the package
//     (a cached lookup table, a global builder, a sync.Once that
//     mutated a shared map) would fail the per-iteration assertion
//     even when the aggregate count matched.
//
// Both members are deterministic by design: the release package
// functions are pure projections from the (OS, arch) coordinate to a
// string and never reach the network, a live Postgres, or a live
// Dokploy. The contention burst is the per-iteration stability check
// the gate's wire contract requires; the coverage member is the
// closed-set scenario check the documented (OS × arch) matrix
// requires.

const (
	// releaseBuildSampleVersion is the literal semver string the
	// archive-name and checksums-name projections are exercised with.
	// The value is irrelevant to the projections themselves — only the
	// shape of the rendered name matters — but using a stable literal
	// makes the test output reproducible and the contention burst's
	// per-iteration assertion deterministic.
	releaseBuildSampleVersion = "1.2.3"
	// releaseBuildSampleVersionPrefix is the literal prefix every
	// archive name and checksums-file name MUST share. The release
	// channel docs and the npm wrapper both rely on the
	// `yalla_<version>_…` prefix; a drift would break URL builders
	// downstream.
	releaseBuildSampleVersionPrefix = "yalla_1.2.3_"
	// releaseBuildChecksumsName is the canonical per-version
	// checksums file name. `release.ChecksumsName` MUST render this
	// literal for `releaseBuildSampleVersion`.
	releaseBuildChecksumsName = "yalla_1.2.3_checksums.txt"

	// releaseBuildWorkers + releaseBuildIterationsPerWorker drive the
	// contention burst. The product is the total per-iteration
	// assertions the burst exercises; the values are deliberately
	// small so the burst fits inside a single second on developer
	// laptops while still exercising the closed-set scenario table
	// many times across many goroutines.
	releaseBuildWorkers              = 32
	releaseBuildIterationsPerWorker  = 128
	releaseBuildBurstTotalIterations = releaseBuildWorkers * releaseBuildIterationsPerWorker
)

// releaseBuildScenario captures one (OS, arch) coordinate's documented
// projections. The coverage member walks the closed-set scenario
// table built from `release.SupportedTargets`; the contention burst
// reuses the same table so every parallel run exercises the identical
// decision set.
type releaseBuildScenario struct {
	target       release.Target
	archiveExt   string
	binaryName   string
	archiveName  string
	checksumName string
}

// buildReleaseBuildScenarios is the closed-set scenario table. The
// scenarios are derived from `release.SupportedTargets` so a future
// (OS, arch) addition picks up coverage automatically. The expected
// projection values are computed from the documented rules (windows
// uses .zip + .exe, everything else uses .tar.gz + bare binary; the
// archive-name template is `yalla_<version>_<os>_<arch><ext>`; the
// checksums template is `yalla_<version>_checksums.txt`).
func buildReleaseBuildScenarios(t *testing.T) []releaseBuildScenario {
	t.Helper()
	if len(release.SupportedTargets) == 0 {
		t.Fatal("release.SupportedTargets is empty; the coverage member would vacuously pass")
	}
	scenarios := make([]releaseBuildScenario, 0, len(release.SupportedTargets))
	for _, tgt := range release.SupportedTargets {
		ext := ".tar.gz"
		binary := "yalla"
		if tgt.OS == "windows" {
			ext = ".zip"
			binary = "yalla.exe"
		}
		scenarios = append(scenarios, releaseBuildScenario{
			target:       tgt,
			archiveExt:   ext,
			binaryName:   binary,
			archiveName:  "yalla_" + releaseBuildSampleVersion + "_" + tgt.OS + "_" + tgt.Arch + ext,
			checksumName: releaseBuildChecksumsName,
		})
	}
	return scenarios
}

// assessReleaseBuildScenario returns a (possibly empty) slice of
// failure reasons describing every way the package's projections
// diverge from the scenario's predicted values. Returning a slice
// (rather than failing inline) lets the contention member aggregate
// failures across many goroutines without t.Fatal'ing the entire
// burst on the first miss.
func assessReleaseBuildScenario(s releaseBuildScenario) []string {
	var reasons []string
	if got := s.target.ArchiveExt(); got != s.archiveExt {
		reasons = append(reasons, fmt.Sprintf("ArchiveExt=%q want %q", got, s.archiveExt))
	}
	if got := s.target.BinaryName(); got != s.binaryName {
		reasons = append(reasons, fmt.Sprintf("BinaryName=%q want %q", got, s.binaryName))
	}
	if got := s.target.ArchiveName(releaseBuildSampleVersion); got != s.archiveName {
		reasons = append(reasons, fmt.Sprintf("ArchiveName=%q want %q", got, s.archiveName))
	}
	if got := release.ChecksumsName(releaseBuildSampleVersion); got != s.checksumName {
		reasons = append(reasons, fmt.Sprintf("ChecksumsName=%q want %q", got, s.checksumName))
	}
	if !strings.HasPrefix(s.target.ArchiveName(releaseBuildSampleVersion), releaseBuildSampleVersionPrefix) {
		reasons = append(reasons, fmt.Sprintf("ArchiveName=%q must start with %q (release URL builders rely on the prefix)",
			s.target.ArchiveName(releaseBuildSampleVersion), releaseBuildSampleVersionPrefix))
	}
	return reasons
}

// TestReleaseBuildCoversCallSites is the closed-set release-derivation
// coverage member of the canonical pair. It walks the scenario table
// built by buildReleaseBuildScenarios and asserts each documented
// projection — ArchiveExt, BinaryName, ArchiveName, ChecksumsName,
// and the shared `yalla_<version>_` archive prefix — matches the
// predicted value for every (OS, arch) coordinate in
// `release.SupportedTargets`. A regression in any of those
// projections trips the gate on the offending scenario name.
//
// The closed-set coverage invariant also asserts the documented
// (OS, arch) matrix is non-empty, contains the six documented combos
// (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64,
// windows/arm64), and contains no off-list coordinate. A future
// addition or removal of a target MUST be a deliberate edit to both
// the package and this test.
func TestReleaseBuildCoversCallSites(t *testing.T) {
	t.Parallel()

	scenarios := buildReleaseBuildScenarios(t)

	wantCoords := map[string]bool{
		"linux_amd64":   false,
		"linux_arm64":   false,
		"darwin_amd64":  false,
		"darwin_arm64":  false,
		"windows_amd64": false,
		"windows_arm64": false,
	}

	for _, scen := range scenarios {
		scen := scen
		t.Run(scen.target.OS+"_"+scen.target.Arch, func(t *testing.T) {
			t.Parallel()
			for _, reason := range assessReleaseBuildScenario(scen) {
				t.Errorf("target %s/%s: %s", scen.target.OS, scen.target.Arch, reason)
			}
		})
		key := scen.target.OS + "_" + scen.target.Arch
		if _, ok := wantCoords[key]; !ok {
			t.Errorf("release.SupportedTargets contains off-list coordinate %q; add to the closed-set coverage table or remove from the package", key)
		} else {
			wantCoords[key] = true
		}
	}

	for key, seen := range wantCoords {
		if !seen {
			t.Errorf("release.SupportedTargets missing documented coordinate %q; every documented (OS, arch) pair MUST appear in SupportedTargets so GoReleaser, the npm wrapper, the Homebrew formula, and the Scoop/WinGet manifests stay in lockstep", key)
		}
	}
}

// TestReleaseBuildPreservesContractUnderContention is the per-decision
// stability member of the canonical pair. It fires
// `releaseBuildWorkers * releaseBuildIterationsPerWorker` goroutines
// that derive each target's projections from a shared slice of
// `release.SupportedTargets`-derived scenarios and asserts every
// goroutine sees the predicted projection for its OWN scenario. A
// cross-write under the race that swapped two goroutines' scenarios
// would fail the per-iteration assertion even when the aggregate pass
// count matched.
//
// The contention burst is the load-bearing stability check the gate's
// wire contract requires: the release-derivation helpers are pure
// today, but a future regression that introduced shared mutable state
// (a cached lookup table, a global builder, a sync.Once that mutated
// a shared map) would surface here before reaching the GoReleaser
// pipeline.
func TestReleaseBuildPreservesContractUnderContention(t *testing.T) {
	t.Parallel()

	scenarios := buildReleaseBuildScenarios(t)

	type failure struct {
		worker    int
		iteration int
		scenario  string
		reasons   []string
	}

	var (
		mu       sync.Mutex
		failures []failure
		total    int
	)

	var wg sync.WaitGroup
	wg.Add(releaseBuildWorkers)
	for w := 0; w < releaseBuildWorkers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < releaseBuildIterationsPerWorker; i++ {
				// Deterministic per-worker + per-iteration index so
				// every parallel run paginates the identical decision
				// set. A cross-write that swapped two goroutines'
				// scenarios would map this iteration to a different
				// target than the one its predicate predicted.
				idx := (w*releaseBuildIterationsPerWorker + i) % len(scenarios)
				scen := scenarios[idx]
				reasons := assessReleaseBuildScenario(scen)

				mu.Lock()
				total++
				if len(reasons) > 0 {
					failures = append(failures, failure{
						worker:    w,
						iteration: i,
						scenario:  scen.target.OS + "_" + scen.target.Arch,
						reasons:   reasons,
					})
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if total != releaseBuildBurstTotalIterations {
		t.Fatalf("observed %d derivations, want %d (workers=%d iters=%d)",
			total, releaseBuildBurstTotalIterations, releaseBuildWorkers, releaseBuildIterationsPerWorker)
	}

	for _, f := range failures {
		t.Errorf("worker %d iteration %d scenario %s: %v", f.worker, f.iteration, f.scenario, f.reasons)
	}
}
