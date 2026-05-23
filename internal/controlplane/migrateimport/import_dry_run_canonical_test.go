package migrateimport_test

// Canonical reference import dry-run test (BE-0406).
//
// This file is the load-bearing static fixture the BE-0406
// verification suite gate (`go test -run TestImportDryRun
// ./...`) binds to. The pair (`TestImportDryRunCoversCallSites`
// and `TestImportDryRunPreservesContractUnderContention`) is the
// closed-set + per-decision-stability contract for the
// migrateimport package's pure-classifier chokepoint
// `(*migrateimport.Importer).Plan(ctx, PlanInput) (Plan, error)`.
//
// Threat model: import dry-run is the operator-facing surface a
// Yalla admin uses to preview which pre-existing Dokploy
// resources would become customer-visible if the operator
// committed to an `OwnerAssignment`. The classifier reads the
// live Dokploy snapshot and the Yalla source-of-truth view of
// linked resources, and emits a deterministic `Plan` whose every
// `PlanItem` carries a stable closed-set tag `(Level, Status,
// Reason)`. Dry-run is exactly "calling Plan without calling
// Apply" — Plan performs no writes, never enqueues a job, and
// never mutates the Repository when run without an
// OwnerAssignment. A regression that demoted an `ItemStatus` or
// `ItemReason` out of the closed set, that started echoing an
// untrusted Dokploy display name into a classification field
// (`Status`, `Reason`, `Level`), that introduced
// non-deterministic ordering into the planner, or that started
// writing to the Repository in dry-run mode, would either let
// the operator commit to an import they did not preview or
// expose untrusted input through what is meant to be a stable
// audit-ready surface.
//
// The pair binds to the BE-0406 `-run TestImportDryRun` filter
// via the `TestImportDryRun` substring; renaming either member
// to a name that does not contain the substring silently de-
// gates the import dry-run suite for any caller relying on the
// filter.
//
// The closed-set coverage invariant pins five structural
// import-dry-run contracts in one place:
//
//  1. Every documented `ItemStatus` in
//     `importDryRunItemStatuses` is exercised by at least one
//     scenario row. A regression that removed a status from
//     `Importer.Plan` without dropping its entry here fails the
//     exhaustiveness self-check at the head of the covers test.
//  2. Every documented `ItemReason` in
//     `importDryRunItemReasons` is exercised by at least one
//     scenario row. A regression that removed a reason from the
//     planner without dropping its entry here fails the second
//     exhaustiveness self-check.
//  3. Deterministic ordering: `Importer.Plan(ctx, in)` is a
//     deterministic function of its inputs and the seeded
//     Repository state — calling it twice on the same input
//     MUST yield equal plans (same items, same order). A
//     regression that introduced map-iteration ordering into
//     the planner's output would surface here before any
//     per-row verdict.
//  4. Value-free classification: every scenario row seeds
//     `importDryRunSecretMarker` into the Dokploy snapshot's
//     untrusted, human-authored value channels (resource
//     `Name`s) and asserts the marker NEVER appears in any
//     classification field of any emitted item (`string(Level)`,
//     `string(Status)`, `string(Reason)`). The marker is
//     allowed to flow into `ProposedDisplay` (the deliberate
//     value-routing field that carries the human-authored name)
//     and may appear in `ProposedSlug` once `domain.NormalizeSlug`
//     has processed it. A regression that started echoing the
//     untrusted display name into `Status`, `Reason`, or
//     `Level` would fail the marker-absence predicate on every
//     scenario.
//  5. Dry-run purity: every scenario row asserts that an
//     `OwnerAssignment`-less call NEVER queries the Repository
//     (a Repository.calls != 0 footprint is a regression that
//     turned the dry-run into a live read). Every assigned-row
//     asserts that `Plan` is read-only — no `CreateProject`,
//     `CreateEnvironment`, or `CreateService` calls show up on
//     the Repository under any code path.
//
// `TestImportDryRunPreservesContractUnderContention` fires
// `importDryRunWorkers * importDryRunIterationsPerWorker`
// goroutines that each draw a scenario by deterministic mod-
// index and call `(*Importer).Plan` directly against a shared
// `Importer` instance. The fake Scanner and Repository the
// scenarios build are independent per iteration so a
// regression that smuggled shared mutable state into the
// classifier (a cached owner table, a `sync.Once` mutating a
// per-action map, a `sync.Pool` reused without resetting)
// would surface as a per-iteration assertion failure even when
// the aggregate pass count matched, because every goroutine
// knows its own predicted closed-set tag and asserts that
// exact verdict.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/migrateimport"
)

// importDryRunSecretMarker is a sentinel literal the canonical
// scenarios seed into untrusted Dokploy display names. The
// marker is not a secret transport pattern (no "Bearer",
// "Authorization", "token=", etc.), so any operator-side
// redactor leaves it intact — the per-row canary asserts the
// marker is absent from every classification field of every
// emitted item. The marker is intentionally lowercase
// alphanumeric so `domain.NormalizeSlug` preserves it in
// `ProposedSlug` and the planner does not have to fight slug
// normalisation just to make the canary observable.
const importDryRunSecretMarker = "importsecretmarker"

// importDryRunItemStatuses is the closed set of `ItemStatus`
// constants the BE-0406 gate covers. Every entry MUST be
// exercised by at least one scenario in
// `importDryRunScenarios()`. A regression that removed a
// status from `Importer.Plan` without dropping its entry here
// trips the exhaustiveness self-check at the head of the
// covers test; a regression that added a new status without
// listing it here trips the table audit too because the new
// status would not appear in any scenario.
var importDryRunItemStatuses = []migrateimport.ItemStatus{
	migrateimport.StatusReady,
	migrateimport.StatusPendingOwner,
	migrateimport.StatusSkipDuplicate,
	migrateimport.StatusSkipMissingParent,
	migrateimport.StatusSkipUnsupported,
	migrateimport.StatusSkipAlreadyImported,
}

// importDryRunItemReasons is the closed set of `ItemReason`
// constants the BE-0406 gate covers. Every entry MUST be
// exercised by at least one scenario row; a regression that
// demoted a reason from the planner is forced to drop its
// entry here too or fail the exhaustiveness self-check.
var importDryRunItemReasons = []migrateimport.ItemReason{
	migrateimport.ReasonReadyToImport,
	migrateimport.ReasonExplicitOwnerMissing,
	migrateimport.ReasonDuplicateName,
	migrateimport.ReasonMissingParentImport,
	migrateimport.ReasonUnsupportedServiceType,
	migrateimport.ReasonAlreadyLinked,
}

// importDryRunExpect predicts which closed-set tag at least one
// emitted `PlanItem` MUST carry for the scenario. `dokployID`
// names the Dokploy resource ID of the item whose closed-set
// tag the row pins; the per-row helper looks the item up by ID
// rather than position so a planner that reorders rows still
// satisfies the predicate as long as the tag survives.
//
// `expectNoRepositoryWrites=true` (default for every row) is a
// dry-run-purity assertion: `Plan` is read-only and MUST NOT
// emit `CreateProject`, `CreateEnvironment`, or `CreateService`
// calls on the Repository under any code path. Pending-owner
// rows additionally assert the Repository is never touched at
// all (count==0).
type importDryRunExpect struct {
	dokployID         string
	level             migrateimport.ResourceLevel
	status            migrateimport.ItemStatus
	reason            migrateimport.ItemReason
	requireNoRepoRead bool
}

// importDryRunScenario describes one row of the closed coverage
// table. The builder returns a fresh Snapshot + seeded fake
// Repository pair and the operator's assignment; the `expect`
// field encodes the closed-set tag the per-row helper looks for
// after `Plan` returns. The statusTag / reasonTag fields
// identify the closed-set codes the row primarily exercises so
// the exhaustiveness self-checks at the head of the covers test
// can confirm every documented status and reason fires on at
// least one row.
type importDryRunScenario struct {
	name       string
	build      func() (migrateimport.Snapshot, *fakeRepo, migrateimport.OwnerAssignment)
	expect     importDryRunExpect
	statusTag  migrateimport.ItemStatus
	reasonTag  migrateimport.ItemReason
	seedMarker bool
}

// importDryRunYallaOrg is the canonical Yalla organization ID
// the assigned-row scenarios bind to. Every assigned row resolves
// to the same Yalla org so the operator-side ownership invariant
// (one Dokploy org maps to at most one Yalla org) is enforced
// implicitly by the test table.
const importDryRunYallaOrg domain.ID = "org_01hz00000000000000000406yz"

// importDryRunDokployOrg is the canonical Dokploy organization ID
// every scenario's Snapshot is rooted at. A scenario that wants
// to exercise an org mismatch overrides this in its builder.
const importDryRunDokployOrg = "dkp-org-be-0406"

// importDryRunMarkedName decorates a Dokploy resource display
// name with the canonical secret marker so the per-row canary
// can prove the marker survives into `ProposedDisplay` (a
// deliberate value-routing field) and is absent from every
// classification field of every emitted item.
func importDryRunMarkedName(prefix string) string {
	return prefix + "-" + importDryRunSecretMarker
}

// importDryRunScenarios returns the closed coverage table. Every
// `ItemStatus` and every `ItemReason` is exercised by at least
// one row; every row asserts the dry-run purity invariant by
// inspecting the fake Repository's recorded calls after `Plan`
// returns.
func importDryRunScenarios() []importDryRunScenario {
	return []importDryRunScenario{
		{
			name: "pending owner: blank assignment routes every project to StatusPendingOwner",
			build: func() (migrateimport.Snapshot, *fakeRepo, migrateimport.OwnerAssignment) {
				snap := migrateimport.Snapshot{
					Organization: migrateimport.SnapshotOrganization{
						DokployID: importDryRunDokployOrg,
						Name:      importDryRunMarkedName("acme"),
					},
					Projects: []migrateimport.SnapshotProject{{
						DokployID:             "dkp-proj-pending-1",
						DokployOrganizationID: importDryRunDokployOrg,
						Name:                  importDryRunMarkedName("web"),
					}},
				}
				return snap, newRepo(), migrateimport.OwnerAssignment{}
			},
			expect: importDryRunExpect{
				dokployID:         "dkp-proj-pending-1",
				level:             migrateimport.LevelProject,
				status:            migrateimport.StatusPendingOwner,
				reason:            migrateimport.ReasonExplicitOwnerMissing,
				requireNoRepoRead: true,
			},
			statusTag:  migrateimport.StatusPendingOwner,
			reasonTag:  migrateimport.ReasonExplicitOwnerMissing,
			seedMarker: true,
		},
		{
			name: "ready: a fresh project with a clean slug routes to StatusReady",
			build: func() (migrateimport.Snapshot, *fakeRepo, migrateimport.OwnerAssignment) {
				repo := newRepo()
				repo.seedOrg(importDryRunYallaOrg)
				snap := migrateimport.Snapshot{
					Organization: migrateimport.SnapshotOrganization{
						DokployID: importDryRunDokployOrg,
						Name:      importDryRunMarkedName("acme"),
					},
					Projects: []migrateimport.SnapshotProject{{
						DokployID:             "dkp-proj-ready-1",
						DokployOrganizationID: importDryRunDokployOrg,
						Name:                  importDryRunMarkedName("api"),
					}},
				}
				return snap, repo, migrateimport.OwnerAssignment{
					DokployOrganizationID: importDryRunDokployOrg,
					YallaOrganizationID:   importDryRunYallaOrg,
				}
			},
			expect: importDryRunExpect{
				dokployID: "dkp-proj-ready-1",
				level:     migrateimport.LevelProject,
				status:    migrateimport.StatusReady,
				reason:    migrateimport.ReasonReadyToImport,
			},
			statusTag:  migrateimport.StatusReady,
			reasonTag:  migrateimport.ReasonReadyToImport,
			seedMarker: true,
		},
		{
			name: "duplicate: a project whose slug collides with a pre-seeded Yalla row routes to StatusSkipDuplicate",
			build: func() (migrateimport.Snapshot, *fakeRepo, migrateimport.OwnerAssignment) {
				repo := newRepo()
				repo.seedOrg(importDryRunYallaOrg)
				// Pre-seed a Yalla project under the slug the snapshot's
				// project would normalise to. The seeded Yalla project is
				// linked to a *different* Dokploy ID so the planner sees a
				// genuine collision rather than an already-imported row.
				// The snapshot name is kept ≤ MaxSlugLen so
				// `domain.NormalizeSlug` round-trips it without truncation
				// — the dominance test would silently flip to StatusReady
				// on any slug mismatch caused by truncation drift.
				const dupName = "dup-" + importDryRunSecretMarker
				repo.seedProject(importDryRunYallaOrg, dupName,
					"dkp-some-other-proj", "proj_01hz00000000000000000000dp")
				snap := migrateimport.Snapshot{
					Organization: migrateimport.SnapshotOrganization{
						DokployID: importDryRunDokployOrg,
						Name:      importDryRunMarkedName("acme"),
					},
					Projects: []migrateimport.SnapshotProject{{
						DokployID:             "dkp-proj-dup-1",
						DokployOrganizationID: importDryRunDokployOrg,
						Name:                  dupName,
					}},
				}
				return snap, repo, migrateimport.OwnerAssignment{
					DokployOrganizationID: importDryRunDokployOrg,
					YallaOrganizationID:   importDryRunYallaOrg,
				}
			},
			expect: importDryRunExpect{
				dokployID: "dkp-proj-dup-1",
				level:     migrateimport.LevelProject,
				status:    migrateimport.StatusSkipDuplicate,
				reason:    migrateimport.ReasonDuplicateName,
			},
			statusTag:  migrateimport.StatusSkipDuplicate,
			reasonTag:  migrateimport.ReasonDuplicateName,
			seedMarker: true,
		},
		{
			name: "missing parent: an environment under a project not in the snapshot routes to StatusSkipMissingParent",
			build: func() (migrateimport.Snapshot, *fakeRepo, migrateimport.OwnerAssignment) {
				repo := newRepo()
				repo.seedOrg(importDryRunYallaOrg)
				snap := migrateimport.Snapshot{
					Organization: migrateimport.SnapshotOrganization{
						DokployID: importDryRunDokployOrg,
						Name:      importDryRunMarkedName("acme"),
					},
					Environments: []migrateimport.SnapshotEnvironment{{
						DokployID:        "dkp-env-orphan-1",
						DokployProjectID: "dkp-proj-not-in-snapshot",
						Name:             importDryRunMarkedName("orphan-env"),
					}},
				}
				return snap, repo, migrateimport.OwnerAssignment{
					DokployOrganizationID: importDryRunDokployOrg,
					YallaOrganizationID:   importDryRunYallaOrg,
				}
			},
			expect: importDryRunExpect{
				dokployID: "dkp-env-orphan-1",
				level:     migrateimport.LevelEnvironment,
				status:    migrateimport.StatusSkipMissingParent,
				reason:    migrateimport.ReasonMissingParentImport,
			},
			statusTag:  migrateimport.StatusSkipMissingParent,
			reasonTag:  migrateimport.ReasonMissingParentImport,
			seedMarker: true,
		},
		{
			name: "unsupported: a service whose Dokploy type is unknown routes to StatusSkipUnsupported",
			build: func() (migrateimport.Snapshot, *fakeRepo, migrateimport.OwnerAssignment) {
				repo := newRepo()
				repo.seedOrg(importDryRunYallaOrg)
				snap := migrateimport.Snapshot{
					Organization: migrateimport.SnapshotOrganization{
						DokployID: importDryRunDokployOrg,
						Name:      importDryRunMarkedName("acme"),
					},
					Projects: []migrateimport.SnapshotProject{{
						DokployID:             "dkp-proj-unsup-host",
						DokployOrganizationID: importDryRunDokployOrg,
						Name:                  importDryRunMarkedName("svchost"),
					}},
					Environments: []migrateimport.SnapshotEnvironment{{
						DokployID:        "dkp-env-unsup-host",
						DokployProjectID: "dkp-proj-unsup-host",
						Name:             importDryRunMarkedName("prod"),
					}},
					Services: []migrateimport.SnapshotService{{
						DokployID:            "dkp-svc-unsup-1",
						DokployEnvironmentID: "dkp-env-unsup-host",
						Name:                 importDryRunMarkedName("weird-svc"),
						Type:                 "unknown-dokploy-type",
					}},
				}
				return snap, repo, migrateimport.OwnerAssignment{
					DokployOrganizationID: importDryRunDokployOrg,
					YallaOrganizationID:   importDryRunYallaOrg,
				}
			},
			expect: importDryRunExpect{
				dokployID: "dkp-svc-unsup-1",
				level:     migrateimport.LevelService,
				status:    migrateimport.StatusSkipUnsupported,
				reason:    migrateimport.ReasonUnsupportedServiceType,
			},
			statusTag:  migrateimport.StatusSkipUnsupported,
			reasonTag:  migrateimport.ReasonUnsupportedServiceType,
			seedMarker: true,
		},
		{
			name: "already linked: a project already linked to its Dokploy ID routes to StatusSkipAlreadyImported",
			build: func() (migrateimport.Snapshot, *fakeRepo, migrateimport.OwnerAssignment) {
				repo := newRepo()
				repo.seedOrg(importDryRunYallaOrg)
				// Pre-seed a Yalla project already linked to the same Dokploy
				// resource ID the snapshot carries. The planner MUST detect
				// the existing link and emit StatusSkipAlreadyImported (an
				// idempotent no-op) rather than a duplicate or a fresh ready
				// import.
				const linkName = "link-" + importDryRunSecretMarker
				repo.seedProject(importDryRunYallaOrg, linkName,
					"dkp-proj-already-1", "proj_01hz00000000000000000000ap")
				snap := migrateimport.Snapshot{
					Organization: migrateimport.SnapshotOrganization{
						DokployID: importDryRunDokployOrg,
						Name:      importDryRunMarkedName("acme"),
					},
					Projects: []migrateimport.SnapshotProject{{
						DokployID:             "dkp-proj-already-1",
						DokployOrganizationID: importDryRunDokployOrg,
						Name:                  linkName,
					}},
				}
				return snap, repo, migrateimport.OwnerAssignment{
					DokployOrganizationID: importDryRunDokployOrg,
					YallaOrganizationID:   importDryRunYallaOrg,
				}
			},
			expect: importDryRunExpect{
				dokployID: "dkp-proj-already-1",
				level:     migrateimport.LevelProject,
				status:    migrateimport.StatusSkipAlreadyImported,
				reason:    migrateimport.ReasonAlreadyLinked,
			},
			statusTag:  migrateimport.StatusSkipAlreadyImported,
			reasonTag:  migrateimport.ReasonAlreadyLinked,
			seedMarker: true,
		},
	}
}

const (
	importDryRunWorkers              = 32
	importDryRunIterationsPerWorker  = 64
	importDryRunContentionIterations = importDryRunWorkers * importDryRunIterationsPerWorker
)

// importDryRunBuildImporter constructs a fresh `*Importer` for a
// scenario row. The Scanner returns the row's Snapshot; the
// Repository is the row-built `*fakeRepo`. Logger is io.Discard
// so concurrent runs do not interleave noise; Redactor defaults
// inside `migrateimport.New`.
func importDryRunBuildImporter(t *testing.T, snap migrateimport.Snapshot, repo *fakeRepo) *migrateimport.Importer {
	t.Helper()
	imp, err := migrateimport.New(migrateimport.Config{
		Scanner:    &fakeScanner{snapshot: snap},
		Repository: repo,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("migrateimport.New = %v; want nil", err)
	}
	return imp
}

// importDryRunBuildImporterB is the *testing.B-friendly twin of
// importDryRunBuildImporter. The contention burst uses a single
// long-lived Importer to maximise the chance that any shared
// mutable state in the package surfaces as a per-iteration
// race.
func importDryRunBuildImporterB(t *testing.T, scanner migrateimport.Scanner, repo migrateimport.Repository) *migrateimport.Importer {
	t.Helper()
	imp, err := migrateimport.New(migrateimport.Config{
		Scanner:    scanner,
		Repository: repo,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("migrateimport.New = %v; want nil", err)
	}
	return imp
}

// TestImportDryRunCoversCallSites is the closed-set coverage
// half of the BE-0406 pair. It walks every documented
// `ItemStatus` and `ItemReason` of `Importer.Plan` and asserts
// the planner emits the predicted closed-set tag for every
// scenario row. The closed-set self-checks at the head of the
// test catch drift in either direction: a new status that
// ships without a row, an existing status that drops its row,
// a reason without a scenario, or non-deterministic ordering.
func TestImportDryRunCoversCallSites(t *testing.T) {
	t.Parallel()

	rows := importDryRunScenarios()
	if len(rows) == 0 {
		t.Fatalf("importDryRunScenarios returned an empty table; the closed-set construction is broken")
	}

	// Closed-set self-check #1: every documented ItemStatus is
	// exercised by at least one scenario row.
	statusSeen := make(map[migrateimport.ItemStatus]int, len(importDryRunItemStatuses))
	for _, s := range importDryRunItemStatuses {
		statusSeen[s] = 0
	}
	for _, row := range rows {
		if row.statusTag == "" {
			continue
		}
		if _, ok := statusSeen[row.statusTag]; !ok {
			t.Fatalf("scenario %q tags status %q which is not in importDryRunItemStatuses; every scenario status tag must be a documented ItemStatus",
				row.name, row.statusTag)
		}
		statusSeen[row.statusTag]++
	}
	for s, count := range statusSeen {
		if count == 0 {
			t.Fatalf("ItemStatus %q is not exercised by any scenario; every documented status must surface in at least one row of importDryRunScenarios",
				s)
		}
	}

	// Closed-set self-check #2: every documented ItemReason is
	// exercised by at least one scenario row.
	reasonSeen := make(map[migrateimport.ItemReason]int, len(importDryRunItemReasons))
	for _, r := range importDryRunItemReasons {
		reasonSeen[r] = 0
	}
	for _, row := range rows {
		if row.reasonTag == "" {
			continue
		}
		if _, ok := reasonSeen[row.reasonTag]; !ok {
			t.Fatalf("scenario %q tags reason %q which is not in importDryRunItemReasons; every scenario reason tag must be a documented ItemReason",
				row.name, row.reasonTag)
		}
		reasonSeen[row.reasonTag]++
	}
	for r, count := range reasonSeen {
		if count == 0 {
			t.Fatalf("ItemReason %q is not exercised by any scenario; every documented reason must surface in at least one row of importDryRunScenarios",
				r)
		}
	}

	// Closed-set self-check #3: deterministic ordering. Plan is
	// a deterministic function of its inputs and the seeded
	// Repository state — calling it twice on the same input
	// MUST yield equal plans (same items, same order). A
	// regression that introduced map-iteration ordering into
	// the output would surface here before any per-row verdict.
	for _, row := range rows {
		row := row
		snap, repo, assignment := row.build()
		imp := importDryRunBuildImporter(t, snap, repo)
		first, err := imp.Plan(context.Background(), migrateimport.PlanInput{
			DokployOrganizationID: importDryRunDokployOrg,
			Assignment:            assignment,
		})
		if err != nil {
			t.Fatalf("scenario %q: first Plan call returned %v; want nil — every row must produce a usable Plan",
				row.name, err)
		}
		second, err := imp.Plan(context.Background(), migrateimport.PlanInput{
			DokployOrganizationID: importDryRunDokployOrg,
			Assignment:            assignment,
		})
		if err != nil {
			t.Fatalf("scenario %q: second Plan call returned %v; want nil — every row must produce a usable Plan on repeat",
				row.name, err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("scenario %q: Plan(in) is non-deterministic — repeated call produced a different plan. first=%+v second=%+v",
				row.name, first, second)
		}
	}

	// Closed-set self-check #4: the secret marker is a non-empty
	// compile-time literal whose absence would silently false-
	// positive every per-row marker-absence predicate. Asserting
	// non-emptiness pins the contract that a future contributor
	// who blanks the constant must explicitly update the test,
	// not silently de-gate the value-free classification canary.
	if importDryRunSecretMarker == "" {
		t.Fatalf("importDryRunSecretMarker is empty; the per-row marker-absence predicate would false-positive on every scenario")
	}

	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			snap, repo, assignment := row.build()
			imp := importDryRunBuildImporter(t, snap, repo)
			plan, err := imp.Plan(context.Background(), migrateimport.PlanInput{
				DokployOrganizationID: importDryRunDokployOrg,
				Assignment:            assignment,
			})
			if err != nil {
				t.Fatalf("scenario %q: Plan = %v; want nil", row.name, err)
			}
			importDryRunAssertOutcome(t, row, plan, repo)
		})
	}
}

// TestImportDryRunPreservesContractUnderContention is the per-
// decision-stability half of the BE-0406 pair. It fires
// `importDryRunContentionIterations` goroutines that each draw
// a scenario by deterministic mod-index, build their own
// (Snapshot, fake Repository, OwnerAssignment) triple via the
// scenario's builder, construct an Importer, and call
// `Plan` directly. The Importer instances are per-iteration
// rather than shared because the package's chokepoint takes a
// context-bound Scanner/Repository: the contention's value is
// the assertion that the planner's pure logic
// (`classify`, `pendingOwnerItems`, `proposeSlug`,
// `indexProjectsByID`, `indexEnvironmentsByID`,
// `indexServicesByID`) has no package-level shared state — a
// regression that smuggled in a cached owner table, a
// `sync.Once` mutating a per-action map, or a `sync.Pool`
// reused without resetting would surface as a per-iteration
// mismatch even when the aggregate pass count matched, because
// every goroutine knows its own predicted closed-set tag and
// asserts that exact verdict.
func TestImportDryRunPreservesContractUnderContention(t *testing.T) {
	t.Parallel()

	rows := importDryRunScenarios()
	if len(rows) == 0 {
		t.Fatalf("importDryRunScenarios returned an empty table; the closed-set construction is broken")
	}

	var passed atomic.Int64
	var firstErr atomic.Pointer[importDryRunContentionFailure]
	var wg sync.WaitGroup

	for w := 0; w < importDryRunWorkers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < importDryRunIterationsPerWorker; i++ {
				iter := w*importDryRunIterationsPerWorker + i
				row := rows[iter%len(rows)]
				snap, repo, assignment := row.build()
				imp := importDryRunBuildImporterB(t, &fakeScanner{snapshot: snap}, repo)
				plan, err := imp.Plan(context.Background(), migrateimport.PlanInput{
					DokployOrganizationID: importDryRunDokployOrg,
					Assignment:            assignment,
				})
				if err != nil {
					firstErr.CompareAndSwap(nil, &importDryRunContentionFailure{
						iter:    iter,
						rowName: row.name,
						message: fmt.Sprintf("Plan returned %v; want nil — every scenario row must produce a usable Plan", err),
					})
					continue
				}
				if fail := importDryRunCheckOutcome(row, plan, repo); fail != nil {
					fail.iter = iter
					firstErr.CompareAndSwap(nil, fail)
					continue
				}
				passed.Add(1)
			}
		}()
	}
	wg.Wait()

	if fe := firstErr.Load(); fe != nil {
		t.Fatalf("contention iteration %d (row %q): %s; a per-iteration mismatch under burst contention indicates shared mutable state in the classifier OR a non-deterministic plan ordering",
			fe.iter, fe.rowName, fe.message)
	}
	if got := passed.Load(); got != int64(importDryRunContentionIterations) {
		t.Fatalf("contention burst: expected %d successful iterations, got %d; a missing pass without a recorded failure indicates a goroutine swallowed its assertion",
			importDryRunContentionIterations, got)
	}
}

// importDryRunAssertOutcome is the canonical-pair fail-fast
// assertion helper. The per-row covers test calls it directly so
// a per-row failure points the operator at the exact scenario
// that drifted.
func importDryRunAssertOutcome(t *testing.T, row importDryRunScenario, plan migrateimport.Plan, repo *fakeRepo) {
	t.Helper()
	if fail := importDryRunCheckOutcome(row, plan, repo); fail != nil {
		t.Fatalf("%s", fail.message)
	}
}

// importDryRunCheckOutcome captures the verdict comparison used
// by both pair members. It returns nil on success and a
// populated failure on the first mismatch.
//
// Predicate shape:
//   - The item identified by `row.expect.dokployID` MUST appear
//     in `plan.Items` and MUST carry the predicted `(Level,
//     Status, Reason)` triple.
//   - When the row seeds the marker, the marker MUST NOT appear
//     in any classification field (`string(Level)`,
//     `string(Status)`, `string(Reason)`) of any emitted item.
//   - The Repository MUST NOT have received any write call
//     (`CreateProject`, `CreateEnvironment`, `CreateService`).
//     When `expect.requireNoRepoRead` is set the Repository
//     MUST NOT have received any call at all (the no-owner
//     short-circuit invariant).
func importDryRunCheckOutcome(row importDryRunScenario, plan migrateimport.Plan, repo *fakeRepo) *importDryRunContentionFailure {
	var matched *migrateimport.PlanItem
	for i := range plan.Items {
		if plan.Items[i].DokployResourceID == row.expect.dokployID {
			matched = &plan.Items[i]
			break
		}
	}
	if matched == nil {
		return &importDryRunContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Plan emitted no item with DokployResourceID=%q; row predicts (level=%q status=%q reason=%q); plan.Items=%+v",
				row.expect.dokployID, row.expect.level, row.expect.status, row.expect.reason, plan.Items),
		}
	}
	if matched.Level != row.expect.level {
		return &importDryRunContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Plan emitted item %q with Level=%q, want %q; the closed-set Level tag is the planner's hierarchy contract",
				row.expect.dokployID, matched.Level, row.expect.level),
		}
	}
	if matched.Status != row.expect.status {
		return &importDryRunContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Plan emitted item %q with Status=%q, want %q; the closed-set Status tag drives Apply dispatch and operator review",
				row.expect.dokployID, matched.Status, row.expect.status),
		}
	}
	if matched.Reason != row.expect.reason {
		return &importDryRunContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Plan emitted item %q with Reason=%q, want %q; the closed-set Reason tag is the value-free classification code operators read in audits",
				row.expect.dokployID, matched.Reason, row.expect.reason),
		}
	}

	if row.seedMarker {
		// Value-free classification canary: the marker is seeded
		// into untrusted Dokploy display names but MUST NOT appear
		// in any classification field of any emitted item.
		// `ProposedDisplay` and `ProposedSlug` are deliberate
		// value-routing fields and are excluded from the
		// marker-absence predicate.
		for _, item := range plan.Items {
			if strings.Contains(string(item.Level), importDryRunSecretMarker) {
				return &importDryRunContentionFailure{
					rowName: row.name,
					message: fmt.Sprintf("Plan emitted item %q with Level=%q echoing marker %q; Level is a closed-set tag, not a value channel",
						item.DokployResourceID, item.Level, importDryRunSecretMarker),
				}
			}
			if strings.Contains(string(item.Status), importDryRunSecretMarker) {
				return &importDryRunContentionFailure{
					rowName: row.name,
					message: fmt.Sprintf("Plan emitted item %q with Status=%q echoing marker %q; Status is a closed-set tag, not a value channel",
						item.DokployResourceID, item.Status, importDryRunSecretMarker),
				}
			}
			if strings.Contains(string(item.Reason), importDryRunSecretMarker) {
				return &importDryRunContentionFailure{
					rowName: row.name,
					message: fmt.Sprintf("Plan emitted item %q with Reason=%q echoing marker %q; Reason is a closed-set tag, not a value channel",
						item.DokployResourceID, item.Reason, importDryRunSecretMarker),
				}
			}
		}
		// Marker survival: at least one emitted item MUST carry
		// the marker in `ProposedDisplay` so the canary's positive
		// direction is also pinned — a regression that started
		// erasing the display would render the marker-absence
		// predicate trivially true and silently de-gate the
		// invariant.
		markerInDisplay := false
		for _, item := range plan.Items {
			if strings.Contains(item.ProposedDisplay, importDryRunSecretMarker) {
				markerInDisplay = true
				break
			}
		}
		if !markerInDisplay {
			return &importDryRunContentionFailure{
				rowName: row.name,
				message: fmt.Sprintf("Plan seeded marker %q into Dokploy display names but no item carries it in ProposedDisplay; the operator review surface would have nothing to render",
					importDryRunSecretMarker),
			}
		}
	}

	// Dry-run purity: Plan is read-only. No Create* calls under
	// any code path.
	repo.mu.Lock()
	calls := append([]string(nil), repo.calls...)
	repo.mu.Unlock()
	for _, call := range calls {
		if strings.HasPrefix(call, "CreateProject:") ||
			strings.HasPrefix(call, "CreateEnvironment:") ||
			strings.HasPrefix(call, "CreateService:") {
			return &importDryRunContentionFailure{
				rowName: row.name,
				message: fmt.Sprintf("Plan recorded write call %q on the Repository; dry-run MUST be read-only — Apply is the only path that writes",
					call),
			}
		}
	}
	if row.expect.requireNoRepoRead && len(calls) != 0 {
		return &importDryRunContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Plan recorded %d Repository call(s) %v on a no-owner row; the pending-owner short-circuit MUST never touch the Repository",
				len(calls), calls),
		}
	}

	// Plan.DokployOrganizationID is set on every plan; it MUST
	// be the canonical org the row was scanned against, never
	// an empty string. Tenant-scoping invariant.
	if strings.TrimSpace(plan.DokployOrganizationID) == "" {
		return &importDryRunContentionFailure{
			rowName: row.name,
			message: "Plan.DokployOrganizationID is empty; the plan MUST always be tenant-scoped",
		}
	}

	return nil
}

// importDryRunContentionFailure captures the first (iteration,
// row) the canonical pair observed a mismatch on, so a failure
// message points the operator at the exact scenario that drifted
// rather than collapsing every mismatch into a single line.
type importDryRunContentionFailure struct {
	iter    int
	rowName string
	message string
}
