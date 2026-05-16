package release_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// BE-0358: Security verification — support access review.
//
// Threat model.
//
//  1. Yalla support staff occasionally need to reach into a customer
//     organization to triage an incident the customer cannot debug from
//     the outside. The mechanism is the time-bounded break-glass
//     session: a support principal authorizes action admin.break_glass
//     (a CapSupport capability that is the engine's sole cross-tenant
//     read/support exception), the unit of work persists a session
//     row, and reviewers later audit every elevated-access decision.
//     Break-glass is access-only: it does NOT mint customer
//     credentials, rotate keys, or grant the support principal any
//     additional capabilities beyond CapSupport. A regression that
//     stamps a session without an audit row, demotes the action
//     capability binding, widens CapSupport to a role that has no
//     business performing cross-tenant access, or quietly entangles
//     the unit of work with a credential-minting code path would
//     silently break the review story for every Yalla customer.
//
//  2. The "review" half of "support access review" rests on a single
//     invariant: every break-glass mutation appends an immutable
//     audit_events row whose Metadata carries
//     `breakGlassElevatedAccessKey = "elevated_access"`. Analytics,
//     alerting, dashboards, and SOC2-flavoured reviews all branch on
//     this exact metadata key. The session row and the audit row are
//     committed in the same Store.Write transaction; a session
//     without its audit trail or an audit row without its session
//     cannot exist. Both the StartSession and the Revoke methods are
//     load-bearing — every START AND every REVOKE must show up on the
//     review trail. Either method losing the elevated_access stamp
//     would silently re-create the gap.
//
//  3. The reason an operator supplies (incident id, ticket id, free
//     text) reaches the audit trail through the store-layer redactor
//     (`output.NewRedactor()`). A regression that bypassed the
//     redactor by reading `in.Reason` straight into the audit
//     metadata could persist secrets a careless operator pasted into
//     the reason field. The matcher pins both methods to reference
//     `svc.redactor` at least once inside their bodies; the existing
//     internal unit test `TestBuildSessionToCreateRedactsReasonValue`
//     covers the runtime evidence.
//
//  4. The break-glass surface is access-only. The store-layer
//     orchestrator MUST NOT reach for any API-key or service-account
//     credential-minting collaborator: a future regression that wired
//     a `svc.keys.Issue(...)` or similar shortcut into the unit of
//     work would turn break-glass from "audit access" to "issue
//     credentials" without any review surface noticing. The matcher
//     rejects ANY reference in `break_glass_service.go` to a closed
//     set of forbidden credential-mint identifiers
//     (`forbiddenCredMintIdentifiers`).
//
//  5. The policy catalog is the authoritative action-to-capability
//     and role-to-capability matrix. Two regressions on the catalog
//     would silently break support access review: (a) demoting or
//     re-mapping `ActionAdminBreakGlass` away from `CapSupport`
//     would either lock support staff out (re-map to `CapOwner`) or
//     grant the cross-tenant exception to roles that should never
//     hold it (re-map to `CapRead`); (b) admitting `CapSupport` to
//     any role other than `RoleSupport` would widen the cross-tenant
//     read/support exception (the engine clause
//     `roleCaps.has(CapSupport) && (required == CapRead || required
//     == CapSupport)`) to roles that have no support remit. The
//     matcher pins both shapes.
//
//  6. The HTTP renderer that projects a break-glass session row to
//     the client wire shape MUST hard-code `ElevatedAccess: true`
//     unconditionally. The client uses this flag to decide whether
//     to display the "elevated" banner; a regression that omitted
//     the field, projected it from the row (where it does not
//     exist), or made it conditional would silently strip the
//     review signal from every list/get/start/revoke response.
//
//  7. The operator-facing contract is part of the public security
//     posture. SECURITY.md MUST document the support-access-review
//     story so an auditor scanning the deployment learns (a) every
//     break-glass session is paired with an audit row stamped
//     elevated_access=true, (b) the action is a CapSupport-only
//     authorization, (c) break-glass is access-only and never mints
//     credentials, and (d) the reason text is run through the
//     store-layer redactor before persistence. The matcher pins the
//     heading and the canonical substrings; a silent removal of
//     either is a regression on equal footing with a code change.
//
// The single-test-file variant of the BE-0344 two-test pattern
// (BE-0353, BE-0354, BE-0355, BE-0356, BE-0357). The runtime half is
// implicit and already covered by
// `internal/controlplane/store/break_glass_test.go` (Postgres-backed
// happy path, tenant isolation, conflict, not-found) and
// `internal/controlplane/httpapi/break_glass_test.go` (success,
// validation failure, authorization failure, not-found, conflict,
// "support cannot mint api keys"); both predate this gate. The
// `TestSupportAccessReviewStaticAnalyzerDetectsRegressions` self-check
// feeds synthetic known-bad and known-good fixtures through every
// matcher so over- and under-tightening of the analyser are both
// caught.

// supportServicePath is the relative path of the store-layer
// orchestrator that owns the break-glass unit of work. Pinned by
// path so a future split or rename forces an explicit update of
// this test alongside the rename.
const supportServicePath = "internal/controlplane/store/break_glass_service.go"

// supportHTTPHandlerPath is the relative path of the HTTP layer
// that owns the break-glass wire-shape renderer. The matcher
// inspects the `breakGlassSessionResourceOf` function so the
// ElevatedAccess: true projection cannot drift.
const supportHTTPHandlerPath = "internal/controlplane/httpapi/break_glass.go"

// supportCatalogPath is the relative path of the policy catalog
// that owns both the action-to-capability map
// (`defaultActionCatalog`) and the role-to-capability matrix
// (`builtinRoleCaps`). A drift in either is a support-access-review
// regression.
const supportCatalogPath = "internal/controlplane/policy/catalog.go"

// supportSecurityDocPath is the relative path of the operator-
// facing security posture document. The test pins both the
// dedicated section heading and the verification-gates table row.
const supportSecurityDocPath = "SECURITY.md"

// supportServiceTypeName is the receiver type name of the store-
// layer orchestrator. Both load-bearing methods (`StartSession`,
// `Revoke`) are pinned by receiver name + method name so a future
// rename forces explicit updates.
const supportServiceTypeName = "BreakGlassService"

// supportServiceReceiverName is the conventional receiver alias
// used everywhere in `break_glass_service.go`. The matcher relies
// on the alias being uniform (it is — `svc` everywhere) to
// distinguish `svc.redactor.Redact` from unrelated selectors that
// happen to share the trailing identifier.
const supportServiceReceiverName = "svc"

// supportRequiredMethodNames is the closed set of break-glass
// service methods that MUST audit-stamp every elevation. A future
// method that mutates session rows (e.g. a hypothetical Extend)
// must be added here in the same edit that adds the method, or the
// matcher will silently pass while the audit trail goes thin.
var supportRequiredMethodNames = []string{"StartSession", "Revoke"}

// supportAuditEventTypeName is the unqualified type name of the
// audit row the unit of work emits. The matcher locates each
// `AuditEvent{...}` composite literal in scope of a required
// method and asserts its Metadata map literal carries the
// elevated-access key.
const supportAuditEventTypeName = "AuditEvent"

// supportAuditMetadataField is the audit-event field whose map
// literal MUST carry the elevated-access key. Pinned by name so a
// future rename of the audit shape forces an explicit update.
const supportAuditMetadataField = "Metadata"

// supportElevatedAccessKeyIdent is the package-private constant
// identifier the store layer uses for the elevated-access metadata
// key. The matcher accepts EITHER the identifier reference (the
// canonical shape) OR the literal string "elevated_access" — both
// land at the same dashboard column — but rejects the absence of
// both shapes.
const supportElevatedAccessKeyIdent = "breakGlassElevatedAccessKey"

// supportElevatedAccessKeyLiteral is the raw string the identifier
// expands to. Accepted as an alternative match.
const supportElevatedAccessKeyLiteral = "elevated_access"

// supportRedactorFieldName is the service field that owns the
// secret-redacting helper. Every required method MUST reference
// `svc.redactor` at least once so a regression that bypasses the
// redactor (reading `in.Reason` or `in.UserAgent` straight into
// the audit event) is caught.
const supportRedactorFieldName = "redactor"

// forbiddenCredMintIdentifiers is the closed set of identifiers
// whose appearance in `break_glass_service.go` would signal the
// unit of work has reached for a credential-minting collaborator.
// The list is curated to the credential-bearing surfaces in this
// store package; a future credential type should either join the
// list (if break-glass must stay away from it) or be reviewed.
var forbiddenCredMintIdentifiers = map[string]struct{}{
	"APIKeyService":      {},
	"APIKeyRepository":   {},
	"APIKeyCreator":      {},
	"APIKeyRotator":      {},
	"APIKeyIssuer":       {},
	"IssueKey":           {},
	"MintKey":            {},
	"RotateKey":          {},
	"NewAPIKey":          {},
	"ServiceAccountKey":  {},
	"ServiceAccountKeys": {},
}

// supportBreakGlassActionIdent is the action constant whose
// capability binding the catalog MUST hold steady. A drift here
// either locks support out (re-mapped to CapOwner) or widens
// cross-tenant access (re-mapped to CapRead).
const supportBreakGlassActionIdent = "ActionAdminBreakGlass"

// supportBreakGlassCapabilityIdent is the capability the action
// binding MUST stay tied to. The engine's cross-tenant exception
// clause is `roleCaps.has(CapSupport) && (required == CapRead ||
// required == CapSupport)`; demoting the action out of CapSupport
// silently re-routes the engine's verdict for break-glass.
const supportBreakGlassCapabilityIdent = "CapSupport"

// supportActionCatalogVarName is the package-level catalog the
// matcher walks for the `ActionAdminBreakGlass -> CapSupport`
// pair. Pinned by name so a future split or rename forces an
// explicit update.
const supportActionCatalogVarName = "defaultActionCatalog"

// supportRoleCapsVarName is the package-level role matrix the
// matcher walks to assert `CapSupport` lives ONLY in
// `RoleSupport`'s row. Pinned by name so a future rename forces
// an explicit update.
const supportRoleCapsVarName = "builtinRoleCaps"

// supportRoleSupportIdent is the only role identifier the matrix
// is allowed to grant `CapSupport` to.
const supportRoleSupportIdent = "RoleSupport"

// supportSessionResourceTypeName is the wire-shape struct the HTTP
// renderer projects a break-glass row into. The matcher pins its
// `breakGlassSessionResourceOf` constructor function to require
// `ElevatedAccess: true` unconditionally.
const supportSessionResourceTypeName = "breakGlassSessionResource"

// supportSessionResourceCtorName is the unexported constructor
// function whose return value MUST carry `ElevatedAccess: true`.
const supportSessionResourceCtorName = "breakGlassSessionResourceOf"

// supportElevatedAccessField is the renderer field that MUST be
// hard-coded `true`. A renamed field forces an explicit update.
const supportElevatedAccessField = "ElevatedAccess"

// requiredSupportSecurityHeading is the literal Markdown heading
// that MUST appear in SECURITY.md to document this story's
// posture.
const requiredSupportSecurityHeading = "## Support Access Review"

// requiredSupportSecuritySubstrings is the closed set of literal
// substrings SECURITY.md MUST contain. Each captures a different
// load-bearing fact: the audit-metadata key the review surface
// branches on, the capability binding, the access-only posture,
// the redactor seam, and the test file path so the gate is
// self-locating.
var requiredSupportSecuritySubstrings = []string{
	"elevated_access",
	"admin.break_glass",
	"CapSupport",
	"output.NewRedactor",
	"support_access_review_static_test.go",
}

// requiredSupportGateRow is the literal substring of the row that
// MUST appear in SECURITY.md's Required Verification Gates table.
const requiredSupportGateRow = "Support access review"

// TestSupportAccessReviewAuditElevation proves that every required
// method on the store-layer break-glass orchestrator appends an
// AuditEvent whose Metadata map literal carries the
// elevated-access key. Both StartSession and Revoke are load-
// bearing: every start AND every revoke must show up on the
// review trail.
func TestSupportAccessReviewAuditElevation(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	fset, file := parseSupportFile(t, root, supportServicePath)
	for _, v := range findSupportAuditElevationRegressions(fset, file) {
		t.Error(v)
	}
}

// TestSupportAccessReviewReasonRedaction proves that every
// required method references `svc.redactor` at least once so a
// regression that bypassed the redactor on the reason or
// user-agent fields is caught.
func TestSupportAccessReviewReasonRedaction(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	fset, file := parseSupportFile(t, root, supportServicePath)
	for _, v := range findSupportRedactorRegressions(fset, file) {
		t.Error(v)
	}
}

// TestSupportAccessReviewNoCredentialMint proves that the store-
// layer break-glass file does NOT reference any credential-
// minting collaborator. Break-glass is access-only.
func TestSupportAccessReviewNoCredentialMint(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	fset, file := parseSupportFile(t, root, supportServicePath)
	for _, v := range findSupportCredMintRegressions(fset, file) {
		t.Error(v)
	}
}

// TestSupportAccessReviewPolicyCatalogBinding proves the policy
// catalog binds `ActionAdminBreakGlass` to `CapSupport` AND that
// only `RoleSupport` holds `CapSupport`. Either drift silently
// breaks the cross-tenant authorization story.
func TestSupportAccessReviewPolicyCatalogBinding(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	fset, file := parseSupportFile(t, root, supportCatalogPath)
	for _, v := range findSupportPolicyCatalogRegressions(fset, file) {
		t.Error(v)
	}
}

// TestSupportAccessReviewElevatedAccessProjection proves the HTTP
// renderer hard-codes `ElevatedAccess: true` in every projected
// session row, so the client always learns the row represents an
// elevated-access decision.
func TestSupportAccessReviewElevatedAccessProjection(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	fset, file := parseSupportFile(t, root, supportHTTPHandlerPath)
	for _, v := range findSupportElevatedAccessProjectionRegressions(fset, file) {
		t.Error(v)
	}
}

// TestSupportAccessReviewSecurityDocumented proves SECURITY.md
// documents the operator-facing support-access-review contract.
// The pinned heading, required substrings, and verification-gates
// row are part of the public security posture.
func TestSupportAccessReviewSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, supportSecurityDocPath)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", supportSecurityDocPath, err)
	}
	doc := string(b)
	if !strings.Contains(doc, requiredSupportSecurityHeading) {
		t.Errorf("%s: missing required heading %q; "+
			"the public security posture for support access review must stay documented.",
			supportSecurityDocPath, requiredSupportSecurityHeading)
	}
	for _, want := range requiredSupportSecuritySubstrings {
		if !strings.Contains(doc, want) {
			t.Errorf("%s: missing required substring %q under %q; "+
				"the documented contract MUST name every load-bearing fact so operators and auditors do not have to read the test file.",
				supportSecurityDocPath, want, requiredSupportSecurityHeading)
		}
	}
	if !strings.Contains(doc, requiredSupportGateRow) {
		t.Errorf("%s: missing verification-gates table row containing %q; "+
			"every security-verification story must surface as a row operators and reviewers can see at a glance.",
			supportSecurityDocPath, requiredSupportGateRow)
	}
}

// TestSupportAccessReviewStaticAnalyzerDetectsRegressions is the
// self-check for the matchers above. Each known-bad synthetic
// snippet MUST produce hits and each known-good snippet MUST
// produce zero hits, so over- and under-tightening of the
// analyser are both caught.
func TestSupportAccessReviewStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("findSupportAuditElevationRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical service stamps elevated_access in both methods",
				source: `package store
type AuditEvent struct{ Metadata map[string]string }
type Tx struct{}
type sessionsRepo struct{}
type auditAppender struct{}
type orgsRepo struct{}
type storeT struct{}
type BreakGlassService struct{
	audit auditAppender
	redactor redactor
	store *storeT
}
type redactor struct{}
func (redactor) Redact(s string) string { return s }
func (auditAppender) Append(any, any, AuditEvent) (AuditEvent, error) { return AuditEvent{}, nil }
const breakGlassElevatedAccessKey = "elevated_access"
const breakGlassElevatedAccessValue = "true"
type StartBreakGlassInput struct{ UserAgent string; Reason string }
type RevokeBreakGlassInput struct{ UserAgent string }
type BreakGlassSession struct{}
func (svc *BreakGlassService) StartSession(in StartBreakGlassInput) (BreakGlassSession, error) {
	event := AuditEvent{Metadata: map[string]string{breakGlassElevatedAccessKey: breakGlassElevatedAccessValue}}
	_ = svc.redactor.Redact(in.UserAgent)
	_, _ = svc.audit.Append(nil, nil, event)
	return BreakGlassSession{}, nil
}
func (svc *BreakGlassService) Revoke(in RevokeBreakGlassInput) (BreakGlassSession, error) {
	event := AuditEvent{Metadata: map[string]string{breakGlassElevatedAccessKey: breakGlassElevatedAccessValue}}
	_ = svc.redactor.Redact(in.UserAgent)
	_, _ = svc.audit.Append(nil, nil, event)
	return BreakGlassSession{}, nil
}
`,
				wantHits: 0,
			},
			{
				name: "StartSession missing elevated_access metadata key is rejected",
				source: `package store
type AuditEvent struct{ Metadata map[string]string }
type BreakGlassService struct{}
type StartBreakGlassInput struct{}
type BreakGlassSession struct{}
func (svc *BreakGlassService) StartSession(in StartBreakGlassInput) (BreakGlassSession, error) {
	event := AuditEvent{Metadata: map[string]string{"some_other_key": "true"}}
	_ = svc.redactor.Redact("")
	_, _ = svc.audit.Append(nil, nil, event)
	return BreakGlassSession{}, nil
}
func (svc *BreakGlassService) Revoke() (BreakGlassSession, error) {
	event := AuditEvent{Metadata: map[string]string{breakGlassElevatedAccessKey: "true"}}
	_ = svc.redactor.Redact("")
	_, _ = svc.audit.Append(nil, nil, event)
	return BreakGlassSession{}, nil
}
`,
				wantHits: 1,
			},
			{
				name: "Revoke omitting the AuditEvent entirely is rejected",
				source: `package store
type AuditEvent struct{ Metadata map[string]string }
type BreakGlassService struct{}
type BreakGlassSession struct{}
func (svc *BreakGlassService) StartSession() (BreakGlassSession, error) {
	event := AuditEvent{Metadata: map[string]string{breakGlassElevatedAccessKey: "true"}}
	_ = svc.redactor.Redact("")
	_, _ = svc.audit.Append(nil, nil, event)
	return BreakGlassSession{}, nil
}
func (svc *BreakGlassService) Revoke() (BreakGlassSession, error) {
	return BreakGlassSession{}, nil
}
`,
				wantHits: 1,
			},
			{
				name: "missing required method is reported (Revoke renamed away)",
				source: `package store
type AuditEvent struct{ Metadata map[string]string }
type BreakGlassService struct{}
type BreakGlassSession struct{}
func (svc *BreakGlassService) StartSession() (BreakGlassSession, error) {
	event := AuditEvent{Metadata: map[string]string{breakGlassElevatedAccessKey: "true"}}
	_, _ = svc.audit.Append(nil, nil, event)
	return BreakGlassSession{}, nil
}
func (svc *BreakGlassService) Terminate() (BreakGlassSession, error) {
	event := AuditEvent{Metadata: map[string]string{breakGlassElevatedAccessKey: "true"}}
	_, _ = svc.audit.Append(nil, nil, event)
	return BreakGlassSession{}, nil
}
`,
				wantHits: 1,
			},
			{
				name: "literal 'elevated_access' is accepted as an alternative to the constant",
				source: `package store
type AuditEvent struct{ Metadata map[string]string }
type BreakGlassService struct{}
type BreakGlassSession struct{}
func (svc *BreakGlassService) StartSession() (BreakGlassSession, error) {
	event := AuditEvent{Metadata: map[string]string{"elevated_access": "true"}}
	_ = svc.redactor.Redact("")
	_, _ = svc.audit.Append(nil, nil, event)
	return BreakGlassSession{}, nil
}
func (svc *BreakGlassService) Revoke() (BreakGlassSession, error) {
	event := AuditEvent{Metadata: map[string]string{"elevated_access": "true"}}
	_ = svc.redactor.Redact("")
	_, _ = svc.audit.Append(nil, nil, event)
	return BreakGlassSession{}, nil
}
`,
				wantHits: 0,
			},
		}
		for _, tc := range tcs {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
				if err != nil {
					t.Fatalf("parse synthetic source: %v", err)
				}
				got := findSupportAuditElevationRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findSupportAuditElevationRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findSupportRedactorRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical service uses svc.redactor in both methods",
				source: `package store
type BreakGlassService struct{}
type BreakGlassSession struct{}
func (svc *BreakGlassService) StartSession() (BreakGlassSession, error) {
	_ = svc.redactor.Redact("")
	return BreakGlassSession{}, nil
}
func (svc *BreakGlassService) Revoke() (BreakGlassSession, error) {
	_ = svc.redactor.Redact("")
	return BreakGlassSession{}, nil
}
`,
				wantHits: 0,
			},
			{
				name: "Revoke bypasses the redactor (raw in.UserAgent into audit)",
				source: `package store
type BreakGlassService struct{}
type BreakGlassSession struct{}
func (svc *BreakGlassService) StartSession() (BreakGlassSession, error) {
	_ = svc.redactor.Redact("")
	return BreakGlassSession{}, nil
}
func (svc *BreakGlassService) Revoke(in RevokeBreakGlassInput) (BreakGlassSession, error) {
	_ = in.UserAgent
	return BreakGlassSession{}, nil
}
`,
				wantHits: 1,
			},
			{
				name: "both methods bypass the redactor",
				source: `package store
type BreakGlassService struct{}
type BreakGlassSession struct{}
func (svc *BreakGlassService) StartSession() (BreakGlassSession, error) {
	return BreakGlassSession{}, nil
}
func (svc *BreakGlassService) Revoke() (BreakGlassSession, error) {
	return BreakGlassSession{}, nil
}
`,
				wantHits: 2,
			},
		}
		for _, tc := range tcs {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
				if err != nil {
					t.Fatalf("parse synthetic source: %v", err)
				}
				got := findSupportRedactorRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findSupportRedactorRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findSupportCredMintRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical file does not reference credential-mint identifiers",
				source: `package store
type BreakGlassService struct{}
func (svc *BreakGlassService) StartSession() error {
	_ = svc.audit
	_ = svc.redactor
	return nil
}
`,
				wantHits: 0,
			},
			{
				name: "APIKeyService field reference is rejected",
				source: `package store
type APIKeyService struct{}
type BreakGlassService struct{ keys *APIKeyService }
func (svc *BreakGlassService) StartSession() error {
	_ = svc.keys
	return nil
}
`,
				// One Ident at the type declaration plus one Ident
				// at the `*APIKeyService` field-type reference.
				wantHits: 2,
			},
			{
				name: "IssueKey call inside the unit of work is rejected",
				source: `package store
type BreakGlassService struct{}
func (svc *BreakGlassService) StartSession() error {
	_ = IssueKey("token")
	return nil
}
func IssueKey(s string) string { return s }
`,
				// Idents named "IssueKey" appear at the call site
				// AND at the function declaration's Name field.
				wantHits: 2,
			},
			{
				name: "ServiceAccountKey field is rejected",
				source: `package store
type ServiceAccountKey struct{}
type BreakGlassService struct{}
`,
				wantHits: 1,
			},
		}
		for _, tc := range tcs {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
				if err != nil {
					t.Fatalf("parse synthetic source: %v", err)
				}
				got := findSupportCredMintRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findSupportCredMintRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findSupportPolicyCatalogRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical catalog binds break-glass to CapSupport and grants it only to RoleSupport",
				source: `package policy
var builtinRoleCaps = map[Role]capSet{
	RoleOwner:     newCapSet(CapSelf, CapRead, CapDeploy, CapWrite, CapAdmin, CapOwner),
	RoleAdmin:     newCapSet(CapSelf, CapRead, CapDeploy, CapWrite, CapAdmin),
	RoleDeveloper: newCapSet(CapSelf, CapRead, CapDeploy, CapWrite),
	RoleViewer:    newCapSet(CapSelf, CapRead),
	RoleCI:        newCapSet(CapSelf, CapRead, CapDeploy),
	RoleSupport:   newCapSet(CapSelf, CapRead, CapSupport),
}
var defaultActionCatalog = map[Action]Capability{
	ActionAdminBreakGlass: CapSupport,
}
`,
				wantHits: 0,
			},
			{
				name: "break-glass demoted to CapRead is rejected",
				source: `package policy
var builtinRoleCaps = map[Role]capSet{
	RoleSupport: newCapSet(CapSelf, CapRead, CapSupport),
}
var defaultActionCatalog = map[Action]Capability{
	ActionAdminBreakGlass: CapRead,
}
`,
				wantHits: 1,
			},
			{
				name: "missing ActionAdminBreakGlass binding is rejected",
				source: `package policy
var builtinRoleCaps = map[Role]capSet{
	RoleSupport: newCapSet(CapSelf, CapRead, CapSupport),
}
var defaultActionCatalog = map[Action]Capability{
	ActionAdminRead: CapSupport,
}
`,
				wantHits: 1,
			},
			{
				name: "CapSupport added to RoleAdmin is rejected",
				source: `package policy
var builtinRoleCaps = map[Role]capSet{
	RoleOwner:   newCapSet(CapSelf, CapRead, CapDeploy, CapWrite, CapAdmin, CapOwner),
	RoleAdmin:   newCapSet(CapSelf, CapRead, CapDeploy, CapWrite, CapAdmin, CapSupport),
	RoleSupport: newCapSet(CapSelf, CapRead, CapSupport),
}
var defaultActionCatalog = map[Action]Capability{
	ActionAdminBreakGlass: CapSupport,
}
`,
				wantHits: 1,
			},
			{
				name: "RoleSupport stripped of CapSupport is rejected",
				source: `package policy
var builtinRoleCaps = map[Role]capSet{
	RoleSupport: newCapSet(CapSelf, CapRead),
}
var defaultActionCatalog = map[Action]Capability{
	ActionAdminBreakGlass: CapSupport,
}
`,
				wantHits: 1,
			},
		}
		for _, tc := range tcs {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
				if err != nil {
					t.Fatalf("parse synthetic source: %v", err)
				}
				got := findSupportPolicyCatalogRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findSupportPolicyCatalogRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})

	t.Run("findSupportElevatedAccessProjectionRegressions", func(t *testing.T) {
		t.Parallel()
		tcs := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical renderer hard-codes ElevatedAccess: true",
				source: `package httpapi
type breakGlassSessionResource struct{ ElevatedAccess bool }
type BreakGlassSession struct{}
func breakGlassSessionResourceOf(s BreakGlassSession) breakGlassSessionResource {
	return breakGlassSessionResource{ElevatedAccess: true}
}
`,
				wantHits: 0,
			},
			{
				name: "ElevatedAccess omitted from the literal is rejected",
				source: `package httpapi
type breakGlassSessionResource struct{ ElevatedAccess bool }
type BreakGlassSession struct{}
func breakGlassSessionResourceOf(s BreakGlassSession) breakGlassSessionResource {
	return breakGlassSessionResource{}
}
`,
				wantHits: 1,
			},
			{
				name: "ElevatedAccess: false is rejected",
				source: `package httpapi
type breakGlassSessionResource struct{ ElevatedAccess bool }
type BreakGlassSession struct{}
func breakGlassSessionResourceOf(s BreakGlassSession) breakGlassSessionResource {
	return breakGlassSessionResource{ElevatedAccess: false}
}
`,
				wantHits: 1,
			},
			{
				name: "ElevatedAccess projected from the row (non-literal) is rejected",
				source: `package httpapi
type breakGlassSessionResource struct{ ElevatedAccess bool }
type BreakGlassSession struct{ ElevatedAccess bool }
func breakGlassSessionResourceOf(s BreakGlassSession) breakGlassSessionResource {
	return breakGlassSessionResource{ElevatedAccess: s.ElevatedAccess}
}
`,
				wantHits: 1,
			},
			{
				name: "missing constructor function is reported",
				source: `package httpapi
type breakGlassSessionResource struct{ ElevatedAccess bool }
func somethingElse() {}
`,
				wantHits: 1,
			},
		}
		for _, tc := range tcs {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				fset := token.NewFileSet()
				file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
				if err != nil {
					t.Fatalf("parse synthetic source: %v", err)
				}
				got := findSupportElevatedAccessProjectionRegressions(fset, file)
				if len(got) != tc.wantHits {
					t.Errorf("findSupportElevatedAccessProjectionRegressions: got %d hits, want %d. Hits:\n  %s",
						len(got), tc.wantHits, strings.Join(got, "\n  "))
				}
			})
		}
	})
}

// findSupportAuditElevationRegressions walks the AST of
// `break_glass_service.go` and reports two regression classes:
//
//  1. A required method (`StartSession`, `Revoke`) on the
//     `*BreakGlassService` receiver does not appear in the file
//     at all. A renamed-away method silently drops the audit
//     trail for its mutation.
//  2. A required method's body does not contain at least one
//     `AuditEvent{...}` composite literal whose `Metadata` field
//     is a map literal containing a key reference (Ident or
//     string literal) that resolves to the elevated-access key.
func findSupportAuditElevationRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, method, detail string) {
		out = append(out, "support access review: "+method+" "+detail+" at "+pos.String()+
			". Every break-glass mutation MUST append an immutable audit_events row whose Metadata carries the elevated-access key — that is how reviewers, alerting, and dashboards discover the cross-tenant access decision. "+
			"See internal/release/support_access_review_static_test.go (BE-0358) and SECURITY.md \"Support Access Review\" for the threat model.")
	}
	methods := map[string]*ast.FuncDecl{}
	ast.Inspect(file, func(n ast.Node) bool {
		decl, ok := n.(*ast.FuncDecl)
		if !ok || decl.Recv == nil || len(decl.Recv.List) == 0 {
			return true
		}
		if !supportReceiverIsBreakGlassService(decl.Recv.List[0]) {
			return true
		}
		methods[decl.Name.Name] = decl
		return true
	})
	for _, want := range supportRequiredMethodNames {
		decl, ok := methods[want]
		if !ok {
			out = append(out, "support access review: required method "+strconv.Quote(want)+
				" missing on *"+supportServiceTypeName+
				". Both StartSession and Revoke are load-bearing — every START and every REVOKE must show up on the review trail. "+
				"See internal/release/support_access_review_static_test.go (BE-0358).")
			continue
		}
		if !supportFuncStampsElevatedAccess(decl) {
			pos := fset.Position(decl.Pos())
			emit(pos, want, "does not append an AuditEvent with Metadata["+supportElevatedAccessKeyIdent+"]")
		}
	}
	sort.Strings(out)
	return out
}

// findSupportRedactorRegressions asserts every required method
// references `svc.redactor` at least once. The runtime test for
// the redactor lives in `break_glass_internal_test.go`
// (TestBuildSessionToCreateRedactsReasonValue). The static gate
// catches a regression that silently drops the redactor seam.
func findSupportRedactorRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	methods := map[string]*ast.FuncDecl{}
	ast.Inspect(file, func(n ast.Node) bool {
		decl, ok := n.(*ast.FuncDecl)
		if !ok || decl.Recv == nil || len(decl.Recv.List) == 0 {
			return true
		}
		if !supportReceiverIsBreakGlassService(decl.Recv.List[0]) {
			return true
		}
		methods[decl.Name.Name] = decl
		return true
	})
	for _, want := range supportRequiredMethodNames {
		decl, ok := methods[want]
		if !ok {
			continue // covered by the audit-elevation matcher
		}
		if !supportFuncReferencesField(decl, supportRedactorFieldName) {
			pos := fset.Position(decl.Pos())
			out = append(out, "support access review: "+want+" does not reference svc."+supportRedactorFieldName+
				" at "+pos.String()+
				". The reason and user-agent fields supplied by the operator MUST flow through svc.redactor before they land on the audit row; a regression that bypassed the redactor could persist secrets a careless operator pasted into the reason field. "+
				"See internal/release/support_access_review_static_test.go (BE-0358).")
		}
	}
	sort.Strings(out)
	return out
}

// findSupportCredMintRegressions walks every identifier in the
// store-layer break-glass file and reports any name in
// `forbiddenCredMintIdentifiers`. Break-glass is access-only; a
// regression that wired a credential-mint collaborator into the
// unit of work would silently turn audit-only access into
// credential issuance.
func findSupportCredMintRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if _, bad := forbiddenCredMintIdentifiers[ident.Name]; bad {
			out = append(out, "support access review: forbidden credential-mint identifier "+
				strconv.Quote(ident.Name)+" at "+fset.Position(ident.Pos()).String()+
				". The break-glass unit of work is access-only — it does NOT mint API keys, rotate keys, or grant the support principal any credentials beyond CapSupport. "+
				"See internal/release/support_access_review_static_test.go (BE-0358) and SECURITY.md \"Support Access Review\" for the threat model.")
		}
		return true
	})
	sort.Strings(out)
	return out
}

// findSupportPolicyCatalogRegressions walks `catalog.go` and
// reports two orthogonal regressions:
//
//  1. `defaultActionCatalog` does NOT contain a
//     `ActionAdminBreakGlass: CapSupport` pair. A drift here
//     either locks support out (re-map to CapOwner) or widens
//     cross-tenant access (re-map to CapRead).
//  2. `builtinRoleCaps` admits `CapSupport` to any role other
//     than `RoleSupport`, OR `RoleSupport`'s row does not include
//     `CapSupport`.
func findSupportPolicyCatalogRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, detail string) {
		out = append(out, "support access review: policy catalog "+detail+" at "+pos.String()+
			". The action-to-capability and role-to-capability matrices in catalog.go are the cross-tenant authorization contract for break-glass; a drift silently routes support access through a different engine clause. "+
			"See internal/release/support_access_review_static_test.go (BE-0358) and SECURITY.md \"Support Access Review\" for the threat model.")
	}

	// Pass 1: ActionAdminBreakGlass -> CapSupport binding.
	actionLit := supportFindMapLiteral(file, supportActionCatalogVarName)
	if actionLit == nil {
		emit(fset.Position(file.Pos()), "is missing the "+supportActionCatalogVarName+" map literal")
	} else {
		found := false
		for _, elt := range actionLit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			keyIdent, ok := kv.Key.(*ast.Ident)
			if !ok || keyIdent.Name != supportBreakGlassActionIdent {
				continue
			}
			valIdent, ok := kv.Value.(*ast.Ident)
			if !ok || valIdent.Name != supportBreakGlassCapabilityIdent {
				emit(fset.Position(kv.Pos()),
					"binds "+supportBreakGlassActionIdent+" to "+exprName(kv.Value)+
						", want "+supportBreakGlassCapabilityIdent)
				found = true // we did find the key, just the value drifted
				break
			}
			found = true
		}
		if !found {
			emit(fset.Position(actionLit.Pos()),
				"is missing the "+supportBreakGlassActionIdent+" -> "+supportBreakGlassCapabilityIdent+" binding")
		}
	}

	// Pass 2: CapSupport appears ONLY in RoleSupport's row, and
	// RoleSupport's row DOES include CapSupport.
	rolesLit := supportFindMapLiteral(file, supportRoleCapsVarName)
	if rolesLit == nil {
		emit(fset.Position(file.Pos()), "is missing the "+supportRoleCapsVarName+" map literal")
	} else {
		supportHasCapSupport := false
		for _, elt := range rolesLit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			roleIdent, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			call, ok := kv.Value.(*ast.CallExpr)
			if !ok {
				continue
			}
			hasCapSupport := false
			for _, arg := range call.Args {
				if ident, ok := arg.(*ast.Ident); ok && ident.Name == supportBreakGlassCapabilityIdent {
					hasCapSupport = true
					break
				}
			}
			if hasCapSupport && roleIdent.Name != supportRoleSupportIdent {
				emit(fset.Position(kv.Pos()),
					"grants "+supportBreakGlassCapabilityIdent+" to "+roleIdent.Name+
						" (only "+supportRoleSupportIdent+" may hold "+supportBreakGlassCapabilityIdent+")")
			}
			if roleIdent.Name == supportRoleSupportIdent && hasCapSupport {
				supportHasCapSupport = true
			}
		}
		if !supportHasCapSupport {
			emit(fset.Position(rolesLit.Pos()),
				"strips "+supportBreakGlassCapabilityIdent+" from "+supportRoleSupportIdent+
					"; the cross-tenant exception clause depends on RoleSupport holding CapSupport")
		}
	}

	sort.Strings(out)
	return out
}

// findSupportElevatedAccessProjectionRegressions walks
// `internal/controlplane/httpapi/break_glass.go` and reports two
// regression classes:
//
//  1. The constructor function `breakGlassSessionResourceOf` does
//     not exist (a rename forces an explicit update of this
//     test).
//  2. The constructor's returned `breakGlassSessionResource{...}`
//     literal either omits `ElevatedAccess`, sets it to a
//     non-true literal, or sets it to anything other than the
//     literal identifier `true`.
func findSupportElevatedAccessProjectionRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, detail string) {
		out = append(out, "support access review: HTTP renderer "+detail+" at "+pos.String()+
			". Every projected break-glass session row MUST carry ElevatedAccess: true so the client always learns the row represents an elevated-access decision. "+
			"See internal/release/support_access_review_static_test.go (BE-0358) and SECURITY.md \"Support Access Review\" for the threat model.")
	}
	var ctor *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		decl, ok := n.(*ast.FuncDecl)
		if !ok || decl.Recv != nil {
			return true
		}
		if decl.Name != nil && decl.Name.Name == supportSessionResourceCtorName {
			ctor = decl
			return false
		}
		return true
	})
	if ctor == nil {
		emit(fset.Position(file.Pos()),
			"is missing the "+supportSessionResourceCtorName+" constructor function")
		sort.Strings(out)
		return out
	}
	if ctor.Body == nil {
		emit(fset.Position(ctor.Pos()),
			"constructor "+supportSessionResourceCtorName+" has no body")
		sort.Strings(out)
		return out
	}
	foundOK := false
	ast.Inspect(ctor.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		typeIdent, ok := lit.Type.(*ast.Ident)
		if !ok || typeIdent.Name != supportSessionResourceTypeName {
			return true
		}
		// Found the renderer's returned literal. Look for
		// ElevatedAccess: true exactly.
		var foundField bool
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != supportElevatedAccessField {
				continue
			}
			foundField = true
			ident, ok := kv.Value.(*ast.Ident)
			if !ok || ident.Name != "true" {
				emit(fset.Position(kv.Pos()),
					"sets "+supportElevatedAccessField+" to "+exprName(kv.Value)+
						" (only the literal identifier `true` is accepted)")
				return false
			}
			foundOK = true
		}
		if !foundField {
			emit(fset.Position(lit.Pos()),
				"omits required field "+supportElevatedAccessField+
					" from the "+supportSessionResourceTypeName+" literal")
		}
		return false
	})
	if !foundOK && len(out) == 0 {
		emit(fset.Position(ctor.Pos()),
			"does not construct a "+supportSessionResourceTypeName+" literal at all")
	}
	sort.Strings(out)
	return out
}

// supportReceiverIsBreakGlassService reports whether the receiver
// field's type names `*BreakGlassService`. The unit of work is
// always a pointer receiver in this codebase; the matcher accepts
// either alias (`svc` is conventional, but the alias does not
// affect the receiver-type check).
func supportReceiverIsBreakGlassService(field *ast.Field) bool {
	switch t := field.Type.(type) {
	case *ast.StarExpr:
		ident, ok := t.X.(*ast.Ident)
		return ok && ident.Name == supportServiceTypeName
	case *ast.Ident:
		return t.Name == supportServiceTypeName
	}
	return false
}

// supportFuncStampsElevatedAccess walks a function body and
// reports whether at least one `AuditEvent{...}` composite literal
// carries a `Metadata` map literal whose keys include the
// elevated-access key. The key may be either the package-private
// identifier `breakGlassElevatedAccessKey` or the equivalent string
// literal "elevated_access".
func supportFuncStampsElevatedAccess(decl *ast.FuncDecl) bool {
	if decl == nil || decl.Body == nil {
		return false
	}
	found := false
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		typeIdent, ok := lit.Type.(*ast.Ident)
		if !ok || typeIdent.Name != supportAuditEventTypeName {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != supportAuditMetadataField {
				continue
			}
			meta, ok := kv.Value.(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, mEl := range meta.Elts {
				mkv, ok := mEl.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if supportKeyIsElevatedAccess(mkv.Key) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// supportKeyIsElevatedAccess accepts both the constant identifier
// and the equivalent string literal — both land on the same
// audit-row column in production.
func supportKeyIsElevatedAccess(key ast.Expr) bool {
	switch k := key.(type) {
	case *ast.Ident:
		return k.Name == supportElevatedAccessKeyIdent
	case *ast.BasicLit:
		if k.Kind != token.STRING {
			return false
		}
		v, err := strconv.Unquote(k.Value)
		if err != nil {
			return false
		}
		return v == supportElevatedAccessKeyLiteral
	}
	return false
}

// supportFuncReferencesField walks a function body and reports
// whether any selector expression has the receiver alias `svc` as
// its root and the requested field as its Sel name. The match is
// exact: `svc.redactor` is a hit, `something.redactor` is not.
func supportFuncReferencesField(decl *ast.FuncDecl, field string) bool {
	if decl == nil || decl.Body == nil {
		return false
	}
	found := false
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			return true
		}
		root, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if root.Name == supportServiceReceiverName && sel.Sel.Name == field {
			found = true
			return false
		}
		return true
	})
	return found
}

// supportFindMapLiteral locates the top-level `var <name> = map{
// ... }` declaration and returns the map's composite literal, or
// nil if the variable is missing or its initialiser is not a map
// literal.
func supportFindMapLiteral(file *ast.File, name string) *ast.CompositeLit {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, n := range vs.Names {
				if n.Name != name {
					continue
				}
				if i >= len(vs.Values) {
					return nil
				}
				lit, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					return nil
				}
				if _, ok := lit.Type.(*ast.MapType); !ok {
					return nil
				}
				return lit
			}
		}
	}
	return nil
}

// exprName renders an expression to a short, human-readable form
// for diagnostic messages. The shapes the matchers reach are
// always one of: Ident, BasicLit, or a short SelectorExpr; a
// fallback returns the AST type name so an unexpected shape is
// still legible.
func exprName(e ast.Expr) string {
	switch n := e.(type) {
	case *ast.Ident:
		return n.Name
	case *ast.BasicLit:
		return n.Value
	case *ast.SelectorExpr:
		root, ok := n.X.(*ast.Ident)
		if ok && n.Sel != nil {
			return root.Name + "." + n.Sel.Name
		}
		if n.Sel != nil {
			return "<sel>." + n.Sel.Name
		}
	}
	return "<unhandled expression>"
}

// parseSupportFile reads and parses a tracked Go source file from
// the project tree and returns the FileSet alongside the AST so
// position diagnostics line up with the AST nodes the matchers
// walk. Re-using the same fset between parse and matcher is what
// makes `fset.Position(node.Pos())` resolve to the file under
// review rather than the empty zero position.
func parseSupportFile(t *testing.T, root, rel string) (*token.FileSet, *ast.File) {
	t.Helper()
	path := filepath.Join(root, rel)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	return fset, file
}
