# validate — request validation toolkit

`internal/controlplane/validate` is the single place handlers and services
validate untrusted request input. It is pure: no I/O, no Postgres, no knowledge
of feature flags or quota.

## Conventions

- **Collector pattern.** Build a `validate.New()` Collector, call validators
  against it (each takes `c *Collector, field string, ...`), then return
  `c.Err()` — nil or one `apierr.InvalidInput` carrying every violation. Never
  short-circuit on the first bad field.
- **Never echo the submitted value.** A `FieldViolation.Reason` carries only
  classification text (bounds, "must not be blank"). Reasons may interpolate
  bounds/counts via `Addf`, never input. This is what lets a secret env var be
  rejected without its value reaching a log/error. Add a "never echoes the
  value" test for any new validator.
- **Policy-dependent rules are options, not lookups.** `Domain` takes
  `DomainOptions{AllowWildcard}`; the caller resolves the feature flag + quota
  and passes the bool. Keep the package free of config/quota imports.
- **Field paths.** Dotted (`build.dockerfile_path`), indexed for slices
  (`env[0].name`), and a distinct segment for sensitive sub-lists
  (`env.secret[0]`).
- **Fuzz every string validator.** Seed `fuzzSeeds` covers long strings,
  invalid UTF-8, path traversal, control chars. A fuzz target asserts no panic
  and re-derives the accept invariants — mirror that for new validators.
- `DecodeJSON` is the strict JSON body decoder: size-capped, unknown-field- and
  trailing-data-rejecting, and every failure is a body-free `apierr.Invalid`.

## JSON parser hardening invariants (BE-0346)

`DecodeJSON` is the single canonical decoder every mutating HTTP handler
funnels through (BE-0345 already rejects any handler that bypasses it). The
function's body MUST keep four AST-shaped hardenings — losing any one of
them re-opens a real attack surface:

1. `json.NewDecoder(&limitedReader{...})` — the reader is wrapped in the
   explicit byte-cap reader BEFORE the decoder sees it (OOM/slow-loris
   defence).
2. `<dec>.DisallowUnknownFields()` — rejects extra keys (mass-assignment /
   schema-confusion / hidden-field smuggling defence).
3. `<dec>.More()` — after `Decode`, asserts the stream is exhausted (JSON
   smuggling defence; a body like `{"a":1}{"b":2}` lets a proxy/WAF see
   one value while the API acts on another).
4. `decodeError(...)` — every failure flows through this fixed-message
   renderer; raw `encoding/json` errors that quote the submitted bytes
   never reach the response (secret-leak / body-echo defence).

The static analyser `TestDecodeJSONKeepsAllHardenings`
(`json_static_test.go`) parses `json.go`, locates `DecodeJSON`, and emits
a build-time failure listing each hardening that is missing; the companion
`TestDecodeJSONHardeningStaticAnalyzerDetectsRegressions` synthesises
known-bad and known-good DecodeJSON variants to prove the analyser fires
on the bad shapes and stays silent on the good one. The runtime backstop
lives in `internal/controlplane/httpapi/json_hardening_test.go` and proves
the hardenings hold end-to-end through `NewHandler` (unknown field,
trailing data, malformed JSON, wrong-typed field, auth-before-decode).

When changing `DecodeJSON`, run the validate package tests AND the httpapi
package tests. The hardenings are not optional and not negotiable: if a
caller cannot live with one of them, add a NEW typed decoder beside
`DecodeJSON` (and a new analyser companion that pins its hardenings) —
never weaken the canonical one.

## SSRF protection for webhooks and Git URLs (BE-0349)

The Yalla Control Plane accepts customer-supplied URLs that downstream
worker code paths later dereference — `URL` is the validator for
notification / deploy / webhook hooks, and `GitRepoURL` is the validator
for service build settings. If either of those URLs were allowed to
point at internal addresses, a tenant could coerce the platform into
fetching short-lived workload credentials from the cloud metadata
service (169.254.169.254 / `metadata.google.internal` / 169.254.170.2),
probing the loopback admin surface of Yalla itself or of Dokploy, or
pivoting through RFC1918 / unique-local-IPv6 ranges into other tenants'
intra-cluster services. The validator-layer defence is
`disallowedSSRFHost` in `ssrf.go`. Every public URL-shaped validator
MUST funnel its parsed host through that helper before returning. The
helper rejects:

1. **IP-literal forms** (`net.ParseIP` parses the host) in any of the
   following ranges: unspecified (`0.0.0.0` / `::`), loopback
   (`127.0.0.0/8`, `::1`), link-local unicast and multicast
   (`169.254.0.0/16` incl. cloud metadata, `fe80::/10`), multicast
   (`224.0.0.0/4`, `ff00::/8`), private networks
   (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), CGNAT
   (`100.64.0.0/10`), benchmark range (`198.18.0.0/15`), and the
   limited broadcast `255.255.255.255`. The 169.254.169.254 cloud
   metadata IP is caught by the link-local check.
2. **Hostname exact-matches**: `localhost`, `ip6-localhost`,
   `ip6-loopback`, `metadata`, `metadata.google.internal`,
   `metadata.aws.internal`, and the bare literal `169.254.169.254`.
3. **Hostname suffixes** (with a leading dot to prevent over-match):
   `.localhost`, `.internal`, `.local`, `.localdomain`.

Reasons are a closed set of value-free classification strings — see
`canonicalSSRFReasons` in `ssrf_test.go`. The reason text NEVER quotes
the submitted host or any other input, so a webhook URL whose query
string contains a token cannot leak through the rejection error.

**Layered defence required.** This package is pure: it performs no DNS
lookups. A public name that resolves to a private IP at fetch time
(DNS-rebinding) cannot be caught here — the worker's actual HTTP
client / git client MUST re-validate the resolved address before
connecting. The validator layer is the first wall; the runtime wall is
not in this package.

The two-test pattern (BE-0344, BE-0345, BE-0346) applies here. The
static analyser `TestSSRFGuardIsCalledFromURLValidators`
(`ssrf_static_test.go`) parses `network.go` and `refs.go`, locates `URL`
and `GitRepoURL`, and asserts each body contains at least one call to
`disallowedSSRFHost`. A future change that splits one of these
validators (e.g. extracts a thin `URL` wrapper that delegates and
forgets the SSRF call site) fails the build BEFORE the regression can
ship. The companion `TestSSRFGuardStaticAnalyzerDetectsRegressions`
self-checks the analyser against synthetic known-bad / known-good
fixtures, including a look-alike-but-wrong helper name fixture that
ensures the analyser pins the exact identifier (so "I rewrote my own
SSRF check" can't silently substitute). The hostname blocklist itself
is sealed by `TestSSRFHostnameListsAreCanonical`, which fails the build
if a required entry is dropped or a suffix entry loses its leading dot.

The runtime backstop lives in `ssrf_test.go`:
`TestURLRejectsSSRFTargets` and `TestGitRepoURLRejectsSSRFTargets`
walk each documented IP-literal range, each hostname, and each suffix
and prove the helper rejects them with a canonical reason from the
closed set. `TestURLAcceptsPublicHosts` and
`TestGitRepoURLAcceptsPublicHosts` keep the positive direction honest
(an analyser-satisfying no-op that rejected every host would still fail
these). `TestSSRFReasonsAreValueFree` plants a secret canary in the
URL query string and a fresh per-iteration IP-literal host, proves the
reason is one of the canonical classification strings, and proves
neither the canary nor the inner host appears in the reason. The fuzz
target `FuzzURL` re-derives the accept invariants from random inputs
and is seeded with one URL per documented forbidden range.

When changing `disallowedSSRFHost`, run the validate package tests
(`go test ./internal/controlplane/validate/...`). The hostname/suffix
sets are sealed by name — dropping a documented entry fails
`TestSSRFHostnameListsAreCanonical`. Adding a new classification string
also requires updating `canonicalSSRFReasons` in `ssrf_test.go` so the
value-free invariant covers it.

## Domain-takeover prevention (BE-0350)

The Yalla Control Plane stores customer-attached hostnames in the
`service_domains` table behind a UNIQUE (hostname, path) constraint
that spans every tenant. The FIRST tenant to land a row owns the
routing for that hostname in the entire cluster — and that uniqueness
is the exact lever a domain-takeover attack pulls. The validator-layer
defence is `disallowedTakeoverHost` in `domain_takeover.go`. The single
public customer-domain validator — `Domain` in `network.go` — MUST
funnel its final, stripped hostname through that helper before
returning. The helper rejects:

1. **IP-literal hostnames** (`net.ParseIP` parses the host) in any
   form. Customer hostnames must be hostnames, never IP addresses — a
   public CA will not issue a TLS certificate for an arbitrary IP the
   platform does not authoritatively own, and a customer claiming a
   raw IP literal could siphon any Host-header request that happens to
   target that literal. The symmetric SSRF guard in `ssrf.go` blocks
   IP-literal OUTBOUND targets; this guard is the symmetric INBOUND
   wall for hostnames the platform agrees to ROUTE traffic for.
2. **Exact-match reserved hostnames**: RFC 6761 / RFC 2606 special-use
   labels (`localhost`, `localdomain`, `local`, `internal`,
   `intranet`, `private`, `corp`, `home`, `home.arpa`, `lan`, `test`,
   `example`, `invalid`) and the bare form of common shared-hosting
   eTLDs (`appspot.com`, `azurewebsites.net`, `cloudfront.net`,
   `elasticbeanstalk.com`, `firebaseapp.com`, `github.io`,
   `gitlab.io`, `herokuapp.com`, `netlify.app`, `pages.dev`,
   `vercel.app`, `web.app`). Sub-tenants under a shared-hosting eTLD
   (`myapp.appspot.com`) are perfectly legitimate; only the bare
   suffix is reserved.
3. **Hostname suffixes** (with a leading dot to prevent over-match):
   `.localhost`, `.localdomain`, `.local`, `.internal`, `.intranet`,
   `.private`, `.corp`, `.home`, `.home.arpa`, `.lan`. The RFC 2606
   documentation-only suffixes (`.test`, `.example`, `.invalid`) are
   intentionally NOT in the suffix list: they are not publicly
   routable and cannot intercept real customer traffic, so they are a
   squatting concern (bounded by the UNIQUE constraint) rather than a
   takeover threat. They remain in the exact-match map as
   defence-in-depth for the bare-label form. This omission also
   keeps every existing `.example` test fixture across the httpapi
   package valid.

Reasons are a closed set of value-free classification strings — see
`canonicalTakeoverReasons` in `domain_takeover_test.go`. The reason
text NEVER quotes the submitted host or any other input, so a
hostname whose label embeds an internal name cannot leak through the
rejection error.

**Layered defence required.** This package is pure: it performs no
DNS lookups and cannot independently prove that a customer actually
owns the hostname they attach. Ownership PROOF (HTTP-01 / DNS-01 /
ALPN-01 challenge, or an external pre-shared verification record) is
a runtime concern that belongs to the certificate-issuance and
routing-attach worker — NOT this layer. The validator rejects every
shape the parser can prove is structurally illegitimate; the runtime
catches the rest.

The two-test pattern (BE-0344, BE-0345, BE-0346, BE-0349) applies
here. The static analyser
`TestDomainTakeoverGuardIsCalledFromDomainValidator`
(`domain_takeover_static_test.go`) parses `network.go`, locates
`Domain`, and asserts the body contains at least one call to
`disallowedTakeoverHost`. A future change that splits `Domain` and
forgets the takeover call fails the build BEFORE the regression can
ship. The companion
`TestDomainTakeoverGuardStaticAnalyzerDetectsRegressions` self-checks
the analyser against synthetic known-bad / known-good fixtures —
including a look-alike-but-wrong helper-name fixture that ensures the
analyser pins the exact identifier (so "I rewrote my own takeover
check" can't silently substitute). The reserved-name lists themselves
are sealed by `TestDomainTakeoverListsAreCanonical`, which fails the
build if a documented entry is dropped or a suffix entry loses its
leading dot.

The runtime backstop lives in `domain_takeover_test.go`:
`TestDomainRejectsTakeoverTargets` walks each IPv4 literal, each
shared-hosting eTLD bare form, each multi-label reserved exact-match
(`home.arpa`), and each reserved suffix and proves the helper rejects
them with a canonical reason from the closed set;
`TestDomainAcceptsPublicHosts` keeps the positive direction honest
(an analyser-satisfying no-op that rejected every host would still
fail these — including `myapp.appspot.com` and `acme.github.io`,
which are sub-tenants under a reserved eTLD and must STAY accepted);
`TestDomainRejectsTakeoverTargetsForWildcard` proves the same
rejection holds when wildcards are enabled (a wildcard makes takeover
strictly worse — the bare suffix locks one routing entry, the
wildcard locks every sub-tenant of that suffix);
`TestDomainTakeoverReasonsAreValueFree` plants a secret canary as a
sub-label of a reserved-suffix host, proves the reason is one of the
canonical classification strings, and proves neither the canary nor
the inner host appears in the reason; and
`TestDomainTakeoverEmptyHostKeepsExistingDiagnostic` pins the
order-of-precedence so `Domain("")` keeps returning the existing
"must not be blank" diagnostic. The fuzz target `FuzzDomain`
re-derives the takeover invariants in its accept branch (any
accepted host MUST NOT parse as an IP literal and MUST NOT end in a
reserved suffix) and is seeded with one host per documented
forbidden category.

Why this is distinct from `disallowedSSRFHost`: SSRF is about
OUTBOUND URLs the worker dereferences (where an IP literal targets
an internal address). Domain-takeover is about INBOUND hostnames the
platform agrees to route traffic for (where an IP literal is a
non-domain and a shared-hosting eTLD is a public namespace nobody
should single-handedly claim). The two helpers share the BE-0344
two-test template shape but live in separate files and check
disjoint sets — a hostname that is legitimate to attach (e.g.
`myapp.example.com`) may still be illegitimate to fetch as a URL if
it resolves to a private IP, and vice versa.

When changing `disallowedTakeoverHost`, run the validate package
tests (`go test ./internal/controlplane/validate/...`). The
hostname/suffix sets are sealed by name — dropping a documented
entry fails `TestDomainTakeoverListsAreCanonical`. Adding a new
classification string also requires updating
`canonicalTakeoverReasons` in `domain_takeover_test.go` so the
value-free invariant covers it.
