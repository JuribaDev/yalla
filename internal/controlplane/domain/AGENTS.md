# internal/controlplane/domain

Stable identity, slug, and naming primitives shared by every control-plane
resource. These are public compatibility contracts — treat changes here as
breaking for stored data, audit records, Dokploy resources, and any agent/CLI
that parses them.

- **IDs** are `<kind>_<26-char crockford-base32 suffix>`, 128 bits of
  `crypto/rand` entropy. Always create them with `NewID(kind)`; never assemble
  the string yourself. Always validate inbound IDs with `ParseID` and assert
  the kind with `id.IsKind(...)` before trusting one — a well-formed ID of the
  wrong kind is still a cross-resource confusion risk.
- **Adding a `Kind`** means adding the constant *and* an entry in the `kinds`
  map; the map is what `Kind.Valid` and `ParseID` consult.
- **Slugs** are canonical `[a-z0-9-]`, 1..`MaxSlugLen` chars, no leading/
  trailing/double hyphens. `NormalizeSlug` is lenient (Unicode-folds, rewrites,
  truncates) and is **idempotent** — that invariant is fuzz-tested, keep it.
  `ValidateSlug`/`ParseSlug` are strict. Slug uniqueness within a parent scope
  is enforced by a DB constraint in the persistence layer, not here.
- **Dokploy names** come only from `DokployName(label, id)`. It embeds the full
  ID so the name is deterministic and globally unique, and caps length so it
  stays inside Docker's 63-char limit. If you change `MaxSlugLen` or the kind
  prefixes, re-check `TestDokployNameStaysWithinDockerLimit`.
- The Unicode transform chain (`transform.Chain`) is **stateful and not
  concurrency-safe** — it must be pooled (`slugTransformerPool`), never shared
  as a package-level value.
- Errors are local sentinels (`errors.Is`-comparable) with **no HTTP
  semantics** and no import of `apierr`/`apienvelope`. The HTTP layer maps them
  to `apierr.InvalidInput`. Error messages must not echo untrusted input
  verbatim (`TestParseIDErrorDoesNotEchoInput`).
- Unit + fuzz tests are required. `FuzzNormalizeSlug` / `FuzzValidateSlug` /
  `FuzzParseID` assert the invariants for arbitrary input; extend them when you
  add a primitive rather than relying on table tests alone.
