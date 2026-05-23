// Package store owns Postgres persistence for Yalla control-plane
// source-of-truth state.
//
// # Transaction pattern
//
// The store is the only place repository code reaches the database, and it
// reaches it in exactly two ways:
//
//   - Store.Read runs a function inside a read-only transaction and hands it a
//     Querier — a consistent snapshot for multi-statement reads, with writes
//     rejected by the database.
//   - Store.Write runs a function inside a single read/write transaction and
//     hands it a *Tx. The transaction commits only when the function returns
//     nil; any error, or a panic, rolls the whole transaction back.
//
// A *Tx can only be obtained from inside Store.Write, and repository mutation
// methods require a *Tx rather than a bare Querier. That is deliberate: it
// makes it structurally impossible to run a mutation outside a transaction,
// which in turn makes it impossible to separate a mutation from the
// authorization and quota checks that share its transaction. A denied
// authorization decision, an exhausted quota, a slug conflict, or a failed
// provisioning-job enqueue all roll back the desired-state write atomically.
//
// # Reference implementation
//
// ProjectRepository and ProjectService are the worked reference for the
// pattern every customer-data table and unit of work follows. ProjectService
// composes — inside one Store.Write transaction — an authorization check, a
// quota reservation, the desired-state write, and a durable provisioning-job
// enqueue. The authorization, quota, and job dependencies are narrow port
// interfaces (Authorizer, QuotaReserver, JobEnqueuer); their real
// implementations land in the policy, quota, and jobs packages in later
// stories, and tests substitute fakes.
//
// # Conventions
//
//   - Every customer-data query is tenant scoped: it filters by
//     organization_id before resource id, so a cross-tenant id can never match
//     and never reveals another organization's data.
//   - Every statement is fully parameterized; no SQL is built by concatenating
//     caller input.
//   - Missing rows are reported as a typed apierr.NotFound; constraint
//     violations as apierr.Conflict; other driver failures as
//     apierr.StoreUnavailable. The raw driver error — which may name columns,
//     constraints, or connection details — is preserved only as the wrapped
//     cause for server-side logging and never reaches the user-facing message.
//
// Schema migrations live in the store/migrate subpackage.
package store
