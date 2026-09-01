# Production readiness

This document is the release gate for `a10-certctl`. The production-supported
scope is certificate/key lifecycle management for ACOS 6.x.y client-SSL
template `certificate-list` entries. Minor, patch, and build releases are not
pinned. A tag must not be described as production-ready until every
mandatory gate below passes on the exact release commit.

## Guarantees in the supported scope

| Concern | Implemented guarantee |
| --- | --- |
| Thin REST wrapper | `SyncCertificate` owns compatibility preflight, validation, immutable naming, upload, binding, read-back verification, old-binding removal, optional reference-safe cleanup, persistence, and logoff. `Session.Raw().DoJSON` is visibly an advanced escape hatch. |
| Pre-staging before a template exists | `CreateManagedCertificate` uploads immutable checksum-versioned certificate/key/chain files without resolving or modifying a client-SSL template. Managed writes on one client/session are serialized. |
| Runtime-only type errors | Public resource identifiers have distinct Go types. PEM, X.509, encrypted keys, issuer order, CA constraints, validity, and certificate/key matching are checked locally before authentication. |
| Identifiers | A logical certificate slot is addressed by client-SSL template/certificate names. L3V partitions are independently addressable by their ACOS-assigned numeric ID or exact name; IDs are resolved through `/partition` before activation. |
| Empty partitions | HTTP 204 from certificate, key, CA, operational-certificate, client-SSL, and virtual-server inventories is normalized to an empty typed result. High-level create/sync therefore works before the first certificate exists. |
| Partial pair replacement | Certificate, key, and chain files are immutable and bundle-checksum-versioned. Certificate and key are posted together. The result is read back and validated for both ACOS's atomic sole-binding replacement and add-then-remove multi-entry behaviour. |
| Simultaneous GUI/API changes | The complete template response is fingerprinted. State is compared before binding, after binding, before and after unbinding, and before persistence. A mismatch returns typed `ConflictError`; cleanup and persistence stop. |
| Unsafe cleanup | Old files are retained by default. Explicit cleanup scans the complete payload of every client-SSL and server-SSL template. Typed certificate-list, SNI, forward-proxy, and backend-mTLS references are covered; unknown 6.x values fail safe by retaining material. |
| Lost mutation response | The state is re-read. Desired state continues, unchanged state remains retryable, and a third state returns `ErrAmbiguousState`. `ReconcileCertificate` converges without blind rollback. |
| Persistence failure | `WriteMemory` sends the documented destination and shared/specified partition fields. Before destructive old-file cleanup, a failure restores the verified baseline binding, removes only files uploaded by the invocation, verifies the restoration, and persists it. An incomplete rollback returns `RollbackError`/`ErrAmbiguousState`. |
| VIP ownership | `FindClientSSLTemplatesByVIP` and the `vip` command map exact IPv4/IPv6 virtual addresses to local or shared client-SSL templates. |
| Secret exposure | Private keys and passphrases are never returned by public state types and are excluded from JSON output. Imported keys are non-exportable by default. |
| Mutex scope | Lifecycle locking coordinates in-flight requests with logoff; a separate managed-write mutex serializes high-level mutations on one client/session. Neither is presented as a distributed ACOS transaction. Independent reads remain concurrent. |

## Residual ACOS limitation

The tested ACOS 6.0.9 certificate and client-SSL endpoints expose neither a
configuration transaction nor an ETag/`If-Match` conditional write. The
library provides transaction-like failure handling through verified,
compensating rollback, but cannot make the final read-to-write interval atomic
against another controller or a GUI user. It fails closed when the subsequent
read detects a conflict and keeps the previous files by default, but
environments with multiple writers must use a single configuration owner or
an external distributed lock.

This is an appliance capability boundary, not something a client-side mutex
can honestly solve.

A lost response to a bind is reconciled by an immediate state read. A third,
unexpected revision is reported as ambiguous; the library does not attempt an
unsafe blind rollback.

## Mandatory release gates

- `gofmt`, `go vet`, unit tests, CLI tests, race tests, and a clean build pass.
- `govulncheck` reports no reachable known vulnerability.
- The compatibility tests accept valid ACOS 6.x.y releases and reject malformed
  or different-major releases before high-level mutation.
- The self-cleaning ACOS 6 lifecycle test passes against the target build.
- The concurrent-session appliance test passes without leaked sessions.
- The unbound-create appliance test pre-stages and removes material without a
  client-SSL template.
- Empty L3V partitions are exercised by exact name and ACOS numeric ID, and
  their empty inventories plus partition-scoped write-memory calls succeed.
- Unit and live-appliance failure injection verify that pre-staged uploads are
  removed and the cleaned state is persisted after a persistence error;
  incomplete rollback is categorized as ambiguous.
- The live test verifies typed state and the final template revision.
- The optional live VIP test maps the data-plane address to the configured
  client-SSL template and matches the served certificate serial to aXAPI state.
- The release commit has a semantic version tag and generated checksums.
- A customer acceptance test confirms the intended template/partition/HA
  topology and explicitly names the sole automation owner or external lock.
- TLS verification is enabled with the production management CA; the lab-only
  `--insecure-skip-verify` option is not used.

## Decision

Passing all automated and appliance gates makes the library suitable for a
controlled production pilot in the supported scope. Broad production rollout
still requires the customer acceptance items above. Features outside the scope
require their own typed model, failure semantics, and live tests before they
can inherit that statement.

## Current verified baseline

The current working tree passed the self-cleaning lifecycle, persisted
unbound-create, injected persistence rollback, concurrent-session,
empty-partition name/ID, and VIP data-plane tests on A10 vThunder ACOS 6.0.9
build 116 with aXAPI 3.0.
This is the tested baseline, not a patch/build restriction.
