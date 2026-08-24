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
| Internal IDs | A logical slot is addressed by the stable client-SSL template name and, for multiple certificate-list entries, the currently bound certificate name. No numeric database ID is exposed. |
| Partial pair replacement | Certificate, key, and chain files are immutable and bundle-checksum-versioned. Certificate and key are posted together. The result is read back and validated for both ACOS's atomic sole-binding replacement and add-then-remove multi-entry behaviour. |
| Simultaneous GUI/API changes | The complete template response is fingerprinted. State is compared before binding, after binding, before and after unbinding, and before persistence. A mismatch returns typed `ConflictError`; cleanup and persistence stop. |
| Unsafe cleanup | Old files are retained by default. Explicit cleanup scans the complete payload of every client-SSL and server-SSL template. Typed certificate-list, SNI, forward-proxy, and backend-mTLS references are covered; unknown 6.x values fail safe by retaining material. |
| Lost mutation response | The state is re-read. Desired state continues, unchanged state remains retryable, and a third state returns `ErrAmbiguousState`. `ReconcileCertificate` converges without blind rollback. |
| VIP ownership | `FindClientSSLTemplatesByVIP` and the `vip` command map exact IPv4/IPv6 virtual addresses to local or shared client-SSL templates. |
| Secret exposure | Private keys and passphrases are never returned by public state types and are excluded from JSON output. Imported keys are non-exportable by default. |
| Mutex scope | Lifecycle locking coordinates in-flight requests with logoff; a separate managed-write mutex serializes high-level mutations on one client/session. Neither is presented as a distributed ACOS transaction. Independent reads remain concurrent. |

## Residual ACOS limitation

The tested ACOS 6.0.9 certificate and client-SSL endpoints expose neither
a configuration transaction nor an ETag/`If-Match` conditional write. The
library therefore cannot make the final read-to-write interval atomic against
another controller or a GUI user. It fails closed when the subsequent read
detects a conflict and keeps the previous files by default, but environments
with multiple writers must use a single configuration owner or an external
distributed lock.

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

The current working tree passed the self-cleaning lifecycle, unbound-create,
concurrent-session, and VIP data-plane tests on A10 vThunder ACOS 6.0.9 build
116 with aXAPI 3.0.
This is the tested baseline, not a patch/build restriction.
