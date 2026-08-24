# Changelog

## v0.0.1

### Added

- Mutex-serialized `CreateManagedCertificate` on `Client` and `Session` for
  safely pre-staging checksum-versioned certificate material before a
  client-SSL template exists.
- A pkg.go.dev-style Go library reference covering configuration parameters,
  certificate properties, return values, errors, and ACOS identifier origins.
- Typed A10 ACOS 6.x.y certificate, key, chain, target, and result APIs with a
  non-pinned compatibility preflight.
- Local PEM, X.509, private-key, passphrase, chain, and pair validation.
- Canonical SHA-256 checksums and checksum-versioned ACOS file names.
- Safe client-SSL template synchronization with read-back verification.
- Reference-aware cleanup and write-memory persistence.
- Administrative CLI, unit tests, and self-cleaning live-appliance test.
- GitHub CI, CodeQL, dependency-review, vulnerability, and release workflows.
- Distinct client-SSL template, certificate, key, and CA identifier types.
- Secret-free `GetManagedCertificateState`, `GetCertificate`, and `GetKey` APIs.
- Optimistic template revisions, caller-supplied preconditions, and typed
  concurrency conflicts for GUI/API races.
- `status`, `--expected-revision`, and opt-in `--cleanup-old` CLI workflows.
- Package documentation, public API example, and an explicit production
  readiness/release gate.
- Secure management-transport defaults that reject plain HTTP, URL-embedded
  credentials, contradictory TLS settings, and negative timeouts.
- Current leaf and issuer-chain validity enforcement before a high-level sync
  opens an appliance session.
- Typed server-SSL backend-mTLS inventory and cross-template reference checks
  so optional cleanup cannot delete a certificate or key used by server-SSL.
- Verified handling for both ACOS atomic sole-binding replacement and
  add-then-remove multi-entry certificate-list rotation semantics.
- Release version embedding in the library User-Agent and unauthenticated
  `build-info` CLI output.
- Typed SNI and forward-proxy certificate-reference inventory.
- Fail-safe cleanup scans of complete client-SSL and server-SSL payloads,
  including unknown ACOS 6.x fields.
- Typed VIP-to-client-SSL-template discovery and the `vip` CLI command.
- Stable `errors.Is` categories for authentication, not-found, conflict,
  unsupported-version, and ambiguous-state failures.
- Synchronization stage reporting and idempotent `ReconcileCertificate`.
- Lost/failed bind-response reconciliation by verified appliance state.
- Explicit `Session.Raw().DoJSON` escape hatch separated from the typed API.
- `preflight` CLI command reporting the ACOS 6.x.y contract and tested baseline.
- Data-plane live acceptance that matches the VIP certificate serial to aXAPI
  template inventory.

### Changed

- Renamed the appliance read to `ACOSVersion` so it cannot be confused with
  `BuildVersion`.
- Renamed the logical managed-state read to `GetManagedCertificateState`,
  preserving `GetCertificate` for exact raw certificate-file inventory.

- Old certificate material is retained by default; deletion requires explicit
  `CleanupOld`/`--cleanup-old` authorization after a full reference scan.
- Checksum-managed names use 128 checksum bits instead of 64.
- Session locking is limited to lifecycle safety and permits concurrent reads;
  it is not presented as an ACOS configuration transaction.
- The supported high-level scope is explicitly A10 client-SSL certificate
  lifecycle management; ACOS server-SSL backend mTLS is not implied.
- Canonical module and release-linker path is `github.com/vpgc/a10-certctl`.

### Removed

- Removed the ambiguous pre-v1 `Session.Version` and `GetCertificateState`
  method names.
