# a10-certctl

A typed Go library and administrative CLI for A10 Thunder/ACOS TLS certificate
lifecycle management through aXAPI v3.

The primary API validates certificates, private keys, chains, targets, and file
names locally. Dedicated Go types distinguish client-SSL template,
certificate, key, and CA names. It uploads a checksum-versioned
certificate/key pair, posts the pair in one binding operation, reads back the
result, and handles both ACOS behaviours: atomic replacement of a sole binding
and add-then-remove rotation for multi-certificate templates.

The supported compatibility contract is ACOS 6.x.y with aXAPI v3; no minor,
patch, or build release is pinned. The current release was live-tested on A10
vThunder ACOS 6.0.9 build 116 with aXAPI 3.0 and checked against the ACOS 6.0.9
aXAPI reference.

## Scope

This module is intentionally A10-only. Its supported high-level workflow is the lifecycle
of TLS server certificate/key pairs in an ACOS client-SSL template's
`certificate-list`, including templates with multiple entries. It also
provides typed SNI and forward-proxy reference inventory, VIP-to-template
resolution, import, binding, unbinding, deletion, and persistence operations
for that workflow.

An ACOS `server-ssl` template is a different feature: its `certificate` object
is a client certificate used for mutual TLS from A10 to a backend server. That
workflow is inventoried so cleanup cannot delete files used by backend mTLS,
but it is not mutated by `SyncCertificate`. CA trust-policy management, ACME
enrollment, HSM keys, virtual-port assignment, and HA/config-sync orchestration
are not silently treated as equivalent certificate operations. They are
outside the current high-level scope. `Session.Raw().DoJSON` is an explicit
advanced escape hatch, not a claim that untyped calls have the guarantees of
`SyncCertificate`.

The release acceptance criteria and residual risks are recorded in
[`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md). Production approval is
for the documented client-SSL workflow, not for every PKI feature exposed by
aXAPI.

The [Go library reference](docs/API.md) documents every high-level parameter,
property, return value, error category, and the origin of ACOS names and
revisions.

## Typed certificate synchronization

```go
certificatePEM, err := os.ReadFile("fullchain.pem")
if err != nil {
    log.Fatal(err)
}
privateKeyPEM, err := os.ReadFile("privkey.pem")
if err != nil {
    log.Fatal(err)
}

bundle, err := a10.ParseCertificateBundle(a10.CertificateBundleInput{
    CertificatePEM: certificatePEM,
    PrivateKeyPEM:  privateKeyPEM,
    // PrivateKeyPassphrase: []byte(os.Getenv("A10_KEY_PASSPHRASE")),
    // CertificateChainPEM: [][]byte{additionalChainPEM},
})
if err != nil {
    // Malformed PEM, unsupported key formats, bad passphrases, invalid chains,
    // and certificate/key mismatches fail before an aXAPI session is opened.
    log.Fatal(err)
}

client, err := a10.New(a10.Config{
    Address:  "a10.example.com",
    Username: os.Getenv("A10_USERNAME"),
    Password: os.Getenv("A10_PASSWORD"),
    // TrustedCertificate: "/etc/pki/a10-management-ca.pem",
})
if err != nil {
    log.Fatal(err)
}

result, err := client.SyncCertificate(
    context.Background(),
    a10.ForClientSSLTemplate("www-client-tls"),
    bundle,
    a10.SyncOptions{},
)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("changed=%t name=%s bundle=%s\n",
    result.Changed,
    result.Certificate.Name,
    result.Certificate.BundleChecksum,
)
```

`SyncCertificate` performs the complete lifecycle:

1. validates all PEM objects, the issuer chain, current validity intervals,
   and the certificate/key match;
2. opens an independent aXAPI authentication session;
3. verifies that the appliance reports a syntactically valid ACOS 6.x.y release;
4. resolves the exact client-SSL template and certificate-list entry;
5. derives an immutable ACOS file name from 128 bits of the complete bundle
   checksum;
6. uploads a non-exportable key, certificate, and optional CA-chain file;
7. binds and reads back the new pair, accepting either ACOS's atomic sole-pair
   replacement or an additional certificate-list entry before explicit old removal;
8. writes the desired running configuration to the active partition's memory;
9. optionally deletes old files only after persistence and only when their
   exact names do not occur in any complete client-SSL or server-SSL response,
   including unknown 6.x fields; and
10. logs off on both success and error paths.

ACOS applies running-configuration changes immediately. The versioned-pair sequence and single
binding document avoid separate certificate/key replacement calls that could
leave a mismatched pair. ACOS may replace a sole binding as part of the
successful bind request; on multi-entry templates the library verifies the added
pair before explicitly removing the selected old binding. Old files remain
available by default in either case.

If persistence fails before old-file cleanup, the high-level workflow performs
a compensating rollback: it restores and verifies the baseline binding,
deletes and verifies only material uploaded by that call, and persists the
restored baseline. `RolledBack` reports a successful compensation. An
incomplete compensation returns `RollbackError`, categorized as
`ErrAmbiguousState`. ACOS does not expose a native transaction for these
endpoints, so this guarantee does not replace single-writer coordination.

For a client-SSL template with multiple `certificate-list` entries, select the
exact entry:

```go
target := a10.ForCertificateBinding("sni-client-tls", "old-example-cert")
result, err := client.SyncCertificate(ctx, target, bundle, a10.SyncOptions{})
```

The zero-value `SyncOptions` is intentionally conservative:

- private keys are marked non-exportable;
- old certificate/key files are retained;
- the final running configuration is written to memory;
- a multi-certificate template is rejected unless its current certificate is
  selected explicitly.

Set `CleanupOld: true` only when the caller wants reference-checked cleanup.
The CLI equivalent is `--cleanup-old`.

## Production safety and concurrency

`GetManagedCertificateState` resolves a logical certificate slot by client-SSL
template name and returns a `TemplateRevision`. No internal numeric ID is
required:

```go
state, err := client.GetManagedCertificateState(
    ctx,
    a10.ForClientSSLTemplate("www-client-tls"),
)
if err != nil {
    log.Fatal(err)
}

result, err := client.SyncCertificate(
    ctx,
    state.Target,
    bundle,
    a10.SyncOptions{ExpectedRevision: state.TemplateRevision},
)
if a10.IsConflict(err) {
    // Another API client or GUI user changed this template. Re-read and make
    // an explicit decision; cleanup and persistence were stopped.
}
```

Every synchronization also performs optimistic checks automatically, even
when `ExpectedRevision` is omitted. The complete client-SSL configuration
response is fingerprinted, including unknown vendor configuration fields but
excluding generated UUID/URL metadata and binding order:

1. when synchronization starts;
2. again after uploads and before binding;
3. after binding and, when ACOS retained it, immediately before removing the
   old binding;
4. after unbinding; and
5. immediately before `write memory`.

Unexpected state produces a typed `*a10.ConflictError`, detectable with
`a10.IsConflict`. Cleanup and persistence stop after a detected conflict. The
session's internal `RWMutex` only prevents logoff from invalidating an in-flight
request; it is not presented as an appliance lock or transaction.

No client library can eliminate the final race between a read and the following
write when the appliance offers no conditional write. For environments in
which GUI users and multiple automation controllers routinely edit the same
template, use one external owner/lock and pass `ExpectedRevision`. Keeping old
files by default limits the impact of an undetectable last-instant race.

A failed or lost bind response triggers an immediate state read. If the desired
state is present, synchronization continues; if the original revision is still
present, the error is safely retryable. Any third state returns a typed
`AmbiguousStateError`, detectable with `errors.Is(err, a10.ErrAmbiguousState)`.
`ReconcileCertificate` reuses the idempotent convergence workflow after
operator review. Rollback is attempted only when the observed template is the
exact state produced by the current invocation; it never overwrites a third,
concurrent state.

## Build and test

```bash
go build ./cmd/a10-certctl
go test ./...
```

The live tests create temporary material and a client-SSL template, exercise
real upload, binding, partition-scoped persistence, read-back and cleanup, and
run concurrent read sessions. They also verify empty L3V partitions by both
name and numeric ID. Temporary persisted material is deleted and that cleanup
is written to memory. A transport-level failure injection additionally proves
on the live appliance that unbound uploads are removed and the cleaned state is
persisted after a failed initial write-memory response.

```bash
export A10_LIVE_TEST=1
export A10_HOST=a10.example.com
export A10_USERNAME=admin
export A10_PASSWORD='...'
export A10_LIVE_INSECURE_SKIP_VERIFY=1 # lab only
export A10_TEST_VIP=10.0.0.20          # optional data-plane validation
export A10_TEST_VIP_INSECURE_SKIP_VERIFY=1 # lab only
export A10_PARTITION=partition-name        # optional name or numeric ID
go test ./pkg/a10 -run '^TestLiveACOS6' -v
```

## CLI environment

```bash
export A10_HOST=a10.example.com
export A10_USERNAME=admin
export A10_PASSWORD='...'
```

For a lab appliance with a self-signed management certificate, add
`--insecure-skip-verify`. For production, prefer `--trusted-certificate`.
Plain HTTP management URLs are rejected by the default client so credentials
cannot be sent without transport encryption. The explicit
`AllowInsecureHTTP`/`--allow-insecure-http` escape hatch is intended only for
isolated labs. Library callers that supply their own `HTTPClient` own its
transport policy (this is primarily useful for tests).

Use environment variables for passwords in automation. Command-line password
arguments can be visible to other local processes.

## CLI examples

Inspect the installed client build without contacting an appliance:

```bash
./a10-certctl build-info
```

Inspect the appliance without exporting private keys:

```bash
./a10-certctl --host "$A10_HOST" --username "$A10_USERNAME" \
  --insecure-skip-verify version

./a10-certctl --host "$A10_HOST" --username "$A10_USERNAME" \
  --insecure-skip-verify preflight

./a10-certctl --host "$A10_HOST" --username "$A10_USERNAME" \
  --insecure-skip-verify list

./a10-certctl --host "$A10_HOST" --username "$A10_USERNAME" \
  --insecure-skip-verify templates

./a10-certctl --host "$A10_HOST" --username "$A10_USERNAME" \
  --insecure-skip-verify vip --address 10.0.0.20

./a10-certctl --host "$A10_HOST" --username "$A10_USERNAME" \
  --insecure-skip-verify status --template CL_SSL_TEMPLATE
```

Rotate the sole/default certificate binding of a client-SSL template:

```bash
./a10-certctl --host "$A10_HOST" --username "$A10_USERNAME" \
  --insecure-skip-verify \
  sync \
  --template CL_SSL_TEMPLATE \
  --cert fullchain.pem \
  --key privkey.pem
```

For compare-before-change automation, pass the `templateRevision` printed by
`status`:

```bash
REVISION=$(./a10-certctl ... status --template CL_SSL_TEMPLATE | jq -r .templateRevision)
./a10-certctl ... sync \
  --template CL_SSL_TEMPLATE \
  --expected-revision "$REVISION" \
  --cert fullchain.pem \
  --key privkey.pem
```

If `certificate-list` has multiple entries, identify the old entry explicitly:

```bash
./a10-certctl --host "$A10_HOST" --username "$A10_USERNAME" \
  --insecure-skip-verify \
  sync \
  --template MULTI_CERT_TEMPLATE \
  --current-cert old-example-cert \
  --name example-com \
  --cert fullchain.pem \
  --key privkey.pem
```

Encrypted PKCS#8 keys are supported. Put the passphrase in the environment
variable named by `--key-passphrase-env`:

```bash
export A10_KEY_PASSPHRASE='...'
./a10-certctl --host "$A10_HOST" --username "$A10_USERNAME" \
  --insecure-skip-verify \
  sync --template CL_SSL_TEMPLATE --cert fullchain.pem --key encrypted-key.pem
```

The high-level `CreateManagedCertificate` operation may be used to safely
pre-stage a future certificate without a client-SSL template. The low-level
`UploadCertificate`/`import` escape hatch remains available. `SyncCertificate`/`sync` refuses
to bind a leaf or chain certificate outside its authenticated X.509 validity
interval.

Import a validated pair without binding it:

```bash
./a10-certctl --host "$A10_HOST" --username "$A10_USERNAME" \
  --insecure-skip-verify \
  import --name manual-example --cert cert.pem --key privkey.pem --chain chain.pem
```

Low-level binding and cleanup commands are also available:

```bash
./a10-certctl ... bind \
  --template CL_SSL_TEMPLATE --cert manual-example --key manual-example \
  --chain manual-example-chain

./a10-certctl ... unbind --template CL_SSL_TEMPLATE --cert manual-example

./a10-certctl ... delete \
  --cert manual-example --key manual-example --chain manual-example-chain
```

## Certificate and chain handling

`--cert` may contain only the leaf certificate or a full chain. With a full
chain, the first PEM block is treated as the leaf and the remaining blocks are
validated in issuer order. Additional `--chain` files may be supplied more than
once. Server chain files are uploaded through `/file/ssl-cert` and connected
with the client-SSL binding's `chain-cert` field. ACOS does not resolve this
field against the separate `/file/ca-cert` trust store.

Bundle names include the first 32 hexadecimal characters of a SHA-256 checksum
covering the canonical leaf certificate, canonical private key, and chain. A
repeat run with the same bundle and binding is a no-op. A changed key receives
a new name even when the certificate is unchanged.

## Output and secret safety

The typed API exposes checksums and certificate metadata but does not JSON
serialize private-key PEM or passphrases. List and find commands use
`/slb/ssl-cert/oper`; they do not export key files. The `find-domain` command
uses the common name exposed by that operational endpoint. ACOS 6.x does not
include SAN values in this response, so SAN-only discovery is not claimed.

## Implemented aXAPI endpoints

- `POST /auth`
- `POST /logoff`
- `POST /active-partition`
- `GET /partition`
- `GET /version/oper`
- `GET /file/ssl-cert/oper`
- `GET /file/ssl-key/oper`
- `GET /file/ca-cert/oper`
- `POST /file/ssl-cert` (multipart)
- `POST /file/ssl-key` (multipart)
- `POST /file/ca-cert` (multipart)
- `GET /slb/ssl-cert/oper`
- `GET /slb/template/client-ssl`
- `GET /slb/template/client-ssl/{name}`
- `GET /slb/template/server-ssl`
- `GET /slb/virtual-server`
- `POST /slb/template/client-ssl/{name}/certificate`
- `DELETE /slb/template/client-ssl/{name}/certificate/{cert}`
- `POST /pki/delete`
- `POST /write/memory`

`Session.Raw().DoJSON` remains available as an advanced escape hatch for other
aXAPI resources.

## Compatibility notes

- Supported contract: ACOS 6.x.y with aXAPI v3; no 6.x minor, patch, or build
  is pinned.
- Tested appliance: A10 vThunder, ACOS 6.0.9 build 116, aXAPI 3.0.
- ACOS running configuration changes are immediate; `write memory` controls
  persistence across reboot, not activation.
- Empty certificate-related and virtual-server inventories may return HTTP
  204; typed list calls normalize that response to an empty result.
- `Config.Partition` and CLI `--partition` accept an exact name or decimal ID;
  `Config.PartitionID` provides a strongly typed library selector.
- The tested ACOS 6.0.9 endpoints expose no appliance transaction or
  conditional-write revision for the certificate/template endpoints.
  `TemplateRevision` is an optimistic
  client-side precondition based on complete logical binding state.
- The library never overwrites checksum-managed files. If a managed name exists
  with conflicting operational certificate metadata, synchronization stops.
- Old material is retained by default. Explicit cleanup scans complete
  client-SSL and server-SSL payloads, including typed SNI/forward-proxy fields
  and unknown future ACOS 6.x fields. Equal unknown values conservatively retain
  files rather than risking deletion.

## GitHub automation

The repository includes formatting, vet, race-test, build, `govulncheck`,
CodeQL, dependency-review, and GoReleaser workflows. CodeQL and dependency
review are skipped for private repositories unless GitHub Code Security is
enabled and `ENABLE_GITHUB_CODE_SECURITY=true` is configured.
