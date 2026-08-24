# Go library reference

This reference explains the parameters, properties, return values, and
identifier origins of `github.com/vpgc/a10-certctl/pkg/a10`.

## Client construction

```go
client, err := a10.New(a10.Config{
    Address:  "a10.example.com",
    Username: os.Getenv("A10_USERNAME"),
    Password: os.Getenv("A10_PASSWORD"),
})
```

| Config property | Required | Meaning |
| --- | --- | --- |
| `Address` | yes | ACOS management hostname or URL; `/axapi/v3` is appended |
| `Username` | yes | aXAPI account |
| `Password` | yes | aXAPI password; excluded from JSON |
| `Partition` | no | ACOS partition selected after authentication |
| `Timeout` | no | HTTP timeout; default 30 seconds |
| `TrustedCertificate` | no | management CA as PEM text or file path |
| `InsecureSkipVerify` | no | lab-only TLS verification bypass |
| `AllowInsecureHTTP` | no | explicit opt-in for plain HTTP |
| `HTTPClient` | no | caller-provided HTTP client |
| `UserAgent` | no | overrides the versioned default User-Agent |

`New` returns a concurrency-safe session factory. Each high-level call opens
and closes its own authenticated aXAPI session.

## Certificate input

`ParseCertificateBundle` accepts:

| Property | Meaning |
| --- | --- |
| `CertificatePEM` | leaf or full-chain PEM; the first block is the leaf |
| `PrivateKeyPEM` | PKCS#1, SEC1, PKCS#8, or encrypted PKCS#8 key |
| `PrivateKeyPassphrase` | transient UTF-8 passphrase; excluded from JSON |
| `CertificateChainPEM` | additional intermediates in leaf-to-root order |

It returns `CertificateBundle`, containing typed `Certificate`, `Key`, `Chain`,
and a canonical complete-bundle `Checksum`. PEM structure, X.509 dates, CA
constraints, chain signatures, and the certificate/key match are validated
before aXAPI is contacted.

## Targets and identifier origin

```go
target := a10.ForClientSSLTemplate("www-client-tls")
```

| Type/property | Source and meaning |
| --- | --- |
| `ClientSSLTemplateName` | operator-defined `client-ssl.name`, returned by `/slb/template/client-ssl` |
| `CertificateFileName` | ACOS certificate file store name, returned by `/file/ssl-cert` and template `certificate-list[].cert` |
| `KeyFileName` | ACOS key file store name, returned by `/file/ssl-key` and `certificate-list[].key` |
| `CAFileName` | ACOS CA store name |
| `VirtualServerName` | operator-defined SLB virtual-server name |
| `CertificateTarget.ClientSSLTemplate` | template containing the logical certificate slot |
| `CertificateTarget.CurrentCertificate` | optional exact current entry for a multi-certificate template |
| `TemplateRevision` | SHA-256 digest of normalized complete template JSON read from ACOS; not an ACOS database ID |

Managed certificate/key names are generated from 128 bits of the canonical
bundle checksum. Callers normally supply only the client-SSL template name.

## High-level calls

### ACOSVersion

```go
ACOSVersion(ctx) (VersionInfo, error)
```

Returns the ACOS and aXAPI versions from `/version/oper`. The explicit name
keeps the appliance version distinct from `BuildVersion`, which identifies the
library/CLI build.

### VerifyCompatibility

```go
VerifyCompatibility(ctx) (VersionInfo, error)
```

Authenticates, reads `/version/oper`, accepts any syntactically valid ACOS
6.x.y release, and closes the temporary session. `TestedACOSVersion` records
the exact qualified baseline.

### GetManagedCertificateState

```go
GetManagedCertificateState(ctx, target) (CertificateState, error)
```

Returns a secret-free state:

| Property | Meaning |
| --- | --- |
| `Target` | selected logical slot |
| `TemplateRevision` | optimistic compare-before-change token |
| `Binding` | certificate, key, optional chain, shared flag, and ACOS metadata |
| `Certificate` | operational X.509 metadata; no PEM private key |
| `Key` | operational key metadata; no private-key bytes |

### SyncCertificate

```go
SyncCertificate(ctx, target, bundle, options) (SyncResult, error)
```

`SyncOptions`:

| Property | Default | Meaning |
| --- | --- | --- |
| `NamePrefix` | target name | prefix for checksum-managed files |
| `ExpectedRevision` | empty | optional compare-before-change precondition |
| `ExportableKey` | false | uploaded keys remain non-exportable |
| `CleanupOld` | false | delete only old files proven unreferenced |
| `NoWriteMemory` | false | skip persistence of running configuration |
| `Shared` | false | set the ACOS binding shared flag |

`SyncResult`:

| Property | Meaning |
| --- | --- |
| `Stage` | last verified lifecycle stage |
| `Changed` | whether the desired pair differed |
| `Uploaded`, `Bound`, `UnboundOld`, `WroteMemory` | performed actions |
| `DeletedOld` | exact removed file names |
| `PreviousBinding` | binding observed before the change |
| `Certificate` | final secret-free managed names and checksums |
| `InitialRevision`, `FinalRevision` | template state before and after synchronization |

ACOS changes running configuration immediately. The method uploads immutable
material, binds the complete pair, reads it back, checks the template revision
around destructive steps, optionally removes unreferenced files, and writes
memory by default.

### CreateManagedCertificate

```go
CreateManagedCertificate(ctx, bundle, CreateOptions{
    NamePrefix: "future-vip",
}) (CreateResult, error)
```

Pre-stages checksum-versioned certificate, private-key, and optional chain
files without requiring or touching a client-SSL template. `NamePrefix` is
required because ACOS certificate resources are named files. Calls through one
`Client`, or one shared `Session`, are mutex-serialized. `CreateResult` reports
the generated material names, uploads, persistence, and final lifecycle stage;
it intentionally contains no binding target.

A10 provides no editable per-certificate comment in either its certificate GUI
workflow or its certificate-file and client-SSL binding APIs. The common
library therefore rejects an Airlock-style activation comment for A10 rather
than silently discarding it.

## Low-level API

`StartSession` returns `Session`, which exposes typed inventory, upload,
binding, unbinding, deletion, VIP discovery, and `WriteMemory` calls. Operations
outside the typed surface are available only through `Session.Raw().DoJSON`.

## Errors

Use `errors.Is` with:

- `ErrAuthentication`
- `ErrNotFound`
- `ErrConflict`
- `ErrUnsupportedVersion`
- `ErrAmbiguousState`

Concrete errors such as `ConflictError`, `CompatibilityError`, `NotFoundError`,
`AmbiguousStateError`, and `APIError` retain diagnostic fields for
`errors.As`.
