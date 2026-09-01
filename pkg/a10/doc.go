// Package a10 provides a typed certificate-lifecycle client for A10
// Thunder/ACOS appliances through aXAPI v3.
//
// Its high-level API validates X.509 certificates, private keys, issuer chains,
// and certificate/key matches locally before contacting an appliance. A
// CertificateTarget addresses a logical certificate slot by client-SSL
// template name, without exposing appliance-internal identifiers. The template
// name is the operator-defined ACOS client-ssl.name returned by aXAPI. For a
// multi-entry certificate-list, ForCertificateBinding additionally accepts the
// current certificate file name returned in certificate-list[].cert.
//
// SyncCertificate uploads checksum-versioned, immutable files; posts the pair
// in one binding request; reads back ACOS's atomic replacement or added list
// binding; and verifies optimistic template revisions around every subsequent
// destructive step. The zero-value SyncOptions retains old files and writes the
// running configuration to memory.
//
// The supported contract is ACOS 6.x.y; patch and build versions are not
// pinned. The tested ACOS 6.0.9 endpoints do not expose a native transaction or
// conditional-write primitive for these resources. High-level methods perform
// verified compensating rollback before destructive cleanup; TemplateRevision
// and ConflictError provide fail-closed conflict detection. Deployments with
// multiple configuration owners must still coordinate ownership outside the
// appliance.
//
// The package's primary flow is New, ParseCertificateBundle,
// ForClientSSLTemplate, GetManagedCertificateState, and SyncCertificate. All input
// structs and result fields are documented in docs/API.md in the module root.
// ACOSVersion reports the appliance version; BuildVersion reports this module's
// own build, so callers never have to infer which version a generic method name
// represents.
package a10
