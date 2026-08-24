package a10

import "context"

type clientPublicContract interface {
	VerifyCompatibility(context.Context) (VersionInfo, error)
	GetManagedCertificateState(context.Context, CertificateTarget) (CertificateState, error)
	CreateManagedCertificate(context.Context, CertificateBundle, CreateOptions) (CreateResult, error)
	SyncCertificate(context.Context, CertificateTarget, CertificateBundle, SyncOptions) (SyncResult, error)
	ReconcileCertificate(context.Context, CertificateTarget, CertificateBundle, SyncOptions) (SyncResult, error)
}

type sessionPublicContract interface {
	Raw() RawSession
	ACOSVersion(context.Context) (VersionInfo, error)
	VerifyCompatibility(context.Context) (VersionInfo, error)
	CreateManagedCertificate(context.Context, CertificateBundle, CreateOptions) (CreateResult, error)
	ListClientSSLTemplates(context.Context) ([]ClientSSLTemplate, error)
	ListServerSSLTemplates(context.Context) ([]ServerSSLTemplate, error)
	ListVirtualServers(context.Context) ([]VirtualServer, error)
	FindClientSSLTemplatesByVIP(context.Context, string) ([]VirtualServerTLSBinding, error)
	SyncCertificate(context.Context, CertificateTarget, CertificateBundle, SyncOptions) (SyncResult, error)
	ReconcileCertificate(context.Context, CertificateTarget, CertificateBundle, SyncOptions) (SyncResult, error)
}

var (
	_ clientPublicContract  = (*Client)(nil)
	_ sessionPublicContract = (*Session)(nil)
)
