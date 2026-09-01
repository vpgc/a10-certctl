package a10

import "fmt"

// ClientSSLTemplateName is the logical ACOS name of a client-SSL template.
// It is deliberately distinct from certificate and key file names so callers
// cannot accidentally swap resource identifiers between API operations.
type ClientSSLTemplateName string

// ServerSSLTemplateName is the logical ACOS name of a server-SSL template.
// Server-SSL certificates authenticate A10 to backend servers and are distinct
// from inbound client-SSL certificate bindings.
type ServerSSLTemplateName string

// VirtualServerName is the logical ACOS name of an SLB virtual server.
type VirtualServerName string

// CertificateFileName identifies a certificate file in the ACOS SSL
// certificate store. Issuing chains use the same store and therefore the same
// identifier type.
type CertificateFileName string

// KeyFileName identifies a private-key file in the ACOS SSL key store.
type KeyFileName string

// CAFileName identifies a certificate file in the separate ACOS CA trust
// store.
type CAFileName string

// PartitionName is the operator-defined name of an ACOS L3V partition.
type PartitionName string

// PartitionID is the numeric identifier ACOS assigns to an L3V partition.
// Zero means that no partition ID was selected.
type PartitionID uint32

// Partition identifies an ACOS L3V partition by both representations returned
// by aXAPI. Name is used with the active-partition and write-memory endpoints.
type Partition struct {
	Name PartitionName `json:"partition-name"`
	ID   PartitionID   `json:"id"`
}

func (name ClientSSLTemplateName) String() string { return string(name) }
func (name ServerSSLTemplateName) String() string { return string(name) }
func (name VirtualServerName) String() string     { return string(name) }
func (name CertificateFileName) String() string   { return string(name) }
func (name KeyFileName) String() string           { return string(name) }
func (name CAFileName) String() string            { return string(name) }
func (name PartitionName) String() string         { return string(name) }
func (id PartitionID) String() string             { return fmt.Sprintf("%d", id) }

// ParsePartitionName validates and returns an ACOS L3V partition name.
func ParsePartitionName(value string) (PartitionName, error) {
	if err := validateObjectName("partition", value); err != nil {
		return "", err
	}
	return PartitionName(value), nil
}

// ParsePartitionID validates and returns an ACOS L3V partition ID.
func ParsePartitionID(value uint64) (PartitionID, error) {
	if value == 0 || value > uint64(^PartitionID(0)) {
		return 0, fmt.Errorf("A10 partition ID %d is outside the supported range", value)
	}
	return PartitionID(value), nil
}

// ParseClientSSLTemplateName validates and returns a client-SSL template name.
func ParseClientSSLTemplateName(value string) (ClientSSLTemplateName, error) {
	if err := validateTemplateName("client-SSL template", value); err != nil {
		return "", err
	}
	return ClientSSLTemplateName(value), nil
}

// ParseServerSSLTemplateName validates and returns a server-SSL template name.
func ParseServerSSLTemplateName(value string) (ServerSSLTemplateName, error) {
	if err := validateTemplateName("server-SSL template", value); err != nil {
		return "", err
	}
	return ServerSSLTemplateName(value), nil
}

// ParseVirtualServerName validates and returns an SLB virtual-server name.
func ParseVirtualServerName(value string) (VirtualServerName, error) {
	if err := validateTemplateName("virtual server", value); err != nil {
		return "", err
	}
	return VirtualServerName(value), nil
}

// ParseCertificateFileName validates and returns an SSL certificate-store
// file name.
func ParseCertificateFileName(value string) (CertificateFileName, error) {
	if err := validateFileName(value); err != nil {
		return "", fmt.Errorf("certificate file name: %w", err)
	}
	return CertificateFileName(value), nil
}

// ParseKeyFileName validates and returns an SSL private-key-store file name.
func ParseKeyFileName(value string) (KeyFileName, error) {
	if err := validateFileName(value); err != nil {
		return "", fmt.Errorf("key file name: %w", err)
	}
	return KeyFileName(value), nil
}

// ParseCAFileName validates and returns a CA trust-store file name.
func ParseCAFileName(value string) (CAFileName, error) {
	if err := validateFileName(value); err != nil {
		return "", fmt.Errorf("CA file name: %w", err)
	}
	return CAFileName(value), nil
}
