package a10

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

// VersionInfo is the useful subset of /version/oper.
type VersionInfo struct {
	HardwarePlatform string `json:"hw-platform"`
	SoftwareVersion  string `json:"sw-version"`
	AXAPIVersion     string `json:"axapi-version"`
	SerialNumber     string `json:"serial-number"`
	Hostname         string `json:"hostname"`
	CurrentTime      string `json:"current-time"`
	Uptime           string `json:"up-time"`
}

// CertificateInfo is ACOS operational certificate metadata. It deliberately
// contains no private-key material.
type CertificateInfo struct {
	Name           CertificateFileName `json:"name"`
	Type           string              `json:"type"`
	Serial         string              `json:"serial"`
	NotBefore      string              `json:"notbefore"`
	NotAfter       string              `json:"notafter"`
	CommonName     string              `json:"common-name"`
	Organization   string              `json:"organization"`
	Subject        string              `json:"subject"`
	Issuer         string              `json:"issuer"`
	NotAfterNumber int64               `json:"notafter-number"`
	Status         string              `json:"status"`
	KeySize        int                 `json:"keysize"`
}

// CertificateBinding connects certificate, key, and optional CA-chain files
// to an ACOS client-SSL template.
type CertificateBinding struct {
	Certificate CertificateFileName `json:"cert"`
	Key         KeyFileName         `json:"key"`
	Chain       CertificateFileName `json:"chain-cert,omitempty"`
	Shared      bool                `json:"shared,omitempty"`
	UUID        string              `json:"uuid,omitempty"`
	A10URL      string              `json:"a10-url,omitempty"`
}

// UnmarshalJSON accepts the integer boolean representation used by aXAPI while
// keeping the public API strongly typed and idiomatic.
func (binding *CertificateBinding) UnmarshalJSON(data []byte) error {
	var wire struct {
		Certificate CertificateFileName `json:"cert"`
		Key         KeyFileName         `json:"key"`
		Chain       CertificateFileName `json:"chain-cert,omitempty"`
		Shared      any                 `json:"shared,omitempty"`
		UUID        string              `json:"uuid,omitempty"`
		A10URL      string              `json:"a10-url,omitempty"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	shared, err := aXAPIBoolean(wire.Shared)
	if err != nil {
		return fmt.Errorf("decode certificate binding shared flag: %w", err)
	}
	*binding = CertificateBinding{
		Certificate: wire.Certificate,
		Key:         wire.Key,
		Chain:       wire.Chain,
		Shared:      shared,
		UUID:        wire.UUID,
		A10URL:      wire.A10URL,
	}
	return nil
}

func aXAPIBoolean(value any) (bool, error) {
	switch typed := value.(type) {
	case nil:
		return false, nil
	case bool:
		return typed, nil
	case float64:
		if typed == 0 {
			return false, nil
		}
		if typed == 1 {
			return true, nil
		}
	}
	return false, fmt.Errorf("expected boolean, 0, or 1; got %v", value)
}

// ServerNameBinding is ACOS's secret-free SNI certificate mapping. Both exact
// and regular-expression variants are represented because they use the same
// SSL certificate/key stores as certificate-list.
type ServerNameBinding struct {
	ServerName             string                `json:"server-name,omitempty"`
	ServerNameRegex        string                `json:"server-name-regex,omitempty"`
	Certificate            CertificateFileName   `json:"server-cert,omitempty"`
	Key                    KeyFileName           `json:"server-key,omitempty"`
	Chain                  CertificateFileName   `json:"server-chain,omitempty"`
	RegexCertificate       CertificateFileName   `json:"server-cert-regex,omitempty"`
	RegexKey               KeyFileName           `json:"server-key-regex,omitempty"`
	RegexChain             CertificateFileName   `json:"server-chain-regex,omitempty"`
	ClientSSLTemplate      ClientSSLTemplateName `json:"sni-template-client-ssl,omitempty"`
	RegexClientSSLTemplate ClientSSLTemplateName `json:"sni-regex-template-client-ssl,omitempty"`
}

// ForwardProxyMaterialReferences is the secret-free certificate material used
// by ACOS SSL forward proxy. It includes both current and legacy 6.x field
// variants documented by aXAPI.
type ForwardProxyMaterialReferences struct {
	CACertificate        CertificateFileName `json:"forward-proxy-ca-cert,omitempty"`
	CAKey                KeyFileName         `json:"forward-proxy-ca-key,omitempty"`
	Certificate          CertificateFileName `json:"fp-ca-certificate,omitempty"`
	Key                  KeyFileName         `json:"fp-ca-key,omitempty"`
	Chain                CertificateFileName `json:"fp-ca-chain-cert,omitempty"`
	AlternateCertificate CertificateFileName `json:"fp-alt-cert,omitempty"`
	AlternateKey         KeyFileName         `json:"fp-alt-key,omitempty"`
	AlternateChain       CertificateFileName `json:"fp-alt-chain-cert,omitempty"`
}

// ClientSSLTemplate is the secret-free certificate-relevant subset of a
// client-SSL template. The complete response is retained privately so cleanup
// remains fail-safe when a later ACOS 6.x release adds reference fields.
type ClientSSLTemplate struct {
	Name             ClientSSLTemplateName          `json:"name"`
	Certificates     []CertificateBinding           `json:"certificate-list,omitempty"`
	ServerNames      []ServerNameBinding            `json:"server-name-list,omitempty"`
	ChainCertificate CertificateFileName            `json:"chain-cert,omitempty"`
	ForwardProxy     ForwardProxyMaterialReferences `json:"-"`
	UUID             string                         `json:"uuid,omitempty"`
	A10URL           string                         `json:"a10-url,omitempty"`

	revisionPayload []byte
}

// MarshalJSON emits only the secret-free typed model while preserving ACOS's
// flat field layout for forward-proxy references.
func (template ClientSSLTemplate) MarshalJSON() ([]byte, error) {
	var wire struct {
		Name             ClientSSLTemplateName `json:"name"`
		Certificates     []CertificateBinding  `json:"certificate-list,omitempty"`
		ServerNames      []ServerNameBinding   `json:"server-name-list,omitempty"`
		ChainCertificate CertificateFileName   `json:"chain-cert,omitempty"`
		ForwardProxyMaterialReferences
		UUID   string `json:"uuid,omitempty"`
		A10URL string `json:"a10-url,omitempty"`
	}
	wire.Name = template.Name
	wire.Certificates = template.Certificates
	wire.ServerNames = template.ServerNames
	wire.ChainCertificate = template.ChainCertificate
	wire.ForwardProxyMaterialReferences = template.ForwardProxy
	wire.UUID = template.UUID
	wire.A10URL = template.A10URL
	return json.Marshal(wire)
}

// ServerCertificateBinding is the client certificate/key pair an ACOS
// server-SSL template presents to a backend server. It shares the same ACOS
// file stores as client-SSL bindings and is included in cleanup reference
// checks even though server-SSL rotation is outside SyncCertificate's scope.
type ServerCertificateBinding struct {
	Certificate CertificateFileName `json:"cert"`
	Key         KeyFileName         `json:"key"`
	Shared      bool                `json:"shared,omitempty"`
	UUID        string              `json:"uuid,omitempty"`
}

// UnmarshalJSON accepts ACOS boolean encodings without exposing passphrases or
// the appliance's reserved encrypted-password field.
func (binding *ServerCertificateBinding) UnmarshalJSON(data []byte) error {
	var wire struct {
		Certificate CertificateFileName `json:"cert"`
		Key         KeyFileName         `json:"key"`
		Shared      any                 `json:"shared,omitempty"`
		UUID        string              `json:"uuid,omitempty"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	shared, err := aXAPIBoolean(wire.Shared)
	if err != nil {
		return fmt.Errorf("decode server-SSL certificate shared flag: %w", err)
	}
	*binding = ServerCertificateBinding{
		Certificate: wire.Certificate,
		Key:         wire.Key,
		Shared:      shared,
		UUID:        wire.UUID,
	}
	return nil
}

// ServerSSLTemplate is the secret-free, certificate-relevant subset of an
// ACOS server-SSL template.
type ServerSSLTemplate struct {
	Name        ServerSSLTemplateName     `json:"name"`
	Certificate *ServerCertificateBinding `json:"certificate,omitempty"`
	UUID        string                    `json:"uuid,omitempty"`
	A10URL      string                    `json:"a10-url,omitempty"`

	referencePayload []byte
}

// UnmarshalJSON retains the complete vendor response privately for optimistic
// concurrency checks while exposing only the supported, strongly typed fields.
// Unknown aXAPI fields cannot be written through this type.
func (template *ClientSSLTemplate) UnmarshalJSON(data []byte) error {
	var wire struct {
		Name             ClientSSLTemplateName `json:"name"`
		Certificates     []CertificateBinding  `json:"certificate-list,omitempty"`
		ServerNames      []ServerNameBinding   `json:"server-name-list,omitempty"`
		ChainCertificate CertificateFileName   `json:"chain-cert,omitempty"`
		ForwardProxyMaterialReferences
		UUID   string `json:"uuid,omitempty"`
		A10URL string `json:"a10-url,omitempty"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*template = ClientSSLTemplate{
		Name:             wire.Name,
		Certificates:     wire.Certificates,
		ServerNames:      wire.ServerNames,
		ChainCertificate: wire.ChainCertificate,
		ForwardProxy:     wire.ForwardProxyMaterialReferences,
		UUID:             wire.UUID,
		A10URL:           wire.A10URL,
		revisionPayload:  append([]byte(nil), data...),
	}
	return nil
}

// UnmarshalJSON retains the complete server-SSL response privately. This is
// used only to prevent unsafe cleanup; reserved encrypted-password fields are
// never exposed or serialized by this package.
func (template *ServerSSLTemplate) UnmarshalJSON(data []byte) error {
	type publicServerSSLTemplate ServerSSLTemplate
	var wire publicServerSSLTemplate
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*template = ServerSSLTemplate(wire)
	template.referencePayload = append([]byte(nil), data...)
	return nil
}

// MaterialNames identifies certificate-related ACOS files to delete.
type MaterialNames struct {
	Certificate CertificateFileName
	Key         KeyFileName
	CA          CAFileName
}

// KeyInfo is the secret-free state available for a non-exportable ACOS key.
type KeyInfo struct {
	Name KeyFileName `json:"name"`
}

// NotFoundError reports a missing typed ACOS object.
type NotFoundError struct {
	Kind string
	Name string
}

func (err *NotFoundError) Error() string {
	return fmt.Sprintf("A10 %s %q was not found", err.Kind, err.Name)
}

func (err *NotFoundError) Is(target error) bool { return target == ErrNotFound }

// IsNotFound reports whether err is a typed A10 not-found error or an aXAPI
// HTTP 404 response.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// UploadOptions controls an ACOS file import.
type UploadOptions struct {
	Replace       bool
	ExportableKey bool
}

type sslCertificateUploadDocument struct {
	Certificate struct {
		Action          string              `json:"action"`
		CertificateType string              `json:"certificate-type"`
		File            CertificateFileName `json:"file"`
		FileHandle      CertificateFileName `json:"file-handle"`
	} `json:"ssl-cert"`
}

type sslKeyUploadDocument struct {
	Key struct {
		Action     string      `json:"action"`
		File       KeyFileName `json:"file"`
		FileHandle KeyFileName `json:"file-handle"`
		Secured    int         `json:"secured"`
	} `json:"ssl-key"`
}

type caCertificateUploadDocument struct {
	Certificate struct {
		Action          string     `json:"action"`
		CertificateType string     `json:"certificate-type"`
		File            CAFileName `json:"file"`
		FileHandle      CAFileName `json:"file-handle"`
	} `json:"ca-cert"`
}

type certificateBindingDocument struct {
	Certificate struct {
		Certificate CertificateFileName `json:"cert"`
		Key         KeyFileName         `json:"key"`
		Chain       CertificateFileName `json:"chain-cert,omitempty"`
		Shared      int                 `json:"shared,omitempty"`
		Passphrase  string              `json:"passphrase,omitempty"`
	} `json:"certificate"`
}

type deleteMaterialDocument struct {
	Delete struct {
		Certificate CertificateFileName `json:"cert-name,omitempty"`
		Key         KeyFileName         `json:"private-key,omitempty"`
		CA          CAFileName          `json:"ca,omitempty"`
	} `json:"delete"`
}

type writeMemoryDocument struct {
	Memory struct {
		Destination        string        `json:"destination"`
		Partition          string        `json:"partition"`
		SpecifiedPartition PartitionName `json:"specified-partition,omitempty"`
	} `json:"memory"`
}

// ACOSVersion returns appliance and aXAPI version information without being
// confused with BuildVersion, which identifies this Go library build.
func (s *Session) ACOSVersion(ctx context.Context) (VersionInfo, error) {
	var document struct {
		Version struct {
			Operational VersionInfo `json:"oper"`
		} `json:"version"`
	}
	err := s.doJSON(ctx, http.MethodGet, "/version/oper", nil, &document, http.StatusOK)
	return document.Version.Operational, err
}

// ListCertificates returns operational metadata for every installed SSL
// certificate.
func (s *Session) ListCertificates(ctx context.Context) ([]CertificateInfo, error) {
	var document struct {
		Certificate struct {
			Operational struct {
				Certificates []CertificateInfo `json:"ssl-certs"`
			} `json:"oper"`
		} `json:"ssl-cert"`
	}
	err := s.doJSON(ctx, http.MethodGet, "/slb/ssl-cert/oper", nil, &document, http.StatusOK, http.StatusNoContent)
	if err == nil && document.Certificate.Operational.Certificates == nil {
		return []CertificateInfo{}, nil
	}
	return document.Certificate.Operational.Certificates, err
}

// GetCertificate resolves exact operational metadata by logical ACOS file
// name. It never exports certificate or private-key bytes.
func (s *Session) GetCertificate(ctx context.Context, name CertificateFileName) (CertificateInfo, error) {
	if err := validateFileName(name.String()); err != nil {
		return CertificateInfo{}, err
	}
	certificates, err := s.ListCertificates(ctx)
	if err != nil {
		return CertificateInfo{}, err
	}
	for _, certificate := range certificates {
		if certificate.Name == name {
			return certificate, nil
		}
	}
	return CertificateInfo{}, &NotFoundError{Kind: "certificate", Name: name.String()}
}

// ListCertificateFiles returns installed server-certificate file names.
func (s *Session) ListCertificateFiles(ctx context.Context) ([]CertificateFileName, error) {
	values, err := s.listFiles(ctx, "/file/ssl-cert/oper", "ssl-cert")
	if err != nil {
		return nil, err
	}
	result := make([]CertificateFileName, len(values))
	for index, value := range values {
		result[index] = CertificateFileName(value)
	}
	return result, nil
}

// ListKeyFiles returns installed private-key file names. No key bytes are
// exported.
func (s *Session) ListKeyFiles(ctx context.Context) ([]KeyFileName, error) {
	values, err := s.listFiles(ctx, "/file/ssl-key/oper", "ssl-key")
	if err != nil {
		return nil, err
	}
	result := make([]KeyFileName, len(values))
	for index, value := range values {
		result[index] = KeyFileName(value)
	}
	return result, nil
}

// GetKey verifies that an exact private-key file exists without exporting key
// bytes from ACOS.
func (s *Session) GetKey(ctx context.Context, name KeyFileName) (KeyInfo, error) {
	if err := validateFileName(name.String()); err != nil {
		return KeyInfo{}, err
	}
	keys, err := s.ListKeyFiles(ctx)
	if err != nil {
		return KeyInfo{}, err
	}
	if !contains(keys, name) {
		return KeyInfo{}, &NotFoundError{Kind: "private key", Name: name.String()}
	}
	return KeyInfo{Name: name}, nil
}

// ListCAFiles returns installed CA certificate file names.
func (s *Session) ListCAFiles(ctx context.Context) ([]CAFileName, error) {
	values, err := s.listFiles(ctx, "/file/ca-cert/oper", "ca-cert")
	if err != nil {
		return nil, err
	}
	result := make([]CAFileName, len(values))
	for index, value := range values {
		result[index] = CAFileName(value)
	}
	return result, nil
}

func (s *Session) listFiles(ctx context.Context, endpoint, root string) ([]string, error) {
	type fileListResource struct {
		Operational struct {
			Files []struct {
				File string `json:"file"`
			} `json:"file-list"`
		} `json:"oper"`
	}
	var document struct {
		Certificates *fileListResource `json:"ssl-cert"`
		Keys         *fileListResource `json:"ssl-key"`
		CAs          *fileListResource `json:"ca-cert"`
	}
	if err := s.doJSON(ctx, http.MethodGet, endpoint, nil, &document, http.StatusOK, http.StatusNoContent); err != nil {
		return nil, err
	}
	var resource *fileListResource
	switch root {
	case "ssl-cert":
		resource = document.Certificates
	case "ssl-key":
		resource = document.Keys
	case "ca-cert":
		resource = document.CAs
	default:
		return nil, fmt.Errorf("aXAPI response did not contain %q", root)
	}
	if resource == nil {
		return []string{}, nil
	}
	result := make([]string, 0, len(resource.Operational.Files))
	for _, item := range resource.Operational.Files {
		if item.File != "" {
			result = append(result, item.File)
		}
	}
	return result, nil
}

// ListClientSSLTemplates returns all client-SSL templates and their bindings.
func (s *Session) ListClientSSLTemplates(ctx context.Context) ([]ClientSSLTemplate, error) {
	var document struct {
		Templates []ClientSSLTemplate `json:"client-ssl-list"`
	}
	err := s.doJSON(ctx, http.MethodGet, "/slb/template/client-ssl", nil, &document, http.StatusOK, http.StatusNoContent)
	if err == nil && document.Templates == nil {
		return []ClientSSLTemplate{}, nil
	}
	return document.Templates, err
}

// GetClientSSLTemplate resolves an exact client-SSL template name.
func (s *Session) GetClientSSLTemplate(ctx context.Context, name ClientSSLTemplateName) (ClientSSLTemplate, error) {
	if err := validateTemplateName("client-SSL template", name.String()); err != nil {
		return ClientSSLTemplate{}, err
	}
	var document struct {
		Template ClientSSLTemplate `json:"client-ssl"`
	}
	endpoint := "/slb/template/client-ssl/" + name.String()
	if err := s.doJSON(ctx, http.MethodGet, endpoint, nil, &document, http.StatusOK); err != nil {
		return ClientSSLTemplate{}, err
	}
	if document.Template.Name != name {
		return ClientSSLTemplate{}, fmt.Errorf("A10 returned client-SSL template %q for requested name %q", document.Template.Name, name)
	}
	return document.Template, nil
}

// ListServerSSLTemplates returns secret-free backend-mTLS certificate
// references. SyncCertificate does not mutate these templates; the inventory
// is used to prevent deletion of shared certificate/key files they reference.
func (s *Session) ListServerSSLTemplates(ctx context.Context) ([]ServerSSLTemplate, error) {
	var document struct {
		Templates []ServerSSLTemplate `json:"server-ssl-list"`
	}
	err := s.doJSON(ctx, http.MethodGet, "/slb/template/server-ssl", nil, &document, http.StatusOK, http.StatusNoContent)
	if err == nil && document.Templates == nil {
		return []ServerSSLTemplate{}, nil
	}
	return document.Templates, err
}

// UploadCertificate imports or replaces a PEM server certificate file.
func (s *Session) UploadCertificate(ctx context.Context, name CertificateFileName, certificatePEM []byte, options UploadOptions) error {
	if _, err := splitCertificates(certificatePEM); err != nil {
		return err
	}
	return s.uploadCertificateFile(ctx, name, certificatePEM, options)
}

// UploadChain imports or replaces a PEM issuing chain in the ACOS SSL
// certificate store. client-SSL chain-cert references resolve against this
// store, not the separate CA trust store.
func (s *Session) UploadChain(ctx context.Context, name CertificateFileName, certificatePEM []byte, options UploadOptions) error {
	certificates, err := splitCertificates(certificatePEM)
	if err != nil {
		return err
	}
	for i, certificate := range certificates {
		if !certificate.parsed.IsCA {
			return fmt.Errorf("chain certificate %d is not a CA certificate", i)
		}
	}
	return s.uploadCertificateFile(ctx, name, certificatePEM, options)
}

func (s *Session) uploadCertificateFile(ctx context.Context, name CertificateFileName, certificatePEM []byte, options UploadOptions) error {
	if err := validateFileName(name.String()); err != nil {
		return err
	}
	metadata := sslCertificateUploadDocument{}
	metadata.Certificate.Action = uploadAction(options.Replace)
	metadata.Certificate.CertificateType = "pem"
	metadata.Certificate.File = name
	metadata.Certificate.FileHandle = name
	return s.doMultipart(ctx, "/file/ssl-cert", metadata, name.String(), certificatePEM, http.StatusOK, http.StatusCreated, http.StatusNoContent)
}

// UploadKey imports or replaces a PEM private-key file. Keys are marked
// non-exportable unless ExportableKey is explicitly set.
func (s *Session) UploadKey(ctx context.Context, name KeyFileName, keyPEM []byte, options UploadOptions) error {
	if err := validateFileName(name.String()); err != nil {
		return err
	}
	if _, err := ParseEncryptedKey(keyPEM, nil); err != nil && !strings.Contains(err.Error(), "no passphrase") {
		return err
	}
	secured := 1
	if options.ExportableKey {
		secured = 0
	}
	metadata := sslKeyUploadDocument{}
	metadata.Key.Action = uploadAction(options.Replace)
	metadata.Key.File = name
	metadata.Key.FileHandle = name
	metadata.Key.Secured = secured
	return s.doMultipart(ctx, "/file/ssl-key", metadata, name.String(), keyPEM, http.StatusOK, http.StatusCreated, http.StatusNoContent)
}

// UploadCA imports or replaces a PEM CA trust-store file. It is not the store
// used by a client-SSL certificate binding's chain-cert attribute.
func (s *Session) UploadCA(ctx context.Context, name CAFileName, certificatePEM []byte, options UploadOptions) error {
	if err := validateFileName(name.String()); err != nil {
		return err
	}
	certificates, err := splitCertificates(certificatePEM)
	if err != nil {
		return err
	}
	for i, certificate := range certificates {
		if !certificate.parsed.IsCA {
			return fmt.Errorf("CA chain certificate %d is not a CA certificate", i)
		}
	}
	metadata := caCertificateUploadDocument{}
	metadata.Certificate.Action = uploadAction(options.Replace)
	metadata.Certificate.CertificateType = "pem"
	metadata.Certificate.File = name
	metadata.Certificate.FileHandle = name
	return s.doMultipart(ctx, "/file/ca-cert", metadata, name.String(), certificatePEM, http.StatusOK, http.StatusCreated, http.StatusNoContent)
}

func uploadAction(replace bool) string {
	if replace {
		return "replace"
	}
	return "import"
}

// BindCertificate adds a certificate binding to a client-SSL template. The
// passphrase is sent only in this request and is never part of returned types.
func (s *Session) BindCertificate(ctx context.Context, template ClientSSLTemplateName, binding CertificateBinding, passphrase []byte) error {
	if err := validateTemplateName("client-SSL template", template.String()); err != nil {
		return err
	}
	if err := validateFileName(binding.Certificate.String()); err != nil {
		return fmt.Errorf("certificate binding: %w", err)
	}
	if err := validateFileName(binding.Key.String()); err != nil {
		return fmt.Errorf("key binding: %w", err)
	}
	body := certificateBindingDocument{}
	body.Certificate.Certificate = binding.Certificate
	body.Certificate.Key = binding.Key
	if binding.Chain != "" {
		if err := validateFileName(binding.Chain.String()); err != nil {
			return fmt.Errorf("chain binding: %w", err)
		}
		body.Certificate.Chain = binding.Chain
	}
	if binding.Shared {
		body.Certificate.Shared = 1
	}
	if len(passphrase) != 0 {
		body.Certificate.Passphrase = string(passphrase)
	}
	endpoint := "/slb/template/client-ssl/" + template.String() + "/certificate"
	return s.doJSON(ctx, http.MethodPost, endpoint, body, nil, http.StatusOK, http.StatusCreated, http.StatusNoContent)
}

// UnbindCertificate removes a certificate binding from a client-SSL template.
func (s *Session) UnbindCertificate(ctx context.Context, template ClientSSLTemplateName, certificate CertificateFileName) error {
	if err := validateTemplateName("client-SSL template", template.String()); err != nil {
		return err
	}
	if err := validateFileName(certificate.String()); err != nil {
		return err
	}
	endpoint := "/slb/template/client-ssl/" + template.String() + "/certificate/" + certificate.String()
	return s.doJSON(ctx, http.MethodDelete, endpoint, nil, nil, http.StatusOK, http.StatusNoContent)
}

// DeleteMaterial deletes unbound certificate, key, and/or CA files.
func (s *Session) DeleteMaterial(ctx context.Context, names MaterialNames) error {
	if names == (MaterialNames{}) {
		return errors.New("no A10 certificate material was selected for deletion")
	}
	if names.Certificate != "" {
		if err := validateFileName(names.Certificate.String()); err != nil {
			return err
		}
	}
	if names.Key != "" {
		if err := validateFileName(names.Key.String()); err != nil {
			return err
		}
	}
	if names.CA != "" {
		if err := validateFileName(names.CA.String()); err != nil {
			return err
		}
	}
	body := deleteMaterialDocument{}
	body.Delete.Certificate = names.Certificate
	body.Delete.Key = names.Key
	body.Delete.CA = names.CA
	return s.doJSON(ctx, http.MethodPost, "/pki/delete", body, nil, http.StatusOK, http.StatusCreated, http.StatusNoContent)
}

// WriteMemory persists the running ACOS configuration.
func (s *Session) WriteMemory(ctx context.Context) error {
	body := writeMemoryDocument{}
	body.Memory.Destination = "primary"
	if s.partition.Name == "" {
		body.Memory.Partition = "shared"
	} else {
		body.Memory.Partition = "specified"
		body.Memory.SpecifiedPartition = s.partition.Name
	}
	return s.doJSON(ctx, http.MethodPost, "/write/memory", body, nil, http.StatusOK, http.StatusCreated, http.StatusNoContent)
}

func validateFileName(name string) error {
	if err := validateObjectName("file", name); err != nil {
		return err
	}
	if len(name) > 245 {
		return errors.New("A10 file name exceeds 245 characters")
	}
	if strings.ContainsAny(name, "/\\") {
		return errors.New("A10 file name must not contain a path separator")
	}
	return nil
}

func validateObjectName(kind, name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%s name is empty", kind)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s name contains a control character", kind)
		}
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("%s name must not contain a path separator", kind)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%s name must not be a relative path segment", kind)
	}
	if strings.ContainsAny(name, "?#") {
		return fmt.Errorf("%s name must not contain URL query or fragment delimiters", kind)
	}
	return nil
}

func validateTemplateName(kind, name string) error {
	if err := validateObjectName(kind, name); err != nil {
		return err
	}
	if len(name) > 127 {
		return fmt.Errorf("%s name exceeds 127 characters", kind)
	}
	return nil
}
