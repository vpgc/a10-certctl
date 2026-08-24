package a10

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/youmark/pkcs8"
)

// Checksum is a SHA-256 digest of canonical certificate or key material.
// DER is hashed rather than PEM text so whitespace and line-ending changes do
// not cause a false certificate rotation.
type Checksum string

func newChecksum(data []byte) Checksum {
	digest := sha256.Sum256(data)
	return Checksum("sha256:" + hex.EncodeToString(digest[:]))
}

// Certificate is a validated X.509 certificate. Its PEM bytes are immutable
// from the caller's perspective.
type Certificate struct {
	Checksum    Checksum  `json:"checksum"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	DNSNames    []string  `json:"dnsNames,omitempty"`
	IPAddresses []net.IP  `json:"ipAddresses,omitempty"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`

	pem    []byte
	parsed *x509.Certificate
}

// ParseCertificate validates exactly one PEM-encoded X.509 certificate.
func ParseCertificate(data []byte) (Certificate, error) {
	blocks, err := splitCertificates(data)
	if err != nil {
		return Certificate{}, err
	}
	if len(blocks) != 1 {
		return Certificate{}, errors.New("certificate must contain exactly one PEM CERTIFICATE block")
	}
	return blocks[0], nil
}

func splitCertificates(data []byte) ([]Certificate, error) {
	rest := bytes.TrimSpace(data)
	if len(rest) == 0 {
		return nil, errors.New("certificate PEM is empty")
	}
	var certificates []Certificate
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("certificate data must contain only PEM CERTIFICATE blocks")
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse X.509 certificate %d: %w", len(certificates), err)
		}
		certificates = append(certificates, certificateFromParsed(parsed))
		rest = bytes.TrimSpace(next)
	}
	return certificates, nil
}

func certificateFromParsed(parsed *x509.Certificate) Certificate {
	return Certificate{
		Checksum:    newChecksum(parsed.Raw),
		Subject:     parsed.Subject.String(),
		Issuer:      parsed.Issuer.String(),
		Serial:      strings.ToUpper(parsed.SerialNumber.Text(16)),
		DNSNames:    append([]string(nil), parsed.DNSNames...),
		IPAddresses: cloneIPs(parsed.IPAddresses),
		NotBefore:   parsed.NotBefore,
		NotAfter:    parsed.NotAfter,
		pem:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parsed.Raw}),
		parsed:      parsed,
	}
}

// PEM returns a copy of the canonical PEM representation.
func (c Certificate) PEM() []byte { return append([]byte(nil), c.pem...) }

func (c Certificate) valid() bool {
	return c.parsed != nil && len(c.pem) != 0 && c.Checksum == newChecksum(c.parsed.Raw)
}

// ValidAt reports whether the certificate is structurally valid and within
// its X.509 validity interval at the supplied time.
func (c Certificate) ValidAt(at time.Time) error {
	if !c.valid() {
		return errors.New("certificate was not created by ParseCertificate")
	}
	at = at.UTC()
	if at.Before(c.parsed.NotBefore) {
		return fmt.Errorf("certificate is not valid before %s", c.parsed.NotBefore.UTC().Format(time.RFC3339))
	}
	if at.After(c.parsed.NotAfter) {
		return fmt.Errorf("certificate expired at %s", c.parsed.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

func cloneIPs(values []net.IP) []net.IP {
	result := make([]net.IP, len(values))
	for i, value := range values {
		result[i] = append(net.IP(nil), value...)
	}
	return result
}

// Key is a validated private key. Checksum is derived from canonical,
// unencrypted PKCS#8 DER. PEM and passphrase are deliberately not JSON fields.
type Key struct {
	Checksum Checksum `json:"checksum"`

	pem        []byte
	passphrase []byte
	privateKey crypto.PrivateKey
}

// ParseKey validates an unencrypted PEM private key.
func ParseKey(data []byte) (Key, error) { return ParseEncryptedKey(data, nil) }

// ParseEncryptedKey validates an encrypted or unencrypted private key.
// PKCS#1 RSA, SEC1 EC, PKCS#8, and encrypted PKCS#8 inputs are supported.
func ParseEncryptedKey(data, passphrase []byte) (Key, error) {
	if !utf8.Valid(passphrase) {
		return Key{}, errors.New("private-key passphrase must be valid UTF-8 for aXAPI")
	}
	trimmed := bytes.TrimSpace(data)
	block, rest := pem.Decode(trimmed)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return Key{}, errors.New("private key must contain one PEM PRIVATE KEY block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return Key{}, errors.New("private key must contain exactly one PEM PRIVATE KEY block")
	}
	privateKey, err := parsePrivateKeyBlock(block, passphrase)
	if err != nil {
		return Key{}, err
	}
	if _, ok := privateKey.(crypto.Signer); !ok {
		return Key{}, fmt.Errorf("unsupported private key type %T", privateKey)
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return Key{}, fmt.Errorf("canonicalize private key: %w", err)
	}
	return Key{
		Checksum:   newChecksum(canonical),
		pem:        append(append([]byte(nil), trimmed...), '\n'),
		passphrase: append([]byte(nil), passphrase...),
		privateKey: privateKey,
	}, nil
}

func parsePrivateKeyBlock(block *pem.Block, passphrase []byte) (crypto.PrivateKey, error) {
	if block.Headers["Proc-Type"] != "" || block.Headers["DEK-Info"] != "" {
		return nil, errors.New("legacy RFC 1423 PEM encryption is unsupported; convert the key to encrypted PKCS#8")
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		if len(passphrase) == 0 {
			return nil, errors.New("private key is encrypted but no passphrase was supplied")
		}
		key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt PKCS#8 private key: %w", err)
		}
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("private key is not valid PKCS#1, SEC1, or PKCS#8 data")
}

// PEM returns a copy of the original private-key PEM representation.
func (k Key) PEM() []byte { return append([]byte(nil), k.pem...) }

func (k Key) valid() bool {
	if k.privateKey == nil || len(k.pem) == 0 {
		return false
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(k.privateKey)
	return err == nil && k.Checksum == newChecksum(canonical)
}

// CertificateBundle is a locally validated certificate/private-key unit.
// Chain contains issuing CA certificates in leaf-to-root order.
type CertificateBundle struct {
	Certificate Certificate   `json:"certificate"`
	Key         Key           `json:"key"`
	Chain       []Certificate `json:"chain,omitempty"`
	Checksum    Checksum      `json:"checksum"`
}

// CertificateBundleInput accepts a leaf certificate or full-chain PEM. If
// CertificatePEM contains multiple blocks, its first block is the leaf and the
// remaining blocks are prepended to CertificateChainPEM.
type CertificateBundleInput struct {
	CertificatePEM       []byte
	PrivateKeyPEM        []byte `json:"-"`
	PrivateKeyPassphrase []byte `json:"-"`
	CertificateChainPEM  [][]byte
}

// ParseCertificateBundle parses and validates all PEM inputs as one unit.
func ParseCertificateBundle(input CertificateBundleInput) (CertificateBundle, error) {
	certificateFile, err := splitCertificates(input.CertificatePEM)
	if err != nil {
		return CertificateBundle{}, err
	}
	leaf := certificateFile[0]
	chain := append([]Certificate(nil), certificateFile[1:]...)
	for i, data := range input.CertificateChainPEM {
		items, err := splitCertificates(data)
		if err != nil {
			return CertificateBundle{}, fmt.Errorf("parse chain input %d: %w", i, err)
		}
		chain = append(chain, items...)
	}
	key, err := ParseEncryptedKey(input.PrivateKeyPEM, input.PrivateKeyPassphrase)
	if err != nil {
		return CertificateBundle{}, err
	}
	return NewCertificateBundle(leaf, key, chain)
}

// NewCertificateBundle verifies the complete pair and its issuer chain.
func NewCertificateBundle(certificate Certificate, key Key, chain []Certificate) (CertificateBundle, error) {
	if !certificate.valid() {
		return CertificateBundle{}, errors.New("certificate was not created by ParseCertificate")
	}
	if !key.valid() {
		return CertificateBundle{}, errors.New("key was not created by ParseKey or ParseEncryptedKey")
	}
	if err := certificateMatchesKey(certificate, key); err != nil {
		return CertificateBundle{}, err
	}
	if err := validateCertificateChain(certificate, chain); err != nil {
		return CertificateBundle{}, err
	}
	bundle := CertificateBundle{Certificate: certificate, Key: key, Chain: append([]Certificate(nil), chain...)}
	bundle.Checksum = bundleChecksum(bundle)
	return bundle, nil
}

func certificateMatchesKey(certificate Certificate, key Key) error {
	signer, ok := key.privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("unsupported private key type %T", key.privateKey)
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.parsed.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal certificate public key: %w", err)
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("marshal private-key public key: %w", err)
	}
	if !bytes.Equal(certificatePublic, keyPublic) {
		return errors.New("certificate and private key do not match")
	}
	return nil
}

func validateCertificateChain(leaf Certificate, chain []Certificate) error {
	child := leaf.parsed
	for i, issuer := range chain {
		if !issuer.valid() {
			return fmt.Errorf("chain certificate %d was not created by ParseCertificate", i)
		}
		if !issuer.parsed.IsCA {
			return fmt.Errorf("chain certificate %d is not a CA certificate", i)
		}
		if err := child.CheckSignatureFrom(issuer.parsed); err != nil {
			return fmt.Errorf("chain certificate %d does not sign the preceding certificate: %w", i, err)
		}
		child = issuer.parsed
	}
	return nil
}

func bundleChecksum(bundle CertificateBundle) Checksum {
	hash := sha256.New()
	writePart := func(data []byte) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(data)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(data)
	}
	writePart([]byte(bundle.Certificate.Checksum))
	writePart([]byte(bundle.Key.Checksum))
	for _, item := range bundle.Chain {
		writePart([]byte(item.Checksum))
	}
	return Checksum("sha256:" + hex.EncodeToString(hash.Sum(nil)))
}

func (b CertificateBundle) validate() error {
	if _, err := NewCertificateBundle(b.Certificate, b.Key, b.Chain); err != nil {
		return err
	}
	if b.Checksum != bundleChecksum(b) {
		return errors.New("certificate bundle checksum is invalid; construct it with NewCertificateBundle or ParseCertificateBundle")
	}
	return nil
}

func (b CertificateBundle) validateForSync(at time.Time) error {
	if err := b.validate(); err != nil {
		return err
	}
	if err := b.Certificate.ValidAt(at); err != nil {
		return fmt.Errorf("leaf certificate: %w", err)
	}
	for index, certificate := range b.Chain {
		if err := certificate.ValidAt(at); err != nil {
			return fmt.Errorf("chain certificate %d: %w", index, err)
		}
	}
	return nil
}

func (b CertificateBundle) chainPEM() []byte {
	var result []byte
	for _, item := range b.Chain {
		result = append(result, item.PEM()...)
	}
	return result
}
