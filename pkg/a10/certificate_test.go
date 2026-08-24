package a10

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/youmark/pkcs8"
)

func TestParseCertificateBundleRejectsMismatchedKey(t *testing.T) {
	certificatePEM, _ := newTestPEMPair(t, "one.example")
	_, otherKeyPEM := newTestPEMPair(t, "two.example")
	_, err := ParseCertificateBundle(CertificateBundleInput{CertificatePEM: certificatePEM, PrivateKeyPEM: otherKeyPEM})
	if err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("expected local mismatch error, got %v", err)
	}
}

func TestParseCertificateBundleCanonicalChecksums(t *testing.T) {
	certificatePEM, keyPEM := newTestPEMPair(t, "checksum.example")
	first, err := ParseCertificateBundle(CertificateBundleInput{CertificatePEM: certificatePEM, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	certificateWithWhitespace := append(append([]byte("\n\t"), certificatePEM...), []byte("\r\n")...)
	second, err := ParseCertificateBundle(CertificateBundleInput{CertificatePEM: certificateWithWhitespace, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	if first.Certificate.Checksum != second.Certificate.Checksum || first.Checksum != second.Checksum {
		t.Fatalf("semantically equal PEM had different checksums: %q / %q", first.Checksum, second.Checksum)
	}
}

func TestParseCertificateBundleAcceptsFullChain(t *testing.T) {
	leafPEM, keyPEM, caPEM := newTestChain(t, "chain.example")
	fullChain := append(append([]byte(nil), leafPEM...), caPEM...)
	bundle, err := ParseCertificateBundle(CertificateBundleInput{CertificatePEM: fullChain, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Chain) != 1 || bundle.Chain[0].parsed.Subject.CommonName != "Test CA" {
		t.Fatalf("unexpected chain: %#v", bundle.Chain)
	}
}

func TestParseEncryptedPKCS8Key(t *testing.T) {
	certificatePEM, keyPEM := newTestPEMPair(t, "encrypted.example")
	block, _ := pem.Decode(keyPEM)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	encryptedDER, err := pkcs8.MarshalPrivateKey(privateKey, []byte("correct horse"), pkcs8.DefaultOpts)
	if err != nil {
		t.Fatal(err)
	}
	encryptedPEM := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedDER})
	bundle, err := ParseCertificateBundle(CertificateBundleInput{
		CertificatePEM: certificatePEM, PrivateKeyPEM: encryptedPEM, PrivateKeyPassphrase: []byte("correct horse"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Key.Checksum == "" {
		t.Fatal("encrypted key has no checksum")
	}
	if _, err := ParseEncryptedKey(encryptedPEM, []byte("wrong")); err == nil {
		t.Fatal("wrong passphrase was accepted")
	}
}

func TestCertificateValidAtUsesAuthenticatedX509Dates(t *testing.T) {
	certificatePEM, _ := newTestPEMPair(t, "validity.example")
	certificate, err := ParseCertificate(certificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate.ValidAt(certificate.NotBefore); err != nil {
		t.Fatalf("certificate was not valid at NotBefore: %v", err)
	}
	if err := certificate.ValidAt(certificate.NotAfter); err != nil {
		t.Fatalf("certificate was not valid at NotAfter: %v", err)
	}
	if err := certificate.ValidAt(certificate.NotBefore.Add(-time.Nanosecond)); err == nil || !strings.Contains(err.Error(), "not valid before") {
		t.Fatalf("expected not-yet-valid error, got %v", err)
	}
	if err := certificate.ValidAt(certificate.NotAfter.Add(time.Nanosecond)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got %v", err)
	}

	// Exported presentation fields are not trusted for safety decisions.
	certificate.NotAfter = time.Now().Add(24 * time.Hour)
	if err := certificate.ValidAt(certificate.parsed.NotAfter.Add(time.Nanosecond)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("mutated presentation field bypassed validity check: %v", err)
	}
}

func TestTypedValuesDoNotJSONSerializeSecrets(t *testing.T) {
	certificatePEM, keyPEM := newTestPEMPair(t, "secret.example")
	bundle, err := ParseCertificateBundle(CertificateBundleInput{
		CertificatePEM: certificatePEM, PrivateKeyPEM: keyPEM, PrivateKeyPassphrase: []byte("secret-passphrase"),
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(struct {
		Bundle CertificateBundle
		Input  CertificateBundleInput
	}{bundle, CertificateBundleInput{PrivateKeyPEM: keyPEM, PrivateKeyPassphrase: []byte("secret-passphrase")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PRIVATE KEY", "secret-passphrase"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("JSON output leaked %q: %s", secret, data)
		}
	}
}

func newTestBundle(t *testing.T, dnsName string) CertificateBundle {
	t.Helper()
	certificatePEM, keyPEM := newTestPEMPair(t, dnsName)
	bundle, err := ParseCertificateBundle(CertificateBundleInput{CertificatePEM: certificatePEM, PrivateKeyPEM: keyPEM})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func newTestPEMPair(t *testing.T, dnsName string) ([]byte, []byte) {
	t.Helper()
	now := time.Now().UTC()
	return newTestPEMPairWithValidity(t, dnsName, now.Add(-time.Minute), now.Add(time.Hour))
}

func newTestPEMPairWithValidity(t *testing.T, dnsName string, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func newTestChain(t *testing.T, dnsName string) ([]byte, []byte, []byte) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}
