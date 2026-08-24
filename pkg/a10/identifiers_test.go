package a10

import (
	"strings"
	"testing"
)

func TestTypedIdentifierParsers(t *testing.T) {
	template, err := ParseClientSSLTemplateName("TLS_TEMPLATE")
	if err != nil || template.String() != "TLS_TEMPLATE" {
		t.Fatalf("unexpected template result: %q, %v", template, err)
	}
	serverTemplate, err := ParseServerSSLTemplateName("BACKEND_MTLS")
	if err != nil || serverTemplate.String() != "BACKEND_MTLS" {
		t.Fatalf("unexpected server template result: %q, %v", serverTemplate, err)
	}
	virtualServer, err := ParseVirtualServerName("VIP_HTTPS")
	if err != nil || virtualServer.String() != "VIP_HTTPS" {
		t.Fatalf("unexpected virtual-server result: %q, %v", virtualServer, err)
	}
	certificate, err := ParseCertificateFileName("site-cert.pem")
	if err != nil || certificate.String() != "site-cert.pem" {
		t.Fatalf("unexpected certificate result: %q, %v", certificate, err)
	}
	key, err := ParseKeyFileName("site-key.pem")
	if err != nil || key.String() != "site-key.pem" {
		t.Fatalf("unexpected key result: %q, %v", key, err)
	}
	ca, err := ParseCAFileName("issuer-ca.pem")
	if err != nil || ca.String() != "issuer-ca.pem" {
		t.Fatalf("unexpected CA result: %q, %v", ca, err)
	}

	for name, parse := range map[string]func(string) error{
		"template":    func(value string) error { _, err := ParseClientSSLTemplateName(value); return err },
		"server":      func(value string) error { _, err := ParseServerSSLTemplateName(value); return err },
		"certificate": func(value string) error { _, err := ParseCertificateFileName(value); return err },
		"key":         func(value string) error { _, err := ParseKeyFileName(value); return err },
		"CA":          func(value string) error { _, err := ParseCAFileName(value); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := parse("../unsafe"); err == nil || !strings.Contains(err.Error(), "path separator") {
				t.Fatalf("unsafe identifier was accepted: %v", err)
			}
		})
	}

	for _, value := range []string{".", "..", "name?query", "name#fragment"} {
		if _, err := ParseClientSSLTemplateName(value); err == nil {
			t.Errorf("unsafe template name %q was accepted", value)
		}
		if _, err := ParseCertificateFileName(value); err == nil {
			t.Errorf("unsafe file name %q was accepted", value)
		}
	}
	if _, err := ParseClientSSLTemplateName(strings.Repeat("t", 127)); err != nil {
		t.Fatalf("documented 127-character template name was rejected: %v", err)
	}
	if _, err := ParseClientSSLTemplateName(strings.Repeat("t", 128)); err == nil {
		t.Fatal("128-character template name was accepted")
	}
	if _, err := ParseCertificateFileName(strings.Repeat("f", 245)); err != nil {
		t.Fatalf("documented 245-character file name was rejected: %v", err)
	}
	if _, err := ParseCertificateFileName(strings.Repeat("f", 246)); err == nil {
		t.Fatal("246-character file name was accepted")
	}
}
