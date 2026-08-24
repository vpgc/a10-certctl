package a10

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseTemplateRevision(t *testing.T) {
	want := TemplateRevision("sha256:" + strings.Repeat("ab", 32))
	got, err := ParseTemplateRevision(want.String())
	if err != nil || got != want {
		t.Fatalf("unexpected revision: %q, %v", got, err)
	}
	for _, value := range []string{"", "ab", "sha256:xyz", "sha256:" + strings.Repeat("a", 63)} {
		if _, err := ParseTemplateRevision(value); err == nil {
			t.Fatalf("invalid revision %q was accepted", value)
		}
	}
}

func TestGetManagedCertificateStateResolvesLogicalNamesWithoutSecrets(t *testing.T) {
	template := ClientSSLTemplate{
		Name: "TLS_TEMPLATE",
		Certificates: []CertificateBinding{{
			Certificate: "site-cert",
			Key:         "site-key",
		}},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE":
			writeJSON(t, w, map[string]any{"client-ssl": template})
		case "/axapi/v3/slb/ssl-cert/oper":
			writeJSON(t, w, map[string]any{"ssl-cert": map[string]any{"oper": map[string]any{
				"ssl-certs": []CertificateInfo{{Name: "site-cert", CommonName: "site.example"}},
			}}})
		case "/axapi/v3/file/ssl-key/oper":
			writeFileInventory(t, w, "ssl-key", map[string]bool{"site-key": true})
		case "/axapi/v3/logoff":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	state, err := client.GetManagedCertificateState(context.Background(), ForClientSSLTemplate("TLS_TEMPLATE"))
	if err != nil {
		t.Fatal(err)
	}
	if state.TemplateRevision != template.Revision() || state.Binding == nil || state.Certificate == nil || state.Key == nil {
		t.Fatalf("incomplete state: %#v", state)
	}
	if state.Certificate.CommonName != "site.example" || state.Key.Name != "site-key" {
		t.Fatalf("unexpected resolved state: %#v", state)
	}
}

func TestGetKeyReturnsTypedNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/file/ssl-key/oper":
			writeFileInventory(t, w, "ssl-key", nil)
		case "/axapi/v3/logoff":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	session, err := client.StartSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.GetKey(context.Background(), "missing")
	if closeErr := session.Close(context.Background()); closeErr != nil {
		t.Fatal(closeErr)
	}
	if !IsNotFound(err) {
		t.Fatalf("expected typed not-found error, got %v", err)
	}
}
