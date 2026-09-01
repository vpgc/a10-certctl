package a10

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSyncCertificateUploadsBindsVerifiesCleansAndWritesMemory(t *testing.T) {
	leafPEM, keyPEM, caPEM := newTestChain(t, "new.example")
	bundle, err := ParseCertificateBundle(CertificateBundleInput{
		CertificatePEM: leafPEM, PrivateKeyPEM: keyPEM, CertificateChainPEM: [][]byte{caPEM},
	})
	if err != nil {
		t.Fatal(err)
	}
	desiredName, desiredChain, err := managedNames(ForClientSSLTemplate("TLS_TEMPLATE"), bundle, "")
	if err != nil {
		t.Fatal(err)
	}
	bindings := []CertificateBinding{{Certificate: "old-cert", Key: "old-key"}}
	certificateFiles := map[string]bool{"old-cert": true}
	keyFiles := map[string]bool{"old-key": true}
	var calls []string
	var deleted MaterialNames

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"sync-token"}}`)
		case r.URL.Path == "/axapi/v3/version/oper":
			writeCompatibleVersion(t, w)
		case r.URL.Path == "/axapi/v3/logoff":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE":
			writeJSON(t, w, map[string]any{"client-ssl": ClientSSLTemplate{Name: "TLS_TEMPLATE", Certificates: bindings}})
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/file/ssl-cert/oper":
			writeFileInventory(t, w, "ssl-cert", certificateFiles)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/file/ssl-key/oper":
			writeFileInventory(t, w, "ssl-key", keyFiles)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/slb/ssl-cert/oper":
			var certificates []CertificateInfo
			if certificateFiles[desiredName.String()] {
				certificates = append(certificates, CertificateInfo{
					Name: desiredName, Serial: "0x" + bundle.Certificate.Serial,
					CommonName: bundle.Certificate.parsed.Subject.CommonName,
				})
			}
			writeJSON(t, w, map[string]any{"ssl-cert": map[string]any{"oper": map[string]any{"ssl-certs": certificates}}})
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/file/ssl-key":
			name := multipartUploadName(t, r, "ssl-key")
			if name != desiredName.String() {
				t.Fatalf("unexpected key name %q", name)
			}
			keyFiles[name] = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/file/ssl-cert":
			name := multipartUploadName(t, r, "ssl-cert")
			if name != desiredName.String() && name != desiredChain.String() {
				t.Fatalf("unexpected certificate name %q", name)
			}
			certificateFiles[name] = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE/certificate":
			var document struct {
				Certificate CertificateBinding `json:"certificate"`
			}
			if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
				t.Fatal(err)
			}
			bindings = append(bindings, document.Certificate)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE/certificate/old-cert":
			bindings = bindings[1:]
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/slb/template/client-ssl":
			writeJSON(t, w, map[string]any{"client-ssl-list": []ClientSSLTemplate{{Name: "TLS_TEMPLATE", Certificates: bindings}}})
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/slb/template/server-ssl":
			writeJSON(t, w, map[string]any{"server-ssl-list": []ServerSSLTemplate{}})
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/pki/delete":
			var document struct {
				Delete struct {
					Certificate string `json:"cert-name"`
					Key         string `json:"private-key"`
					CA          string `json:"ca"`
				} `json:"delete"`
			}
			if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
				t.Fatal(err)
			}
			deleted = MaterialNames{
				Certificate: CertificateFileName(document.Delete.Certificate),
				Key:         KeyFileName(document.Delete.Key),
				CA:          CAFileName(document.Delete.CA),
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/write/memory":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.SyncCertificate(context.Background(), ForClientSSLTemplate("TLS_TEMPLATE"), bundle, SyncOptions{CleanupOld: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !result.Uploaded || !result.Bound || !result.UnboundOld || !result.WroteMemory {
		t.Fatalf("unexpected result: %#v", result)
	}
	if deleted != (MaterialNames{Certificate: "old-cert", Key: "old-key"}) {
		t.Fatalf("unexpected cleanup: %#v", deleted)
	}
	wantCalls := []string{
		"POST /axapi/v3/auth",
		"GET /axapi/v3/version/oper",
		"GET /axapi/v3/slb/template/client-ssl/TLS_TEMPLATE",
		"GET /axapi/v3/file/ssl-cert/oper",
		"GET /axapi/v3/file/ssl-key/oper",
		"GET /axapi/v3/slb/ssl-cert/oper",
		"POST /axapi/v3/file/ssl-key",
		"POST /axapi/v3/file/ssl-cert",
		"POST /axapi/v3/file/ssl-cert",
		"GET /axapi/v3/slb/template/client-ssl/TLS_TEMPLATE",
		"POST /axapi/v3/slb/template/client-ssl/TLS_TEMPLATE/certificate",
		"GET /axapi/v3/slb/template/client-ssl/TLS_TEMPLATE",
		"GET /axapi/v3/slb/template/client-ssl/TLS_TEMPLATE",
		"DELETE /axapi/v3/slb/template/client-ssl/TLS_TEMPLATE/certificate/old-cert",
		"GET /axapi/v3/slb/template/client-ssl/TLS_TEMPLATE",
		"GET /axapi/v3/slb/template/client-ssl/TLS_TEMPLATE",
		"POST /axapi/v3/write/memory",
		"GET /axapi/v3/slb/template/client-ssl",
		"GET /axapi/v3/slb/template/server-ssl",
		"POST /axapi/v3/pki/delete",
		"POST /axapi/v3/write/memory",
		"POST /axapi/v3/logoff",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("call sequence mismatch\nwant: %#v\n got: %#v", wantCalls, calls)
	}
}

func TestCreateManagedCertificatePreStagesWithoutTemplate(t *testing.T) {
	bundle := newTestBundle(t, "staged.example")
	name, _, err := managedNamesForPrefix(bundle, "future-vip")
	if err != nil {
		t.Fatal(err)
	}
	certificateFiles := map[string]bool{}
	keyFiles := map[string]bool{}
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"create-token"}}`)
		case r.URL.Path == "/axapi/v3/version/oper":
			writeCompatibleVersion(t, w)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/file/ssl-cert/oper":
			writeFileInventory(t, w, "ssl-cert", certificateFiles)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/file/ssl-key/oper":
			writeFileInventory(t, w, "ssl-key", keyFiles)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/slb/ssl-cert/oper":
			writeJSON(t, w, map[string]any{"ssl-cert": map[string]any{"oper": map[string]any{"ssl-certs": []CertificateInfo{}}}})
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/file/ssl-key":
			uploaded := multipartUploadName(t, r, "ssl-key")
			if uploaded != name.String() {
				t.Fatalf("unexpected key name %q", uploaded)
			}
			keyFiles[uploaded] = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/file/ssl-cert":
			uploaded := multipartUploadName(t, r, "ssl-cert")
			if uploaded != name.String() {
				t.Fatalf("unexpected certificate name %q", uploaded)
			}
			certificateFiles[uploaded] = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/write/memory":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/axapi/v3/logoff":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request (a template must not be required): %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CreateManagedCertificate(context.Background(), bundle, CreateOptions{NamePrefix: "future-vip"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !result.Uploaded || !result.WroteMemory || result.Certificate.Name != name || result.Certificate.Target != (CertificateTarget{}) {
		t.Fatalf("unexpected create result: %#v", result)
	}
	for _, call := range calls {
		if strings.Contains(call, "/slb/template/client-ssl") {
			t.Fatalf("unbound creation accessed a template: %s", call)
		}
	}
}

func TestSyncCertificateEquivalentVersionedPairIsNoOp(t *testing.T) {
	bundle := newTestBundle(t, "same.example")
	name, _, _ := managedNames(ForClientSSLTemplate("TLS_TEMPLATE"), bundle, "")
	var writes int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/version/oper":
			writeCompatibleVersion(t, w)
		case "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE":
			writeJSON(t, w, map[string]any{"client-ssl": ClientSSLTemplate{Name: "TLS_TEMPLATE", Certificates: []CertificateBinding{{Certificate: name, Key: KeyFileName(name)}}}})
		case "/axapi/v3/file/ssl-cert/oper":
			writeFileInventory(t, w, "ssl-cert", map[string]bool{name.String(): true})
		case "/axapi/v3/file/ssl-key/oper":
			writeFileInventory(t, w, "ssl-key", map[string]bool{name.String(): true})
		case "/axapi/v3/slb/ssl-cert/oper":
			writeJSON(t, w, map[string]any{"ssl-cert": map[string]any{"oper": map[string]any{"ssl-certs": []CertificateInfo{{
				Name: name, Serial: "0x" + bundle.Certificate.Serial, CommonName: "same.example",
			}}}}})
		case "/axapi/v3/logoff":
			w.WriteHeader(http.StatusOK)
		default:
			writes++
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	client, _ := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	result, err := client.SyncCertificate(context.Background(), ForClientSSLTemplate("TLS_TEMPLATE"), bundle, SyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Uploaded || result.Bound || result.WroteMemory || writes != 0 {
		t.Fatalf("equivalent pair was not a no-op: result=%#v writes=%d", result, writes)
	}
}

func TestSyncCertificateRejectsAmbiguousTemplateBeforeWrites(t *testing.T) {
	bundle := newTestBundle(t, "ambiguous.example")
	var writes int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/version/oper":
			writeCompatibleVersion(t, w)
		case "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE":
			writeJSON(t, w, map[string]any{"client-ssl": ClientSSLTemplate{Name: "TLS_TEMPLATE", Certificates: []CertificateBinding{
				{Certificate: "one", Key: "one"}, {Certificate: "two", Key: "two"},
			}}})
		case "/axapi/v3/logoff":
			w.WriteHeader(http.StatusOK)
		default:
			writes++
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	client, _ := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	_, err := client.SyncCertificate(context.Background(), ForClientSSLTemplate("TLS_TEMPLATE"), bundle, SyncOptions{})
	if err == nil || !strings.Contains(err.Error(), "has 2 certificate bindings") || writes != 0 {
		t.Fatalf("unexpected result: err=%v writes=%d", err, writes)
	}
}

func TestSyncCertificateDetectsConcurrentChangeAfterBinding(t *testing.T) {
	bundle := newTestBundle(t, "concurrent.example")
	desiredName, _, err := managedNames(ForClientSSLTemplate("TLS_TEMPLATE"), bundle, "")
	if err != nil {
		t.Fatal(err)
	}
	bindings := []CertificateBinding{{Certificate: "old-cert", Key: "old-key"}}
	certificateFiles := map[string]bool{"old-cert": true}
	keyFiles := map[string]bool{"old-key": true}
	var destructiveCalls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"token"}}`)
		case r.URL.Path == "/axapi/v3/version/oper":
			writeCompatibleVersion(t, w)
		case r.URL.Path == "/axapi/v3/logoff":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE":
			writeJSON(t, w, map[string]any{"client-ssl": ClientSSLTemplate{Name: "TLS_TEMPLATE", Certificates: bindings}})
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/file/ssl-cert/oper":
			writeFileInventory(t, w, "ssl-cert", certificateFiles)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/file/ssl-key/oper":
			writeFileInventory(t, w, "ssl-key", keyFiles)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/slb/ssl-cert/oper":
			writeJSON(t, w, map[string]any{"ssl-cert": map[string]any{"oper": map[string]any{"ssl-certs": []CertificateInfo{}}}})
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/file/ssl-key":
			keyFiles[multipartUploadName(t, r, "ssl-key")] = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/file/ssl-cert":
			certificateFiles[multipartUploadName(t, r, "ssl-cert")] = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE/certificate":
			var document struct {
				Certificate CertificateBinding `json:"certificate"`
			}
			if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
				t.Fatal(err)
			}
			bindings = append(bindings, document.Certificate)
			// Simulate an independent GUI/API writer immediately after our bind.
			bindings = append(bindings, CertificateBinding{Certificate: "gui-cert", Key: "gui-key"})
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete || r.URL.Path == "/axapi/v3/pki/delete" || r.URL.Path == "/axapi/v3/write/memory":
			destructiveCalls++
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, _ := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	result, err := client.SyncCertificate(
		context.Background(),
		ForClientSSLTemplate("TLS_TEMPLATE"),
		bundle,
		SyncOptions{CleanupOld: true},
	)
	if !IsConflict(err) {
		t.Fatalf("expected typed conflict, got %v", err)
	}
	if !result.Bound || result.UnboundOld || result.WroteMemory || destructiveCalls != 0 {
		t.Fatalf("unsafe conflict result: result=%#v destructiveCalls=%d", result, destructiveCalls)
	}
	if _, ok := findBinding(bindings, "old-cert"); !ok {
		t.Fatal("known-good old binding was removed after a conflict")
	}
	if _, ok := findBinding(bindings, desiredName); !ok {
		t.Fatal("new safe binding was not retained after a conflict")
	}
}

func TestSyncCertificateExpectedRevisionRejectsStaleCaller(t *testing.T) {
	bundle := newTestBundle(t, "revision.example")
	template := ClientSSLTemplate{
		Name:         "TLS_TEMPLATE",
		Certificates: []CertificateBinding{{Certificate: "old-cert", Key: "old-key"}},
	}
	stale := ClientSSLTemplate{Name: "TLS_TEMPLATE"}.Revision()
	var writes int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/version/oper":
			writeCompatibleVersion(t, w)
		case "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE":
			writeJSON(t, w, map[string]any{"client-ssl": template})
		case "/axapi/v3/logoff":
			w.WriteHeader(http.StatusOK)
		default:
			writes++
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	client, _ := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	_, err := client.SyncCertificate(
		context.Background(),
		ForClientSSLTemplate("TLS_TEMPLATE"),
		bundle,
		SyncOptions{ExpectedRevision: stale},
	)
	if !IsConflict(err) || writes != 0 {
		t.Fatalf("expected stale-revision conflict before writes, err=%v writes=%d", err, writes)
	}
}

func TestSyncCertificateRejectsExpiredLeafBeforeAuthentication(t *testing.T) {
	now := time.Now().UTC()
	certificatePEM, keyPEM := newTestPEMPairWithValidity(
		t,
		"expired.example",
		now.Add(-2*time.Hour),
		now.Add(-time.Hour),
	)
	bundle, err := ParseCertificateBundle(CertificateBundleInput{
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  keyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expired certificate reached the appliance")
	}))
	defer server.Close()
	client, err := New(Config{
		Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SyncCertificate(context.Background(), ForClientSSLTemplate("TLS_TEMPLATE"), bundle, SyncOptions{})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected local expiry error, got %v", err)
	}
}

func TestSyncCertificateHandlesAtomicBindingReplacementAndKeepsOldFiles(t *testing.T) {
	bundle := newTestBundle(t, "safe-default.example")
	desiredName, _, _ := managedNames(ForClientSSLTemplate("TLS_TEMPLATE"), bundle, "")
	bindings := []CertificateBinding{{Certificate: "old-cert", Key: "old-key"}}
	certificateFiles := map[string]bool{"old-cert": true}
	keyFiles := map[string]bool{"old-key": true}
	var deleteCalls int
	var unbindCalls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"token"}}`)
		case r.URL.Path == "/axapi/v3/version/oper":
			writeCompatibleVersion(t, w)
		case r.URL.Path == "/axapi/v3/logoff":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE":
			writeJSON(t, w, map[string]any{"client-ssl": ClientSSLTemplate{Name: "TLS_TEMPLATE", Certificates: bindings}})
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/file/ssl-cert/oper":
			writeFileInventory(t, w, "ssl-cert", certificateFiles)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/file/ssl-key/oper":
			writeFileInventory(t, w, "ssl-key", keyFiles)
		case r.Method == http.MethodGet && r.URL.Path == "/axapi/v3/slb/ssl-cert/oper":
			writeJSON(t, w, map[string]any{"ssl-cert": map[string]any{"oper": map[string]any{"ssl-certs": []CertificateInfo{}}}})
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/file/ssl-key":
			keyFiles[multipartUploadName(t, r, "ssl-key")] = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/file/ssl-cert":
			certificateFiles[multipartUploadName(t, r, "ssl-cert")] = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE/certificate":
			var document struct {
				Certificate CertificateBinding `json:"certificate"`
			}
			if err := json.NewDecoder(r.Body).Decode(&document); err != nil {
				t.Fatal(err)
			}
			// ACOS replaces the sole binding atomically on a non-SNI template.
			bindings = []CertificateBinding{document.Certificate}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/certificate/old-cert"):
			unbindCalls++
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/axapi/v3/pki/delete":
			deleteCalls++
			w.WriteHeader(http.StatusInternalServerError)
		case r.URL.Path == "/axapi/v3/write/memory":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	result, err := client.SyncCertificate(context.Background(), ForClientSSLTemplate("TLS_TEMPLATE"), bundle, SyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.UnboundOld || unbindCalls != 0 || deleteCalls != 0 || !certificateFiles["old-cert"] || !keyFiles["old-key"] {
		t.Fatalf("atomic replacement was mishandled: result=%#v certs=%v keys=%v unbinds=%d deletes=%d", result, certificateFiles, keyFiles, unbindCalls, deleteCalls)
	}
	if _, ok := findBinding(bindings, desiredName); !ok {
		t.Fatal("new certificate was not left bound")
	}
}

func TestSyncCertificateReconcilesFailedBindResponse(t *testing.T) {
	for _, test := range []struct {
		name          string
		applyDesired  bool
		wantAmbiguous bool
	}{
		{name: "desired state was applied", applyDesired: true},
		{name: "third state is ambiguous", wantAmbiguous: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			bundle := newTestBundle(t, "response-loss.example")
			desiredName, _, _ := managedNames(ForClientSSLTemplate("TLS_TEMPLATE"), bundle, "")
			bindings := []CertificateBinding{{Certificate: "old-cert", Key: "old-key"}}
			certificateFiles := map[string]bool{"old-cert": true}
			keyFiles := map[string]bool{"old-key": true}
			var writeCalls int
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch {
				case request.URL.Path == "/axapi/v3/auth":
					_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
				case request.URL.Path == "/axapi/v3/version/oper":
					writeCompatibleVersion(t, writer)
				case request.URL.Path == "/axapi/v3/logoff":
					writer.WriteHeader(http.StatusOK)
				case request.Method == http.MethodGet && request.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE":
					writeJSON(t, writer, map[string]any{"client-ssl": ClientSSLTemplate{Name: "TLS_TEMPLATE", Certificates: bindings}})
				case request.URL.Path == "/axapi/v3/file/ssl-cert/oper":
					writeFileInventory(t, writer, "ssl-cert", certificateFiles)
				case request.URL.Path == "/axapi/v3/file/ssl-key/oper":
					writeFileInventory(t, writer, "ssl-key", keyFiles)
				case request.URL.Path == "/axapi/v3/slb/ssl-cert/oper":
					writeJSON(t, writer, map[string]any{"ssl-cert": map[string]any{"oper": map[string]any{"ssl-certs": []CertificateInfo{}}}})
				case request.Method == http.MethodPost && request.URL.Path == "/axapi/v3/file/ssl-key":
					keyFiles[multipartUploadName(t, request, "ssl-key")] = true
					writer.WriteHeader(http.StatusNoContent)
				case request.Method == http.MethodPost && request.URL.Path == "/axapi/v3/file/ssl-cert":
					certificateFiles[multipartUploadName(t, request, "ssl-cert")] = true
					writer.WriteHeader(http.StatusNoContent)
				case request.Method == http.MethodPost && request.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE/certificate":
					var document struct {
						Certificate CertificateBinding `json:"certificate"`
					}
					if err := json.NewDecoder(request.Body).Decode(&document); err != nil {
						t.Fatal(err)
					}
					if test.applyDesired {
						bindings = []CertificateBinding{document.Certificate}
					} else {
						bindings = []CertificateBinding{{Certificate: "gui-cert", Key: "gui-key"}}
					}
					writer.WriteHeader(http.StatusInternalServerError)
				case request.URL.Path == "/axapi/v3/write/memory":
					writeCalls++
					writer.WriteHeader(http.StatusNoContent)
				default:
					t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
				}
			}))
			defer server.Close()
			client, _ := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
			result, err := client.ReconcileCertificate(context.Background(), ForClientSSLTemplate("TLS_TEMPLATE"), bundle, SyncOptions{})
			if test.wantAmbiguous {
				if !errors.Is(err, ErrAmbiguousState) || result.UnboundOld || writeCalls != 0 {
					t.Fatalf("unexpected ambiguous result: result=%#v err=%v writes=%d", result, err, writeCalls)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !result.Bound || !result.UnboundOld || !result.WroteMemory || result.Stage != SyncStageComplete || writeCalls != 1 {
				t.Fatalf("failed bind response was not reconciled: %#v writes=%d", result, writeCalls)
			}
			if binding, ok := findBinding(bindings, desiredName); !ok || binding.Key != KeyFileName(desiredName) {
				t.Fatalf("desired state not retained: %#v", bindings)
			}
		})
	}
}

func TestCleanupRetainsFilesReferencedByServerSSL(t *testing.T) {
	var deleteCalls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/slb/template/client-ssl":
			writeJSON(t, writer, map[string]any{"client-ssl-list": []ClientSSLTemplate{}})
		case "/axapi/v3/slb/template/server-ssl":
			_, _ = io.WriteString(writer, `{
				"server-ssl-list":[{
					"name":"BACKEND_MTLS",
					"certificate":{"cert":"old-cert","key":"old-key","shared":1,"encrypted":"redacted"}
				}]
			}`)
		case "/axapi/v3/pki/delete":
			deleteCalls++
			writer.WriteHeader(http.StatusNoContent)
		case "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.StartSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deleted, cleanupErr := session.deleteUnreferenced(
		context.Background(),
		CertificateBinding{Certificate: "old-cert", Key: "old-key"},
		CertificateBinding{Certificate: "new-cert", Key: "new-key"},
	)
	closeErr := session.Close(context.Background())
	if err := errors.Join(cleanupErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if deleteCalls != 0 || len(deleted) != 0 {
		t.Fatalf("server-SSL referenced files were deleted: calls=%d deleted=%v", deleteCalls, deleted)
	}
}

func TestCleanupRetainsFilesReferencedByUnknownACOS6Fields(t *testing.T) {
	var deleteCalls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/slb/template/client-ssl":
			_, _ = io.WriteString(writer, `{
				"client-ssl-list":[{
					"name":"FUTURE_ACOS6_TEMPLATE",
					"future-certificate-reference":"old-cert",
					"future-key-reference":"old-key",
					"future-chain-reference":"old-chain"
				}]
			}`)
		case "/axapi/v3/slb/template/server-ssl":
			_, _ = io.WriteString(writer, `{"server-ssl-list":[]}`)
		case "/axapi/v3/pki/delete":
			deleteCalls++
			writer.WriteHeader(http.StatusNoContent)
		case "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusOK)
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
	deleted, cleanupErr := session.deleteUnreferenced(
		context.Background(),
		CertificateBinding{Certificate: "old-cert", Key: "old-key", Chain: "old-chain"},
		CertificateBinding{Certificate: "new-cert", Key: "new-key", Chain: "new-chain"},
	)
	if err := errors.Join(cleanupErr, session.Close(context.Background())); err != nil {
		t.Fatal(err)
	}
	if deleteCalls != 0 || len(deleted) != 0 {
		t.Fatalf("unknown ACOS 6.x references were not handled fail-safe: calls=%d deleted=%v", deleteCalls, deleted)
	}
}

func TestClientSSLTemplateModelsSNIAndForwardProxyWithoutSecrets(t *testing.T) {
	var template ClientSSLTemplate
	if err := json.Unmarshal([]byte(`{
		"name":"TLS_TEMPLATE",
		"chain-cert":"legacy-chain",
		"forward-proxy-ca-cert":"legacy-ca-cert",
		"forward-proxy-ca-key":"legacy-ca-key",
		"fp-ca-certificate":"proxy-ca-cert",
		"fp-ca-key":"proxy-ca-key",
		"fp-ca-chain-cert":"proxy-ca-chain",
		"fp-alt-cert":"proxy-alt-cert",
		"fp-alt-key":"proxy-alt-key",
		"fp-alt-chain-cert":"proxy-alt-chain",
		"forward-passphrase":"must-not-escape",
		"server-name-list":[{
			"server-name":"www.example.test",
			"server-cert":"site-cert",
			"server-key":"site-key",
			"server-chain":"site-chain",
			"server-passphrase":"must-not-escape"
		}]
	}`), &template); err != nil {
		t.Fatal(err)
	}
	if len(template.ServerNames) != 1 || template.ServerNames[0].Certificate != "site-cert" ||
		template.ForwardProxy.AlternateChain != "proxy-alt-chain" || template.ChainCertificate != "legacy-chain" {
		t.Fatalf("incomplete typed client-SSL reference model: %#v", template)
	}
	encoded, err := json.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "must-not-escape") {
		t.Fatalf("reserved password field escaped the secret-free model: %s", encoded)
	}
}

func TestTemplateRevisionIsSemanticAndOrderIndependent(t *testing.T) {
	first := ClientSSLTemplate{Name: "TLS_TEMPLATE", UUID: "one", Certificates: []CertificateBinding{
		{Certificate: "a", Key: "a", Shared: true, UUID: "binding-one"},
		{Certificate: "b", Key: "b"},
	}}
	second := ClientSSLTemplate{Name: "TLS_TEMPLATE", UUID: "two", Certificates: []CertificateBinding{
		{Certificate: "b", Key: "b", A10URL: "/generated"},
		{Certificate: "a", Key: "a", Shared: true},
	}}
	if first.Revision() != second.Revision() {
		t.Fatal("binding order or generated metadata changed the logical revision")
	}
	second.Certificates[0].Key = "other-key"
	if first.Revision() == second.Revision() {
		t.Fatal("logical binding change did not change the revision")
	}
}

func TestTemplateRevisionDetectsUnknownVendorFieldChanges(t *testing.T) {
	var first, second ClientSSLTemplate
	if err := json.Unmarshal([]byte(`{
		"name":"TLS_TEMPLATE",
		"uuid":"generated-one",
		"cipher-template":"modern",
		"certificate-list":[{"cert":"site","key":"site","shared":0,"uuid":"binding-one"}]
	}`), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{
		"name":"TLS_TEMPLATE",
		"uuid":"generated-two",
		"cipher-template":"legacy",
		"certificate-list":[{"cert":"site","key":"site","shared":0,"uuid":"binding-two"}]
	}`), &second); err != nil {
		t.Fatal(err)
	}
	if first.Revision() == second.Revision() {
		t.Fatal("change to an otherwise unknown client-SSL field was not detected")
	}
	second.revisionPayload = []byte(`{
		"name":"TLS_TEMPLATE",
		"uuid":"different-generated-value",
		"cipher-template":"modern",
		"certificate-list":[{"cert":"site","key":"site","shared":0,"uuid":"different-binding-uuid"}]
	}`)
	if first.Revision() != second.Revision() {
		t.Fatal("generated UUID metadata changed the logical revision")
	}
}

func TestManagedCertificateCollisionUsesAvailableStrongMetadata(t *testing.T) {
	certificate := newTestBundle(t, "identity.example").Certificate
	inventory := []CertificateInfo{{
		Name: "managed", Serial: "0x" + certificate.Serial,
		CommonName:     certificate.parsed.Subject.CommonName,
		NotAfterNumber: certificate.parsed.NotAfter.Unix(), KeySize: 2048,
	}}
	if err := verifyManagedCertificateCollision(inventory, "managed", certificate); err != nil {
		t.Fatalf("matching managed certificate was rejected: %v", err)
	}
	inventory[0].KeySize = 4096
	if err := verifyManagedCertificateCollision(inventory, "managed", certificate); err == nil {
		t.Fatal("managed certificate collision with a different key size was accepted")
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func writeCompatibleVersion(t *testing.T, writer http.ResponseWriter) {
	t.Helper()
	writeJSON(t, writer, map[string]any{
		"version": map[string]any{"oper": VersionInfo{SoftwareVersion: "6.9.1, build 42", AXAPIVersion: "3.0"}},
	})
}

func writeFileInventory(t *testing.T, writer http.ResponseWriter, root string, values map[string]bool) {
	t.Helper()
	var files []map[string]string
	for name, exists := range values {
		if exists {
			files = append(files, map[string]string{"file": name})
		}
	}
	writeJSON(t, writer, map[string]any{root: map[string]any{"oper": map[string]any{"file-list": files}}})
}

func multipartUploadName(t *testing.T, request *http.Request, root string) string {
	t.Helper()
	if err := request.ParseMultipartForm(4 << 20); err != nil {
		t.Fatal(err)
	}
	part, _, err := request.FormFile("json")
	if err != nil {
		t.Fatal(err)
	}
	defer part.Close()
	var metadata map[string]map[string]any
	if err := json.NewDecoder(part).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	name, _ := metadata[root]["file"].(string)
	if name == "" {
		t.Fatalf("missing file in multipart metadata: %s", fmt.Sprint(metadata))
	}
	return name
}
