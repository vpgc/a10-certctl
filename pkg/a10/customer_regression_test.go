package a10

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestEmptyPartitionInventoriesAcceptNoContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/file/ssl-cert/oper", "/axapi/v3/file/ssl-key/oper", "/axapi/v3/file/ca-cert/oper",
			"/axapi/v3/slb/ssl-cert/oper", "/axapi/v3/slb/template/client-ssl", "/axapi/v3/slb/virtual-server":
			writer.WriteHeader(http.StatusNoContent)
		case "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusNoContent)
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
	defer session.Close(context.Background())
	certificates, err := session.ListCertificateFiles(context.Background())
	if err != nil || len(certificates) != 0 {
		t.Fatalf("certificate files: %#v, %v", certificates, err)
	}
	keys, err := session.ListKeyFiles(context.Background())
	if err != nil || len(keys) != 0 {
		t.Fatalf("key files: %#v, %v", keys, err)
	}
	cas, err := session.ListCAFiles(context.Background())
	if err != nil || len(cas) != 0 {
		t.Fatalf("CA files: %#v, %v", cas, err)
	}
	operational, err := session.ListCertificates(context.Background())
	if err != nil || len(operational) != 0 {
		t.Fatalf("operational certificates: %#v, %v", operational, err)
	}
	templates, err := session.ListClientSSLTemplates(context.Background())
	if err != nil || len(templates) != 0 {
		t.Fatalf("client-SSL templates: %#v, %v", templates, err)
	}
	virtualServers, err := session.ListVirtualServers(context.Background())
	if err != nil || len(virtualServers) != 0 {
		t.Fatalf("virtual servers: %#v, %v", virtualServers, err)
	}
}

func TestPartitionCanBeSelectedByIDAndWriteMemoryUsesResolvedName(t *testing.T) {
	var active activePartitionDocument
	var write writeMemoryDocument
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/partition":
			writeJSON(t, writer, map[string]any{"partition-list": []Partition{{Name: "pre-prod-tag2", ID: 2}}})
		case "/axapi/v3/active-partition":
			if err := json.NewDecoder(request.Body).Decode(&active); err != nil {
				t.Fatal(err)
			}
			writer.WriteHeader(http.StatusNoContent)
		case "/axapi/v3/write/memory":
			if err := json.NewDecoder(request.Body).Decode(&write); err != nil {
				t.Fatal(err)
			}
			writer.WriteHeader(http.StatusNoContent)
		case "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(Config{Address: server.URL, Username: "admin", Password: "password", Partition: "2", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.StartSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := session.ActivePartition(); got != (Partition{Name: "pre-prod-tag2", ID: 2}) {
		t.Fatalf("unexpected active partition: %#v", got)
	}
	if err := session.WriteMemory(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active.Partition.Name != "pre-prod-tag2" {
		t.Fatalf("unexpected active-partition request: %#v", active)
	}
	want := writeMemoryDocument{}
	want.Memory.Destination = "primary"
	want.Memory.Partition = "specified"
	want.Memory.SpecifiedPartition = "pre-prod-tag2"
	if !reflect.DeepEqual(write, want) {
		t.Fatalf("unexpected write-memory request: %#v", write)
	}
}

func TestWriteMemoryUsesSharedPartitionWithoutSelector(t *testing.T) {
	var write writeMemoryDocument
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/write/memory":
			if err := json.NewDecoder(request.Body).Decode(&write); err != nil {
				t.Fatal(err)
			}
			writer.WriteHeader(http.StatusNoContent)
		case "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusNoContent)
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
	defer session.Close(context.Background())
	if err := session.WriteMemory(context.Background()); err != nil {
		t.Fatal(err)
	}
	if write.Memory.Destination != "primary" || write.Memory.Partition != "shared" || write.Memory.SpecifiedPartition != "" {
		t.Fatalf("unexpected write-memory request: %#v", write)
	}
}

func TestCreateManagedCertificateRollsBackUploadsWhenWriteMemoryFails(t *testing.T) {
	bundle := newTestBundle(t, "rollback.example")
	certificateFiles := map[string]bool{}
	keyFiles := map[string]bool{}
	var deleteCalls int
	var writeCalls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case request.URL.Path == "/axapi/v3/version/oper":
			writeCompatibleVersion(t, writer)
		case request.URL.Path == "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && request.URL.Path == "/axapi/v3/file/ssl-cert/oper":
			if len(certificateFiles) == 0 {
				writer.WriteHeader(http.StatusNoContent)
			} else {
				writeFileInventory(t, writer, "ssl-cert", certificateFiles)
			}
		case request.Method == http.MethodGet && request.URL.Path == "/axapi/v3/file/ssl-key/oper":
			if len(keyFiles) == 0 {
				writer.WriteHeader(http.StatusNoContent)
			} else {
				writeFileInventory(t, writer, "ssl-key", keyFiles)
			}
		case request.URL.Path == "/axapi/v3/slb/ssl-cert/oper":
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && request.URL.Path == "/axapi/v3/file/ssl-key":
			keyFiles[multipartUploadName(t, request, "ssl-key")] = true
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && request.URL.Path == "/axapi/v3/file/ssl-cert":
			certificateFiles[multipartUploadName(t, request, "ssl-cert")] = true
			writer.WriteHeader(http.StatusNoContent)
		case request.URL.Path == "/axapi/v3/write/memory":
			writeCalls++
			if writeCalls == 1 {
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(writer, `{"response":{"err":{"code":1023524871,"msg":"bad memory payload","location":"memory"}}}`)
			} else {
				writer.WriteHeader(http.StatusNoContent)
			}
		case request.URL.Path == "/axapi/v3/pki/delete":
			deleteCalls++
			var body deleteMaterialDocument
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			delete(certificateFiles, body.Delete.Certificate.String())
			delete(keyFiles, body.Delete.Key.String())
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	result, err := client.CreateManagedCertificate(context.Background(), bundle, CreateOptions{NamePrefix: "rollback"})
	if err == nil || errors.Is(err, ErrAmbiguousState) {
		t.Fatalf("expected original persistence error after successful rollback, got %v", err)
	}
	if !result.RolledBack || result.Stage != SyncStageRolledBack || deleteCalls != 1 || writeCalls != 2 {
		t.Fatalf("unexpected rollback result: %#v, deletes=%d writes=%d", result, deleteCalls, writeCalls)
	}
	if len(certificateFiles) != 0 || len(keyFiles) != 0 {
		t.Fatalf("uploaded material remained: certificates=%v keys=%v", certificateFiles, keyFiles)
	}
}

func TestSyncCertificateRestoresBaselineWhenWriteMemoryFails(t *testing.T) {
	bundle := newTestBundle(t, "sync-rollback.example")
	desiredName, _, err := managedNames(ForClientSSLTemplate("TLS_TEMPLATE"), bundle, "")
	if err != nil {
		t.Fatal(err)
	}
	bindings := []CertificateBinding{{Certificate: "old-cert", Key: "old-key"}}
	certificateFiles := map[string]bool{"old-cert": true}
	keyFiles := map[string]bool{"old-key": true}
	writeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case request.URL.Path == "/axapi/v3/version/oper":
			writeCompatibleVersion(t, writer)
		case request.URL.Path == "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodGet && request.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE":
			writeJSON(t, writer, map[string]any{"client-ssl": ClientSSLTemplate{Name: "TLS_TEMPLATE", Certificates: bindings}})
		case request.Method == http.MethodGet && request.URL.Path == "/axapi/v3/file/ssl-cert/oper":
			writeFileInventory(t, writer, "ssl-cert", certificateFiles)
		case request.Method == http.MethodGet && request.URL.Path == "/axapi/v3/file/ssl-key/oper":
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
			var body struct {
				Certificate CertificateBinding `json:"certificate"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			bindings = append(bindings, body.Certificate)
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodDelete && request.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE/certificate/old-cert":
			bindings = removeTestBinding(bindings, "old-cert")
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodDelete && request.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE/certificate/"+desiredName.String():
			bindings = removeTestBinding(bindings, desiredName)
			writer.WriteHeader(http.StatusNoContent)
		case request.URL.Path == "/axapi/v3/pki/delete":
			var body deleteMaterialDocument
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			delete(certificateFiles, body.Delete.Certificate.String())
			delete(keyFiles, body.Delete.Key.String())
			writer.WriteHeader(http.StatusNoContent)
		case request.URL.Path == "/axapi/v3/write/memory":
			writeCalls++
			if writeCalls == 1 {
				writer.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(writer, `{"response":{"err":{"code":1,"msg":"injected persistence failure","location":"memory"}}}`)
			} else {
				writer.WriteHeader(http.StatusNoContent)
			}
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	result, err := client.SyncCertificate(context.Background(), ForClientSSLTemplate("TLS_TEMPLATE"), bundle, SyncOptions{})
	if err == nil || errors.Is(err, ErrAmbiguousState) {
		t.Fatalf("expected original persistence error after successful rollback, got %v", err)
	}
	if !result.RolledBack || result.Stage != SyncStageRolledBack || writeCalls != 2 {
		t.Fatalf("unexpected rollback result: %#v writes=%d", result, writeCalls)
	}
	if len(bindings) != 1 || bindings[0].Certificate != "old-cert" || bindings[0].Key != "old-key" {
		t.Fatalf("baseline binding was not restored: %#v", bindings)
	}
	if certificateFiles[desiredName.String()] || keyFiles[desiredName.String()] {
		t.Fatalf("desired material remained after rollback: certificates=%v keys=%v", certificateFiles, keyFiles)
	}
}

func removeTestBinding(bindings []CertificateBinding, name CertificateFileName) []CertificateBinding {
	result := bindings[:0]
	for _, binding := range bindings {
		if binding.Certificate != name {
			result = append(result, binding)
		}
	}
	return result
}
