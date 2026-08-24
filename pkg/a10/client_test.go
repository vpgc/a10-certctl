package a10

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionAuthenticatesUsesSignatureAndLogsOff(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("User-Agent") != "a10-certctl/dev" {
			t.Fatalf("unexpected user agent %q", r.Header.Get("User-Agent"))
		}
		switch r.URL.Path {
		case "/axapi/v3/auth":
			var request authRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Credentials.Username != "admin" || request.Credentials.Password != "password" {
				t.Fatalf("unexpected credentials: %#v", request.Credentials)
			}
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"session-token"}}`)
		case "/axapi/v3/version/oper":
			if got := r.Header.Get("Authorization"); got != "A10 session-token" {
				t.Fatalf("unexpected authorization header %q", got)
			}
			_, _ = io.WriteString(w, `{"version":{"oper":{"sw-version":"6.0.8","axapi-version":"3.0"}}}`)
		case "/axapi/v3/logoff":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
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
	version, err := session.ACOSVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version.SoftwareVersion != "6.0.8" {
		t.Fatalf("unexpected version: %#v", version)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /axapi/v3/auth", "GET /axapi/v3/version/oper", "POST /axapi/v3/logoff"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("call sequence mismatch\nwant: %#v\n got: %#v", want, calls)
	}
}

func TestUploadCertificateUsesA10MultipartContract(t *testing.T) {
	certificatePEM, _ := newTestPEMPair(t, "multipart.example")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/file/ssl-cert":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Fatal(err)
			}
			jsonFile, jsonHeader, err := r.FormFile("json")
			if err != nil {
				t.Fatal(err)
			}
			defer jsonFile.Close()
			if jsonHeader.Filename != "blob" {
				t.Fatalf("unexpected JSON part filename %q", jsonHeader.Filename)
			}
			var metadata map[string]map[string]any
			if err := json.NewDecoder(jsonFile).Decode(&metadata); err != nil {
				t.Fatal(err)
			}
			if metadata["ssl-cert"]["action"] != "import" || metadata["ssl-cert"]["file-handle"] != "cert.pem" {
				t.Fatalf("unexpected metadata: %#v", metadata)
			}
			file, header, err := r.FormFile("file")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			data, _ := io.ReadAll(file)
			if header.Filename != "cert.pem" || string(data) != string(certificatePEM) {
				t.Fatal("certificate multipart part mismatch")
			}
			w.WriteHeader(http.StatusNoContent)
		case "/axapi/v3/logoff":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	client, _ := New(Config{Address: server.URL, Username: "admin", Password: "password", HTTPClient: server.Client()})
	session, err := client.StartSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close(context.Background())
	if err := session.UploadCertificate(context.Background(), "cert.pem", certificatePEM, UploadOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestAPIErrorIsStructuredAndDoesNotEchoRequestSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"response":{"err":{"code":42,"msg":"bad credentials","location":"credentials"}}}`)
	}))
	defer server.Close()
	client, _ := New(Config{Address: server.URL, Username: "admin", Password: "top-secret", HTTPClient: server.Client()})
	_, err := client.StartSession(context.Background())
	if err == nil {
		t.Fatal("authentication unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "top-secret") || !strings.Contains(err.Error(), "aXAPI code 42") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("authentication category was lost: %v", err)
	}
	if strings.Contains(err.Error(), "bad credentials") {
		t.Fatalf("appliance response text was included in the log-safe error: %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Message != "bad credentials" {
		t.Fatalf("structured appliance detail was not retained: %#v", apiErr)
	}
}

func TestEndpointEscapesSpacesOnce(t *testing.T) {
	client, err := New(Config{Address: "https://a10.example", Username: "admin", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	got := client.endpoint("/slb/template/client-ssl/name with space")
	want := "https://a10.example/axapi/v3/slb/template/client-ssl/name%20with%20space"
	if got != want {
		t.Fatalf("endpoint mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestEndpointPreservesQueryString(t *testing.T) {
	client, err := New(Config{Address: "https://a10.example", Username: "admin", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	got := client.endpoint("/slb/ssl-cert/oper?sortby-name=true")
	want := "https://a10.example/axapi/v3/slb/ssl-cert/oper?sortby-name=true"
	if got != want {
		t.Fatalf("endpoint mismatch\nwant: %s\n got: %s", want, got)
	}
}

func TestConfigurationRejectsUnsafeOrAmbiguousManagementTransport(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   string
	}{
		{
			name:   "plain HTTP without custom transport",
			config: Config{Address: "http://a10.example", Username: "admin", Password: "password"},
			want:   "must use https",
		},
		{
			name:   "credentials in URL",
			config: Config{Address: "https://admin:password@a10.example", Username: "admin", Password: "password"},
			want:   "must not contain credentials",
		},
		{
			name: "contradictory TLS settings",
			config: Config{
				Address: "https://a10.example", Username: "admin", Password: "password",
				InsecureSkipVerify: true, TrustedCertificate: "management-ca.pem",
			},
			want: "cannot be combined",
		},
		{
			name:   "negative timeout",
			config: Config{Address: "https://a10.example", Username: "admin", Password: "password", Timeout: -time.Second},
			want:   "must not be negative",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestObjectNamesRejectPathSeparators(t *testing.T) {
	if err := validateObjectName("client-SSL template", "parent/child"); err == nil {
		t.Fatal("path separator was accepted")
	}
}

func TestSessionCloseWaitsForInflightRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	loggedOff := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(w, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/slow":
			close(started)
			<-release
			w.WriteHeader(http.StatusOK)
		case "/axapi/v3/logoff":
			close(loggedOff)
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
	requestDone := make(chan error, 1)
	go func() {
		requestDone <- session.Raw().DoJSON(context.Background(), http.MethodGet, "/slow", nil, nil, http.StatusOK)
	}()
	<-started
	closeDone := make(chan error, 1)
	go func() { closeDone <- session.Close(context.Background()) }()
	select {
	case <-loggedOff:
		t.Fatal("session logged off while a request was still in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if err := session.Raw().DoJSON(context.Background(), http.MethodGet, "/slow", nil, nil, http.StatusOK); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed session accepted a request: %v", err)
	}
}
