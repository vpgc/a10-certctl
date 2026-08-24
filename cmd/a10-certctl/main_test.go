package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDomainMatches(t *testing.T) {
	tests := []struct {
		domain, commonName string
		want               bool
	}{
		{"www.example.com", "www.example.com", true},
		{"WWW.EXAMPLE.COM.", "www.example.com", true},
		{"api.example.com", "*.example.com", true},
		{"deep.api.example.com", "*.example.com", false},
		{"example.com", "*.example.com", false},
	}
	for _, test := range tests {
		if got := domainMatches(test.domain, test.commonName); got != test.want {
			t.Errorf("domainMatches(%q, %q) = %t, want %t", test.domain, test.commonName, got, test.want)
		}
	}
}

func TestRunBuildInfoNeedsNoApplianceCredentials(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"build-info"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"version": "dev"`) {
		t.Fatalf("unexpected build info: %s", stdout.String())
	}
}

func TestRunVersionUsesAuthenticatedSessionAndPrintsNoPassword(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls = append(calls, request.Method+" "+request.URL.Path)
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/version/oper":
			_, _ = io.WriteString(writer, `{"version":{"oper":{"sw-version":"6.0.8","axapi-version":"3.0"}}}`)
		case "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--host", server.URL,
		"--allow-insecure-http",
		"--username", "admin",
		"--password", "top-secret",
		"version",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"sw-version": "6.0.8"`) || strings.Contains(stdout.String(), "top-secret") {
		t.Fatalf("unsafe or incomplete output: %s", stdout.String())
	}
	want := []string{"POST /axapi/v3/auth", "GET /axapi/v3/version/oper", "POST /axapi/v3/logoff"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected calls: %v", calls)
	}
}

func TestRunPreflightReportsContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/version/oper":
			_, _ = io.WriteString(writer, `{"version":{"oper":{"sw-version":"6.4.2, build 7","axapi-version":"3.0"}}}`)
		case "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--host", server.URL, "--allow-insecure-http", "--username", "admin", "--password", "secret", "preflight",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"compatible": true`) ||
		!strings.Contains(stdout.String(), `"contract": "ACOS 6.x.y"`) ||
		!strings.Contains(stdout.String(), `"testedWith": "6.0.9, build 116"`) {
		t.Fatalf("unexpected preflight output: %s", stdout.String())
	}
}

func TestMutatingCommandRejectsUnsupportedMajorBeforeMutation(t *testing.T) {
	var mutationCalls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/version/oper":
			_, _ = io.WriteString(writer, `{"version":{"oper":{"sw-version":"7.0.0","axapi-version":"3.0"}}}`)
		case "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusOK)
		default:
			mutationCalls++
			writer.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--host", server.URL, "--allow-insecure-http", "--username", "admin", "--password", "secret",
		"bind", "--template", "TLS_TEMPLATE", "--cert", "site-cert", "--key", "site-key", "--no-write-memory",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "unsupported ACOS version") || mutationCalls != 0 {
		t.Fatalf("unsupported appliance reached mutation: err=%v mutations=%d", err, mutationCalls)
	}
}

func TestRunStatusResolvesLogicalTemplateSlot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE":
			_, _ = io.WriteString(writer, `{"client-ssl":{"name":"TLS_TEMPLATE","certificate-list":[{"cert":"site-cert","key":"site-key","shared":0}]}}`)
		case "/axapi/v3/slb/ssl-cert/oper":
			_, _ = io.WriteString(writer, `{"ssl-cert":{"oper":{"ssl-certs":[{"name":"site-cert","common-name":"site.example"}]}}}`)
		case "/axapi/v3/file/ssl-key/oper":
			_, _ = io.WriteString(writer, `{"ssl-key":{"oper":{"file-list":[{"file":"site-key"}]}}}`)
		case "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--host", server.URL, "--allow-insecure-http", "--username", "admin", "--password", "secret",
		"status", "--template", "TLS_TEMPLATE",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"templateRevision": "sha256:`) ||
		!strings.Contains(stdout.String(), `"common-name": "site.example"`) ||
		strings.Contains(stdout.String(), "secret") {
		t.Fatalf("unexpected status output: %s", stdout.String())
	}
}

func TestRunDeleteRejectsPathBeforeAuthentication(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--host", "http://127.0.0.1:1", "--allow-insecure-http", "--username", "admin", "--password", "secret",
		"delete", "--cert", "../unsafe",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "path separator") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAdministrativeCommands(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case request.URL.Path == "/axapi/v3/logoff":
			writer.WriteHeader(http.StatusOK)
		case request.URL.Path == "/axapi/v3/version/oper":
			_, _ = io.WriteString(writer, `{"version":{"oper":{"sw-version":"6.7.2, build 9","axapi-version":"3.0"}}}`)
		case request.Method == http.MethodGet && request.URL.Path == "/axapi/v3/slb/ssl-cert/oper":
			_, _ = io.WriteString(writer, `{"ssl-cert":{"oper":{"ssl-certs":[{"name":"site-cert","common-name":"www.example.com"}]}}}`)
		case request.Method == http.MethodGet && request.URL.Path == "/axapi/v3/slb/template/client-ssl":
			_, _ = io.WriteString(writer, `{"client-ssl-list":[{"name":"TLS_TEMPLATE","certificate-list":[{"cert":"site-cert","key":"site-key"}]}]}`)
		case request.Method == http.MethodPost && request.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE/certificate":
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodDelete && request.URL.Path == "/axapi/v3/slb/template/client-ssl/TLS_TEMPLATE/certificate/site-cert":
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && request.URL.Path == "/axapi/v3/pki/delete":
			writer.WriteHeader(http.StatusNoContent)
		case request.Method == http.MethodPost && request.URL.Path == "/axapi/v3/write/memory":
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()

	common := []string{
		"--host", server.URL,
		"--allow-insecure-http",
		"--username", "admin",
		"--password", "secret",
	}
	tests := []struct {
		name       string
		arguments  []string
		wantOutput string
	}{
		{name: "list", arguments: []string{"list"}, wantOutput: `"site-cert"`},
		{name: "templates", arguments: []string{"templates"}, wantOutput: `"TLS_TEMPLATE"`},
		{name: "find domain", arguments: []string{"find-domain", "--domain", "www.example.com"}, wantOutput: `"www.example.com"`},
		{name: "bind", arguments: []string{"bind", "--template", "TLS_TEMPLATE", "--cert", "site-cert", "--key", "site-key", "--chain", "site-chain", "--no-write-memory"}},
		{name: "unbind", arguments: []string{"unbind", "--template", "TLS_TEMPLATE", "--cert", "site-cert", "--no-write-memory"}},
		{name: "delete", arguments: []string{"delete", "--cert", "site-cert", "--key", "site-key", "--chain", "site-chain", "--ca", "trust-ca", "--no-write-memory"}},
		{name: "write memory", arguments: []string{"write-memory"}, wantOutput: "saved"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			arguments := append(append([]string(nil), common...), test.arguments...)
			if err := run(arguments, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			if test.wantOutput != "" && !strings.Contains(stdout.String(), test.wantOutput) {
				t.Fatalf("output %q does not contain %q", stdout.String(), test.wantOutput)
			}
			if strings.Contains(stdout.String(), "secret") || strings.Contains(stderr.String(), "secret") {
				t.Fatal("CLI output leaked the appliance password")
			}
		})
	}
}

func TestRunHelpAndUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("help output is incomplete: %s", stdout.String())
	}
	if err := run([]string{"--host", "https://a10.example", "--username", "admin", "--password", "secret", "unknown"}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unexpected unknown-command result: %v", err)
	}
}
