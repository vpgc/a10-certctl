package a10

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFindClientSSLTemplatesByVIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/axapi/v3/auth":
			_, _ = io.WriteString(writer, `{"authresponse":{"signature":"token"}}`)
		case "/axapi/v3/slb/virtual-server":
			_, _ = io.WriteString(writer, `{
				"virtual-server-list":[
					{"name":"VIP_HTTPS","ip-address":"10.0.0.20","port-list":[
						{"port-number":443,"protocol":"https","template-client-ssl":"TLS_SITE"},
						{"port-number":8443,"protocol":"tcp","template-client-ssl-shared":"SHARED_TLS"}
					]},
					{"name":"OTHER","ip-address":"10.0.0.21","port-list":[
						{"port-number":443,"protocol":"https","template-client-ssl":"OTHER_TLS"}
					]}
				]
			}`)
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
	bindings, findErr := session.FindClientSSLTemplatesByVIP(context.Background(), "10.0.0.20")
	if closeErr := session.Close(context.Background()); closeErr != nil {
		t.Fatal(closeErr)
	}
	if findErr != nil {
		t.Fatal(findErr)
	}
	if len(bindings) != 2 || bindings[0].ClientSSLTemplate != "TLS_SITE" ||
		bindings[1].ClientSSLTemplate != "SHARED_TLS" || !bindings[1].SharedPartitionTemplate {
		t.Fatalf("unexpected VIP bindings: %#v", bindings)
	}
}

func TestFindClientSSLTemplatesByVIPRejectsInvalidAddressBeforeRequest(t *testing.T) {
	session := &Session{}
	if _, err := session.FindClientSSLTemplatesByVIP(context.Background(), "not-an-ip"); err == nil {
		t.Fatal("invalid VIP address was accepted")
	}
}
