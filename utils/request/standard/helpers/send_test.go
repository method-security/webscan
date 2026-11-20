package standard_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	standardhelpers "github.com/Method-Security/webscan/utils/request/standard/helpers"
)

func TestSendHTTPRequestReusesContextClientConnections(t *testing.T) {
	var newConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	config := common.SendHttpRequestConfig{
		Request:   &common.HttpRequest{Method: common.HttpMethodGet},
		Timeout:   5,
		VerifyTls: true,
	}
	ctx := standardhelpers.WithReusableClient(context.Background(), config)

	for i := 0; i < 2; i++ {
		resp, _, err := standardhelpers.SendHTTPRequest(ctx, server.URL, nil, nil, config)
		if err != nil {
			t.Fatalf("SendHTTPRequest returned error: %v", err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatalf("closing response body: %v", err)
		}
	}

	if got := newConnections.Load(); got != 1 {
		t.Fatalf("expected one reused connection, got %d", got)
	}
}

func TestSendHTTPRequestScopeDecidesCrossDomainRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/landed" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		http.Redirect(w, r, strings.Replace(serverURL(r), "127.0.0.1", "localhost", 1)+"/landed", http.StatusFound)
	}))
	defer server.Close()

	cases := []struct {
		name    string
		domains []string
		cidrs   []string
		blocked bool
	}{
		{"any host is followed without a scope", nil, nil, false},
		{"seeded host is followed", []string{"localhost"}, nil, false},
		{"unseeded host is blocked", []string{"other.test"}, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			config := common.SendHttpRequestConfig{
				Request:      &common.HttpRequest{Method: common.HttpMethodGet},
				Timeout:      5,
				MaxRedirects: 3,
				ScopeDomains: c.domains,
				ScopeCidrs:   c.cidrs,
			}
			resp, _, err := standardhelpers.SendHTTPRequest(context.Background(), server.URL+"/start", nil, nil, config)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if c.blocked && (err == nil || !strings.Contains(err.Error(), "out-of-scope redirect blocked")) {
				t.Fatalf("expected the redirect to be blocked, got %v", err)
			}
			if !c.blocked && err != nil {
				t.Fatalf("expected the redirect to be followed, got %v", err)
			}
		})
	}
}

func serverURL(r *http.Request) string {
	return "http://" + r.Host
}
