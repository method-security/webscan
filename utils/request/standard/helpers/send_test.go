package standard_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
