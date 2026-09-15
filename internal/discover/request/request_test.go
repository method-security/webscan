package discoverrequest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"
)

func TestPerformRequestPreservesEncodedPathOnWire(t *testing.T) {
	path := "/ftp/package.json.bak%2500.md"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.RequestURI != path {
			t.Errorf("server received RequestURI %q, want %q", request.RequestURI, path)
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	report := PerformRequest(context.Background(), discover.DiscoverRequestConfig{
		Target:          server.URL + path,
		HttpMethod:      common.HttpMethodGet,
		MaxRedirects:    0,
		FollowRedirects: false,
		VerifyTls:       true,
		Timeout:         5,
		UserAgent:       common.UserAgentPresetCurl,
	})
	if len(report.Errors) > 0 {
		t.Fatalf("PerformRequest() returned errors: %v", report.Errors)
	}
}
