package discoverpage_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"
	discoverpage "github.com/Method-Security/webscan/internal/discover/page"
)

func TestPageCaptureCapturesFilteredWafResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<title>Attention Required! | Cloudflare</title>Cloudflare's security service blocked this request"))
	}))
	t.Cleanup(server.Close)

	report := discoverpage.PerformPageCapture(context.Background(), discover.DiscoverPageConfig{
		Target:                     server.URL,
		ResponseCodes:              "200-299",
		MaxRedirects:               5,
		Timeout:                    10,
		IgnoreCrossDomainRedirects: true,
		UserAgent:                  common.UserAgentPresetCurl,
		RequestMethod:              common.RequestMethodStandard,
	}, nil)

	if report.Result.Request != nil {
		t.Fatal("expected filtered response to stay out of the page request field")
	}
	if report.Result.HtmlTitle != nil {
		t.Fatalf("expected title from filtered response to be omitted, got %q", *report.Result.HtmlTitle)
	}
	if report.Result.WafDetection == nil || report.Result.WafDetection.Request == nil || report.Result.WafDetection.Request.Response == nil {
		t.Fatal("expected WAF detection with its filtered request response")
	}
	if report.Result.WafDetection.Provider != common.WafProviderEnumCloudflare {
		t.Fatalf("expected Cloudflare WAF detection, got %s", report.Result.WafDetection.Provider)
	}
	if status := report.Result.WafDetection.Request.Response.StatusCode; status == nil || *status != http.StatusForbidden {
		t.Fatalf("expected captured WAF status %d, got %v", http.StatusForbidden, status)
	}
}
