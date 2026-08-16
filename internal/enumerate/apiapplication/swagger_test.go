package apiapplication

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
)

func TestFindOpenAPISpecRebasesFallbackPathsAfterInitialRedirect(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/docs/", http.StatusFound)
		case "/docs/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>API docs</body></html>"))
		case "/docs/openapi":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"Example","version":"1.0.0"},"paths":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	specURL, _, _, err := findOpenAPISpec(context.Background(), server.URL, 5, false, "", common.UserAgentPresetChrome, nil, []string{"/openapi"})
	if err != nil {
		t.Fatalf("findOpenAPISpec() error = %v", err)
	}
	if want := server.URL + "/docs/openapi"; specURL != want {
		t.Fatalf("findOpenAPISpec() schema URL = %q, want %q", specURL, want)
	}
}

func TestFindOpenAPISpecPreservesOriginalFallbackPathsAfterInitialRedirect(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/docs", http.StatusFound)
		case "/docs":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>API docs</body></html>"))
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"Example","version":"1.0.0"},"paths":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	specURL, _, _, err := findOpenAPISpec(context.Background(), server.URL, 5, false, "", common.UserAgentPresetChrome, nil, []string{"/openapi.json"})
	if err != nil {
		t.Fatalf("findOpenAPISpec() error = %v", err)
	}
	if want := server.URL + "/openapi.json"; specURL != want {
		t.Fatalf("findOpenAPISpec() schema URL = %q, want %q", specURL, want)
	}
}

func TestExtractSpecURLFromRenderedContentResolvesRelativeToCanonicalDocument(t *testing.T) {
	t.Parallel()

	html := `<a href="openapi.json">spec</a>`
	specURLs := extractSpecURLFromRenderedContent(html, "https://example.com/docs/")
	if len(specURLs) != 1 {
		t.Fatalf("extractSpecURLFromRenderedContent() returned %d URLs, want 1", len(specURLs))
	}
	if want := "https://example.com/docs/openapi.json"; specURLs[0] != want {
		t.Fatalf("extractSpecURLFromRenderedContent() URL = %q, want %q", specURLs[0], want)
	}
}

func TestSwaggerInitialRequestAllowsCanonicalizationRedirects(t *testing.T) {
	t.Parallel()

	config := createSendHTTPRequestConfig("https://example.com", "", swaggerInitialMaxRedirects, true, 5, false, common.UserAgentPresetChrome, common.RequestMethodStandard, nil, nil)
	if config.MaxRedirects != swaggerInitialMaxRedirects {
		t.Fatalf("MaxRedirects = %d, want %d", config.MaxRedirects, swaggerInitialMaxRedirects)
	}
	if !config.IgnoreCrossDomainRedirects {
		t.Fatal("initial Swagger request should block cross-domain redirects")
	}
}

func TestFindOpenAPISpecDoesNotFollowProbeRedirects(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>API docs</body></html>"))
		case "/openapi":
			http.Redirect(w, r, "/real-openapi", http.StatusFound)
		case "/real-openapi":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"Example","version":"1.0.0"},"paths":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, _, _, err := findOpenAPISpec(context.Background(), server.URL, 5, false, "", common.UserAgentPresetChrome, nil, []string{"/openapi"})
	if err == nil {
		t.Fatal("findOpenAPISpec() should not accept a spec reached through a real probe redirect")
	}
}
