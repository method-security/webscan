package cms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumeratecmswordpressfern "github.com/Method-Security/webscan/generated/go/enumerate/cms/wordpress"
)

func TestCMSProbeTargetURLKeepsOriginalRootForPageRedirect(t *testing.T) {
	t.Parallel()

	response := redirectResponse(
		"https://example.com",
		"https://www.example.com/wp-login.php?redirect_to=https%3A%2F%2Fexample.com%2F&reauth=1",
	)

	if got, want := cmsProbeTargetURL("https://example.com", response), "https://www.example.com"; got != want {
		t.Fatalf("cmsProbeTargetURL() = %q, want %q", got, want)
	}
}

func TestCMSProbeTargetURLUsesCanonicalDirectoryRoot(t *testing.T) {
	t.Parallel()

	response := redirectResponse(
		"https://example.com",
		"https://www.example.com/blog/",
	)

	if got, want := cmsProbeTargetURL("https://example.com", response), "https://www.example.com/blog/"; got != want {
		t.Fatalf("cmsProbeTargetURL() = %q, want %q", got, want)
	}
}

func TestCMSProbeTargetURLKeepsOriginalSubdirectoryForLoginPageRedirect(t *testing.T) {
	t.Parallel()

	response := redirectResponse(
		"https://example.com/site",
		"https://example.com/site/user/login",
	)

	if got, want := cmsProbeTargetURL("https://example.com/site", response), "https://example.com/site"; got != want {
		t.Fatalf("cmsProbeTargetURL() = %q, want %q", got, want)
	}
}

func TestWordPressPageRedirectDoesNotBecomeProbeRoot(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/wp-login.php?redirect_to=%2F&reauth=1", http.StatusFound)
		case "/wp-login.php":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>WordPress login</body></html>"))
		case "/wp-json":
			http.NotFound(w, r)
		case "/wp-content/plugins/akismet/readme.txt":
			_, _ = w.Write([]byte("=== Akismet ===\nStable tag: 5.4\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	config := &enumeratecmswordpressfern.EnumerateWordpressPluginsConfig{
		Plugins:   []string{"akismet"},
		Timeout:   5,
		UserAgent: common.UserAgentPresetChrome,
	}

	result, _ := scanTarget(context.Background(), server.URL, config)
	if len(result.Plugins) != 1 || result.Plugins[0].Name != "akismet" {
		t.Fatalf("scanTarget() plugins = %#v, want akismet found from the site root", result.Plugins)
	}
}

func redirectResponse(chain ...string) *common.HttpRequestResponse {
	return &common.HttpRequestResponse{
		Response: &common.HttpResponse{
			RedirectChain: chain,
		},
	}
}
