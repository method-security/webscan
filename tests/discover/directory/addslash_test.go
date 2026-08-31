package directory_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
	discoverdirectory "github.com/Method-Security/webscan/internal/discover/directory"
)

// aliasServer mimics an nginx location with an alias and no autoindex: the bare path falls
// through to the catch-all and 404s, and only the directory form reveals the directory.
type aliasServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
}

func newAliasServer(t *testing.T) *aliasServer {
	t.Helper()
	s := &aliasServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.URL.Path)
		s.mu.Unlock()

		switch r.URL.Path {
		case "/static/":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<html><head><title>403 Forbidden</title></head><body>forbidden</body></html>"))
		case "/pub/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body><h1>Index of /pub</h1><a href=\"docs/\">docs/</a></body></html>"))
		case "/pub/secret/":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<html><head><title>403 Forbidden</title></head><body>nothing here for you</body></html>"))
		case "/.well-known/":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<html><head><title>403 Forbidden</title></head><body>forbidden</body></html>"))
		case "/static/app.js":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`var PLATFORM = { token: "seeded-integration-token", base: "/api/v1" };`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<html><head><title>404 Not Found</title></head><body>the requested url was not found on this server</body></html>"))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *aliasServer) saw(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, seen := range s.requests {
		if seen == path {
			return true
		}
	}
	return false
}

func boolPtr(v bool) *bool { return &v }
func intPtr(v int) *int    { return &v }

func directoryConfig(target string, addSlash bool, recursionDepth int) discover.DiscoverDirectoryConfig {
	return discover.DiscoverDirectoryConfig{
		Targets:                     []string{target},
		Paths:                       []string{"static", "app", ".well-known", "pub", "secret"},
		Extensions:                  []string{"js"},
		AddSlash:                    boolPtr(addSlash),
		RecursionDepth:              intPtr(recursionDepth),
		HttpMethods:                 []common.HttpMethod{common.HttpMethodGet},
		ResponseCodes:               "200-299,403",
		EnableCommonResponseFilters: true,
		VerifyTls:                   false,
		Threshold:                   0.25,
		Timeout:                     10,
		GlobalRateLimit:             0,
		IgnoreCrossDomainRedirects:  true,
		MaxRedirectsBaselineRequest: 5,
		GlobalTimeout:               60,
		Retries:                     0,
		Sleep:                       0,
		Jitter:                      0,
		Threads:                     4,
		UserAgent:                   common.UserAgentPresetCurl,
	}
}

func findingPaths(t *testing.T, report *discover.DiscoverDirectoryReport) []string {
	t.Helper()
	var paths []string
	for _, target := range report.Result.Targets {
		for _, attempt := range target.Attempts {
			if attempt.Request != nil {
				paths = append(paths, attempt.Request.Path)
			}
		}
	}
	sort.Strings(paths)
	return paths
}

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

// Without add-slash the directory form is never requested, so the directory and everything
// under it stay invisible however the sweep is otherwise configured.
func TestDirectoryDiscoveryWithoutAddSlashMissesTheDirectory(t *testing.T) {
	server := newAliasServer(t)

	report, err := discoverdirectory.RunDirectoryDiscovery(context.Background(), directoryConfig(server.URL, false, 1))
	if err != nil {
		t.Fatalf("RunDirectoryDiscovery returned error: %v", err)
	}

	if server.saw("/static/") {
		t.Error("the directory form was requested with add-slash off")
	}
	if got := findingPaths(t, report); len(got) != 0 {
		t.Errorf("expected no findings, got %q", got)
	}
}

// With add-slash the 403 on the directory form opens a frontier, and the bundle underneath it
// becomes reachable. Both wordlist entries are bare words; the .js comes from extensions.
func TestDirectoryDiscoveryWithAddSlashReachesTheBundle(t *testing.T) {
	server := newAliasServer(t)

	report, err := discoverdirectory.RunDirectoryDiscovery(context.Background(), directoryConfig(server.URL, true, 1))
	if err != nil {
		t.Fatalf("RunDirectoryDiscovery returned error: %v", err)
	}

	if !server.saw("/static/") {
		t.Fatal("the directory form was never requested with add-slash on")
	}

	// The 403 bodies are identical across both directories, so the common-response detector
	// collapses them as findings. The frontier they open is the point, not the finding.
	if found := findingPaths(t, report); !contains(found, "/static/app.js") {
		t.Errorf("expected /static/app.js among findings, got %q", found)
	}

	var frontiers []string
	for _, target := range report.Result.Targets {
		for _, frontier := range target.Frontiers {
			frontiers = append(frontiers, frontier.BasePath)
		}
	}
	if !contains(frontiers, "/static/") {
		t.Errorf("expected /static/ to open a frontier, got %q", frontiers)
	}
}

// The slash is added to the entry as supplied, never to a variant we derived by appending an
// extension, so /app.js/ is never probed.
func TestDirectoryDiscoveryDoesNotSlashExtensionVariants(t *testing.T) {
	server := newAliasServer(t)

	if _, err := discoverdirectory.RunDirectoryDiscovery(context.Background(), directoryConfig(server.URL, true, 1)); err != nil {
		t.Fatalf("RunDirectoryDiscovery returned error: %v", err)
	}

	for _, path := range []string{"/app.js/", "/static/app.js/"} {
		if server.saw(path) {
			t.Errorf("an extension-derived variant was probed with a trailing slash: %s", path)
		}
	}
}

// A dotted name is a directory as often as it is a file. .well-known, .git and .svn are all
// commonly served only through the directory form, so they must still get the slash probe.
func TestDirectoryDiscoverySlashesDottedDirectories(t *testing.T) {
	server := newAliasServer(t)

	report, err := discoverdirectory.RunDirectoryDiscovery(context.Background(), directoryConfig(server.URL, true, 1))
	if err != nil {
		t.Fatalf("RunDirectoryDiscovery returned error: %v", err)
	}

	if !server.saw("/.well-known/") {
		t.Fatal("a dotted directory entry never received a trailing-slash probe")
	}
	var frontiers []string
	for _, target := range report.Result.Targets {
		for _, frontier := range target.Frontiers {
			frontiers = append(frontiers, frontier.BasePath)
		}
	}
	if !contains(frontiers, "/.well-known/") {
		t.Errorf("expected /.well-known/ to open a frontier, got %q", frontiers)
	}
}

// Every 403 on a host tends to share one boilerplate body, so the common-response detector
// collapses them. Recursion must still descend, or a second forbidden directory anywhere on the
// host silently switches the feature off.
func TestDirectoryDiscoveryRecursesDespiteIdenticalForbiddenBodies(t *testing.T) {
	server := newAliasServer(t)

	report, err := discoverdirectory.RunDirectoryDiscovery(context.Background(), directoryConfig(server.URL, true, 1))
	if err != nil {
		t.Fatalf("RunDirectoryDiscovery returned error: %v", err)
	}

	var frontiers []string
	for _, target := range report.Result.Targets {
		for _, frontier := range target.Frontiers {
			frontiers = append(frontiers, frontier.BasePath)
		}
	}
	for _, want := range []string{"/static/", "/.well-known/"} {
		if !contains(frontiers, want) {
			t.Errorf("expected %q to open a frontier despite the shared 403 body, got %q", want, frontiers)
		}
	}
}

// A 2xx outside response-codes never reaches the findings pipeline, so it has to be judged on
// status like any other unfiltered response. Restricting findings to 403 must not stop a live
// 200 directory from opening a frontier.
func TestDirectoryDiscoveryRecursesIntoSuccessOutsideResponseCodes(t *testing.T) {
	server := newAliasServer(t)

	config := directoryConfig(server.URL, true, 1)
	config.ResponseCodes = "403"

	if _, err := discoverdirectory.RunDirectoryDiscovery(context.Background(), config); err != nil {
		t.Fatalf("RunDirectoryDiscovery returned error: %v", err)
	}

	// Asserted against the requests the server received rather than the report: with findings
	// restricted to 403 this target produces none, and a target with no findings is not reported.
	if !server.saw("/pub/") {
		t.Fatal("the 200 directory was never probed")
	}
	if !server.saw("/pub/secret/") {
		t.Error("a 200 directory outside response-codes did not open a frontier")
	}
}

func TestDirectoryDiscoveryReportsTargetWafDetectionFromFilteredAttempt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-Mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Cloudflare's security service blocked this request"))
	}))
	t.Cleanup(server.Close)

	config := directoryConfig(server.URL, false, 0)
	config.Paths = []string{"admin"}
	config.ResponseCodes = "200-299"
	config.EnableCommonResponseFilters = false
	config.Threads = 1

	report, err := discoverdirectory.RunDirectoryDiscovery(context.Background(), config)
	if err != nil {
		t.Fatalf("RunDirectoryDiscovery returned error: %v", err)
	}
	if report.Result == nil || len(report.Result.Targets) != 1 {
		t.Fatalf("expected one target with WAF detection, got %#v", report.Result)
	}

	target := report.Result.Targets[0]
	if len(target.Attempts) != 0 {
		t.Fatalf("expected WAF-blocked attempt to stay filtered from findings, got %d attempts", len(target.Attempts))
	}
	if target.WafDetection == nil {
		t.Fatal("expected target-level WAF detection")
	}
	if target.WafDetection.Provider != common.WafProviderEnumCloudflare {
		t.Fatalf("expected Cloudflare WAF detection, got %s", target.WafDetection.Provider)
	}
}
