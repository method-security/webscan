package enumeratejavascript_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Method-Security/webscan/generated/go/enumerate"
	enumeratejavascript "github.com/Method-Security/webscan/internal/enumerate/javascript/helpers"
)

const sourceURL = "https://portal.example.com/main.abc123.js"

func pathsOf(endpoints []*enumerate.JavascriptEndpoint) []string {
	paths := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		paths = append(paths, endpoint.Path)
	}
	return paths
}

func findEndpoint(t *testing.T, endpoints []*enumerate.JavascriptEndpoint, path string) *enumerate.JavascriptEndpoint {
	t.Helper()
	for _, endpoint := range endpoints {
		if endpoint.Path == path {
			return endpoint
		}
	}
	t.Fatalf("expected an endpoint at %s, got %v", path, pathsOf(endpoints))
	return nil
}

func TestAnalyzeSourceRecoversWrappedRelativeCalls(t *testing.T) {
	source := []byte(`class S {
		deleteFile(n){ return this.dataService.getRequest("general/DeleteFile?fileName="+n) }
		profile(u){ return this.dataService.getRequest("User/GetUserProfileDetails?userId="+u) }
	}
	const env = { serviceApiEndpoint: "https://portal.example.com/serviceapi/v1" };`)

	analysis := enumeratejavascript.AnalyzeSource(source, sourceURL, 0, 0)

	endpoint := findEndpoint(t, analysis.Endpoints, "general/DeleteFile")
	if endpoint.Rooted {
		t.Fatalf("expected a relative literal to be unrooted before rooting runs")
	}
	if len(endpoint.QueryParams) != 1 || endpoint.QueryParams[0] != "fileName" {
		t.Fatalf("expected the fileName query param, got %v", endpoint.QueryParams)
	}
	if endpoint.CallExpression == nil || *endpoint.CallExpression != "this.dataService.getRequest" {
		t.Fatalf("expected the wrapper call to be recorded, got %v", endpoint.CallExpression)
	}

	if !contains(analysis.Origins, "https://portal.example.com/serviceapi/v1") {
		t.Fatalf("expected the configured API base, got %v", analysis.Origins)
	}
}

func TestAnalyzeSourceRootsRelativeCallsAgainstConfiguredBase(t *testing.T) {
	source := []byte(`const env={serviceApiEndpoint:"https://portal.example.com/serviceapi/v1"};
	class S { del(n){ return this.dataService.getRequest("general/DeleteFile?fileName="+n) } }`)

	analysis := enumeratejavascript.AnalyzeSource(source, sourceURL, 0, 0)
	rooted := enumeratejavascript.RootEndpoints(analysis.Endpoints, analysis.Origins, "portal.example.com")

	endpoint := findEndpoint(t, rooted, "/serviceapi/v1/general/DeleteFile")
	if !endpoint.Rooted {
		t.Fatalf("expected the endpoint to be marked rooted")
	}
	if endpoint.BaseUrl == nil || *endpoint.BaseUrl != "https://portal.example.com" {
		t.Fatalf("expected the configured origin as base, got %v", endpoint.BaseUrl)
	}
}

func TestAnalyzeSourceKeepsRootRelativePathsUntouched(t *testing.T) {
	source := []byte(`fetch("/api/v1/widgets?limit=10");const env={apiUrl:"https://portal.example.com/serviceapi/v1"};`)

	analysis := enumeratejavascript.AnalyzeSource(source, sourceURL, 0, 0)
	rooted := enumeratejavascript.RootEndpoints(analysis.Endpoints, analysis.Origins, "portal.example.com")

	endpoint := findEndpoint(t, rooted, "/api/v1/widgets")
	if endpoint.Method == nil || string(*endpoint.Method) != "GET" {
		t.Fatalf("expected a GET method, got %v", endpoint.Method)
	}
}

func TestAnalyzeSourceDropsStaticAssetReferences(t *testing.T) {
	source := []byte(`const a="/assets/logo.png";const b="/styles/app.css";const c=fetch("/api/real")`)

	analysis := enumeratejavascript.AnalyzeSource(source, sourceURL, 0, 0)
	for _, path := range pathsOf(analysis.Endpoints) {
		if strings.HasSuffix(path, ".png") || strings.HasSuffix(path, ".css") {
			t.Fatalf("expected static assets to be dropped, got %v", pathsOf(analysis.Endpoints))
		}
	}
}

func TestBaseCandidatesInScopeExcludesThirdPartyOrigins(t *testing.T) {
	candidates := []string{"https://portal.example.com/serviceapi/v1", "https://identity.other.com/"}

	kept := enumeratejavascript.BaseCandidatesInScope(candidates, "https://portal.example.com/main.js", true)
	if len(kept) != 1 || kept[0] != "https://portal.example.com/serviceapi/v1" {
		t.Fatalf("expected only the in-scope origin, got %v", kept)
	}

	kept = enumeratejavascript.BaseCandidatesInScope(candidates, "https://portal.example.com/main.js", false)
	if len(kept) != 2 {
		t.Fatalf("expected both origins when scoping is off, got %v", kept)
	}
}

// Windowing exists because tree-sitter collapses on whole minified bundles; this pins that a
// multi-window minified body still yields its calls.
func TestAnalyzeSourceHandlesMultiWindowMinifiedBundle(t *testing.T) {
	source, err := os.ReadFile("testdata/angular-minified-app.js")
	if err != nil {
		t.Fatalf("reading bundle fixture: %s", err)
	}

	if len(source) <= enumeratejavascript.DefaultWindowBytes {
		t.Fatalf("fixture must exceed one analysis window to exercise windowing, got %d bytes", len(source))
	}

	analysis := enumeratejavascript.AnalyzeSource(source, sourceURL, 0, 0)
	paths := pathsOf(analysis.Endpoints)

	for _, expected := range []string{
		"general/DeleteFile",
		"general/InsertFile",
		"User/GetTermsAndConditionsIdByUserId",
		"Order/GetAttachmentByOrder",
	} {
		if !contains(paths, expected) {
			t.Fatalf("expected %s among %d endpoints: %v", expected, len(paths), paths)
		}
	}

	endpoint := findEndpoint(t, analysis.Endpoints, "Order/GetAttachmentByOrder")
	if len(endpoint.QueryParams) < 4 {
		t.Fatalf("expected the recovered query params, got %v", endpoint.QueryParams)
	}
}

// A sign-out page sits deeper than the API base, so depth alone must not decide.
func TestPreferredBaseIgnoresPagesAndPicksTheApiRoot(t *testing.T) {
	candidates := []string{
		"https://portal.example.com",
		"https://portal.example.com/serviceapi/v1",
		"https://portal.example.com/ofis.id",
		"https://identity.example.com",
		"https://identity.example.com/v5.0/webapps/pages/public/signout.aspx",
	}
	endpoints := []*enumerate.JavascriptEndpoint{{Path: "general/DeleteFile", SourceUrl: sourceURL}}

	rooted := enumeratejavascript.RootEndpoints(endpoints, candidates, "portal.example.com")
	endpoint := findEndpoint(t, rooted, "/serviceapi/v1/general/DeleteFile")
	if endpoint.BaseUrl == nil || *endpoint.BaseUrl != "https://portal.example.com" {
		t.Fatalf("expected the API base, got %v", endpoint.BaseUrl)
	}
}

func TestPreferredBaseLeavesEndpointsAloneWhenNoBaseQualifies(t *testing.T) {
	endpoints := []*enumerate.JavascriptEndpoint{{Path: "general/DeleteFile", SourceUrl: sourceURL}}

	rooted := enumeratejavascript.RootEndpoints(endpoints, []string{"https://cdn.example.com"}, "portal.example.com")
	if len(rooted) != 1 || rooted[0].Rooted {
		t.Fatalf("expected the endpoint to stay unrooted, got %v", rooted)
	}
}

func TestAnalyzeSourceReadsVerbFromClientCall(t *testing.T) {
	source := []byte(`this.http.post("/serviceapi/v1/User/Update",p);this.dataService.getRequest("User/Read?id="+i)`)

	analysis := enumeratejavascript.AnalyzeSource(source, sourceURL, 0, 0)

	posted := findEndpoint(t, analysis.Endpoints, "/serviceapi/v1/User/Update")
	if posted.Method == nil || string(*posted.Method) != "POST" {
		t.Fatalf("expected POST read off the call, got %v", posted.Method)
	}

	wrapped := findEndpoint(t, analysis.Endpoints, "User/Read")
	if wrapped.Method != nil {
		t.Fatalf("expected no verb guessed from a wrapper, got %v", *wrapped.Method)
	}
}

// `/x/` and `/x` are different URIs, so rooting must not clean the trailing slash away.
func TestRootEndpointsPreservesTrailingSlash(t *testing.T) {
	endpoints := []*enumerate.JavascriptEndpoint{
		{Path: "orders/list/", SourceUrl: sourceURL},
		{Path: "orders/list", SourceUrl: sourceURL},
	}

	rooted := enumeratejavascript.RootEndpoints(endpoints, []string{"https://portal.example.com/serviceapi/v1"}, "portal.example.com")

	paths := pathsOf(rooted)
	if !contains(paths, "/serviceapi/v1/orders/list/") {
		t.Fatalf("expected the trailing slash to survive rooting, got %v", paths)
	}
	if !contains(paths, "/serviceapi/v1/orders/list") {
		t.Fatalf("expected the slashless path to remain distinct, got %v", paths)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
