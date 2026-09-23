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
	rooted := enumeratejavascript.RootEndpoints(analysis.Endpoints, analysis.Origins, []string{"portal.example.com"})

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
	rooted := enumeratejavascript.RootEndpoints(analysis.Endpoints, analysis.Origins, []string{"portal.example.com"})

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

	kept := enumeratejavascript.BaseCandidatesInScope(candidates, []string{"portal.example.com"}, true)
	if len(kept) != 1 || kept[0] != "https://portal.example.com/serviceapi/v1" {
		t.Fatalf("expected only the in-scope origin, got %v", kept)
	}

	kept = enumeratejavascript.BaseCandidatesInScope(candidates, []string{"portal.example.com"}, false)
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

	rooted := enumeratejavascript.RootEndpoints(endpoints, candidates, []string{"portal.example.com"})
	endpoint := findEndpoint(t, rooted, "/serviceapi/v1/general/DeleteFile")
	if endpoint.BaseUrl == nil || *endpoint.BaseUrl != "https://portal.example.com" {
		t.Fatalf("expected the API base, got %v", endpoint.BaseUrl)
	}
}

func TestPreferredBaseLeavesEndpointsAloneWhenNoBaseQualifies(t *testing.T) {
	endpoints := []*enumerate.JavascriptEndpoint{{Path: "general/DeleteFile", SourceUrl: sourceURL}}

	rooted := enumeratejavascript.RootEndpoints(endpoints, []string{"https://cdn.example.com"}, []string{"portal.example.com"})
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

	rooted := enumeratejavascript.RootEndpoints(endpoints, []string{"https://portal.example.com/serviceapi/v1"}, []string{"portal.example.com"})

	paths := pathsOf(rooted)
	if !contains(paths, "/serviceapi/v1/orders/list/") {
		t.Fatalf("expected the trailing slash to survive rooting, got %v", paths)
	}
	if !contains(paths, "/serviceapi/v1/orders/list") {
		t.Fatalf("expected the slashless path to remain distinct, got %v", paths)
	}
}

// A bare origin literal is a base candidate, never an endpoint with an empty path.
func TestAnalyzeSourceDropsBareOriginLiterals(t *testing.T) {
	source := []byte(`const a="https://cdn.example.com";const b="https://api.example.com/";fetch("https://api.example.com/v1/orders")`)

	analysis := enumeratejavascript.AnalyzeSource(source, sourceURL, 0, 0)

	for _, endpoint := range analysis.Endpoints {
		if endpoint.Path == "" || endpoint.Path == "/" {
			t.Fatalf("expected no empty-path endpoint, got %+v", endpoint)
		}
	}
	if !contains(pathsOf(analysis.Endpoints), "/v1/orders") {
		t.Fatalf("expected the real endpoint to survive, got %v", pathsOf(analysis.Endpoints))
	}
	if !contains(analysis.Origins, "https://cdn.example.com") {
		t.Fatalf("expected the bare origin to remain a base candidate, got %v", analysis.Origins)
	}
}

// An application states its base in one bundle and makes its calls in another, so rooting must run
// over the candidates pooled from every bundle rather than per bundle.
func TestRootEndpointsUsesBaseDeclaredInAnotherBundle(t *testing.T) {
	entry := enumeratejavascript.AnalyzeSource(
		[]byte(`const env={serviceApiEndpoint:"https://portal.example.com/serviceapi/v1"};`), "https://portal.example.com/main.js", 0, 0)
	chunk := enumeratejavascript.AnalyzeSource(
		[]byte(`class S{del(n){return this.dataService.getRequest("general/DeleteFile?fileName="+n)}}`), "https://portal.example.com/44.js", 0, 0)

	if len(chunk.Origins) != 0 {
		t.Fatalf("expected the chunk to declare no base of its own, got %v", chunk.Origins)
	}

	pooled := append(append([]string{}, entry.Origins...), chunk.Origins...)
	endpoints := append(append([]*enumerate.JavascriptEndpoint{}, entry.Endpoints...), chunk.Endpoints...)
	rooted := enumeratejavascript.RootEndpoints(endpoints, pooled, []string{"portal.example.com"})

	endpoint := findEndpoint(t, rooted, "/serviceapi/v1/general/DeleteFile")
	if endpoint.BaseUrl == nil || *endpoint.BaseUrl != "https://portal.example.com" {
		t.Fatalf("expected the base from the other bundle, got %v", endpoint.BaseUrl)
	}
	if endpoint.SourceUrl != "https://portal.example.com/44.js" {
		t.Fatalf("expected the chunk to stay the source of record, got %s", endpoint.SourceUrl)
	}
}

func TestBaseCandidatesInScopeSpansEveryAnalyzedHost(t *testing.T) {
	candidates := []string{
		"https://portal.example.com/serviceapi/v1",
		"https://cdn.example.net/assets",
		"https://identity.other.com/auth",
	}

	kept := enumeratejavascript.BaseCandidatesInScope(candidates, []string{"portal.example.com", "cdn.example.net"}, true)
	if len(kept) != 2 {
		t.Fatalf("expected both analyzed hosts to stay in scope, got %v", kept)
	}
}

// A full endpoint under the API root must not outrank the root itself, or relative literals get
// joined onto the longer path.
func TestPreferredBasePrefersTheApiRootOverADeeperEndpoint(t *testing.T) {
	candidates := []string{
		"https://portal.example.com/serviceapi/v1",
		"https://portal.example.com/serviceapi/v1/User/GetProfile",
		"https://portal.example.com/api/v2/services/orders/detail",
	}
	endpoints := []*enumerate.JavascriptEndpoint{{Path: "general/DeleteFile", SourceUrl: sourceURL}}

	rooted := enumeratejavascript.RootEndpoints(endpoints, candidates, []string{"portal.example.com"})
	findEndpoint(t, rooted, "/serviceapi/v1/general/DeleteFile")
}

func TestPreferredBaseIgnoresStaticAssetCandidates(t *testing.T) {
	candidates := []string{"https://portal.example.com/static/api/bundle.js"}
	endpoints := []*enumerate.JavascriptEndpoint{{Path: "general/DeleteFile", SourceUrl: sourceURL}}

	rooted := enumeratejavascript.RootEndpoints(endpoints, candidates, []string{"portal.example.com"})
	if rooted[0].Rooted {
		t.Fatalf("expected a static asset not to be used as a base, got %+v", rooted[0])
	}
}

// The base is the same whether it was written with a trailing slash or without.
func TestRootEndpointsDiscardsTheBaseWrittenWithATrailingSlash(t *testing.T) {
	endpoints := []*enumerate.JavascriptEndpoint{
		{Path: "/serviceapi/v1/", BaseUrl: strPtr("https://portal.example.com"), Rooted: true, SourceUrl: sourceURL},
		{Path: "general/DeleteFile", SourceUrl: sourceURL},
	}

	rooted := enumeratejavascript.RootEndpoints(endpoints, []string{"https://portal.example.com/serviceapi/v1"}, []string{"portal.example.com"})
	for _, endpoint := range rooted {
		if strings.Trim(endpoint.Path, "/") == "serviceapi/v1" {
			t.Fatalf("expected the base itself to be discarded, got %v", pathsOf(rooted))
		}
	}
	findEndpoint(t, rooted, "/serviceapi/v1/general/DeleteFile")
}

func strPtr(value string) *string { return &value }

// An API serves JSON and XML as readily as a file server does, so those stay eligible as endpoints
// even though the crawler counts them as static assets.
func TestAnalyzeSourceKeepsDataDocumentEndpoints(t *testing.T) {
	source := []byte(`fetch("/api/v1/config.json");fetch("/feeds/products.xml");fetch("/exports/report.csv");` +
		`const a="/assets/logo.png";const b="/static/app.js";const c="/styles/app.css";`)

	paths := pathsOf(enumeratejavascript.AnalyzeSource(source, sourceURL, 0, 0).Endpoints)

	for _, want := range []string{"/api/v1/config.json", "/feeds/products.xml", "/exports/report.csv"} {
		if !contains(paths, want) {
			t.Fatalf("expected %s to remain an endpoint, got %v", want, paths)
		}
	}
	for _, unwanted := range []string{"/assets/logo.png", "/static/app.js", "/styles/app.css"} {
		if contains(paths, unwanted) {
			t.Fatalf("expected %s to be dropped as an asset, got %v", unwanted, paths)
		}
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
