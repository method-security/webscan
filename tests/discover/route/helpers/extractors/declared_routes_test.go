package extractors_test

import (
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
	extractors "github.com/Method-Security/webscan/internal/discover/route/helpers/extractors"
)

const bundleURL = "https://example.com/static/js/main.4f2a91.js?v=3"

func findDeclared(t *testing.T, routes []*discover.RouteDetails, path string) *discover.RouteDetails {
	t.Helper()
	for _, route := range routes {
		if route.Path == path {
			return route
		}
	}
	paths := make([]string, 0, len(routes))
	for _, route := range routes {
		paths = append(paths, string(route.Method)+" "+route.Path)
	}
	t.Fatalf("expected a declared route at %q, got %v", path, paths)
	return nil
}

func TestExtractDeclaredRouteTemplatesUsesOriginNotBundleURL(t *testing.T) {
	// The bundle is served from a deep path, but a declared route is relative to the application.
	// Folding observed literals requires exact BaseUrl equality, so anything but the origin breaks it.
	routes := extractors.ExtractDeclaredRouteTemplates(`{ path: "/documents/:id", component: Doc }`, bundleURL)

	route := findDeclared(t, routes, "/documents/{id}")
	if route.BaseUrl != "https://example.com" {
		t.Errorf("BaseUrl = %q, want the origin", route.BaseUrl)
	}
}

func TestExtractDeclaredRouteTemplatesKeepsDeclaredVerb(t *testing.T) {
	routes := extractors.ExtractDeclaredRouteTemplates(`router.post('/documents/:id', handler)`, bundleURL)

	route := findDeclared(t, routes, "/documents/{id}")
	if route.Method != common.HttpMethodPost {
		t.Errorf("method = %q, want POST", route.Method)
	}
}

func TestExtractDeclaredRouteTemplatesSeparatesVerbsOnOnePath(t *testing.T) {
	routes := extractors.ExtractDeclaredRouteTemplates(
		`router.get('/documents/:id', read); router.delete('/documents/:id', destroy)`, bundleURL)

	methods := map[common.HttpMethod]struct{}{}
	for _, route := range routes {
		if route.Path == "/documents/{id}" {
			methods[route.Method] = struct{}{}
		}
	}
	if _, ok := methods[common.HttpMethodGet]; !ok {
		t.Errorf("expected a GET declaration, got %v", methods)
	}
	if _, ok := methods[common.HttpMethodDelete]; !ok {
		t.Errorf("expected a DELETE declaration, got %v", methods)
	}
}

func TestExtractDeclaredRouteTemplatesIgnoresBracketedNonRoutes(t *testing.T) {
	// A bracketed string that declares no parameter is a regex or selector, not a route.
	routes := extractors.ExtractDeclaredRouteTemplates(`var re = "/assets/[0-9]+/thumb"; var sel = "/a[href]";`, bundleURL)

	for _, route := range routes {
		t.Errorf("expected no declared routes, got %q", route.Path)
	}
}

func TestExtractDeclaredRouteTemplatesReadsNextJsManifestEntries(t *testing.T) {
	routes := extractors.ExtractDeclaredRouteTemplates(`{"/documents/[id]":["static/chunks/doc.js"],"/docs/[...slug]":["x.js"]}`, bundleURL)

	findDeclared(t, routes, "/documents/{id}")
	findDeclared(t, routes, "/docs/{slug}")
}

func TestExtractDeclaredRouteTemplatesTakesLiteralsOnlyFromRouteTables(t *testing.T) {
	// <Route> delimits a route table, so its literal is a real declaration. A bare `path:` key
	// appears in ordinary config objects, so its literal is not.
	routes := extractors.ExtractDeclaredRouteTemplates(
		`<Route path="/settings" element={<S/>} /> ; { path: "/tmp/cache", ttl: 30 }`, bundleURL)

	findDeclared(t, routes, "/settings")
	for _, route := range routes {
		if route.Path == "/tmp/cache" {
			t.Errorf("expected a bare path: literal not to be treated as a route")
		}
	}
}

func TestExtractDeclaredRouteTemplatesRejectsUnparseableSourceURL(t *testing.T) {
	routes := extractors.ExtractDeclaredRouteTemplates(`{ path: "/documents/:id" }`, "not-a-url")

	if len(routes) != 0 {
		t.Errorf("expected no routes when the origin cannot be determined, got %d", len(routes))
	}
}
