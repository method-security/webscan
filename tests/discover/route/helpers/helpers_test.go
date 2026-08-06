package helpers_test

import (
	"sort"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
	discoverroute "github.com/Method-Security/webscan/internal/discover/route/helpers"
)

func routeAt(path string) *discover.RouteDetails {
	return &discover.RouteDetails{
		BaseUrl: "https://example.com",
		Path:    path,
		Method:  common.HttpMethodGet,
	}
}

func pathsOf(routes []*discover.RouteDetails) []string {
	paths := make([]string, 0, len(routes))
	for _, route := range routes {
		paths = append(paths, route.Path)
	}
	sort.Strings(paths)
	return paths
}

func findRoute(t *testing.T, routes []*discover.RouteDetails, path string) *discover.RouteDetails {
	t.Helper()
	for _, route := range routes {
		if route.Path == path {
			return route
		}
	}
	t.Fatalf("expected a route at %q, got %v", path, pathsOf(routes))
	return nil
}

func TestCollapseTemplatedRoutesFoldsNumericSiblings(t *testing.T) {
	routes := discoverroute.CollapseTemplatedRoutes([]*discover.RouteDetails{
		routeAt("/documents/1042"),
		routeAt("/documents/3517"),
		routeAt("/documents/6820"),
		routeAt("/documents/8394"),
	})

	if len(routes) != 1 {
		t.Fatalf("expected 4 sibling paths to fold into 1 route, got %v", pathsOf(routes))
	}
	route := findRoute(t, routes, "/documents/{documentId}")
	if len(route.PathParams) != 1 {
		t.Fatalf("expected exactly one path param, got %d", len(route.PathParams))
	}
	param := route.PathParams[0]
	if param.Name != "documentId" {
		t.Errorf("expected param name derived from the preceding segment, got %q", param.Name)
	}
	sort.Strings(param.ExampleValues)
	want := []string{"1042", "3517", "6820", "8394"}
	if len(param.ExampleValues) != len(want) {
		t.Fatalf("expected every observed value retained as an example, got %v", param.ExampleValues)
	}
	for i, value := range want {
		if param.ExampleValues[i] != value {
			t.Errorf("example values = %v, want %v", param.ExampleValues, want)
			break
		}
	}
	if route.PathTemplate == nil || *route.PathTemplate != "/documents/{documentId}" {
		t.Errorf("expected PathTemplate to mirror the collapsed path, got %v", route.PathTemplate)
	}
}

func TestCollapseTemplatedRoutesFoldsSlugSiblingsOnCardinality(t *testing.T) {
	// Slugs match none of the shape patterns, so only sibling cardinality can catch them.
	routes := discoverroute.CollapseTemplatedRoutes([]*discover.RouteDetails{
		routeAt("/products/widget-pro"),
		routeAt("/products/gizmo-max"),
		routeAt("/products/thing-lite"),
	})

	if len(routes) != 1 {
		t.Fatalf("expected 3 slug siblings to fold into 1 route, got %v", pathsOf(routes))
	}
	findRoute(t, routes, "/products/{productId}")
}

func TestCollapseTemplatedRoutesLeavesSubThresholdSiblingsAlone(t *testing.T) {
	// Two distinct values is below the cardinality threshold and is just as likely to be two
	// genuinely different endpoints.
	routes := discoverroute.CollapseTemplatedRoutes([]*discover.RouteDetails{
		routeAt("/products/widget-pro"),
		routeAt("/products/gizmo-max"),
	})

	if len(routes) != 2 {
		t.Fatalf("expected sub-threshold siblings to stay separate, got %v", pathsOf(routes))
	}
}

func TestCollapseTemplatedRoutesPreservesVersionSegments(t *testing.T) {
	routes := discoverroute.CollapseTemplatedRoutes([]*discover.RouteDetails{
		routeAt("/api/v1/users"),
		routeAt("/api/v2/users"),
		routeAt("/api/v3/users"),
	})

	if len(routes) != 3 {
		t.Fatalf("expected API versions to remain distinct endpoints, got %v", pathsOf(routes))
	}
}

func TestCollapseTemplatedRoutesPreservesStaticAssetNames(t *testing.T) {
	routes := discoverroute.CollapseTemplatedRoutes([]*discover.RouteDetails{
		routeAt("/assets/app.js"),
		routeAt("/assets/vendor.js"),
		routeAt("/assets/main.js"),
	})

	if len(routes) != 3 {
		t.Fatalf("expected dotted filenames to remain distinct, got %v", pathsOf(routes))
	}
}

func TestCollapseTemplatedRoutesTemplatesUuidOnShapeAlone(t *testing.T) {
	// Shape is per-route evidence, so a single observation is enough.
	routes := discoverroute.CollapseTemplatedRoutes([]*discover.RouteDetails{
		routeAt("/sessions/3f2504e0-4f89-11d3-9a0c-0305e82c3301"),
	})

	route := findRoute(t, routes, "/sessions/{sessionId}")
	if len(route.PathParams) != 1 || route.PathParams[0].Name != "sessionId" {
		t.Fatalf("expected a single sessionId path param, got %v", route.PathParams)
	}
}

func TestCollapseTemplatedRoutesNamesEachPositionDistinctly(t *testing.T) {
	// The ontology keys a WebEndpointParameter on (parameter_name, parameter_location), so two
	// path params on one route must not share a name.
	routes := discoverroute.CollapseTemplatedRoutes([]*discover.RouteDetails{
		routeAt("/orders/12/items/45"),
	})

	route := findRoute(t, routes, "/orders/{orderId}/items/{itemId}")
	if len(route.PathParams) != 2 {
		t.Fatalf("expected both positions captured, got %v", route.PathParams)
	}
	if route.PathParams[0].Name == route.PathParams[1].Name {
		t.Errorf("path param names collided: %q", route.PathParams[0].Name)
	}
}

func TestCollapseTemplatedRoutesKeepsMethodsSeparate(t *testing.T) {
	get := routeAt("/documents/1042")
	post := routeAt("/documents/3517")
	post.Method = common.HttpMethodPost

	routes := discoverroute.CollapseTemplatedRoutes([]*discover.RouteDetails{get, post})

	if len(routes) != 2 {
		t.Fatalf("expected GET and POST to stay separate endpoints, got %d", len(routes))
	}
}

func TestCollapseTemplatedRoutesMergesQueryParamsOfFoldedSiblings(t *testing.T) {
	first := routeAt("/documents/1042")
	first.QueryParams = []*discover.RouteQueryParam{{Name: "format", ExampleValues: []string{"pdf"}}}
	second := routeAt("/documents/3517")
	second.QueryParams = []*discover.RouteQueryParam{{Name: "download", ExampleValues: []string{"1"}}}

	routes := discoverroute.CollapseTemplatedRoutes([]*discover.RouteDetails{first, second})

	route := findRoute(t, routes, "/documents/{documentId}")
	if len(route.QueryParams) != 2 {
		t.Fatalf("expected query params from both siblings to survive the fold, got %v", route.QueryParams)
	}
}

func TestMergePathParamsUnionsExampleValues(t *testing.T) {
	merged := discoverroute.MergePathParams(
		[]*discover.RoutePathParam{{Name: "documentId", ExampleValues: []string{"1042"}}},
		[]*discover.RoutePathParam{{Name: "documentId", ExampleValues: []string{"1042", "3517"}}},
	)

	if len(merged) != 1 {
		t.Fatalf("expected one merged param, got %d", len(merged))
	}
	if len(merged[0].ExampleValues) != 2 {
		t.Errorf("expected deduplicated union of examples, got %v", merged[0].ExampleValues)
	}
}
