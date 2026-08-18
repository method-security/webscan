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

func declaredRoute(t *testing.T, declared string) *discover.RouteDetails {
	t.Helper()
	template, params, ok := discoverroute.NormalizeDeclaredTemplate(declared)
	if !ok {
		t.Fatalf("expected %q to declare a path parameter", declared)
	}
	route := routeAt(template)
	route.PathParams = params
	route.PathTemplate = &template
	return route
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

func TestNormalizeDeclaredTemplateHandlesEachConvention(t *testing.T) {
	cases := []struct {
		declared string
		template string
		param    string
	}{
		{"/documents/:id", "/documents/{id}", "id"},
		{"/documents/:documentId?", "/documents/{documentId}", "documentId"},
		{"/documents/[id]", "/documents/{id}", "id"},
		{"/documents/{id}", "/documents/{id}", "id"},
	}

	for _, testCase := range cases {
		template, params, ok := discoverroute.NormalizeDeclaredTemplate(testCase.declared)
		if !ok {
			t.Errorf("%q: expected a declared parameter", testCase.declared)
			continue
		}
		if template != testCase.template {
			t.Errorf("%q: template = %q, want %q", testCase.declared, template, testCase.template)
		}
		if len(params) != 1 || params[0].Name != testCase.param {
			t.Errorf("%q: params = %v, want a single %q", testCase.declared, params, testCase.param)
		}
	}
}

func TestNormalizeDeclaredTemplateRejectsCatchAllParams(t *testing.T) {
	// One placeholder cannot stand for the many segments a catch-all matches.
	for _, path := range []string{"/[...slug]", "/docs/[...slug]", "/docs/[[...slug]]", "/[locale]/[...slug]"} {
		if template, _, ok := discoverroute.NormalizeDeclaredTemplate(path); ok {
			t.Errorf("%q: expected no declaration, got template %q", path, template)
		}
	}
}

func TestNormalizeDeclaredTemplateRejectsUnanchoredTemplates(t *testing.T) {
	// Without a literal segment the template swallows every path of that length.
	for _, path := range []string{"/:slug", "/[id]", "/{id}", "/[locale]/[page]"} {
		if template, _, ok := discoverroute.NormalizeDeclaredTemplate(path); ok {
			t.Errorf("%q: expected no declaration, got template %q", path, template)
		}
	}
}

func TestNormalizeDeclaredTemplateKeepsAnchoredMultiSegmentTemplates(t *testing.T) {
	// One literal segment plus exact segment-count matching is enough to anchor it.
	template, params, ok := discoverroute.NormalizeDeclaredTemplate("/[locale]/products/[id]")

	if !ok {
		t.Fatalf("expected a usable declaration")
	}
	if template != "/{locale}/products/{id}" {
		t.Errorf("template = %q", template)
	}
	if len(params) != 2 {
		t.Errorf("expected two params, got %v", params)
	}
}

func TestHasDeclaredParamSyntaxSpansUnusableForms(t *testing.T) {
	// Used to stop a refused template falling through as a fetchable literal.
	for _, path := range []string{"/:id", "/[id]", "/{id}", "/docs/[...slug]", "/:locale/:page"} {
		if !discoverroute.HasDeclaredParamSyntax(path) {
			t.Errorf("%q: expected parameter syntax to be recognized", path)
		}
	}
	for _, path := range []string{"/about", "/api/v2/users", "/assets/app.js"} {
		if discoverroute.HasDeclaredParamSyntax(path) {
			t.Errorf("%q: expected no parameter syntax", path)
		}
	}
}

func TestApplyDeclaredRouteTemplatesFoldsPartialSegmentPlaceholders(t *testing.T) {
	// Folding must match embedded placeholders or observed values are never captured.
	template := "/ftp/order_{orderId}.pdf"
	declared := routeAt(template)
	declared.PathParams = []*discover.RoutePathParam{{Name: "orderId"}}
	declared.PathTemplate = &template

	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		declared,
		routeAt("/ftp/order_1042.pdf"),
		routeAt("/ftp/order_3517.pdf"),
	})

	if len(routes) != 1 {
		t.Fatalf("expected the literals to fold, got %v", pathsOf(routes))
	}
	route := findRoute(t, routes, template)
	sort.Strings(route.PathParams[0].ExampleValues)
	got := route.PathParams[0].ExampleValues
	if len(got) != 2 || got[0] != "1042" || got[1] != "3517" {
		t.Errorf("example values = %v, want [1042 3517]", got)
	}
}

func TestApplyDeclaredRouteTemplatesRejectsPartialSegmentMismatch(t *testing.T) {
	template := "/ftp/order_{orderId}.pdf"
	declared := routeAt(template)
	declared.PathParams = []*discover.RoutePathParam{{Name: "orderId"}}
	declared.PathTemplate = &template

	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		declared,
		routeAt("/ftp/invoice_1042.pdf"),
	})

	// The literal prefix differs, so this is a different file, not an instance of the template.
	findRoute(t, routes, "/ftp/invoice_1042.pdf")
}

func TestApplyDeclaredRouteTemplatesNormalizesOriginForFolding(t *testing.T) {
	// An explicit default port must not split one application in two.
	declared := declaredRoute(t, "/documents/:id")
	literal := routeAt("/documents/1042")
	literal.BaseUrl = "https://example.com:443"

	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{declared, literal})

	if len(routes) != 1 {
		t.Fatalf("expected the literal to fold despite the explicit port, got %v", pathsOf(routes))
	}
	route := findRoute(t, routes, "/documents/{id}")
	if len(route.PathParams) != 1 || len(route.PathParams[0].ExampleValues) != 1 {
		t.Errorf("expected the observed value captured, got %v", route.PathParams)
	}
}

func TestNormalizeDeclaredTemplateIgnoresLiteralPaths(t *testing.T) {
	// Nothing is inferred from shape, so a numeric segment is just a literal here.
	for _, path := range []string{"/about", "/documents/1042", "/api/v2/users", "/assets/app.js"} {
		if _, _, ok := discoverroute.NormalizeDeclaredTemplate(path); ok {
			t.Errorf("%q: expected no declared parameter", path)
		}
	}
}

func TestApplyDeclaredRouteTemplatesFoldsLiteralsIntoDeclaration(t *testing.T) {
	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		declaredRoute(t, "/documents/:id"),
		routeAt("/documents/1042"),
		routeAt("/documents/3517"),
		routeAt("/documents/6820"),
		routeAt("/documents/8394"),
	})

	if len(routes) != 1 {
		t.Fatalf("expected observed literals to fold into the declared route, got %v", pathsOf(routes))
	}
	route := findRoute(t, routes, "/documents/{id}")
	if len(route.PathParams) != 1 {
		t.Fatalf("expected one path param, got %d", len(route.PathParams))
	}
	param := route.PathParams[0]
	if param.Name != "id" {
		t.Errorf("expected the declared name, got %q", param.Name)
	}
	sort.Strings(param.ExampleValues)
	want := []string{"1042", "3517", "6820", "8394"}
	if len(param.ExampleValues) != len(want) {
		t.Fatalf("expected each observed value retained, got %v", param.ExampleValues)
	}
	for i, value := range want {
		if param.ExampleValues[i] != value {
			t.Errorf("example values = %v, want %v", param.ExampleValues, want)
			break
		}
	}
}

func TestApplyDeclaredRouteTemplatesLeavesUndeclaredLiteralsAlone(t *testing.T) {
	// Without a declaration there is no evidence, so the literals stay as distinct endpoints.
	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		routeAt("/documents/1042"),
		routeAt("/documents/3517"),
		routeAt("/documents/6820"),
	})

	if len(routes) != 3 {
		t.Fatalf("expected undeclared literals to survive untouched, got %v", pathsOf(routes))
	}
}

func TestApplyDeclaredRouteTemplatesPreservesTopLevelPages(t *testing.T) {
	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		routeAt("/about"),
		routeAt("/contact"),
		routeAt("/pricing"),
	})

	if len(routes) != 3 {
		t.Fatalf("expected top-level pages to survive as distinct endpoints, got %v", pathsOf(routes))
	}
}

func TestApplyDeclaredRouteTemplatesPrefersExplicitLiteralDeclaration(t *testing.T) {
	// Router semantics: a declared literal is not swallowed by a matching template.
	explicit := routeAt("/documents/new")
	evidence := discoverroute.DeclaredRouteEvidence
	explicit.Evidence = &evidence
	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		declaredRoute(t, "/documents/:id"),
		explicit,
		routeAt("/documents/1042"),
	})

	findRoute(t, routes, "/documents/{id}")
	findRoute(t, routes, "/documents/new")
}

func TestApplyDeclaredRouteTemplatesRespectsSegmentCount(t *testing.T) {
	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		declaredRoute(t, "/documents/:id"),
		routeAt("/documents/1042/comments"),
	})

	// The literal has an extra segment, so it is not an instance of the declared template.
	findRoute(t, routes, "/documents/1042/comments")
}

func TestApplyDeclaredRouteTemplatesKeepsMethodsSeparate(t *testing.T) {
	post := routeAt("/documents/1042")
	post.Method = common.HttpMethodPost

	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		declaredRoute(t, "/documents/:id"),
		post,
	})

	if len(routes) != 2 {
		t.Fatalf("expected a POST literal not to fold into a GET declaration, got %v", pathsOf(routes))
	}
}

func TestApplyDeclaredRouteTemplatesMergesQueryParamsOfFoldedLiterals(t *testing.T) {
	first := routeAt("/documents/1042")
	first.QueryParams = []*discover.RouteQueryParam{{Name: "format", ExampleValues: []string{"pdf"}}}
	second := routeAt("/documents/3517")
	second.QueryParams = []*discover.RouteQueryParam{{Name: "download", ExampleValues: []string{"1"}}}

	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		declaredRoute(t, "/documents/:id"),
		first,
		second,
	})

	route := findRoute(t, routes, "/documents/{id}")
	if len(route.QueryParams) != 2 {
		t.Fatalf("expected query params from both literals to survive the fold, got %v", route.QueryParams)
	}
}

func TestApplyDeclaredRouteTemplatesHandlesMultipleParameters(t *testing.T) {
	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		declaredRoute(t, "/orders/:orderId/items/:itemId"),
		routeAt("/orders/12/items/45"),
	})

	route := findRoute(t, routes, "/orders/{orderId}/items/{itemId}")
	if len(route.PathParams) != 2 {
		t.Fatalf("expected both declared params, got %v", route.PathParams)
	}
	for _, param := range route.PathParams {
		if len(param.ExampleValues) != 1 {
			t.Errorf("expected %q to capture its observed value, got %v", param.Name, param.ExampleValues)
		}
	}
}

func TestMergeWebRoutesKeepsDerivationProvenance(t *testing.T) {
	// A found-location tag arriving first must not displace how the route was derived.
	found := routeAt("/documents/new")
	foundEvidence := "CONST:X"
	found.Evidence = &foundEvidence
	declared := routeAt("/documents/new")
	declaredEvidence := discoverroute.DeclaredRouteEvidence
	declared.Evidence = &declaredEvidence

	merged := discoverroute.MergeWebRoutes([]*discover.RouteDetails{found, declared})

	if len(merged) != 1 {
		t.Fatalf("expected one merged route, got %d", len(merged))
	}
	if merged[0].Evidence == nil || *merged[0].Evidence != discoverroute.DeclaredRouteEvidence {
		t.Errorf("evidence = %v, want %q", merged[0].Evidence, discoverroute.DeclaredRouteEvidence)
	}
}

func TestMergeWebRoutesRanksDeclarationAboveInterpolation(t *testing.T) {
	// Declared routes are collected first, so order alone must not decide the surviving tag.
	tagged := func(evidence string) *discover.RouteDetails {
		route := routeAt("/rest/basket/{basketId}")
		route.Evidence = &evidence
		return route
	}
	for _, order := range [][]*discover.RouteDetails{
		{tagged(discoverroute.DeclaredRouteEvidence), tagged(discoverroute.InterpolatedRouteEvidence)},
		{tagged(discoverroute.InterpolatedRouteEvidence), tagged(discoverroute.DeclaredRouteEvidence)},
	} {
		merged := discoverroute.MergeWebRoutes(order)
		if len(merged) != 1 || *merged[0].Evidence != discoverroute.DeclaredRouteEvidence {
			t.Errorf("evidence = %v, want %q", merged[0].Evidence, discoverroute.DeclaredRouteEvidence)
		}
	}
}

func TestApplyDeclaredRouteTemplatesKeepsLiteralAfterMergeWithFoundEvidence(t *testing.T) {
	// The end-to-end shape of the same bug: losing the tag folds the declared literal away.
	found := routeAt("/documents/new")
	foundEvidence := "CONST:X"
	found.Evidence = &foundEvidence
	declared := routeAt("/documents/new")
	declaredEvidence := discoverroute.DeclaredRouteEvidence
	declared.Evidence = &declaredEvidence

	merged := discoverroute.MergeWebRoutes([]*discover.RouteDetails{found, declared})
	routes := discoverroute.ApplyDeclaredRouteTemplates(append(merged, declaredRoute(t, "/documents/:id")))

	findRoute(t, routes, "/documents/{id}")
	findRoute(t, routes, "/documents/new")
}

func TestMergePathParamsUnionsExampleValues(t *testing.T) {
	merged := discoverroute.MergePathParams(
		[]*discover.RoutePathParam{{Name: "id", ExampleValues: []string{"1042"}}},
		[]*discover.RoutePathParam{{Name: "id", ExampleValues: []string{"1042", "3517"}}},
	)

	if len(merged) != 1 {
		t.Fatalf("expected one merged param, got %d", len(merged))
	}
	if len(merged[0].ExampleValues) != 2 {
		t.Errorf("expected deduplicated union of examples, got %v", merged[0].ExampleValues)
	}
}
