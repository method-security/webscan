package extractors_test

import (
	"testing"

	"github.com/Method-Security/webscan/generated/go/discover"
	extractors "github.com/Method-Security/webscan/internal/discover/route/helpers/extractors"
)

func interpolated(t *testing.T, content string) []*discover.RouteDetails {
	t.Helper()
	return extractors.ExtractInterpolatedRouteTemplates(content, bundleURL)
}

func onlyRoute(t *testing.T, routes []*discover.RouteDetails) *discover.RouteDetails {
	t.Helper()
	if len(routes) != 1 {
		paths := make([]string, 0, len(routes))
		for _, route := range routes {
			paths = append(paths, route.Path)
		}
		t.Fatalf("expected exactly one route, got %v", paths)
	}
	return routes[0]
}

func TestExtractInterpolatedRoutesStripsInterpolatedOrigin(t *testing.T) {
	// The dominant shape in shipped bundles: the API base is itself interpolated, so a plain
	// leading-slash rule would match nothing.
	route := onlyRoute(t, interpolated(t, "const u = `${this.hostServer}/rest/basket/${basketId}`"))

	if route.Path != "/rest/basket/{basketId}" {
		t.Errorf("path = %q, want /rest/basket/{basketId}", route.Path)
	}
	if route.BaseUrl != "https://example.com" {
		t.Errorf("BaseUrl = %q, want the bundle origin", route.BaseUrl)
	}
}

func TestExtractInterpolatedRoutesNamesFromExpressionWhenMeaningful(t *testing.T) {
	route := onlyRoute(t, interpolated(t, "fetch(`/rest/track/${this.orderId}`)"))

	if len(route.PathParams) != 1 || route.PathParams[0].Name != "orderId" {
		t.Fatalf("expected the expression to name the param, got %v", route.PathParams)
	}
}

func TestExtractInterpolatedRoutesFallsBackWhenExpressionIsMinified(t *testing.T) {
	// Bundles collapse locals to one or two characters, which carry no meaning; the preceding
	// segment is the better evidence.
	route := onlyRoute(t, interpolated(t, "fetch(`/rest/baskets/${e}`)"))

	if len(route.PathParams) != 1 || route.PathParams[0].Name != "basketId" {
		t.Fatalf("expected a name derived from the preceding segment, got %v", route.PathParams)
	}
}

func TestExtractInterpolatedRoutesHandlesMultipleParameters(t *testing.T) {
	route := onlyRoute(t, interpolated(t, "fetch(`${h}/rest/basket/${e}/coupon/${i}`)"))

	if route.Path != "/rest/basket/{basketId}/coupon/{couponId}" {
		t.Errorf("path = %q", route.Path)
	}
	if len(route.PathParams) != 2 {
		t.Fatalf("expected two params, got %v", route.PathParams)
	}
	if route.PathParams[0].Name == route.PathParams[1].Name {
		t.Errorf("param names collided: %q", route.PathParams[0].Name)
	}
}

func TestExtractInterpolatedRoutesHandlesPartialSegmentInterpolation(t *testing.T) {
	// ConstructURL substitutes {name} anywhere in the path, so a placeholder embedded in a
	// filename is still executable.
	route := onlyRoute(t, interpolated(t, "fetch(`${h}/ftp/order_${e}.pdf`)"))

	if route.Path != "/ftp/order_{orderId}.pdf" {
		t.Errorf("path = %q, want /ftp/order_{orderId}.pdf", route.Path)
	}
}

func TestExtractInterpolatedRoutesAcceptsWrappedExpressions(t *testing.T) {
	// Wrapping an id in encodeURIComponent is standard practice, and whitespace inside an
	// interpolation says nothing about whether the literal is a URL. Validation therefore runs on
	// the substituted template rather than the raw literal.
	for declaration, want := range map[string]string{
		"fetch(`/api/user/${encodeURIComponent(id)}`)": "/api/user/{userId}",
		"fetch(`/api/item/${ id }`)":                   "/api/item/{itemId}",
	} {
		route := onlyRoute(t, interpolated(t, declaration))
		if route.Path != want {
			t.Errorf("%s: path = %q, want %q", declaration, route.Path, want)
		}
	}
}

func TestExtractInterpolatedRoutesRejectsNonPathInterpolations(t *testing.T) {
	cases := map[string]string{
		"markup":              "const h = `<code>${e.data[0].orderId}</code>`",
		"inline style":        "const s = `scaleX(${this.value/100})`",
		"protocol relative":   "const u = `//${window.location.host}/rest/x`",
		"query only":          "const u = `${this.hostServer}/rest/languages?v=${e}`",
		"leading param":       "const u = `${this.host}/${e}/reviews`",
		"whole path is param": "const u = `${this.host}/${e}`",
		"no interpolation":    "const u = `/rest/languages`",
		// A closing tag is slash-prefixed and survives every other check.
		"closing tag": "const x = `</div>${y}`",
		"prose":       "const p = `/5 items ${count}`",
	}

	for name, content := range cases {
		if routes := interpolated(t, content); len(routes) != 0 {
			t.Errorf("%s: expected no routes, got %q", name, routes[0].Path)
		}
	}
}

func TestExtractInterpolatedRoutesTagsProvenance(t *testing.T) {
	// An interpolation proves a parameter exists but does not reliably name it, so it must be
	// distinguishable from a route-table declaration downstream.
	route := onlyRoute(t, interpolated(t, "fetch(`${h}/rest/basket/${e}`)"))

	if route.Evidence == nil || *route.Evidence != "interpolated" {
		t.Errorf("evidence = %v, want interpolated", route.Evidence)
	}
}
