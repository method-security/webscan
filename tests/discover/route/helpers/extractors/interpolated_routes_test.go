package extractors_test

import (
	"strings"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
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
			paths = append(paths, string(route.Method)+" "+route.Path)
		}
		t.Fatalf("expected exactly one route, got %v", paths)
	}
	return routes[0]
}

func TestExtractInterpolatedRoutesKeepsResolvableBasePrefix(t *testing.T) {
	// An API base routinely holds a path; treating it as origin-only drops the prefix.
	route := onlyRoute(t, interpolated(t,
		"const API=`${this.host}/api/v2`;\nthis.http.get(`${API}/reports/${reportId}`);"))

	if route.Path != "/api/v2/reports/{reportId}" {
		t.Errorf("path = %q, want the base prefix retained", route.Path)
	}
	if route.BaseUrl != "https://example.com" {
		t.Errorf("BaseUrl = %q, want the bundle origin", route.BaseUrl)
	}
}

func TestExtractInterpolatedRoutesKeepsEnclosingVerb(t *testing.T) {
	for declaration, want := range map[string]common.HttpMethod{
		"const A=`${h}/api/v2`;\nthis.http.post(`${A}/sessions/${sessionId}/refresh`, b);": common.HttpMethodPost,
		"const A=`${h}/api/v2`;\nthis.http.put(`${A}/reports/${reportId}`, b);":            common.HttpMethodPut,
		"const A=`${h}/api/v2`;\nthis.http.delete(`${A}/reports/${reportId}`);":            common.HttpMethodDelete,
		"const A=`${h}/api/v2`;\nthis.http.patch(`${A}/users/${userId}`, b);":              common.HttpMethodPatch,
	} {
		route := onlyRoute(t, interpolated(t, declaration))
		if route.Method != want {
			t.Errorf("method = %q, want %q for %q", route.Method, want, declaration)
		}
	}
}

func TestExtractInterpolatedRoutesReadsFetchOptionsMethod(t *testing.T) {
	route := onlyRoute(t, interpolated(t, "fetch(`/api/v2/user/${userId}`, { method: 'DELETE' })"))

	if route.Method != common.HttpMethodDelete {
		t.Errorf("method = %q, want DELETE", route.Method)
	}
}

func TestExtractInterpolatedRoutesSkipsUndeterminableMethod(t *testing.T) {
	// Defaulting to GET reported every POST, PUT and DELETE as a GET.
	routes := interpolated(t, "const url = `/api/v2/user/${userId}`;")

	for _, route := range routes {
		t.Errorf("expected no route without a determinable method, got %s %s", route.Method, route.Path)
	}
}

func TestExtractInterpolatedRoutesMarksUnresolvableBaseAsUnrooted(t *testing.T) {
	// The base may carry a path, so rooting is deferred to corroboration rather than guessed.
	route := onlyRoute(t, interpolated(t, "this.http.get(`${this.hostServer}/rest/basket/${id}`);"))

	if route.Evidence == nil || !strings.HasPrefix(*route.Evidence, "interpolated-unrooted") {
		t.Errorf("evidence = %v, want an unrooted candidate", route.Evidence)
	}
	if route.Path != "/rest/basket/{param3}" {
		t.Errorf("path = %q, want the tail that followed the base", route.Path)
	}
}

func TestExtractInterpolatedRoutesMarksAmbiguousBaseAsUnrooted(t *testing.T) {
	// Minified bundles reuse short names; conflicting assignments mean the base is unknown.
	route := onlyRoute(t, interpolated(t,
		"var A=`${h}/api/v1`;\nvar A=`${h}/api/v2`;\nthis.http.get(`${A}/reports/${id}`);"))

	if route.Evidence == nil || !strings.HasPrefix(*route.Evidence, "interpolated-unrooted") {
		t.Errorf("evidence = %v, want an unrooted candidate", route.Evidence)
	}
	if !strings.HasSuffix(*route.Evidence, ":A") {
		t.Errorf("evidence = %q, want the base name recorded", *route.Evidence)
	}
}

func TestExtractInterpolatedRoutesTreatsNavigationAsGet(t *testing.T) {
	// window.open is a GET by definition, not an inferred default.
	route := onlyRoute(t, interpolated(t, "window.open(`/ftp/order_${e}.pdf`)"))

	if route.Method != common.HttpMethodGet {
		t.Errorf("method = %q, want GET", route.Method)
	}
}

func TestExtractInterpolatedRoutesTreatsAssignedNavigationAsGet(t *testing.T) {
	route := onlyRoute(t, interpolated(t,
		"openPDF(e){let i=`/ftp/order_${e}.pdf`;window.open(i)}"))

	if route.Method != common.HttpMethodGet {
		t.Errorf("method = %q, want GET", route.Method)
	}
}

func TestExtractInterpolatedRoutesAcceptsRootedLiteralWithoutBase(t *testing.T) {
	route := onlyRoute(t, interpolated(t, "this.http.get(`/api/v2/reports/${reportId}`);"))

	if route.Path != "/api/v2/reports/{reportId}" {
		t.Errorf("path = %q", route.Path)
	}
}

func TestExtractInterpolatedRoutesNamesFromExpressionWhenMeaningful(t *testing.T) {
	route := onlyRoute(t, interpolated(t, "fetch(`/rest/track/${this.orderId}`, {method:'GET'})"))

	if len(route.PathParams) != 1 || route.PathParams[0].Name != "orderId" {
		t.Fatalf("expected the expression to name the param, got %v", route.PathParams)
	}
}

func TestExtractInterpolatedRoutesUsesPositionalNameWhenMinified(t *testing.T) {
	// The preceding segment is as often a verb as a resource, and it varied by call site.
	first := onlyRoute(t, interpolated(t,
		"const A=`${h}/api/v2`;\nthis.http.put(`${A}/widgets/archive/${e}/id/${i}`, b);"))
	second := onlyRoute(t, interpolated(t,
		"const A=`${h}/api/v2`;\nthis.http.put(`${A}/widgets/archive/${t}/id/${n}`, b);"))

	if first.Path != "/api/v2/widgets/archive/{param3}/id/{param5}" {
		t.Errorf("path = %q, want positional names", first.Path)
	}
	if first.Path != second.Path {
		t.Errorf("names must not vary by call site: %q vs %q", first.Path, second.Path)
	}
}

func TestExtractInterpolatedRoutesNamesFromAdjacentLiteralText(t *testing.T) {
	// Literal text inside the same segment is adjacent evidence, unlike the preceding segment.
	route := onlyRoute(t, interpolated(t, "fetch(`/ftp/order_${e}.pdf`, {method:'GET'})"))

	if route.Path != "/ftp/order_{orderId}.pdf" {
		t.Errorf("path = %q, want /ftp/order_{orderId}.pdf", route.Path)
	}
}

func TestExtractInterpolatedRoutesHandlesMultipleParameters(t *testing.T) {
	route := onlyRoute(t, interpolated(t,
		"const A=`${h}/api/v2`;\nthis.http.put(`${A}/basket/${basketId}/coupon/${couponId}`, b);"))

	if route.Path != "/api/v2/basket/{basketId}/coupon/{couponId}" {
		t.Errorf("path = %q", route.Path)
	}
	if len(route.PathParams) != 2 || route.PathParams[0].Name == route.PathParams[1].Name {
		t.Fatalf("expected two distinctly named params, got %v", route.PathParams)
	}
}

func TestExtractInterpolatedRoutesAcceptsWrappedExpressions(t *testing.T) {
	route := onlyRoute(t, interpolated(t, "this.http.get(`/api/user/${encodeURIComponent(accountId)}`)"))

	if route.Path != "/api/user/{accountId}" {
		t.Errorf("path = %q, want the unwrapped argument as the name", route.Path)
	}
}

func TestExtractInterpolatedRoutesRejectsNonPathInterpolations(t *testing.T) {
	cases := map[string]string{
		"markup":              "this.http.get(`<code>${e.data[0].orderId}</code>`)",
		"inline style":        "this.http.get(`scaleX(${this.value/100})`)",
		"protocol relative":   "this.http.get(`//${window.location.host}/rest/x`)",
		"query only":          "const A=`${h}/api`;\nthis.http.get(`${A}/languages?v=${e}`)",
		"whole path is param": "const A=`${h}/api`;\nthis.http.get(`${A}/${e}`)",
		"no interpolation":    "this.http.get(`/rest/languages`)",
		"closing tag":         "this.http.get(`</div>${y}`)",
		"prose":               "this.http.get(`/5 items ${count}`)",
	}

	for name, content := range cases {
		if routes := interpolated(t, content); len(routes) != 0 {
			t.Errorf("%s: expected no routes, got %q", name, routes[0].Path)
		}
	}
}

func TestExtractInterpolatedRoutesTagsProvenance(t *testing.T) {
	// Must stay distinguishable from a route-table declaration downstream.
	route := onlyRoute(t, interpolated(t, "this.http.get(`/rest/basket/${basketId}`)"))

	if route.Evidence == nil || *route.Evidence != "interpolated" {
		t.Errorf("evidence = %v, want interpolated", route.Evidence)
	}
}

func TestExtractInterpolatedRoutesKeepsCandidatesFromDistinctBases(t *testing.T) {
	// Two bases sharing a tail must both survive, or a route recoverable from one is lost when the
	// other never corroborates.
	routes := interpolated(t,
		"this.http.get(`${this.apiA}/reports/${id}`);\nthis.http.get(`${this.apiB}/reports/${id}`);")

	if len(routes) != 2 {
		paths := make([]string, 0, len(routes))
		for _, route := range routes {
			paths = append(paths, *route.Evidence)
		}
		t.Fatalf("expected a candidate per base, got %v", paths)
	}
}
