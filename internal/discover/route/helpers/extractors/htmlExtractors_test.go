package discoverroute_test

import (
	"reflect"
	"testing"

	"github.com/Method-Security/webscan/generated/go/discover"
	extractors "github.com/Method-Security/webscan/internal/discover/route/helpers/extractors"
)

func TestExtractFormRoutesDeduplicatesFieldNames(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			doc := documentFrom(t, `<form action="/contact" method="`+method+`">
				<input type="hidden" name="isClient" value="false">
				<input type="checkbox" name="isClient" value="true">
				<input name="email">
				<textarea name="message"></textarea>
			</form>`)
			config := discover.DiscoverRouteConfig{Target: "https://example.com", IgnoreCrossDomainRoutes: true}
			routes, _, errors := extractors.ExtractFormRoutes(doc, config.Target, config)
			if len(errors) != 0 || len(routes) != 1 {
				t.Fatalf("routes = %v, errors = %v", routes, errors)
			}
			params := routes[0].QueryParams
			if method == "POST" {
				params = routes[0].BodyParams
			}
			var names []string
			for _, param := range params {
				names = append(names, param.Name)
			}
			if !reflect.DeepEqual(names, []string{"isClient", "email", "message"}) {
				t.Errorf("parameter names = %v", names)
			}
		})
	}
}

func TestExtractLinkRoutesPreservesQueryParameters(t *testing.T) {
	doc := documentFrom(t, `<link rel="alternate" href="/api/embed?url=https%3A%2F%2Fexample.com%2Fpage">
		<link rel="alternate" href="/api/embed?url=https%3A%2F%2Fexample.com%2Fpage&amp;format=xml">`)
	config := discover.DiscoverRouteConfig{Target: "https://example.com", IgnoreCrossDomainRoutes: true}
	routes, _, errors := extractors.ExtractLinkRoutes(doc, config.Target, config)
	if len(errors) != 0 || len(routes) != 1 {
		t.Fatalf("routes = %v, errors = %v", routes, errors)
	}
	if routes[0].Path != "/api/embed" {
		t.Errorf("path = %q", routes[0].Path)
	}
	got := make(map[string][]string)
	for _, param := range routes[0].QueryParams {
		got[param.Name] = param.ExampleValues
	}
	want := map[string][]string{"url": {"https://example.com/page"}, "format": {"xml"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("query params = %#v, want %#v", got, want)
	}
}

func TestExtractLinkRoutesExcludesDeclaredStylesheets(t *testing.T) {
	doc := documentFrom(t, `<link rel="stylesheet" href="/styles/theme.cssx?v=1">
		<link rel="alternate StyleSheet" href="/dynamic-style.do?theme=dark">
		<link rel="alternate" href="/api/render?format=html">`)
	config := discover.DiscoverRouteConfig{Target: "https://example.com", IgnoreCrossDomainRoutes: true}
	routes, _, errors := extractors.ExtractLinkRoutes(doc, config.Target, config)
	if len(errors) != 0 || len(routes) != 1 {
		t.Fatalf("routes = %v, errors = %v", routes, errors)
	}
	if routes[0].Path != "/api/render" {
		t.Errorf("path = %q, want /api/render", routes[0].Path)
	}
}
