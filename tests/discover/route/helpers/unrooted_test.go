package helpers_test

import (
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
	discoverroute "github.com/Method-Security/webscan/internal/discover/route/helpers"
)

func tagged(path string, evidence string) *discover.RouteDetails {
	route := routeAt(path)
	if evidence != "" {
		route.Evidence = &evidence
	}
	return route
}

func candidateOf(path string, base string) *discover.RouteDetails {
	route := tagged(path, discoverroute.UnrootedEvidenceFor(base))
	template := path
	route.PathTemplate = &template
	route.PathParams = []*discover.RoutePathParam{{Name: "param2"}}
	return route
}

func candidate(path string) *discover.RouteDetails {
	route := tagged(path, discoverroute.InterpolatedUnrootedEvidence)
	template := path
	route.PathTemplate = &template
	route.PathParams = []*discover.RoutePathParam{{Name: "param2"}}
	return route
}

func TestResolveUnrootedAcceptsCandidateAlreadyRooted(t *testing.T) {
	// The application serves paths under /rest, so the candidate needs no prefix.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		tagged("/rest/user", ""),
		candidate("/rest/basket/{param2}"),
	})

	route := findRoute(t, routes, "/rest/basket/{param2}")
	if route.Evidence == nil || *route.Evidence != discoverroute.InterpolatedRouteEvidence {
		t.Errorf("evidence = %v, want it retagged as resolved", route.Evidence)
	}
	if route.PathTemplate == nil || *route.PathTemplate != "/rest/basket/{param2}" {
		t.Errorf("PathTemplate = %v, want it to track Path", route.PathTemplate)
	}
}

func TestResolveUnrootedRecoversMissingPrefix(t *testing.T) {
	// The application serves the anchor only under /api/v2, so that is the missing prefix.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/api/v2/appmessages", ""),
		tagged("/api/v2/health", ""),
		candidate("/appmessages/{param2}"),
	})

	route := findRoute(t, routes, "/api/v2/appmessages/{param2}")
	if route.PathTemplate == nil || *route.PathTemplate != "/api/v2/appmessages/{param2}" {
		t.Errorf("PathTemplate = %v, want the rooted path", route.PathTemplate)
	}
}

func TestResolveUnrootedDropsAmbiguousPrefix(t *testing.T) {
	// Two versions serve the same anchor, so which one the base held is unknown.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/api/v1/reports", ""),
		tagged("/api/v2/reports", ""),
		candidate("/reports/{param2}"),
	})

	if len(routes) != 2 {
		t.Fatalf("expected the candidate dropped, got %v", pathsOf(routes))
	}
}

func TestResolveUnrootedDropsUncorroboratedCandidate(t *testing.T) {
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		candidate("/appmessages/{param2}"),
	})

	if len(routes) != 1 {
		t.Fatalf("expected the candidate dropped, got %v", pathsOf(routes))
	}
}

func TestResolveUnrootedIgnoresInterpolatedCorroboration(t *testing.T) {
	// A candidate must not be corroborated by another interpolated route, or a wrong prefix
	// confirms itself.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/appmessages/1", discoverroute.InterpolatedRouteEvidence),
		candidate("/appmessages/{param2}"),
		candidate("/appmessages/{param2}/detail"),
	})

	if len(routes) != 1 {
		t.Fatalf("expected both candidates dropped, got %v", pathsOf(routes))
	}
}

func TestResolveUnrootedCorroboratesOnlyOnObservedRoutes(t *testing.T) {
	// A route-table declaration is a client-side route: an SPA serving /products while its API lives
	// at /api/v2/products would otherwise confirm the wrong prefix.
	for _, evidence := range []string{"CONST:X", "sourcemap:app.ts", discoverroute.DeclaredRouteEvidence} {
		routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
			tagged("/rest/products", evidence),
			candidate("/rest/basket/{param2}"),
		})
		for _, route := range routes {
			if route.Path == "/rest/basket/{param2}" {
				t.Errorf("%s must not corroborate a candidate", evidence)
			}
		}
	}

	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		candidate("/rest/basket/{param2}"),
	})
	findRoute(t, routes, "/rest/basket/{param2}")
}

func TestResolveUnrootedIgnoresClientRouteDeclarations(t *testing.T) {
	// The SPA declares /reports as a client route while the API serves /api/v2/reports; the
	// candidate must take the observed API prefix, not the client route.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/reports", discoverroute.DeclaredRouteEvidence),
		tagged("/api/v2/reports", ""),
		candidate("/reports/{param2}"),
	})

	findRoute(t, routes, "/api/v2/reports/{param2}")
}

func TestResolveUnrootedAnchorsOnFirstLiteralSegment(t *testing.T) {
	// A leading placeholder is not an anchor; the first fixed segment is.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/api/v2/basket/1/items", ""),
		candidate("/{param1}/basket/{param3}"),
	})

	findRoute(t, routes, "/api/v2/{param1}/basket/{param3}")
}

func TestResolveUnrootedDropsCandidateWithNoLiteralSegment(t *testing.T) {
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		candidate("/{param1}"),
	})

	if len(routes) != 1 {
		t.Fatalf("expected the candidate dropped, got %v", pathsOf(routes))
	}
}

func TestResolveUnrootedLeavesOtherRoutesUntouched(t *testing.T) {
	observed := tagged("/rest/products", "")
	declared := tagged("/documents/{id}", discoverroute.DeclaredRouteEvidence)

	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{observed, declared})

	if len(routes) != 2 {
		t.Fatalf("expected both routes kept, got %v", pathsOf(routes))
	}
	if *declared.Evidence != discoverroute.DeclaredRouteEvidence {
		t.Errorf("declared evidence was modified: %q", *declared.Evidence)
	}
}

func TestResolveUnrootedKeepsMethodOfCandidate(t *testing.T) {
	route := candidate("/rest/basket/{param2}")
	route.Method = common.HttpMethodPut

	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		route,
	})

	if findRoute(t, routes, "/rest/basket/{param2}").Method != common.HttpMethodPut {
		t.Errorf("method was not preserved through rooting")
	}
}

func TestApplyDeclaredRouteTemplatesDropsUnresolvedCandidate(t *testing.T) {
	// Defence in depth: a candidate that never went through resolution must not reach the report.
	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		candidate("/rest/basket/{param2}"),
	})

	for _, route := range routes {
		if route.Path == "/rest/basket/{param2}" {
			t.Errorf("an unrooted candidate reached the output")
		}
	}
}

func TestResolveUnrootedInheritsPrefixFromSameBase(t *testing.T) {
	// One candidate for this base is corroborated directly; the other has no observed anchor of its
	// own, but the base has been shown to contribute no prefix.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		candidateOf("/rest/basket/{param2}", "hostServer"),
		candidateOf("/ftp/order_{param2}.pdf", "hostServer"),
	})

	findRoute(t, routes, "/rest/basket/{param2}")
	findRoute(t, routes, "/ftp/order_{param2}.pdf")
}

func TestResolveUnrootedInheritsNonEmptyPrefixFromSameBase(t *testing.T) {
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/api/v2/reports", ""),
		candidateOf("/reports/{param2}", "apiBase"),
		candidateOf("/exports/{param2}", "apiBase"),
	})

	findRoute(t, routes, "/api/v2/reports/{param2}")
	findRoute(t, routes, "/api/v2/exports/{param2}")
}

func TestResolveUnrootedDoesNotInheritAcrossDifferentBases(t *testing.T) {
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/api/v2/reports", ""),
		candidateOf("/reports/{param2}", "apiBase"),
		candidateOf("/exports/{param2}", "otherBase"),
	})

	findRoute(t, routes, "/api/v2/reports/{param2}")
	for _, route := range routes {
		if route.Path == "/api/v2/exports/{param2}" {
			t.Errorf("a different base must not inherit the prefix")
		}
	}
}

func TestResolveUnrootedDoesNotInheritWhenBasePrefixesDisagree(t *testing.T) {
	// The same base rooted two ways means its value is not consistent evidence.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		tagged("/api/v2/reports", ""),
		candidateOf("/rest/basket/{param2}", "base"),
		candidateOf("/reports/{param2}", "base"),
		candidateOf("/unseen/{param2}", "base"),
	})

	for _, route := range routes {
		if route.Path == "/unseen/{param2}" || route.Path == "/api/v2/unseen/{param2}" {
			t.Errorf("expected no inheritance from a base with disagreeing prefixes, got %q", route.Path)
		}
	}
}

func TestResolveUnrootedDoesNotInheritWithoutRecordedBase(t *testing.T) {
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		candidate("/rest/basket/{param2}"),
		candidate("/ftp/order_{param2}.pdf"),
	})

	findRoute(t, routes, "/rest/basket/{param2}")
	for _, route := range routes {
		if route.Path == "/ftp/order_{param2}.pdf" {
			t.Errorf("a candidate with no recorded base must not inherit")
		}
	}
}
