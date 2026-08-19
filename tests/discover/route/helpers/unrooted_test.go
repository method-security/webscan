package helpers_test

import (
	"regexp"
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

var placeholderPattern = regexp.MustCompile(`\{([^{}]+)\}`)

func withCandidateShape(route *discover.RouteDetails, path string) *discover.RouteDetails {
	template := path
	route.PathTemplate = &template
	for _, match := range placeholderPattern.FindAllStringSubmatch(path, -1) {
		route.PathParams = append(route.PathParams, &discover.RoutePathParam{Name: match[1]})
	}
	return route
}

func candidateOf(path string, base string) *discover.RouteDetails {
	return withCandidateShape(tagged(path, discoverroute.UnrootedEvidenceFor(base)), path)
}

func candidate(path string) *discover.RouteDetails {
	return withCandidateShape(tagged(path, discoverroute.InterpolatedUnrootedEvidence), path)
}

func TestResolveUnrootedAcceptsCandidateAlreadyRooted(t *testing.T) {
	// The application serves paths under /rest, so the candidate needs no prefix.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		tagged("/rest/user", ""),
		candidate("/rest/basket/{param3}"),
	})

	route := findRoute(t, routes, "/rest/basket/{param3}")
	if route.Evidence == nil || *route.Evidence != discoverroute.InterpolatedRouteEvidence {
		t.Errorf("evidence = %v, want it retagged as resolved", route.Evidence)
	}
	if route.PathTemplate == nil || *route.PathTemplate != "/rest/basket/{param3}" {
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

	route := findRoute(t, routes, "/api/v2/appmessages/{param4}")
	if route.PathTemplate == nil || *route.PathTemplate != "/api/v2/appmessages/{param4}" {
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
			candidate("/rest/basket/{param3}"),
		})
		for _, route := range routes {
			if route.Path == "/rest/basket/{param3}" {
				t.Errorf("%s must not corroborate a candidate", evidence)
			}
		}
	}

	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		candidate("/rest/basket/{param3}"),
	})
	findRoute(t, routes, "/rest/basket/{param3}")
}

func TestResolveUnrootedIgnoresClientRouteDeclarations(t *testing.T) {
	// The SPA declares /reports as a client route while the API serves /api/v2/reports; the
	// candidate must take the observed API prefix, not the client route.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/reports", discoverroute.DeclaredRouteEvidence),
		tagged("/api/v2/reports", ""),
		candidate("/reports/{param2}"),
	})

	findRoute(t, routes, "/api/v2/reports/{param4}")
}

func TestResolveUnrootedAnchorsOnFirstLiteralSegment(t *testing.T) {
	// A leading placeholder is not an anchor; the first fixed segment is.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/api/v2/basket/1/items", ""),
		candidate("/{param1}/basket/{param3}"),
	})

	findRoute(t, routes, "/api/v2/{param3}/basket/{param5}")
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
	route := candidate("/rest/basket/{param3}")
	route.Method = common.HttpMethodPut

	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		route,
	})

	if findRoute(t, routes, "/rest/basket/{param3}").Method != common.HttpMethodPut {
		t.Errorf("method was not preserved through rooting")
	}
}

func TestApplyDeclaredRouteTemplatesDropsUnresolvedCandidate(t *testing.T) {
	// Defence in depth: a candidate that never went through resolution must not reach the report.
	routes := discoverroute.ApplyDeclaredRouteTemplates([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		candidate("/rest/basket/{param3}"),
	})

	for _, route := range routes {
		if route.Path == "/rest/basket/{param3}" {
			t.Errorf("an unrooted candidate reached the output")
		}
	}
}

func TestResolveUnrootedInheritsPrefixFromSameBase(t *testing.T) {
	// One candidate for this base is corroborated directly; the other has no observed anchor of its
	// own, but the base has been shown to contribute no prefix.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		candidateOf("/rest/basket/{param3}", "hostServer"),
		candidateOf("/ftp/order_{param2}.pdf", "hostServer"),
	})

	findRoute(t, routes, "/rest/basket/{param3}")
	findRoute(t, routes, "/ftp/order_{param2}.pdf")
}

func TestResolveUnrootedInheritsNonEmptyPrefixFromSameBase(t *testing.T) {
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/api/v2/reports", ""),
		candidateOf("/reports/{param2}", "apiBase"),
		candidateOf("/exports/{param2}", "apiBase"),
	})

	findRoute(t, routes, "/api/v2/reports/{param4}")
	findRoute(t, routes, "/api/v2/exports/{param4}")
}

func TestResolveUnrootedDoesNotInheritAcrossDifferentBases(t *testing.T) {
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/api/v2/reports", ""),
		candidateOf("/reports/{param2}", "apiBase"),
		candidateOf("/exports/{param2}", "otherBase"),
	})

	findRoute(t, routes, "/api/v2/reports/{param4}")
	for _, route := range routes {
		if route.Path == "/api/v2/exports/{param4}" {
			t.Errorf("a different base must not inherit the prefix")
		}
	}
}

func TestResolveUnrootedDoesNotInheritWhenBasePrefixesDisagree(t *testing.T) {
	// The same base rooted two ways means its value is not consistent evidence.
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		tagged("/api/v2/reports", ""),
		candidateOf("/rest/basket/{param3}", "base"),
		candidateOf("/reports/{param2}", "base"),
		candidateOf("/unseen/{param2}", "base"),
	})

	for _, route := range routes {
		if route.Path == "/unseen/{param2}" || route.Path == "/api/v2/unseen/{param4}" {
			t.Errorf("expected no inheritance from a base with disagreeing prefixes, got %q", route.Path)
		}
	}
}

func TestResolveUnrootedDoesNotInheritWithoutRecordedBase(t *testing.T) {
	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		tagged("/rest/products", ""),
		candidate("/rest/basket/{param3}"),
		candidate("/ftp/order_{param2}.pdf"),
	})

	findRoute(t, routes, "/rest/basket/{param3}")
	for _, route := range routes {
		if route.Path == "/ftp/order_{param2}.pdf" {
			t.Errorf("a candidate with no recorded base must not inherit")
		}
	}
}

func TestUnrootedEvidenceCountsAsDerivationProvenance(t *testing.T) {
	// Source-map tagging must not strip the marker; losing it skips rooting and lets the
	// unprefixed tail reach the report.
	evidence := discoverroute.UnrootedEvidenceFor("hostServer")
	if discoverroute.EvidenceRank(&evidence) < 2 {
		t.Errorf("rank = %d, want it protected as derivation provenance", discoverroute.EvidenceRank(&evidence))
	}
	if !discoverroute.IsProvenanceEvidence(evidence) {
		t.Errorf("expected an unrooted candidate to be treated as provenance")
	}
}

func TestResolveUnrootedCorroboratesWithinOriginOnly(t *testing.T) {
	// A path served by another origin says nothing about this one.
	other := tagged("/rest/products", "")
	other.BaseUrl = "https://other.example.com"

	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		other,
		candidate("/rest/basket/{param3}"),
	})

	for _, route := range routes {
		if route.Path == "/rest/basket/{param3}" {
			t.Errorf("a foreign origin must not corroborate a candidate")
		}
	}
}

func TestResolveUnrootedDoesNotInheritAcrossOrigins(t *testing.T) {
	foreign := candidateOf("/reports/{param2}", "apiBase")
	foreign.BaseUrl = "https://other.example.com"
	foreignObserved := tagged("/api/v2/reports", "")
	foreignObserved.BaseUrl = "https://other.example.com"

	routes := discoverroute.ResolveUnrootedInterpolatedRoutes([]*discover.RouteDetails{
		foreignObserved,
		foreign,
		candidateOf("/exports/{param2}", "apiBase"),
	})

	for _, route := range routes {
		if route.Path == "/api/v2/exports/{param4}" {
			t.Errorf("a prefix corroborated on another origin must not be inherited here")
		}
	}
}
