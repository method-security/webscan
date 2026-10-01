package discoverroute_test

import (
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
	discoverroute "github.com/Method-Security/webscan/internal/discover/route/helpers"
)

func routeAt(path string) *discover.RouteDetails {
	return routeAtBase("https://example.com", path)
}

func routeAtBase(baseURL string, path string) *discover.RouteDetails {
	return &discover.RouteDetails{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
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

func TestMergeWebRoutesFiltersChangingHighEntropySegments(t *testing.T) {
	routes := []*discover.RouteDetails{
		routeAt("/transport/aevpqlxmkdoruwicntbz"),
		routeAt("/transport/qmtxvafnlozprewicbdu"),
		routeAt("/transport/health"),
	}

	merged := discoverroute.MergeWebRoutes(routes)

	if len(merged) != 1 {
		t.Fatalf("expected only the stable route to remain, got %d", len(merged))
	}
	if merged[0].Path != "/transport/health" {
		t.Errorf("path = %q, want %q", merged[0].Path, "/transport/health")
	}
}

func TestMergeWebRoutesKeepsSingleHighEntropySegment(t *testing.T) {
	route := routeAt("/documents/aevpqlxmkdoruwicntbz")

	merged := discoverroute.MergeWebRoutes([]*discover.RouteDetails{route})

	if len(merged) != 1 {
		t.Fatalf("expected a single opaque resource route to remain, got %d", len(merged))
	}
}

func TestMergeWebRoutesKeepsNamedHighEntropySiblingRoutes(t *testing.T) {
	merged := discoverroute.MergeWebRoutes([]*discover.RouteDetails{
		routeAt("/settings/emailverification"),
		routeAt("/settings/accountmanagement"),
		routeAt("/settings/authorizationcode"),
		routeAt("/settings/customerrelations"),
		routeAt("/settings/profilemanagement"),
		routeAt("/reports/quickbrownfox"),
		routeAt("/reports/lazyjumpsover"),
	})

	if len(merged) != 7 {
		t.Fatalf("expected named sibling routes to remain, got %d routes", len(merged))
	}
}

func TestMergeWebRoutesGroupsHighEntropySegmentsAcrossMethods(t *testing.T) {
	postRoute := routeAt("/transport/qmtxvafnlozprewicbdu")
	postRoute.Method = common.HttpMethodPost

	merged := discoverroute.MergeWebRoutes([]*discover.RouteDetails{
		routeAt("/transport/aevpqlxmkdoruwicntbz"),
		postRoute,
	})

	if len(merged) != 0 {
		t.Fatalf("expected method differences not to split noisy URL families, got %d routes", len(merged))
	}
}

func TestMergeWebRoutesDoesNotGroupHighEntropySegmentsAcrossOrigins(t *testing.T) {
	merged := discoverroute.MergeWebRoutes([]*discover.RouteDetails{
		routeAt("/transport/aevpqlxmkdoruwicntbz"),
		routeAtBase("https://api.example.com", "/transport/qmtxvafnlozprewicbdu"),
	})

	if len(merged) != 2 {
		t.Fatalf("expected origin-specific route families to remain independent, got %d routes", len(merged))
	}
}

func TestMergeWebRoutesCountsDistinctHighEntropySiblingPaths(t *testing.T) {
	merged := discoverroute.MergeWebRoutes([]*discover.RouteDetails{
		routeAt("/transport/aevpqlxmkdoruwicntbz"),
		routeAt("/transport/aevpqlxmkdoruwicntbz"),
	})

	if len(merged) != 1 {
		t.Fatalf("expected repeated sightings of one URL not to create a noisy route family, got %d routes", len(merged))
	}
}
