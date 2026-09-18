package discoverroute_test

import (
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
