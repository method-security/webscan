package discoverroute_test

import (
	"reflect"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
	discoverroute "github.com/Method-Security/webscan/internal/discover/route/helpers"
)

func TestParseBodyParams(t *testing.T) {
	for _, tt := range []struct {
		name    string
		body    string
		want    map[string][]string
		wantErr bool
	}{
		{
			name: "JSON subscription array",
			body: `[{"id":"4","channel":"/meta/subscribe","subscription":"/sn/meta/channel_redirect/example","clientId":"example"}]`,
		},
		{
			name: "JSON array with whitespace",
			body: " \n\t[1,2,3] \n",
		},
		{
			name: "empty JSON array",
			body: `[]`,
		},
		{
			name:    "malformed JSON array",
			body:    `[{"id":"4"}`,
			wantErr: true,
		},
		{
			name: "JSON object with whitespace",
			body: " \n" + `{"name":"example","count":2}`,
			want: map[string][]string{"name": {`"example"`}, "count": {"2"}},
		},
		{
			name: "nested JSON array remains a field value",
			body: `{"ids":[1,2]}`,
			want: map[string][]string{"ids": {`[1,2]`}},
		},
		{
			name: "form values including JSON",
			body: `name=example&ids=%5B1%2C2%5D&flag=`,
			want: map[string][]string{"name": {"example"}, "ids": {"[1,2]"}, "flag": {}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			params, err := discoverroute.ParseBodyParams(tt.body)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseBodyParams() error = %v, want error %v", err, tt.wantErr)
			}
			var got map[string][]string
			if len(params) > 0 {
				got = make(map[string][]string)
			}
			for _, param := range params {
				got[param.Name] = param.ExampleValues
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseBodyParams() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

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
