package enumeratejavascript

import (
	"context"
	"strings"
	"testing"

	"github.com/Method-Security/webscan/generated/go/enumerate"
)

const sharedRuntime = `r.u=e=>e+"."+{1:"aaaa1111",2:"bbbb2222",3:"cccc3333"}[e]+".js",r.p="",`

func runtimeArtifact(url string) *artifact {
	return &artifact{
		details: &enumerate.JavascriptArtifact{Url: url, Kind: enumerate.JavascriptArtifactKindEntry},
		source:  []byte(sharedRuntime),
	}
}

// Two targets embedding the same runtime must not turn "nothing new to fetch" into a failure.
func TestFetchDeclaredChunksIsQuietWhenAnotherTargetClaimedTheChunks(t *testing.T) {
	config := enumerate.EnumerateJavascriptConfig{MaxArtifacts: 10, Timeout: 1}
	fetched := map[string]struct{}{}
	remaining := config.MaxArtifacts

	// Claim every chunk as though a previous target had already fetched them.
	for _, name := range []string{"1.aaaa1111.js", "2.bbbb2222.js", "3.cccc3333.js"} {
		fetched["https://app.example.com/"+name] = struct{}{}
	}

	artifacts, errs := fetchDeclaredChunks(context.Background(), config, runtimeArtifact("https://app.example.com/runtime.js"), fetched, &remaining)
	if len(artifacts) != 0 {
		t.Fatalf("expected no new artifacts, got %d", len(artifacts))
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors when every chunk was already claimed, got %v", errs)
	}
	if remaining != config.MaxArtifacts {
		t.Fatalf("expected the budget to be untouched, got %d", remaining)
	}
}

// A chunk dropped by the budget must stay reachable from a later target.
func TestFetchDeclaredChunksDoesNotClaimChunksItSkips(t *testing.T) {
	config := enumerate.EnumerateJavascriptConfig{MaxArtifacts: 1, Timeout: 1}
	fetched := map[string]struct{}{}
	remaining := config.MaxArtifacts

	_, errs := fetchDeclaredChunks(context.Background(), config, runtimeArtifact("https://app.example.com/runtime.js"), fetched, &remaining)

	budgetErrors := 0
	for _, e := range errs {
		if strings.Contains(e, "max-artifacts reached") {
			budgetErrors++
		}
	}
	if budgetErrors != 1 {
		t.Fatalf("expected one budget error, got %v", errs)
	}
	// Only the single chunk the budget allowed may be claimed; the other two stay available.
	if len(fetched) != 1 {
		t.Fatalf("expected exactly one claimed chunk, got %d: %v", len(fetched), fetched)
	}
	if remaining != 0 {
		t.Fatalf("expected the budget to be spent, got %d", remaining)
	}
}
