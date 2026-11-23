package discoverroute_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/Method-Security/webscan/generated/go/discover"
	capturerouteextractors "github.com/Method-Security/webscan/internal/discover/route/helpers/extractors"
	"github.com/PuerkitoBio/goquery"
)

func scriptAssetConfig(collectStaticAssets bool, ignoreCrossDomain bool) discover.DiscoverRouteConfig {
	return discover.DiscoverRouteConfig{
		Target:                        "https://app.example.com",
		CollectStaticAssets:           collectStaticAssets,
		IgnoreCrossDomainStaticAssets: ignoreCrossDomain,
	}
}

func documentFrom(t *testing.T, html string) *goquery.Document {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		t.Fatalf("parsing document: %s", err)
	}
	return doc
}

func TestExtractScriptAssetsRecordsReferencedBundles(t *testing.T) {
	doc := documentFrom(t, `<html><head>
		<script src="/runtime.abc123.js"></script>
		<script src="polyfills.def456.js"></script>
		<script src="https://app.example.com/main.789xyz.js?v=2"></script>
		<script>console.log("inline")</script>
	</head></html>`)

	urls, errors := capturerouteextractors.ExtractScriptAssets(doc, "https://app.example.com/login", scriptAssetConfig(true, true))
	if len(errors) != 0 {
		t.Fatalf("expected no errors, got %v", errors)
	}

	sort.Strings(urls)
	expected := []string{
		"https://app.example.com/main.789xyz.js",
		"https://app.example.com/polyfills.def456.js",
		"https://app.example.com/runtime.abc123.js",
	}
	if len(urls) != len(expected) {
		t.Fatalf("expected %d bundles, got %d: %v", len(expected), len(urls), urls)
	}
	for i, want := range expected {
		if urls[i] != want {
			t.Fatalf("expected %s, got %s", want, urls[i])
		}
	}
}

func TestExtractScriptAssetsHonorsStaticAssetPolicy(t *testing.T) {
	doc := documentFrom(t, `<html><head><script src="/main.abc.js"></script></head></html>`)

	urls, _ := capturerouteextractors.ExtractScriptAssets(doc, "https://app.example.com/", scriptAssetConfig(false, true))
	if len(urls) != 0 {
		t.Fatalf("expected no bundles when static assets are not collected, got %v", urls)
	}
}

func TestExtractScriptAssetsExcludesCrossDomainBundles(t *testing.T) {
	doc := documentFrom(t, `<html><head>
		<script src="https://cdn.other.com/vendor.js"></script>
		<script src="/main.abc.js"></script>
	</head></html>`)

	urls, _ := capturerouteextractors.ExtractScriptAssets(doc, "https://app.example.com/", scriptAssetConfig(true, true))
	if len(urls) != 1 || urls[0] != "https://app.example.com/main.abc.js" {
		t.Fatalf("expected only the in-scope bundle, got %v", urls)
	}

	urls, _ = capturerouteextractors.ExtractScriptAssets(doc, "https://app.example.com/", scriptAssetConfig(true, false))
	if len(urls) != 2 {
		t.Fatalf("expected both bundles when cross-domain assets are allowed, got %v", urls)
	}
}
