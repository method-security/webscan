package enumeratejavascript

import (
	"encoding/json"
	"testing"

	"github.com/Method-Security/webscan/generated/go/enumerate"
)

func assertJSONKeys(t *testing.T, value map[string]any, expected ...string) {
	t.Helper()
	if len(value) != len(expected) {
		t.Fatalf("expected keys %v, got %v", expected, value)
	}
	for _, key := range expected {
		if _, exists := value[key]; !exists {
			t.Fatalf("expected key %q in %v", key, value)
		}
	}
}

func TestJavascriptSignalShape(t *testing.T) {
	exampleValue := "open"
	report := enumerate.EnumerateJavascriptReport{
		Config: &enumerate.EnumerateJavascriptConfig{Targets: []string{"https://app.example.com"}},
		Result: &enumerate.EnumerateJavascriptResult{
			Targets: []string{"https://app.example.com"},
			WebApplications: []*enumerate.JavascriptApplicationDetails{{
				BaseUrl: "https://app.example.com",
				Bundles: &enumerate.JavascriptBundleDetails{
					Local:  []*enumerate.JavascriptArtifact{{Url: "https://app.example.com/main.js", Kind: enumerate.JavascriptArtifactKindEntry, SizeBytes: 1234}},
					Remote: []*enumerate.JavascriptArtifact{{Url: "https://cdn.example.net/chunk.js", Kind: enumerate.JavascriptArtifactKindChunk, SizeBytes: 456}},
				},
				Endpoints: []*enumerate.JavascriptEndpoint{{
					Path:      "/api/orders",
					SourceUrl: "https://app.example.com/main.js",
					QueryParams: []*enumerate.JavascriptEndpointParam{{
						Name:         "status",
						ExampleValue: &exampleValue,
					}},
					BodyParams: []*enumerate.JavascriptEndpointParam{{Name: "limit"}},
				}},
				Secrets: []*enumerate.JavascriptSecret{{Kind: "api-key", SourceUrl: "https://app.example.com/main.js"}},
			}},
		},
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var signal map[string]any
	if err := json.Unmarshal(encoded, &signal); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	assertJSONKeys(t, signal, "config", "result")
	result := signal["result"].(map[string]any)
	assertJSONKeys(t, result, "targets", "webApplications")
	application := result["webApplications"].([]any)[0].(map[string]any)
	assertJSONKeys(t, application, "baseUrl", "bundles", "endpoints", "secrets")
	bundles := application["bundles"].(map[string]any)
	assertJSONKeys(t, bundles, "local", "remote")
	artifact := bundles["local"].([]any)[0].(map[string]any)
	assertJSONKeys(t, artifact, "url", "kind", "sizeBytes")
	endpoint := application["endpoints"].([]any)[0].(map[string]any)
	assertJSONKeys(t, endpoint, "path", "queryParams", "bodyParams", "sourceUrl")
	queryParam := endpoint["queryParams"].([]any)[0].(map[string]any)
	assertJSONKeys(t, queryParam, "name", "exampleValue")
	bodyParam := endpoint["bodyParams"].([]any)[0].(map[string]any)
	assertJSONKeys(t, bodyParam, "name")
	secret := application["secrets"].([]any)[0].(map[string]any)
	assertJSONKeys(t, secret, "kind", "sourceUrl")
}

// owners is the single application the collector tests enqueue against.
var owners = []string{"https://app.example.com"}

// The budget is documented as run-wide, so an explicit target must draw on it too.
func TestCollectorSpendsBudgetOnTargets(t *testing.T) {
	c := testCollector(2)

	if !c.spend() || !c.spend() {
		t.Fatalf("expected the first two retrievals to be allowed")
	}
	if c.spend() {
		t.Fatalf("expected the third retrieval to be refused")
	}
	if c.remaining != 0 {
		t.Fatalf("expected the budget to be spent, got %d", c.remaining)
	}
}

func TestCollectorBudgetIsUnlimitedWhenUnset(t *testing.T) {
	c := testCollector(0)
	for range 50 {
		if !c.spend() {
			t.Fatalf("expected an unset budget to allow every retrieval")
		}
	}
}

// A target another stage already claimed must not be charged, or the budget is spent twice on one
// URL and later targets are dropped for no retrieval.
func TestCollectorDoesNotChargeForAnAlreadyClaimedTarget(t *testing.T) {
	c := testCollector(3)

	// A page target claims the bundle it references.
	c.enqueue("https://app.example.com/main.js", enumerate.JavascriptArtifactKindEntry, owners)
	before := c.remaining

	// The same bundle named explicitly as a target is already claimed, so it costs nothing.
	if c.claim("https://app.example.com/main.js") {
		t.Fatalf("expected the bundle to be claimed already")
	}
	if c.remaining != before {
		t.Fatalf("expected no budget to be spent on an already-claimed target, got %d", c.remaining)
	}
}

// A target the budget refuses must not stay claimed, or the run records it as handled.
func TestCollectorReleasesATargetTheBudgetRefuses(t *testing.T) {
	c := testCollector(1)
	c.remaining = 0

	if !c.claim("https://app.example.com/main.js") {
		t.Fatalf("expected a fresh claim to succeed")
	}
	if c.spend() {
		t.Fatalf("expected an exhausted budget to refuse")
	}
	delete(c.claimed, "https://app.example.com/main.js")
	if len(c.claimed) != 0 {
		t.Fatalf("expected the refused target to be released, got %v", c.claimed)
	}
}

func testCollector(maxArtifacts int) *collector {
	return newCollector(enumerate.EnumerateJavascriptConfig{MaxArtifacts: maxArtifacts, Timeout: 1})
}

// Pages share entry bundles, so a bundle named by several pages must be queued once.
func TestCollectorQueuesEachBundleOnce(t *testing.T) {
	c := testCollector(0)

	c.enqueue("https://app.example.com/main.js", enumerate.JavascriptArtifactKindEntry, owners)
	c.enqueue("https://app.example.com/main.js", enumerate.JavascriptArtifactKindEntry, owners)
	c.enqueue("https://app.example.com/vendor.js", enumerate.JavascriptArtifactKindEntry, owners)

	if len(c.pendingBundles()) != 2 {
		t.Fatalf("expected 2 queued bundles, got %d", len(c.pendingBundles()))
	}
	if len(c.errors) != 0 {
		t.Fatalf("expected a repeated reference to be quiet, got %v", c.errors)
	}
}

// A URL dropped by the budget must not stay claimed, or the run would record it as handled.
func TestCollectorReleasesArtifactsDroppedByTheBudget(t *testing.T) {
	c := testCollector(1)
	for _, u := range []string{"https://app.example.com/a.js", "https://app.example.com/b.js", "https://app.example.com/c.js"} {
		c.enqueue(u, enumerate.JavascriptArtifactKindChunk, owners)
	}

	c.drainQueue(t.Context(), reportFailures)

	if len(c.claimed) != 1 {
		t.Fatalf("expected only the retrieved URL to stay claimed, got %d: %v", len(c.claimed), c.claimed)
	}
	if c.remaining != 0 {
		t.Fatalf("expected the budget to be spent, got %d", c.remaining)
	}
	budget := 0
	for _, e := range c.errors {
		if len(e) > 0 && (e[len(e)-len("max-artifacts reached"):] == "max-artifacts reached") {
			budget++
		}
	}
	if budget != 1 {
		t.Fatalf("expected one budget error, got %v", c.errors)
	}
}

// A budget message survives even when individual retrieval failures are suppressed, or
// --fetch-source-maps could retrieve nothing and still exit clean.
func TestCollectorReportsBudgetEvenWhenFailuresAreQuiet(t *testing.T) {
	c := testCollector(1)
	c.remaining = 0
	c.enqueue("https://app.example.com/main.js.map", enumerate.JavascriptArtifactKindSourceMap, owners)

	c.drainQueue(t.Context(), quietFailures)

	if len(c.errors) != 1 {
		t.Fatalf("expected the budget skip to be reported, got %v", c.errors)
	}
}

// An exhausted budget reports what it skipped rather than failing silently.
func TestCollectorReportsSkippedArtifactsWhenBudgetIsExhausted(t *testing.T) {
	c := testCollector(1)
	c.remaining = 0
	c.enqueue("https://app.example.com/a.js", enumerate.JavascriptArtifactKindChunk, owners)

	c.drainQueue(t.Context(), reportFailures)

	if len(c.errors) != 1 {
		t.Fatalf("expected a skip to be reported, got %v", c.errors)
	}
	if len(c.claimed) != 0 {
		t.Fatalf("expected nothing to stay claimed, got %v", c.claimed)
	}
}

// analyzed adds an artifact to the collector as if it had been retrieved and owned by each owner.
func (c *collector) analyzed(url string, kind enumerate.JavascriptArtifactKind, source string, owners []string) {
	c.addOwners(url, owners)
	c.record(&artifact{url: url, kind: kind, source: []byte(source)})
}

// A bundle the application's own host serves is a local asset; one another host serves is a remote
// asset of that same application, never a local asset of the host serving it.
func TestAnalyzeSplitsBundlesByWhoServesThem(t *testing.T) {
	c := testCollector(0)
	app := []string{"https://app.example.com"}
	c.addOwners("https://app.example.com", app)
	c.record(&artifact{url: "https://app.example.com", isPage: true})
	c.analyzed("https://app.example.com/main.js", enumerate.JavascriptArtifactKindEntry, `const a=1;`, app)
	c.analyzed("https://cdn.vendor.net/vendor.js", enumerate.JavascriptArtifactKindEntry, `const b=2;`, app)
	c.analyzed("https://cdn.vendor.net/44.chunk.js", enumerate.JavascriptArtifactKindChunk, `const d=3;`, app)

	result := c.analyze(enumerate.EnumerateJavascriptConfig{})
	if len(result.applications) != 1 {
		t.Fatalf("expected one application, got %d", len(result.applications))
	}

	application := result.applications[0]
	if application.BaseUrl != "https://app.example.com" {
		t.Fatalf("expected the application that loaded the bundles, got %s", application.BaseUrl)
	}
	if len(application.Bundles.Local) != 1 || application.Bundles.Local[0].Url != "https://app.example.com/main.js" {
		t.Fatalf("expected only the same-host bundle to be local, got %v", application.Bundles.Local)
	}
	if len(application.Bundles.Remote) != 2 {
		t.Fatalf("expected the CDN bundle and its chunk to be remote assets, got %v", application.Bundles.Remote)
	}
}

func TestAnalyzeProjectsBundleProvenanceFromCollectorState(t *testing.T) {
	c := testCollector(0)
	c.addOwners("https://app.example.com/main.js", []string{"https://app.example.com"})
	c.record(&artifact{
		url:         "https://app.example.com/main.js",
		kind:        enumerate.JavascriptArtifactKindEntry,
		sizeBytes:   1234,
		contentType: "application/javascript",
		source:      []byte(`fetch("/api/orders")`),
	})

	result := c.analyze(enumerate.EnumerateJavascriptConfig{})
	application := result.applications[0]
	bundle := application.Bundles.Local[0]
	if bundle.Url != "https://app.example.com/main.js" || bundle.Kind != enumerate.JavascriptArtifactKindEntry || bundle.SizeBytes != 1234 {
		t.Fatalf("expected bundle provenance to survive, got %+v", bundle)
	}
}

func TestAnalyzeExtensionlessScriptWithoutReportingAWebFile(t *testing.T) {
	c := testCollector(0)
	owner := []string{"https://app.example.com"}
	c.analyzed("https://cdn.vendor.net/scripts/loader?version=1", enumerate.JavascriptArtifactKindEntry,
		`fetch("/api/orders")`, owner)

	result := c.analyze(enumerate.EnumerateJavascriptConfig{})
	if len(result.applications) != 1 {
		t.Fatalf("expected one application, got %d", len(result.applications))
	}
	application := result.applications[0]
	if application.Bundles != nil {
		t.Fatalf("extensionless script must not be reported as a file, got %+v", application.Bundles)
	}
	if len(application.Endpoints) != 1 || application.Endpoints[0].Path != "/api/orders" {
		t.Fatalf("expected to retain endpoints analyzed from the script, got %+v", application.Endpoints)
	}
}

func TestSignalArtifactsRequireFileEnding(t *testing.T) {
	artifacts := []*artifact{
		{url: "https://cdn.example.com/main.js?cache=1"},
		{url: "https://cdn.example.com/main.js.map"},
		{url: "https://cdn.example.com/scripts/loader"},
		{url: "https://cdn.example.com/main.js/"},
		{url: "https://cdn.example.com/index.html"},
		{url: "https://cdn.example.com/.htaccess"},
	}
	got := signalArtifacts(artifacts)
	if len(got) != 3 {
		t.Fatalf("expected three file-shaped artifacts, got %+v", got)
	}
	for _, expected := range []string{
		"https://cdn.example.com/main.js?cache=1",
		"https://cdn.example.com/main.js.map",
		"https://cdn.example.com/.htaccess",
	} {
		found := false
		for _, artifact := range got {
			found = found || artifact.Url == expected
		}
		if !found {
			t.Fatalf("expected %s in %+v", expected, got)
		}
	}
}

// A bundle a CDN serves to two applications belongs to both, rather than to whichever reached it first.
func TestAnalyzeReportsASharedBundleUnderEveryApplication(t *testing.T) {
	c := testCollector(0)
	c.analyzed("https://cdn.vendor.net/shared.js", enumerate.JavascriptArtifactKindEntry, `const a=1;`,
		[]string{"https://one.example.com", "https://two.example.com"})

	result := c.analyze(enumerate.EnumerateJavascriptConfig{})
	if len(result.applications) != 2 {
		t.Fatalf("expected both applications, got %d", len(result.applications))
	}
	for _, application := range result.applications {
		if len(application.Bundles.Remote) != 1 {
			t.Fatalf("expected %s to hold the shared bundle remotely, got %v", application.BaseUrl, application.Bundles)
		}
	}
}

// A root-relative path resolves against the application that loaded the bundle, so it sits under it.
func TestAnalyzeRootsRelativePathsAgainstTheOwningApplication(t *testing.T) {
	c := testCollector(0)
	c.analyzed("https://app.example.com/main.js", enumerate.JavascriptArtifactKindEntry,
		`fetch("/serviceapi/v1/User/Read");`, []string{"https://app.example.com"})

	result := c.analyze(enumerate.EnumerateJavascriptConfig{})
	if len(result.applications) != 1 {
		t.Fatalf("expected the one application, got %d", len(result.applications))
	}
	application := result.applications[0]
	if application.BaseUrl != "https://app.example.com" {
		t.Fatalf("expected the owning application, got %s", application.BaseUrl)
	}
	if len(application.Endpoints) != 1 || application.Endpoints[0].Path != "/serviceapi/v1/User/Read" {
		t.Fatalf("expected the endpoint under the owning application, got %v", application.Endpoints)
	}
}

// A bundle calling an API on a sibling host names an application of its own, rather than filing the
// endpoint under whichever application happened to load the bundle.
func TestAnalyzeFilesEndpointsUnderTheHostServingThem(t *testing.T) {
	c := testCollector(0)
	c.analyzed("https://app.example.com/main.js", enumerate.JavascriptArtifactKindEntry,
		`const env={serviceApiEndpoint:"https://app.example.com/serviceapi/v1"};`+
			`fetch("https://api.example.com/v1/User/Read");fetch("https://api.example.com/v1/Order/List");`,
		[]string{"https://app.example.com"})

	result := c.analyze(enumerate.EnumerateJavascriptConfig{})
	byBase := map[string]*enumerate.JavascriptApplicationDetails{}
	for _, application := range result.applications {
		byBase[application.BaseUrl] = application
	}

	if loader := byBase["https://app.example.com"]; loader == nil || len(loader.Endpoints) != 0 {
		t.Fatalf("expected the loading application to hold the bundle but not the endpoint, got %v", loader)
	}
	serving := byBase["https://api.example.com"]
	if serving == nil || len(serving.Endpoints) != 2 {
		t.Fatalf("expected the serving host to hold the endpoint, got %v", serving)
	}
	if serving.Bundles != nil {
		t.Fatalf("expected the serving host to serve no bundles of its own, got %v", serving.Bundles)
	}
}

// An absolute link to an unrelated host is not an endpoint of anything being scanned, so it must not
// stand up an application of its own.
func TestAnalyzeDropsCrossDomainEndpointsWhenAsked(t *testing.T) {
	c := newCollector(enumerate.EnumerateJavascriptConfig{
		Targets:                    []string{"https://app.example.com"},
		IgnoreCrossDomainEndpoints: true,
	})
	c.analyzed("https://app.example.com/main.js", enumerate.JavascriptArtifactKindEntry,
		`const env={serviceApiEndpoint:"https://app.example.com/serviceapi/v1"};`+
			`fetch("https://facebook.com/nasa/share");fetch("https://api.example.com/v1/User/Read");`,
		[]string{"https://app.example.com"})

	result := c.analyze(enumerate.EnumerateJavascriptConfig{
		Targets:                    []string{"https://app.example.com"},
		IgnoreCrossDomainEndpoints: true,
	})
	for _, application := range result.applications {
		if application.BaseUrl == "https://facebook.com" {
			t.Fatalf("expected an unrelated host to be dropped, got %v", application)
		}
	}
}

// A base on a sibling host the operator also targeted must still root the relative literals that
// hang off it, the same way an absolute URL to that host is kept.
func TestAnalyzeRootsAgainstABaseOnAnotherTargetedHost(t *testing.T) {
	config := enumerate.EnumerateJavascriptConfig{
		Targets:                    []string{"https://app.example.com", "https://api.example.com"},
		IgnoreCrossDomainEndpoints: true,
	}
	c := newCollector(config)
	c.analyzed("https://app.example.com/main.js", enumerate.JavascriptArtifactKindEntry,
		`const env={serviceApiEndpoint:"https://api.example.com/v1"};`+
			`class S{read(u){return this.dataService.getRequest("User/Read?userId="+u)}}`,
		[]string{"https://app.example.com"})

	result := c.analyze(config)
	if len(result.unrooted) != 0 {
		t.Fatalf("expected the literal to root against the targeted sibling, got %v", result.unrooted)
	}
	for _, application := range result.applications {
		if application.BaseUrl != "https://api.example.com" {
			continue
		}
		if len(application.Endpoints) != 1 || application.Endpoints[0].Path != "/v1/User/Read" {
			t.Fatalf("expected the rooted path under the serving host, got %v", application.Endpoints)
		}
		return
	}
	t.Fatalf("expected an application for the serving host, got %v", result.applications)
}
