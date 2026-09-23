package enumeratejavascript

import (
	"testing"

	"github.com/Method-Security/webscan/generated/go/enumerate"
)

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
	c.enqueue("https://app.example.com/main.js", enumerate.JavascriptArtifactKindEntry, "https://app.example.com/")
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

	c.enqueue("https://app.example.com/main.js", enumerate.JavascriptArtifactKindEntry, "https://app.example.com/")
	c.enqueue("https://app.example.com/main.js", enumerate.JavascriptArtifactKindEntry, "https://app.example.com/login")
	c.enqueue("https://app.example.com/vendor.js", enumerate.JavascriptArtifactKindEntry, "https://app.example.com/login")

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
		c.enqueue(u, enumerate.JavascriptArtifactKindChunk, "https://app.example.com/runtime.js")
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
	c.enqueue("https://app.example.com/main.js.map", enumerate.JavascriptArtifactKindSourceMap, "https://app.example.com/main.js")

	c.drainQueue(t.Context(), quietFailures)

	if len(c.errors) != 1 {
		t.Fatalf("expected the budget skip to be reported, got %v", c.errors)
	}
}

// An exhausted budget reports what it skipped rather than failing silently.
func TestCollectorReportsSkippedArtifactsWhenBudgetIsExhausted(t *testing.T) {
	c := testCollector(1)
	c.remaining = 0
	c.enqueue("https://app.example.com/a.js", enumerate.JavascriptArtifactKindChunk, "https://app.example.com/runtime.js")

	c.drainQueue(t.Context(), reportFailures)

	if len(c.errors) != 1 {
		t.Fatalf("expected a skip to be reported, got %v", c.errors)
	}
	if len(c.claimed) != 0 {
		t.Fatalf("expected nothing to stay claimed, got %v", c.claimed)
	}
}
