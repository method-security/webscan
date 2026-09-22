package enumeratejavascript

import (
	"testing"

	"github.com/Method-Security/webscan/generated/go/enumerate"
)

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
