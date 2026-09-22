package enumeratejavascript_test

import (
	"testing"

	enumeratejavascript "github.com/Method-Security/webscan/internal/enumerate/javascript/helpers"
)

const appShell = `<!doctype html><html><head>
  <link rel="stylesheet" href="/styles.abc.css">
  <script src="runtime.111.js"></script>
  <script src="/polyfills.222.js"></script>
  <script src="https://app.example.com/main.333.js?v=2"></script>
  <script src="https://cdn.example.net/vendor.444.js"></script>
  <script src="//evil.example.org/x.js"></script>
  <script>console.log("inline")</script>
</head></html>`

func TestExtractScriptReferencesResolvesEveryDeclaredBundle(t *testing.T) {
	refs := enumeratejavascript.ExtractScriptReferences(appShell, "https://app.example.com/login")

	expected := []string{
		"https://app.example.com/runtime.111.js",
		"https://app.example.com/polyfills.222.js",
		"https://app.example.com/main.333.js?v=2",
		"https://cdn.example.net/vendor.444.js",
	}
	if len(refs) != len(expected) {
		t.Fatalf("expected %d references, got %d: %v", len(expected), len(refs), refs)
	}
	for i, want := range expected {
		if refs[i] != want {
			t.Fatalf("reference %d: expected %s, got %s", i, want, refs[i])
		}
	}
}

// A protocol-relative src parses as a host and would send the fetch off-target.
func TestExtractScriptReferencesDropsProtocolRelativeSources(t *testing.T) {
	for _, ref := range enumeratejavascript.ExtractScriptReferences(appShell, "https://app.example.com/") {
		if ref == "https://evil.example.org/x.js" || ref == "//evil.example.org/x.js" {
			t.Fatalf("expected a protocol-relative src to be dropped, got %s", ref)
		}
	}
}

func TestExtractScriptReferencesIgnoresNonJavascriptAndInlineScripts(t *testing.T) {
	html := `<html><head>
	  <script src="/analytics.json"></script>
	  <script src="/app.css"></script>
	  <script type="application/json">{"a":1}</script>
	  <script src="/real.js"></script>
	</head></html>`

	refs := enumeratejavascript.ExtractScriptReferences(html, "https://app.example.com/")
	if len(refs) != 1 || refs[0] != "https://app.example.com/real.js" {
		t.Fatalf("expected only the JavaScript reference, got %v", refs)
	}
}

func TestExtractScriptReferencesDeduplicatesRepeatedSources(t *testing.T) {
	html := `<html><head><script src="/main.js"></script><script src="/main.js"></script></head></html>`

	if refs := enumeratejavascript.ExtractScriptReferences(html, "https://app.example.com/"); len(refs) != 1 {
		t.Fatalf("expected one reference, got %v", refs)
	}
}

// Angular ships `<base href="/">` with bare bundle names, so a page below the root must still
// resolve them against the declared base rather than its own directory.
func TestExtractScriptReferencesHonorsBaseHref(t *testing.T) {
	html := `<html><head><base href="/"><script src="runtime.111.js"></script></head></html>`

	refs := enumeratejavascript.ExtractScriptReferences(html, "https://app.example.com/a/b/page")
	if len(refs) != 1 || refs[0] != "https://app.example.com/runtime.111.js" {
		t.Fatalf("expected the base href to root the bundle, got %v", refs)
	}
}

func TestExtractScriptReferencesHonorsANestedBaseHref(t *testing.T) {
	html := `<html><head><base href="/app/"><script src="runtime.111.js"></script></head></html>`

	refs := enumeratejavascript.ExtractScriptReferences(html, "https://app.example.com/a/b/page")
	if len(refs) != 1 || refs[0] != "https://app.example.com/app/runtime.111.js" {
		t.Fatalf("expected the nested base href to be applied, got %v", refs)
	}
}

// Without a base href a relative src still resolves against the page's own directory.
func TestExtractScriptReferencesFallsBackToThePageDirectory(t *testing.T) {
	html := `<html><head><script src="runtime.111.js"></script></head></html>`

	refs := enumeratejavascript.ExtractScriptReferences(html, "https://app.example.com/a/b/page")
	if len(refs) != 1 || refs[0] != "https://app.example.com/a/b/runtime.111.js" {
		t.Fatalf("expected page-relative resolution, got %v", refs)
	}
}

func TestLooksLikeHTMLRecognisesShellsAndBlockPages(t *testing.T) {
	if !enumeratejavascript.LooksLikeHTML("<!doctype html><html></html>", "") {
		t.Fatalf("expected a doctype body to read as HTML")
	}
	if !enumeratejavascript.LooksLikeHTML("(()=>{})()", "text/html; charset=utf-8") {
		t.Fatalf("expected an HTML content type to read as HTML")
	}
	if enumeratejavascript.LooksLikeHTML("(()=>{})()", "application/javascript") {
		t.Fatalf("expected JavaScript not to read as HTML")
	}
}
