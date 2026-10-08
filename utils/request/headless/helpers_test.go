package headless

import (
	"strings"
	"testing"
)

func TestAppendRedirectURLLockedPreservesBounceFlows(t *testing.T) {
	chain := []string{"https://auth.example.com/login"}

	added, err := appendRedirectURLLocked(&chain, "https://app.example.net/", 10)
	if err != nil {
		t.Fatalf("append first redirect: %v", err)
	}
	if !added {
		t.Fatal("expected cross-domain hop to be appended")
	}

	added, err = appendRedirectURLLocked(&chain, "https://auth.example.com/login", 10)
	if err != nil {
		t.Fatalf("append bounce redirect: %v", err)
	}
	if !added {
		t.Fatal("expected bounce back to the original URL to be appended")
	}

	want := []string{
		"https://auth.example.com/login",
		"https://app.example.net/",
		"https://auth.example.com/login",
	}
	if len(chain) != len(want) {
		t.Fatalf("chain length = %d, want %d (%v)", len(chain), len(want), chain)
	}
	for i, got := range chain {
		if got != want[i] {
			t.Fatalf("chain[%d] = %q, want %q", i, got, want[i])
		}
	}
}

func TestFirstCrossDomainRedirectBlocksIntermediateBounceHop(t *testing.T) {
	chain := []string{
		"https://auth.example.com/login",
		"https://app.example.net/callback",
		"https://auth.example.com/login",
	}

	got, ok := firstCrossDomainRedirect(chain)
	if !ok {
		t.Fatal("expected intermediate cross-domain hop to be detected")
	}
	if got != "https://app.example.net/callback" {
		t.Fatalf("cross-domain URL = %q, want %q", got, "https://app.example.net/callback")
	}
}

func TestFirstCrossDomainRedirectAllowsScopedRedirects(t *testing.T) {
	chain := []string{
		"https://example.com/login",
		"https://www.example.com/login",
		"https://api.example.com/callback",
	}

	if got, ok := firstCrossDomainRedirect(chain); ok {
		t.Fatalf("unexpected cross-domain URL %q for in-scope redirect chain", got)
	}
}

func TestIsChromeTextDocumentViewerHTMLAllowsLargeJSONDocuments(t *testing.T) {
	payload := `{"items":[` + strings.Repeat(`{"id":1},`, 40000) + `{"id":2}]}`
	htmlContent := `<html><head><meta name="color-scheme" content="light dark"><meta charset="utf-8"></head><body><pre>` + payload + `</pre></body></html>`

	if len(htmlContent) <= 256*1024 {
		t.Fatalf("test fixture must exceed the old viewer size limit, got %d bytes", len(htmlContent))
	}
	if !isChromeTextDocumentViewerHTML(htmlContent) {
		t.Fatal("expected large Chrome text document viewer HTML to be detected")
	}
	body, ok := extractChromeJSONDocumentViewerBody(htmlContent)
	if !ok {
		t.Fatal("expected large Chrome JSON viewer body to be extracted")
	}
	if string(body) != payload {
		t.Fatal("expected extracted JSON viewer body to match the original payload")
	}
}

func TestIsChromeTextDocumentViewerHTMLRejectsPageContentWithPreTag(t *testing.T) {
	htmlContent := `<html><head><meta name="color-scheme" content="light dark"></head><body><main><pre>{"id":1}</pre></main></body></html>`

	if isChromeTextDocumentViewerHTML(htmlContent) {
		t.Fatal("expected normal page HTML containing a pre tag to be rejected")
	}
}

func TestIsChromeTextDocumentViewerHTMLAllowsJSONFormatterContainer(t *testing.T) {
	htmlContent := `<html><head><meta name="color-scheme" content="light dark"><meta charset="utf-8"></head><body><pre>{"id":1}</pre><div class="json-formatter-container"></div></body></html>`

	if !isChromeTextDocumentViewerHTML(htmlContent) {
		t.Fatal("expected Chrome JSON formatter viewer HTML to be detected")
	}
	body, ok := extractChromeJSONDocumentViewerBody(htmlContent)
	if !ok || string(body) != `{"id":1}` {
		t.Fatal("expected Chrome JSON formatter viewer body to be extracted")
	}
}

func TestExtractChromeJSONDocumentViewerBodyRejectsPlainText(t *testing.T) {
	htmlContent := `<html><head><meta name="color-scheme" content="light dark"></head><body><pre>hello world</pre></body></html>`

	if _, ok := extractChromeJSONDocumentViewerBody(htmlContent); ok {
		t.Fatal("expected plain text Chrome viewer body to be rejected as JSON")
	}
}

func TestExtractChromeJSONDocumentViewerBodyDecodesSerializedHTMLText(t *testing.T) {
	htmlContent := `<html><head><meta name="color-scheme" content="light dark"></head><body><pre>{"html":"&lt;section data-label=\"A&amp;B\"&gt;"}</pre></body></html>`

	body, ok := extractChromeJSONDocumentViewerBody(htmlContent)
	if !ok {
		t.Fatal("expected serialized Chrome JSON viewer body to be extracted")
	}
	if string(body) != `{"html":"<section data-label=\"A&B\">"}` {
		t.Fatalf("body = %q, want decoded JSON text", string(body))
	}
}
