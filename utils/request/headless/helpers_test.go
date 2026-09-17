package headless

import (
	"strings"
	"testing"
)

func TestIsChromeTextDocumentViewerHTMLAllowsLargeJSONDocuments(t *testing.T) {
	payload := `{"items":[` + strings.Repeat(`{"id":1},`, 40000) + `{"id":2}]}`
	htmlContent := `<html><head><meta name="color-scheme" content="light dark"><meta charset="utf-8"></head><body><pre>` + payload + `</pre></body></html>`

	if len(htmlContent) <= 256*1024 {
		t.Fatalf("test fixture must exceed the old viewer size limit, got %d bytes", len(htmlContent))
	}
	if !isChromeTextDocumentViewerHTML(htmlContent) {
		t.Fatal("expected large Chrome text document viewer HTML to be detected")
	}
}

func TestIsChromeTextDocumentViewerHTMLRejectsPageContentWithPreTag(t *testing.T) {
	htmlContent := `<html><head><meta name="color-scheme" content="light dark"></head><body><main><pre>{"id":1}</pre></main></body></html>`

	if isChromeTextDocumentViewerHTML(htmlContent) {
		t.Fatal("expected normal page HTML containing a pre tag to be rejected")
	}
}
