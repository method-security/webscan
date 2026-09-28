package enumeratejavascript

import (
	"testing"

	"github.com/BishopFox/jsluice"
)

func TestNormalizeTemplatePathRejectsGluedExpressions(t *testing.T) {
	placeholder := jsluice.ExpressionPlaceholder
	for _, path := range []string{
		"/users/:id" + placeholder,
		"/users/[id" + placeholder + "]",
		"/docs/[[...path" + placeholder + "]]",
		"/files/*" + placeholder,
		"/files/" + placeholder + "*",
	} {
		if normalized, ok := normalizeTemplatePath(path); ok {
			t.Errorf("expected %q to be rejected, got %q", path, normalized)
		}
	}
}

func TestNormalizeTemplatePathPreservesWholeSegmentParameters(t *testing.T) {
	for input, want := range map[string]string{
		"/users/" + jsluice.ExpressionPlaceholder: "/users/{param}",
		"/users/:id":  "/users/{id}",
		"/users/[id]": "/users/{id}",
		"/files/*":    "/files/{wildcard}",
	} {
		if got, ok := normalizeTemplatePath(input); !ok || got != want {
			t.Errorf("normalizeTemplatePath(%q) = %q, %v; want %q", input, got, ok, want)
		}
	}
}
