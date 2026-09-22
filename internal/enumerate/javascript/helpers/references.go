package enumeratejavascript

import (
	// Standard
	"net/url"
	"sort"
	"strings"

	// External
	goquery "github.com/PuerkitoBio/goquery"
)

// ExtractScriptReferences returns the JavaScript a page loads, in document order.
//
// Only the bundles the document itself declares are returned. A lazily-loaded chunk is never a
// script tag — the bundler injects it at runtime and removes the element once it has loaded — so
// reaching those is the chunk manifest's job, not this one.
func ExtractScriptReferences(html string, pageURL string) []string {
	document, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return nil
	}

	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}

	seen := map[string]struct{}{}
	references := []string{}

	document.Find("script[src]").Each(func(_ int, selection *goquery.Selection) {
		src, exists := selection.Attr("src")
		if !exists || strings.TrimSpace(src) == "" {
			return
		}
		// A protocol-relative reference parses as a host and would send the fetch off-target.
		if strings.HasPrefix(src, "//") {
			return
		}

		reference, err := url.Parse(strings.TrimSpace(src))
		if err != nil {
			return
		}
		resolved := base.ResolveReference(reference)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			return
		}
		if !isJavascriptPath(resolved.EscapedPath()) {
			return
		}

		resolved.Fragment = ""
		absolute := resolved.String()
		if _, exists := seen[absolute]; exists {
			return
		}
		seen[absolute] = struct{}{}
		references = append(references, absolute)
	})

	return references
}

// isJavascriptPath reports a path that names a JavaScript file.
func isJavascriptPath(path string) bool {
	lowered := strings.ToLower(path)
	for _, suffix := range []string{".js", ".mjs", ".cjs"} {
		if strings.HasSuffix(lowered, suffix) {
			return true
		}
	}
	// An extensionless bundle route is still JavaScript when the page loads it as a script.
	return !strings.Contains(lowered[strings.LastIndex(lowered, "/")+1:], ".")
}

// LooksLikeHTML reports a body an HTML parser should read rather than a JavaScript analyzer.
func LooksLikeHTML(body string, contentType string) bool {
	if strings.Contains(strings.ToLower(contentType), "text/html") {
		return true
	}
	leading := strings.ToLower(strings.TrimSpace(body))
	if len(leading) > 512 {
		leading = leading[:512]
	}
	return strings.HasPrefix(leading, "<!doctype html") || strings.HasPrefix(leading, "<html")
}

// SortedUnique returns the unique values of a slice in a stable order.
func SortedUnique(values []string) []string {
	seen := map[string]struct{}{}
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}
