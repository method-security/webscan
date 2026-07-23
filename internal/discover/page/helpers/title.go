package discoverpage

import (
	// Standard
	"strings"
	// External
	"github.com/PuerkitoBio/goquery"
)

// ExtractHTMLTitle returns the first non-empty <title> text from HTML.
func ExtractHTMLTitle(html string) string {
	if html == "" {
		return ""
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(doc.Find("title").First().Text())
}
