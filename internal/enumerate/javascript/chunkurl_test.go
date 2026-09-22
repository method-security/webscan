package enumeratejavascript

import (
	"testing"
)

func TestResolveChunkURLJoinsWithoutDoubleSlashes(t *testing.T) {
	cases := []struct {
		name       string
		entryURL   string
		publicPath string
		chunk      string
		expected   string
	}{
		{"no public path", "https://app.example.com/main.abc.js", "", "12.hash.js", "https://app.example.com/12.hash.js"},
		{"root public path", "https://app.example.com/main.abc.js", "/", "12.hash.js", "https://app.example.com/12.hash.js"},
		{"trailing slash", "https://app.example.com/main.abc.js", "/static/js/", "12.hash.js", "https://app.example.com/static/js/12.hash.js"},
		{"no trailing slash", "https://app.example.com/main.abc.js", "/static/js", "12.hash.js", "https://app.example.com/static/js/12.hash.js"},
		{"absolute public path", "https://app.example.com/main.abc.js", "https://cdn.example.com/app/", "12.hash.js", "https://cdn.example.com/app/12.hash.js"},
		{"rooted chunk name", "https://app.example.com/main.abc.js", "/static/", "/assets/vendor.js", "https://app.example.com/assets/vendor.js"},
		{"relative chunk name", "https://app.example.com/sub/main.abc.js", "", "./assets/vendor.js", "https://app.example.com/sub/assets/vendor.js"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := resolveChunkURL(testCase.entryURL, testCase.publicPath, testCase.chunk)
			if err != nil {
				t.Fatalf("resolving: %s", err)
			}
			if got != testCase.expected {
				t.Fatalf("expected %s, got %s", testCase.expected, got)
			}
		})
	}
}

// A protocol-relative name would resolve to another host and send the fetch off-target.
func TestResolveChunkURLRejectsProtocolRelativeNames(t *testing.T) {
	if _, err := resolveChunkURL("https://app.example.com/main.abc.js", "", "//evil.example.net/x.js"); err == nil {
		t.Fatalf("expected a protocol-relative chunk name to be rejected")
	}
}
