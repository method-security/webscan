package witnesshelpers

import (
	// Standard
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	// External
	"github.com/PuerkitoBio/goquery"
	"github.com/spaolacci/murmur3"
)

const (
	maxFaviconBytes  = 1 << 20 // 1 MiB
	shodanLineLength = 76
)

// ExtractFaviconURL parses rendered HTML for a favicon link tag and resolves
// the href as an absolute URL against finalURL. Falls back to
// <scheme>://<host>/favicon.ico if no link tag is found.
func ExtractFaviconURL(html, finalURL string) string {
	parsed, err := neturl.Parse(finalURL)
	if err != nil || parsed.Host == "" {
		return ""
	}

	// Try to extract from <link rel="icon"> or <link rel="shortcut icon">
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err == nil {
		var faviconHref string
		doc.Find("link").Each(func(_ int, s *goquery.Selection) {
			rel, _ := s.Attr("rel")
			rel = strings.ToLower(strings.TrimSpace(rel))
			if rel == "icon" || rel == "shortcut icon" {
				if href, exists := s.Attr("href"); exists && href != "" {
					faviconHref = href
				}
			}
		})
		if faviconHref != "" {
			resolved, resolveErr := parsed.Parse(faviconHref)
			if resolveErr == nil {
				return resolved.String()
			}
		}
	}

	// Fallback: /favicon.ico at root
	return fmt.Sprintf("%s://%s/favicon.ico", parsed.Scheme, parsed.Host)
}

// FetchFavicon downloads the favicon at faviconURL using a fresh HTTP client
// that respects verifyTLS and timeout. The caller supplies userAgent (typically
// the resolved discover-page UA) so favicon traffic matches what the headless
// browser advertised - servers that vary their favicon on UA work correctly.
//
// IMPORTANT: a fresh context is derived from `ctx` instead of using `ctx` as a
// deadline-bearing parent. The combined headless capture exhausts most of its
// own `requestCtx` window during navigation + DOM stabilization; if we reused
// that deadline here, the favicon fetch could see ~0s of slack and always
// time out. We still inherit cancellation by piggy-backing on `ctx.Done()`
// (so a parent cancel propagates) but reset the timeout to a fresh budget.
//
// Returns the raw bytes and a Shodan-compatible mmh3-32 hash (signed int32,
// decimal string). On non-2xx, network error, or empty body, it returns
// (nil, "", nil) - caller treats this as not found.
func FetchFavicon(ctx context.Context, faviconURL string, timeout int, verifyTLS bool, userAgent string) ([]byte, string, error) {
	if faviconURL == "" {
		return nil, "", nil
	}

	fetchTimeout := time.Duration(timeout) * time.Second

	// Derive a fresh-timeout context that still cancels when the parent does.
	fetchCtx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-fetchCtx.Done():
		}
	}()

	client := &http.Client{
		Timeout: fetchTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS}, //nolint:gosec
		},
	}

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, faviconURL, nil)
	if err != nil {
		return nil, "", nil
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", nil
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", nil
	}

	limited := io.LimitReader(resp.Body, maxFaviconBytes)
	body, err := io.ReadAll(limited)
	if err != nil || len(body) == 0 {
		return nil, "", nil
	}

	hashStr := computeFaviconHash(body)
	return body, hashStr, nil
}

// computeFaviconHash computes the Shodan-compatible mmh3-32 hash of a favicon.
// Algorithm: base64-encode, insert '\n' every 76 chars (Python encodebytes style),
// append trailing '\n', then murmur3.Sum32 cast to signed int32.
func computeFaviconHash(data []byte) string {
	// Standard base64 encoding (no line wrapping yet)
	encoded := base64.StdEncoding.EncodeToString(data)

	// Insert '\n' every 76 chars to match Python's base64.encodebytes
	var sb strings.Builder
	for i := 0; i < len(encoded); i += shodanLineLength {
		end := i + shodanLineLength
		if end > len(encoded) {
			end = len(encoded)
		}
		sb.WriteString(encoded[i:end])
		sb.WriteByte('\n')
	}
	encodedBytes := sb.String()

	// murmur3.Sum32, cast to signed int32 for Shodan compatibility
	h := murmur3.Sum32([]byte(encodedBytes))
	signed := int32(h) //nolint:gosec
	return fmt.Sprintf("%d", signed)
}
