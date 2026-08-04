package witnesshelpers

import (
	// Standard
	"context"
	"encoding/base64"
	"fmt"
	neturl "net/url"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

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

// FetchFavicon downloads the favicon at faviconURL through the shared request
// helper (request.SendRequest) so the fetch honors the same config the rest of
// the witness scan runs under - most importantly MaxRedirects and
// IgnoreCrossDomainRedirects, but also VerifyTls, Timeout, UserAgent, and any
// proxy settings carried on the context. A favicon that 3xx-redirects to a
// different host is therefore dropped (rather than silently followed) when
// cross-domain redirects are disabled.
//
// The favicon fetch is pinned to the STANDARD request method regardless of the
// witness config's RequestMethod: favicons are binary assets and the standard
// HTTP capture preserves the raw bytes, whereas headless/browserbase
// navigations do not reliably return the underlying image bytes.
//
// Returns the raw bytes and a Shodan-compatible mmh3-32 hash (signed int32,
// decimal string). On a blocked cross-domain redirect, non-2xx, network error,
// or empty body, it returns (nil, "", nil) - caller treats this as not found.
func FetchFavicon(ctx context.Context, faviconURL string, config discover.DiscoverWitnessConfig) ([]byte, string, error) {
	if faviconURL == "" {
		return nil, "", nil
	}

	baseURL, path, queryParams, err := requesthelpers.SplitTargetURL(faviconURL)
	if err != nil {
		return nil, "", nil
	}

	sendConfig := common.SendHttpRequestConfig{
		Request: &common.HttpRequest{
			BaseUrl: baseURL,
			Path:    path,
			Method:  common.HttpMethodGet,
			Params: &common.HttpRequestParams{
				Query: queryParams,
			},
		},
		MaxRedirects:               config.MaxRedirects,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		IgnoreCrossDomainRedirects: config.IgnoreCrossDomainRedirects,
		UserAgent:                  config.UserAgent,
		RequestMethod:              common.RequestMethodStandard,
	}

	// Carry proxy settings from the context, matching the other discover flows.
	requesthelpers.ApplyProxySettings(ctx, &sendConfig)

	resp, err := request.SendRequest(ctx, sendConfig)
	if err != nil || resp == nil || resp.Response == nil {
		return nil, "", nil
	}

	statusCode := resp.Response.StatusCode
	if statusCode == nil || *statusCode < 200 || *statusCode >= 300 {
		return nil, "", nil
	}

	body := faviconResponseBytes(resp.Response.ResponseBody)
	if len(body) == 0 {
		return nil, "", nil
	}
	if len(body) > maxFaviconBytes {
		body = body[:maxFaviconBytes]
	}

	hashStr := computeFaviconHash(body)
	return body, hashStr, nil
}

// faviconResponseBytes returns the raw favicon octets from a captured Body.
// The standard HTTP capture stores image responses as a base64-encoded binary
// body, so those are decoded back to their real bytes; text/json kinds (e.g. an
// SVG favicon served as text) fall through to the literal string content.
func faviconResponseBytes(body *common.Body) []byte {
	if body == nil {
		return nil
	}
	if body.Kind == "binary" {
		if body.Binary == nil {
			return nil
		}
		decoded, err := base64.StdEncoding.DecodeString(body.Binary.Base64)
		if err != nil {
			return nil
		}
		return decoded
	}
	if str := requesthelpers.GetResponseBodyStringFromBodyStruct(body); str != nil {
		return []byte(*str)
	}
	return nil
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
