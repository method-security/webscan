package standard

import (
	// Standard
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	utils "github.com/Method-Security/webscan/utils"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/projectdiscovery/useragent"
)

// ResolveUserAgent returns a User-Agent string based on the given preset.
// If preset is nil or RANDOM, a random browser UA is picked.
func ResolveUserAgent(preset *common.UserAgentPreset) string {
	if preset == nil || *preset == common.UserAgentPresetRandom {
		return pickRandomUserAgent()
	}
	switch *preset {
	case common.UserAgentPresetChrome:
		return pickUserAgentByFilter(useragent.Chrome)
	case common.UserAgentPresetFirefox:
		return pickUserAgentByFilter(useragent.Mozilla)
	case common.UserAgentPresetSafari:
		// Chrome and Edge UAs are also tagged "Safari" because they forked from WebKit.
		// Exclude them so we only pick genuine Safari UAs.
		return pickUserAgentByFilter(func(ua *useragent.UserAgent) bool {
			return useragent.ContainsTags(ua, "Safari") && !useragent.ContainsTagsAny(ua, "Chrome", "Chromium", "Edge")
		})
	case common.UserAgentPresetEdge:
		return pickUserAgentByFilter(func(ua *useragent.UserAgent) bool {
			return useragent.ContainsTagsAny(ua, "Edge")
		})
	default:
		return pickRandomUserAgent()
	}
}

func pickRandomUserAgent() string {
	if ua := useragent.PickRandom(); ua != nil {
		return ua.Raw
	}
	return fallbackUserAgent
}

func pickUserAgentByFilter(filter useragent.Filter) string {
	uas, err := useragent.PickWithFilters(1, filter)
	if err == nil && len(uas) > 0 {
		return uas[0].Raw
	}
	return pickRandomUserAgent()
}

const fallbackUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

func SendHTTPRequest(ctx context.Context, url string, headers map[string]string, bodyReader io.Reader, config common.SendHttpRequestConfig) (*http.Response, []string, error) {
	log := svc1log.FromContext(ctx)
	log.Debug("Sending request", svc1log.SafeParam("url", url), svc1log.SafeParam("maxRedirects", config.MaxRedirects))

	// Configure HTTP Client
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !config.VerifyTls},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Initialize Redirect Chain
	redirectChain := []string{url}

	// Buffer the body if it exists
	var bodyBuffer *bytes.Buffer
	if bodyReader != nil {
		bodyBuffer = &bytes.Buffer{}
		if _, err := io.Copy(bodyBuffer, bodyReader); err != nil {
			log.Error("Failed to buffer request body", svc1log.SafeParam("error", err))
			return nil, redirectChain, fmt.Errorf("failed to buffer request body: %v", err)
		}
	}

	// Resolve User-Agent once so the same value is used across all redirects.
	// Resolving inside the loop would pick a different random UA per redirect,
	// which no real browser does and can trip bot-detection.
	resolvedUserAgent := ResolveUserAgent(config.UserAgent)

	// Handle Redirects (Runs once if MaxRedirects == 0 which is for requests that don't follow redirects)
	currentURL := url
	for redirects := 0; redirects <= config.MaxRedirects; redirects++ {
		var reqBody io.Reader
		if bodyBuffer != nil {
			reqBody = bytes.NewReader(bodyBuffer.Bytes())
		}

		// Create Request (Set Method, URL, Body)
		req, err := http.NewRequest(string(config.Request.Method), currentURL, reqBody)
		if err != nil {
			log.Error("Failed to create request", svc1log.SafeParam("error", err))
			return nil, redirectChain, fmt.Errorf("failed to create request: %v", err)
		}

		// Set Headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		// Set a realistic User-Agent if the caller didn't provide one
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", resolvedUserAgent)
		}

		// Send Request
		resp, err := client.Do(req)
		if err != nil {
			log.Error("Failed to send request", svc1log.SafeParam("error", err))
			return nil, redirectChain, fmt.Errorf("redirect request failed: %v", err)
		}

		// Check if Response is not a redirect, return
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, redirectChain, nil
		}

		// Get Location Header (Case Insensitive)
		location := resp.Header.Get("Location")
		if location == "" {
			log.Debug("No location header found returning response", svc1log.SafeParam("url", currentURL), svc1log.SafeParam("status", resp.StatusCode))
			return resp, redirectChain, nil
		}

		// Parse Redirect Location
		nextURL, err := resp.Request.URL.Parse(location)
		if err != nil {
			log.Error("Failed to parse redirect location", svc1log.SafeParam("error", err))
			return nil, redirectChain, fmt.Errorf("failed to parse redirect location: %v", err)
		}

		// Check if redirect is cross-domain and should be blocked
		if config.IgnoreCrossDomainRedirects {
			originalURL, parseErr := neturl.Parse(url)
			if parseErr == nil && originalURL.Hostname() != nextURL.Hostname() {
				log.Info("Blocking cross-domain redirect", svc1log.SafeParam("from", currentURL), svc1log.SafeParam("to", nextURL.String()))
				err = resp.Body.Close()
				if err != nil {
					log.Error("Failed to close response body", svc1log.SafeParam("error", err))
				}
				return nil, redirectChain, fmt.Errorf("cross-domain redirect blocked: %s -> %s", currentURL, nextURL.String()) // Dont change this comment used for DD metric
			}
		}

		// Check if this is just a trailing slash redirect (should not count as a redirect)
		if utils.IsTrailingSlashRedirect(currentURL, nextURL.String()) {
			log.Debug("Detected trailing slash redirect, not counting as redirect", svc1log.SafeParam("from", currentURL), svc1log.SafeParam("to", nextURL.String()))
			// Close Response Body
			err = resp.Body.Close()
			if err != nil {
				log.Error("Failed to close response body", svc1log.SafeParam("error", err))
				return nil, redirectChain, fmt.Errorf("failed to close response body: %v", err)
			}
			// Update current URL but don't increment redirect count
			currentURL = nextURL.String()
			redirects-- // Decrement to offset the loop increment
			continue
		}

		// Close Response Body
		err = resp.Body.Close()
		if err != nil {
			log.Error("Failed to close response body", svc1log.SafeParam("error", err))
			return nil, redirectChain, fmt.Errorf("failed to close response body: %v", err)
		}

		// Update Redirect Chain + Current URL
		log.Debug("Following redirect", svc1log.SafeParam("from", currentURL), svc1log.SafeParam("to", nextURL.String()))
		redirectChain = append(redirectChain, nextURL.String())
		currentURL = nextURL.String()
	}

	return nil, redirectChain, fmt.Errorf("maximum redirects (%d) exceeded for %s", config.MaxRedirects, url)
}
