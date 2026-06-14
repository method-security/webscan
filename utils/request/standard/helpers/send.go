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
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	useragent "github.com/Method-Security/webscan/utils/useragent"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

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
			log.Error("Failed to buffer request body", svc1log.SafeParam("error", err.Error()))
			return nil, redirectChain, fmt.Errorf("failed to buffer request body: %v", err)
		}
	}

	resolvedUserAgent := useragent.Resolve(config.UserAgent)

	// Handle Redirects (Runs once if MaxRedirects == 0 which is for requests that don't follow redirects)
	currentURL := url
	for redirects := 0; redirects <= config.MaxRedirects; redirects++ {
		var reqBody io.Reader
		if bodyBuffer != nil {
			reqBody = bytes.NewReader(bodyBuffer.Bytes())
		}

		// Create Request (Set Method, URL, Body). Bind the caller's context so a
		// cancelled/expired request actually aborts the in-flight dial.
		req, err := http.NewRequestWithContext(ctx, string(config.Request.Method), currentURL, reqBody)
		if err != nil {
			log.Error("Failed to create request", svc1log.SafeParam("url", currentURL), svc1log.SafeParam("error", err.Error()))
			return nil, redirectChain, fmt.Errorf("failed to create request for %s: %v", currentURL, err)
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
			detail := requesthelpers.ClassifyTransportError(err)
			log.Error("Failed to send request",
				svc1log.SafeParam("url", currentURL),
				svc1log.SafeParam("category", string(detail.Category)),
				svc1log.SafeParam("error", detail.Cause))
			return nil, redirectChain, fmt.Errorf("request to %s failed [%s]: %s", currentURL, detail.Category, detail.Cause)
		}

		// Check if Response is not a redirect, return
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			// Trailing-slash redirects update currentURL without adding a new
			// redirectChain entry (they are not counted as real redirects).
			// Update the last chain entry in-place so the chain length stays
			// accurate and callers get the true canonical URL without a
			// spurious extra hop.
			if currentURL != redirectChain[len(redirectChain)-1] {
				redirectChain[len(redirectChain)-1] = currentURL
			}
			return resp, redirectChain, nil
		}

		// Get Location Header (Case Insensitive)
		location := resp.Header.Get("Location")
		if location == "" {
			log.Debug("No location header found returning response", svc1log.SafeParam("url", currentURL), svc1log.SafeParam("status", resp.StatusCode))
			if currentURL != redirectChain[len(redirectChain)-1] {
				redirectChain[len(redirectChain)-1] = currentURL
			}
			return resp, redirectChain, nil
		}

		// Parse Redirect Location first — we need the resolved URL to decide
		// whether this is a trailing-slash hop before applying the budget check.
		nextURL, err := resp.Request.URL.Parse(location)
		if err != nil {
			log.Error("Failed to parse redirect location", svc1log.SafeParam("error", err.Error()))
			return nil, redirectChain, fmt.Errorf("failed to parse redirect location: %v", err)
		}

		// Check if this is just a trailing slash redirect (should not count as a
		// redirect and must be checked BEFORE the budget gate so that
		// MaxRedirects=0 callers still get transparent slash-normalisation).
		if utils.IsTrailingSlashRedirect(currentURL, nextURL.String()) {
			log.Debug("Detected trailing slash redirect, not counting as redirect", svc1log.SafeParam("from", currentURL), svc1log.SafeParam("to", nextURL.String()))
			// Close Response Body
			err = resp.Body.Close()
			if err != nil {
				log.Error("Failed to close response body", svc1log.SafeParam("error", err.Error()))
				return nil, redirectChain, fmt.Errorf("failed to close response body: %v", err)
			}
			// Update current URL but don't increment redirect count
			currentURL = nextURL.String()
			redirects-- // Decrement to offset the loop increment
			continue
		}

		// Check if redirect is cross-domain and should be blocked.  This runs
		// BEFORE the budget gate so that callers with IgnoreCrossDomainRedirects=true
		// still get a cross-domain error even when MaxRedirects=0 — matching the
		// original behaviour where the cross-domain guard was always evaluated before
		// the loop counter increment that caused the budget to be exceeded.
		if config.IgnoreCrossDomainRedirects {
			originalURL, parseErr := neturl.Parse(url)
			if parseErr == nil && originalURL.Hostname() != nextURL.Hostname() {
				log.Info("Blocking cross-domain redirect", svc1log.SafeParam("from", currentURL), svc1log.SafeParam("to", nextURL.String()))
				err = resp.Body.Close()
				if err != nil {
					log.Error("Failed to close response body", svc1log.SafeParam("error", err.Error()))
				}
				return nil, redirectChain, fmt.Errorf("cross-domain redirect blocked: %s -> %s", currentURL, nextURL.String()) // Dont change this comment used for DD metric
			}
		}

		// Budget check — only for non-trailing-slash, non-cross-domain redirects.
		// With MaxRedirects=0 the caller opts into "give me the redirect response
		// as-is so I can read Location/Set-Cookie" (e.g. wp-login.php success
		// detection where the 302 to /wp-admin/ IS the success signal).  Without
		// this, a 3xx-with-Location on a MaxRedirects=0 call would surface as
		// "maximum redirects exceeded" and the response would be inaccessible.
		if redirects >= config.MaxRedirects {
			log.Debug("Redirect budget exhausted; returning redirect response as-is",
				svc1log.SafeParam("url", currentURL),
				svc1log.SafeParam("status", resp.StatusCode),
				svc1log.SafeParam("location", location),
				svc1log.SafeParam("maxRedirects", config.MaxRedirects))
			if currentURL != redirectChain[len(redirectChain)-1] {
				redirectChain[len(redirectChain)-1] = currentURL
			}
			return resp, redirectChain, nil
		}

		// Close Response Body
		err = resp.Body.Close()
		if err != nil {
			log.Error("Failed to close response body", svc1log.SafeParam("error", err.Error()))
			return nil, redirectChain, fmt.Errorf("failed to close response body: %v", err)
		}

		// Update Redirect Chain + Current URL
		log.Debug("Following redirect", svc1log.SafeParam("from", currentURL), svc1log.SafeParam("to", nextURL.String()))
		redirectChain = append(redirectChain, nextURL.String())
		currentURL = nextURL.String()
	}

	return nil, redirectChain, fmt.Errorf("maximum redirects (%d) exceeded for %s", config.MaxRedirects, url)
}
