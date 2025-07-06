package headless

import (
	// Standard
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"

	// Utils
	utils "github.com/Method-Security/webscan/utils"

	// External
	rod "github.com/go-rod/rod"
	proto "github.com/go-rod/rod/lib/proto"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// setupHeaderInterception sets up the header interception for the page
func setupHeaderInterception(page *rod.Page) {
	page.MustEvalOnNewDocument(`
		window.responseHeaders = new Map();
		const originalFetch = window.fetch;
		window.fetch = async function(url, options) {
			const response = await originalFetch(url, options);
			// Store headers for this URL
			window.responseHeaders.set(url, Object.fromEntries(response.headers.entries()));
			
			// If this is a redirect, follow it and capture those headers too
			if (response.redirected) {
				const redirectResponse = await fetch(response.url, options);
				window.responseHeaders.set(response.url, Object.fromEntries(redirectResponse.headers.entries()));
				return redirectResponse;
			}
			return response;
		};

		// Also intercept XMLHttpRequest
		const originalXHR = window.XMLHttpRequest.prototype.open;
		window.XMLHttpRequest.prototype.open = function(method, url) {
			this.addEventListener('load', function() {
				window.responseHeaders.set(url, Object.fromEntries(this.getAllResponseHeaders().split('\r\n').reduce((acc, line) => {
					const [key, value] = line.split(': ');
					if (key && value) acc[key] = value;
					return acc;
				}, {})));
			});
			return originalXHR.apply(this, arguments);
		};
	`)
}

// handleNavigation sets up tracking for top-level frame navigations
func handleNavigation(page *rod.Page, redirectChain *[]string, requestComplete chan struct{}, once *sync.Once, log svc1log.Logger, maxRedirects int, redirectError chan error) {
	// Set up event listeners for navigation errors
	go page.EachEvent(
		func(e *proto.PageFrameNavigated) {
			if e.Frame.ParentID == "" && e.Frame.URL != "" && !utils.IsStaticAsset(e.Frame.URL) {
				// Check for Chrome error pages
				if strings.HasPrefix(e.Frame.URL, "chrome-error://") {
					log.Warn("Navigation resulted in Chrome error page, indicating network/connection failure",
						svc1log.SafeParam("errorURL", e.Frame.URL),
						svc1log.SafeParam("originalURL", (*redirectChain)[0]))
					return
				}

				// Check if URL is already in chain
				exists := false
				for _, url := range *redirectChain {
					if url == e.Frame.URL {
						exists = true
						break
					}
				}
				if !exists {
					// Check if this is just a trailing slash redirect
					if len(*redirectChain) > 0 {
						lastURL := (*redirectChain)[len(*redirectChain)-1]
						if utils.IsTrailingSlashRedirect(lastURL, e.Frame.URL) {
							log.Info("Detected trailing slash redirect, not counting as redirect",
								svc1log.SafeParam("from", lastURL),
								svc1log.SafeParam("to", e.Frame.URL))
							// Update the last URL in the chain but don't add a new entry
							(*redirectChain)[len(*redirectChain)-1] = e.Frame.URL
							once.Do(func() { close(requestComplete) })
							return
						}
					}

					// Check if we've exceeded max redirects
					// Count actual redirects (excluding initial URL)
					actualRedirects := len(*redirectChain)
					if actualRedirects > maxRedirects && maxRedirects >= 0 {
						log.Info("Max redirects reached", svc1log.SafeParam("maxRedirects", strconv.Itoa(maxRedirects)), svc1log.SafeParam("actualRedirects", strconv.Itoa(actualRedirects)))
						once.Do(func() {
							redirectError <- fmt.Errorf("max redirects (%d) exceeded", maxRedirects)
							close(requestComplete)
						})
						return
					}
					*redirectChain = append(*redirectChain, e.Frame.URL)
					log.Info("Top-level frame navigated", svc1log.SafeParam("url", e.Frame.URL))
					once.Do(func() { close(requestComplete) })
				}
			}
		},
		func(e *proto.PageLoadEventFired) {
			// Page load completed successfully
			once.Do(func() { close(requestComplete) })
		},
	)()
}

// performNavigation handles the actual page navigation based on config
func performNavigation(ctx context.Context, page *rod.Page, constructedURL *string, config common.SendHttpRequestConfig) error {
	// Initialize logging
	log := svc1log.FromContext(ctx)

	// Always use simple navigation - redirect handling is done by the event listeners
	log.Info("Navigating to URL", svc1log.SafeParam("maxRedirects", strconv.Itoa(config.MaxRedirects)))

	// Use Navigate instead of MustNavigate to handle errors
	err := page.Navigate(*constructedURL)
	if err != nil {
		// Check for specific navigation errors - but don't fail immediately
		var navErr *rod.NavigationError
		if errors.As(err, &navErr) {
			log.Warn("Navigation encountered error but continuing", svc1log.SafeParam("error", navErr.Reason))
			return nil // Don't fail - page might still be partially loaded
		}
		log.Warn("Navigation encountered error but continuing", svc1log.SafeParam("error", err.Error()))
		return nil // Don't fail - page might still be partially loaded
	}

	// Try to wait for the initial navigation to complete, but don't fail if it times out
	err = page.WaitLoad()
	if err != nil {
		// Log all errors but don't treat any as fatal - page might still have useful content
		errStr := err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			log.Info("Navigation load timeout - this is normal for slow pages, continuing anyway")
		} else if strings.Contains(errStr, "Execution context was destroyed") || strings.Contains(errStr, "-32000") {
			log.Info("Execution context destroyed during navigation (likely due to redirect), continuing")
		} else if strings.Contains(errStr, "timeout") {
			log.Info("Navigation timeout encountered, continuing anyway - page might still have useful content")
		} else {
			log.Info("Wait load encountered error, continuing anyway - page might still have useful content", svc1log.SafeParam("error", err.Error()))
		}
		// Never return an error - always continue to try to extract data
	}

	return nil
}

// waitForPageLoad waits for the page to stabilize and load
func waitForPageLoad(page *rod.Page, minDOMStabalizeTimeSeconds int, log svc1log.Logger) error {
	log.Info("Waiting for DOM stabilization", svc1log.SafeParam("seconds", strconv.Itoa(minDOMStabalizeTimeSeconds)))

	// Use context-aware sleep that can be cancelled if page context times out
	select {
	case <-time.After(time.Duration(minDOMStabalizeTimeSeconds) * time.Second):
		// Normal case - sleep completed
	case <-page.GetContext().Done():
		// Context cancelled/timed out during sleep
		log.Warn("DOM stabilization interrupted by context timeout")
		return page.GetContext().Err()
	}

	// Use non-panicking versions - treat timeouts as warnings, not errors
	err := page.WaitLoad()
	if err != nil {
		errStr := err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			log.Info("Page load wait timed out during DOM stabilization (this is normal)")
		} else if strings.Contains(errStr, "Execution context was destroyed") || strings.Contains(errStr, "-32000") {
			log.Info("Execution context destroyed during page load wait (likely due to redirect)")
		} else {
			log.Warn("Page load wait encountered error during DOM stabilization", svc1log.SafeParam("error", err.Error()))
		}
		// Don't return error for any of these cases - they're expected during DOM stabilization
	}

	if err != nil {
		errStr := err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			log.Info("Page stable wait timed out during DOM stabilization (this is normal)")
		} else if strings.Contains(errStr, "Execution context was destroyed") || strings.Contains(errStr, "-32000") {
			log.Info("Execution context destroyed during page stable wait (likely due to redirect)")
		} else {
			log.Warn("Page stable wait encountered error during DOM stabilization", svc1log.SafeParam("error", err.Error()))
		}
		// Don't return error for any of these cases - they're expected during DOM stabilization
	}

	return nil
}

// safeEval safely evaluates JavaScript on the page
func safeEval(page *rod.Page, js string) (string, error) {
	result, err := page.Eval(js)
	if err != nil {
		return "", err
	}
	return result.Value.Str(), nil
}

// isChromErrorPage checks if the current page is a Chrome error page
func isChromeErrorPage(page *rod.Page) bool {
	// Check if URL starts with chrome-error://
	finalURL, err := safeEval(page, `() => window.location.href`)
	if err == nil && strings.HasPrefix(finalURL, "chrome-error://") {
		return true
	}

	// Check for specific Chrome error page indicators in the HTML
	htmlContent, err := page.HTML()
	if err != nil {
		return false
	}

	// Look for Chrome error page specific CSS classes and content
	errorIndicators := []string{
		"chrome://theme/IDR_ERROR_NETWORK_GENERIC",
	}
	for _, indicator := range errorIndicators {
		if strings.Contains(htmlContent, indicator) {
			return true
		}
	}

	return false
}

// filterRedirectChain filters the redirect chain based on the original host
func filterRedirectChain(redirectChain []string) []string {
	// If the chain is empty, return it as is
	if len(redirectChain) == 0 {
		return redirectChain
	}

	filteredChain := make([]string, 0, len(redirectChain))
	for _, url := range redirectChain {
		// Filter out Chrome's internal error pages and about:blank pages
		if url == "about:blank" || strings.HasPrefix(url, "chrome-error://") {
			continue
		}

		filteredChain = append(filteredChain, url)
	}

	return filteredChain
}

// getResponseHeaders retrieves the captured response headers
func getResponseHeaders(page *rod.Page, log svc1log.Logger) map[string][]string {
	responseHeaders, err := page.Eval(`() => {
		const headers = {};
		if (window.responseHeaders) {
			window.responseHeaders.forEach((value, key) => {
				Object.assign(headers, value);
			});
		}
		return headers;
	}`)
	if err != nil {
		// Check if it's an execution context destroyed error (common during redirects)
		errStr := err.Error()
		if strings.Contains(errStr, "Execution context was destroyed") || strings.Contains(errStr, "-32000") {
			log.Info("Execution context destroyed while getting response headers (likely due to redirect)")
		} else {
			log.Error("Failed to get response headers", svc1log.SafeParam("error", err.Error()))
		}
		return make(map[string][]string)
	}

	headerMap := make(map[string][]string)
	if responseHeaders.Value.Map() != nil {
		for k, v := range responseHeaders.Value.Map() {
			headerMap[k] = []string{v.Str()}
		}
	}
	return headerMap
}

// getStatusCodeFromPage attempts to get the actual HTTP status code
func getStatusCodeFromPage(page *rod.Page) int {
	// First, try to get status from stored response
	statusStr, err := safeEval(page, `() => window.lastResponseStatus || 0`)
	if err == nil && statusStr != "" && statusStr != "0" {
		if status, err := strconv.Atoi(statusStr); err == nil && status > 0 {
			return status
		}
	}

	// Try to get status from performance timing API
	statusStr, err = safeEval(page, `() => {
		const entries = performance.getEntriesByType('navigation');
		if (entries.length > 0 && entries[0].responseStatus) {
			return entries[0].responseStatus;
		}
		return 0;
	}`)

	if err == nil && statusStr != "" && statusStr != "0" {
		if status, err := strconv.Atoi(statusStr); err == nil && status > 0 {
			return status
		}
	}

	// Default to 0 if we can't determine status
	return 0
}

// cleanErrMsg extracts meaningful error message from navigation errors
func cleanErrMsg(err error) string {
	if err == nil {
		return "unknown error"
	}

	// Check for rod.NavigationError
	var navErr *rod.NavigationError
	if errors.As(err, &navErr) {
		return navErr.Reason
	}

	// Check for common network errors
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "ERR_CONNECTION_REFUSED"):
		return "connection refused"
	case strings.Contains(errStr, "ERR_NAME_NOT_RESOLVED"):
		return "DNS resolution failed"
	case strings.Contains(errStr, "ERR_CONNECTION_TIMED_OUT"):
		return "connection timeout"
	case strings.Contains(errStr, "ERR_SSL_PROTOCOL_ERROR"):
		return "SSL protocol error"
	case strings.Contains(errStr, "ERR_CERT_"):
		return "certificate error"
	case strings.Contains(errStr, "ERR_INTERNET_DISCONNECTED"):
		return "no internet connection"
	case strings.Contains(errStr, "ERR_ADDRESS_UNREACHABLE"):
		return "address unreachable"
	case strings.Contains(errStr, "Execution context was destroyed") || strings.Contains(errStr, "-32000"):
		return "execution context destroyed during navigation (likely redirect)"
	case strings.Contains(errStr, "timeout"):
		return "request timeout"
	default:
		return errStr
	}
}
