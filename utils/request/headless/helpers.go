package headless

import (
	// Standard
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	utils "github.com/Method-Security/webscan/utils"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	// External
	goquery "github.com/PuerkitoBio/goquery"
	rod "github.com/go-rod/rod"
	proto "github.com/go-rod/rod/lib/proto"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// NetworkHeaderCapture stores captured response headers
type NetworkHeaderCapture struct {
	Headers map[string][]string
	mutex   sync.RWMutex
}

// NewNetworkHeaderCapture creates a new header capture instance
func NewNetworkHeaderCapture() *NetworkHeaderCapture {
	return &NetworkHeaderCapture{
		Headers: make(map[string][]string),
	}
}

// SetHeaders safely sets headers
func (n *NetworkHeaderCapture) SetHeaders(headers map[string][]string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.Headers = cloneHeaders(headers)
}

// GetHeaders safely gets headers
func (n *NetworkHeaderCapture) GetHeaders() map[string][]string {
	n.mutex.RLock()
	defer n.mutex.RUnlock()
	return cloneHeaders(n.Headers)
}

// setupHeaderInterception sets up network event monitoring to capture response headers
func setupHeaderInterception(page *rod.Page) *NetworkHeaderCapture {
	headerCapture := NewNetworkHeaderCapture()

	// Enable network domain to capture network events
	page.MustEval(`() => {
		// Store for backward compatibility, but we'll use network events for actual capture
		window.responseHeaders = new Map();
	}`)

	// Enable network domain
	page.EnableDomain(proto.NetworkEnable{})

	// Set up network event listeners
	go page.EachEvent(
		func(e *proto.NetworkResponseReceived) {
			// Only capture headers for main document responses
			if e.Type == proto.NetworkResourceTypeDocument && e.Response != nil && !isInternalBrowserURL(e.Response.URL) {
				headers := make(map[string][]string)
				for key, value := range e.Response.Headers {
					// Convert gson.JSON to string
					headers[key] = []string{value.Str()}
				}
				headerCapture.SetHeaders(headers)
			}
		},
	)()

	return headerCapture
}

func loadNetworkResourceBody(page *rod.Page, resourceURL string) ([]byte, map[string][]string, int, error) {
	result, err := proto.NetworkLoadNetworkResource{
		FrameID: page.FrameID,
		URL:     resourceURL,
		Options: &proto.NetworkLoadNetworkResourceOptions{
			DisableCache:       true,
			IncludeCredentials: true,
		},
	}.Call(page)
	if err != nil {
		return nil, nil, 0, err
	}
	if result == nil || result.Resource == nil {
		return nil, nil, 0, fmt.Errorf("network resource load returned no resource")
	}
	resource := result.Resource
	if !resource.Success {
		if resource.NetErrorName != "" {
			return nil, nil, 0, fmt.Errorf("network resource load failed: %s", resource.NetErrorName)
		}
		return nil, nil, 0, fmt.Errorf("network resource load failed")
	}

	headers := make(map[string][]string)
	for key, value := range resource.Headers {
		headers[key] = []string{value.Str()}
	}

	statusCode := 0
	if resource.HTTPStatusCode != nil {
		statusCode = int(*resource.HTTPStatusCode)
	}

	if resource.Stream == "" {
		return nil, headers, statusCode, nil
	}
	defer func() {
		_ = proto.IOClose{Handle: resource.Stream}.Call(page)
	}()

	body, err := readIOStream(page, resource.Stream)
	if err != nil {
		return nil, headers, statusCode, err
	}
	return body, headers, statusCode, nil
}

func readIOStream(page *rod.Page, handle proto.IOStreamHandle) ([]byte, error) {
	var body []byte
	chunkSize := 64 * 1024
	for {
		readResult, err := proto.IORead{
			Handle: handle,
			Size:   &chunkSize,
		}.Call(page)
		if err != nil {
			return nil, err
		}
		if readResult.Base64Encoded {
			chunk, err := base64.StdEncoding.DecodeString(readResult.Data)
			if err != nil {
				return nil, err
			}
			body = append(body, chunk...)
		} else {
			body = append(body, []byte(readResult.Data)...)
		}
		if readResult.EOF {
			break
		}
	}
	return body, nil
}

// handleNavigation sets up tracking for top-level frame navigations
func handleNavigation(ctx context.Context, page *rod.Page, redirectChain *[]string, redirectChainMu *sync.Mutex, requestComplete chan struct{}, once *sync.Once, maxRedirects int, redirectError chan error) {
	log := svc1log.FromContext(ctx)

	// Use a simple completion flag to prevent further event processing
	var completed int32 // Use atomic operations for thread safety

	// Enable network events to capture HTTP redirects
	enableNetworkErr := proto.NetworkEnable{}.Call(page)
	if enableNetworkErr != nil {
		log.Warn("Failed to enable network tracking for redirects", svc1log.SafeParam("error", enableNetworkErr))
	}

	// Set up event listeners for navigation events and network redirects
	go page.EachEvent(
		func(e *proto.NetworkRequestWillBeSent) {
			if e.Type != proto.NetworkResourceTypeDocument || e.RedirectResponse == nil {
				return
			}
			if e.RedirectResponse.Status < 300 || e.RedirectResponse.Status >= 400 {
				return
			}

			locationURL := e.Request.URL
			if location := headerValue(e.RedirectResponse.Headers, "location"); location != "" {
				locationURL = resolveRedirectLocation(e.RedirectResponse.URL, location)
			}
			log.Debug("Captured HTTP redirect request", svc1log.SafeParam("from", e.RedirectResponse.URL), svc1log.SafeParam("to", locationURL), svc1log.SafeParam("status", e.RedirectResponse.Status))

			redirectChainMu.Lock()
			added, err := appendRedirectURLLocked(redirectChain, locationURL, maxRedirects)
			if err != nil {
				redirectChainMu.Unlock()
				log.Info("Max redirects reached", svc1log.SafeParam("maxRedirects", strconv.Itoa(maxRedirects)))
				signalRedirectError(err, redirectError, requestComplete, once, &completed)
				return
			}
			redirectChainMu.Unlock()
			if added {
				log.Debug("Added redirect URL to chain", svc1log.SafeParam("url", locationURL))
			}
		},
		// Capture HTTP redirect responses at the network level
		func(e *proto.NetworkResponseReceived) {
			// Only capture redirect responses for the main document
			if e.Type == proto.NetworkResourceTypeDocument && e.Response.Status >= 300 && e.Response.Status < 400 {
				// Extract the Location header from the redirect response
				if location := headerValue(e.Response.Headers, "location"); location != "" {
					locationURL := resolveRedirectLocation(e.Response.URL, location)
					log.Debug("Captured HTTP redirect", svc1log.SafeParam("from", e.Response.URL), svc1log.SafeParam("to", locationURL), svc1log.SafeParam("status", e.Response.Status))

					redirectChainMu.Lock()
					added, err := appendRedirectURLLocked(redirectChain, locationURL, maxRedirects)
					if err != nil {
						redirectChainMu.Unlock()
						log.Info("Max redirects reached", svc1log.SafeParam("maxRedirects", strconv.Itoa(maxRedirects)))
						signalRedirectError(err, redirectError, requestComplete, once, &completed)
						return
					}
					redirectChainMu.Unlock()
					if added {
						log.Debug("Added redirect URL to chain", svc1log.SafeParam("url", locationURL))
					}
				}
			}
		},
		func(e *proto.PageFrameNavigated) {
			if e.Frame.ParentID == "" && e.Frame.URL != "" && !utils.IsStaticAsset(e.Frame.URL) {
				// Check for Chrome error pages
				if strings.HasPrefix(e.Frame.URL, "chrome-error://") {
					log.Warn("Navigation resulted in Chrome error page, indicating network/connection failure",
						svc1log.SafeParam("errorURL", e.Frame.URL),
						svc1log.SafeParam("originalURL", firstRedirectURL(redirectChain, redirectChainMu)))
					// Still complete the request even on error pages
					once.Do(func() {
						atomic.StoreInt32(&completed, 1)
						close(requestComplete)
					})
					return
				}

				redirectChainMu.Lock()
				added, err := appendRedirectURLLocked(redirectChain, e.Frame.URL, maxRedirects)
				if err != nil {
					redirectChainMu.Unlock()
					log.Info("Max redirects reached", svc1log.SafeParam("maxRedirects", strconv.Itoa(maxRedirects)))
					signalRedirectError(err, redirectError, requestComplete, once, &completed)
					return
				}
				chain := strings.Join(*redirectChain, " -> ")
				redirectChainMu.Unlock()

				if added {
					log.Info("Top-level frame navigated", svc1log.SafeParam("url", e.Frame.URL))
					log.Info("Updated redirect chain", svc1log.SafeParam("chain", chain))
					once.Do(func() {
						atomic.StoreInt32(&completed, 1)
						close(requestComplete)
					})
				} else {
					log.Debug("Ignoring already-seen top-level frame navigation", svc1log.SafeParam("url", e.Frame.URL))
				}
			}
		},
		func(e *proto.PageLoadEventFired) {
			// Check if request is already complete
			if atomic.LoadInt32(&completed) == 1 {
				return
			}

			// Page load completed successfully
			log.Info("Page load event fired")
			once.Do(func() {
				atomic.StoreInt32(&completed, 1)
				close(requestComplete)
			})
		},
		func(e *proto.PageLifecycleEvent) {
			// Check if request is already complete
			if atomic.LoadInt32(&completed) == 1 {
				return
			}

			// Additional lifecycle events that might indicate completion
			if e.Name == "load" || e.Name == "DOMContentLoaded" {
				log.Info("Page lifecycle event fired", svc1log.SafeParam("event", e.Name))
				once.Do(func() {
					atomic.StoreInt32(&completed, 1)
					close(requestComplete)
				})
			}
		},
		func(e *proto.PageFrameStoppedLoading) {
			// Check if request is already complete
			if atomic.LoadInt32(&completed) == 1 {
				return
			}

			// Frame finished loading
			if e.FrameID != "" {
				log.Info("Frame stopped loading", svc1log.SafeParam("frameID", string(e.FrameID)))
				once.Do(func() {
					atomic.StoreInt32(&completed, 1)
					close(requestComplete)
				})
			}
		},
	)()
}

func signalRedirectError(err error, redirectError chan error, requestComplete chan struct{}, once *sync.Once, completed *int32) {
	select {
	case redirectError <- err:
	default:
	}
	once.Do(func() {
		atomic.StoreInt32(completed, 1)
		close(requestComplete)
	})
}

func appendRedirectURLLocked(redirectChain *[]string, redirectURL string, maxRedirects int) (bool, error) {
	if chainContainsURL(*redirectChain, redirectURL) {
		return false, nil
	}

	if len(*redirectChain) > 0 {
		lastURL := (*redirectChain)[len(*redirectChain)-1]
		if utils.IsTrailingSlashRedirect(lastURL, redirectURL) {
			(*redirectChain)[len(*redirectChain)-1] = redirectURL
			return false, nil
		}
	}

	actualRedirects := len(*redirectChain) - 1
	if actualRedirects >= maxRedirects && maxRedirects >= 0 {
		return false, fmt.Errorf("max redirects (%d) exceeded", maxRedirects)
	}

	*redirectChain = append(*redirectChain, redirectURL)
	return true, nil
}

func headerValue(headers proto.NetworkHeaders, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value.Str()
		}
	}
	return ""
}

func resolveRedirectLocation(responseURL, location string) string {
	base, err := url.Parse(responseURL)
	if err != nil {
		return location
	}
	next, err := base.Parse(location)
	if err != nil {
		return location
	}
	return next.String()
}

func firstRedirectURL(redirectChain *[]string, redirectChainMu *sync.Mutex) string {
	redirectChainMu.Lock()
	defer redirectChainMu.Unlock()
	if len(*redirectChain) == 0 {
		return ""
	}
	return (*redirectChain)[0]
}

func chainContainsURL(chain []string, candidate string) bool {
	normalizedCandidate := normalizeDefaultPort(candidate)
	for _, existing := range chain {
		if normalizeDefaultPort(existing) == normalizedCandidate {
			return true
		}
	}
	return false
}

func normalizeDefaultPort(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if port := parsed.Port(); port != "" && isDefaultPort(strings.ToLower(parsed.Scheme), port) {
		hostname := parsed.Hostname()
		if strings.Contains(hostname, ":") {
			hostname = "[" + hostname + "]"
		}
		parsed.Host = hostname
	}
	return parsed.String()
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}

func cloneHeaders(headers map[string][]string) map[string][]string {
	result := make(map[string][]string, len(headers))
	for key, values := range headers {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func isInternalBrowserURL(raw string) bool {
	return raw == "" ||
		raw == "about:blank" ||
		strings.HasPrefix(raw, "chrome://") ||
		strings.HasPrefix(raw, "chrome-error://") ||
		strings.HasPrefix(raw, "chrome-extension://") ||
		strings.HasPrefix(raw, "devtools://")
}

func isChromePDFViewerHTML(htmlContent string) bool {
	content := strings.ToLower(htmlContent)
	return strings.Contains(content, `type="application/pdf"`)
}

func isChromeStaticAssetViewerHTML(htmlContent string) bool {
	if isChromePDFViewerHTML(htmlContent) {
		return true
	}
	if !shouldParseStaticAssetViewerHTML(htmlContent) {
		return false
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return false
	}
	body := doc.Find("body")
	if body.Length() != 1 {
		return false
	}
	children := body.Children()
	if children.Length() != 1 {
		return false
	}

	media := children.First()
	switch strings.ToLower(goquery.NodeName(media)) {
	case "img":
		_, ok := media.Attr("src")
		return ok
	case "video", "audio":
		if _, ok := media.Attr("src"); ok {
			return true
		}
		return media.Find("source[src]").Length() > 0
	default:
		return false
	}
}

func shouldParseStaticAssetViewerHTML(htmlContent string) bool {
	const maxViewerShellHTMLBytes = 256 * 1024
	if htmlContent == "" || len(htmlContent) > maxViewerShellHTMLBytes {
		return false
	}

	content := strings.ToLower(htmlContent)
	mediaTags := strings.Count(content, "<img") +
		strings.Count(content, "<video") +
		strings.Count(content, "<audio")
	return mediaTags == 1
}

func shouldLoadStaticResource(htmlContent, constructedURL, finalURL string) bool {
	if utils.IsStaticAsset(constructedURL) || utils.IsStaticAsset(finalURL) {
		return true
	}
	return isChromeStaticAssetViewerHTML(htmlContent)
}

func isValidStaticResourceBody(body []byte) bool {
	return len(body) > 0 && requesthelpers.IsDetectedBinaryBody(body)
}

func headersForLoadedStaticResource(existingHeaders, loadedHeaders map[string][]string, body []byte) map[string][]string {
	headers := existingHeaders
	if len(loadedHeaders) > 0 {
		headers = loadedHeaders
	}
	return cloneHeadersWithBodyMetadata(headers, body)
}

func cloneHeadersWithBodyMetadata(headers map[string][]string, body []byte) map[string][]string {
	cloned := cloneHeadersWithoutContentEncoding(headers)
	contentType := requesthelpers.DetectContentTypeFromBytes(body)
	contentLength := strconv.Itoa(len(body))
	replacedContentType := false
	replacedContentLength := false
	for key := range cloned {
		switch {
		case strings.EqualFold(key, "Content-Type"):
			cloned[key] = []string{contentType}
			replacedContentType = true
		case strings.EqualFold(key, "Content-Length"):
			cloned[key] = []string{contentLength}
			replacedContentLength = true
		}
	}
	if !replacedContentType {
		cloned["Content-Type"] = []string{contentType}
	}
	if !replacedContentLength {
		cloned["Content-Length"] = []string{contentLength}
	}
	return cloned
}

func cloneHeadersWithoutContentEncoding(headers map[string][]string) map[string][]string {
	cloned := cloneHeaders(headers)
	for key := range cloned {
		if strings.EqualFold(key, "Content-Encoding") {
			delete(cloned, key)
		}
	}
	return cloned
}

func cloneHeadersWithContentType(headers map[string][]string, contentType string) map[string][]string {
	cloned := cloneHeadersWithoutContentEncoding(headers)
	replaced := false
	for key := range cloned {
		if strings.EqualFold(key, "Content-Type") {
			cloned[key] = []string{contentType}
			replaced = true
		}
	}
	if !replaced {
		cloned["Content-Type"] = []string{contentType}
	}
	return cloned
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

	// Skip the WaitLoad here - waitForPageLoad will handle this more efficiently
	// This eliminates a duplicate wait operation that was slowing down requests

	return nil
}

// waitForPageLoad waits for the page to stabilize and load
func waitForPageLoad(page *rod.Page, minDOMStabalizeTimeSeconds int, log svc1log.Logger) error {
	// Quick check if document is already ready - this can save significant time
	readyState, err := safeEval(page, `() => document.readyState`)
	if err == nil && readyState == "complete" {
		log.Info("DOM already in complete state, skipping stabilization wait")
		return nil
	}

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

	// Single WaitLoad call is sufficient - remove duplicate
	err = page.WaitLoad()
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
func getResponseHeaders(ctx context.Context, page *rod.Page, headerCapture *NetworkHeaderCapture) map[string][]string {
	log := svc1log.FromContext(ctx)

	// First try to get headers from network capture
	if headerCapture != nil {
		headers := headerCapture.GetHeaders()
		if len(headers) > 0 {
			log.Info("Retrieved headers from network capture", svc1log.SafeParam("headerCount", len(headers)))
			return headers
		}
	}

	// Fallback to JavaScript extraction (for backward compatibility)
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

// isCrossDomainRedirect checks if a redirect URL points to a different domain than the original URL.
// Relative redirect URLs (e.g. "/login") are resolved against the original URL first so that
// same-domain relative redirects are not incorrectly flagged as cross-domain.
func isCrossDomainRedirect(originalURL, redirectURL string) bool {
	parsedOriginal, err := url.Parse(originalURL)
	if err != nil {
		return false
	}
	resolved, err := parsedOriginal.Parse(redirectURL)
	if err != nil {
		return false
	}
	return parsedOriginal.Hostname() != resolved.Hostname()
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
