package headless

import (
	// Standard
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	standardhelpers "github.com/Method-Security/webscan/utils/request/standard/helpers"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	rod "github.com/go-rod/rod"
	launcher "github.com/go-rod/rod/lib/launcher"
	proto "github.com/go-rod/rod/lib/proto"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// marshalHeaders marshals the headers map to a JSON string to be used in the Headless browser
func marshalHeaders(headers map[string][]string) string {
	if headers == nil {
		return "{}"
	}
	headerStr := "{"
	for k, v := range headers {
		// Convert the slice of values to a JavaScript array
		values := make([]string, len(v))
		for i, val := range v {
			// Escape single quotes in values to prevent JS syntax errors
			escapedVal := strings.ReplaceAll(val, "'", "\\'")
			values[i] = fmt.Sprintf("'%s'", escapedVal)
		}
		headerStr += fmt.Sprintf("'%s': [%s],", k, strings.Join(values, ","))
	}
	// Remove trailing comma if present
	if len(headers) > 0 {
		headerStr = strings.TrimSuffix(headerStr, ",")
	}
	headerStr += "}"
	return headerStr
}

// marshalBody marshals the body to a JSON string to be used in the Headless browser
func marshalBody(body *common.Body) string {
	if body == nil {
		return "null"
	}
	bodyString := requesthelpers.GetResponseBodyStringFromBodyStruct(body)
	if bodyString == nil {
		return "null"
	}
	// Escape the body string for JavaScript
	escapedBody := strings.ReplaceAll(*bodyString, "'", "\\'")
	escapedBody = strings.ReplaceAll(escapedBody, "\n", "\\n")
	escapedBody = strings.ReplaceAll(escapedBody, "\r", "\\r")
	return fmt.Sprintf("'%s'", escapedBody)
}

// getHost returns the host of a URL
func getHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

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

// setupNavigationTracking sets up tracking for top-level frame navigations
func setupNavigationTracking(page *rod.Page, redirectChain *[]string, requestComplete chan struct{}, once *sync.Once, log svc1log.Logger, maxRedirects int, redirectError chan error) {
	// Set up event listeners for navigation errors
	go page.EachEvent(
		func(e *proto.PageFrameNavigated) {
			if e.Frame.ParentID == "" && e.Frame.URL != "" && !utils.IsStaticAsset(e.Frame.URL) {
				// Check if URL is already in chain
				exists := false
				for _, url := range *redirectChain {
					if url == e.Frame.URL {
						exists = true
						break
					}
				}
				if !exists {
					// Check if we've exceeded max redirects
					if len(*redirectChain) > maxRedirects {
						log.Info("Max redirects reached", svc1log.SafeParam("maxRedirects", strconv.Itoa(maxRedirects)))
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

// filterRedirectChain filters the redirect chain based on the original host
func filterRedirectChain(redirectChain []string, originalHost string) []string {
	// If the chain is empty, return it as is
	if len(redirectChain) == 0 {
		return redirectChain
	}

	filteredChain := make([]string, 0, len(redirectChain))
	for _, url := range redirectChain {
		if url == "about:blank" {
			continue
		}
		host := getHost(url)
		if host != originalHost && !strings.HasSuffix(host, "."+originalHost) {
			continue
		}
		filteredChain = append(filteredChain, url)
	}

	// If after filtering we have no URLs, return the original chain
	if len(filteredChain) == 0 {
		return redirectChain
	}

	return filteredChain
}

// performNavigation handles the actual page navigation based on config
func performNavigation(page *rod.Page, config common.SendHttpRequestConfig, constructedURL *string, request *common.HttpRequest, log svc1log.Logger) error {
	if config.MaxRedirects > 0 {
		log.Info("Following redirects with limit", svc1log.SafeParam("maxRedirects", strconv.Itoa(config.MaxRedirects)))

		// Use Navigate instead of MustNavigate to handle errors
		err := page.Navigate(*constructedURL)
		if err != nil {
			// Check for specific navigation errors
			var navErr *rod.NavigationError
			if errors.As(err, &navErr) {
				return fmt.Errorf("navigation failed: %s", navErr.Reason)
			}
			return fmt.Errorf("navigation failed: %v", err)
		}

		// Wait for the initial navigation to complete
		err = page.WaitLoad()
		if err != nil {
			// Check if it's a timeout
			if errors.Is(err, context.DeadlineExceeded) {
				return fmt.Errorf("navigation timeout")
			}
			return fmt.Errorf("wait load failed: %v", err)
		}
	} else {
		log.Info("Not following redirects", svc1log.SafeParam("maxRedirects", strconv.Itoa(config.MaxRedirects)))
		script := fmt.Sprintf(`
			() => {
				return fetch("%s", {
					method: "%s",
					headers: %s,
					body: %s,
					credentials: "include",
					redirect: "manual"
				}).then(response => {
					window.lastResponseStatus = response.status;
					return response;
				}).catch(e => {
					window.navigationError = e.message;
					throw e;
				});
			}
		`, *constructedURL, request.Method,
			marshalHeaders(request.Params.Headers),
			marshalBody(request.Params.Body))

		_, err := page.Eval(script)
		if err != nil {
			// Check for navigation error stored in window
			navError, _ := page.Eval(`() => window.navigationError`)
			if navError.Value.Str() != "" {
				return fmt.Errorf("fetch failed: %s", navError.Value.Str())
			}
			return fmt.Errorf("fetch evaluation failed: %v", err)
		}
	}

	return nil
}

// waitForPageLoad waits for the page to stabilize and load
func waitForPageLoad(page *rod.Page, minDOMStabalizeTimeSeconds int, log svc1log.Logger) error {
	log.Info("Waiting for DOM stabilization", svc1log.SafeParam("seconds", strconv.Itoa(minDOMStabalizeTimeSeconds)))
	time.Sleep(time.Duration(minDOMStabalizeTimeSeconds) * time.Second)

	// Use non-panicking versions
	err := page.WaitLoad()
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("wait load failed: %v", err)
	}

	err = page.WaitStable(300 * time.Millisecond)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("wait stable failed: %v", err)
	}

	return nil
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
		log.Error("Failed to get response headers", svc1log.SafeParam("error", err))
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

// safeEval safely evaluates JavaScript on the page
func safeEval(page *rod.Page, js string) (string, error) {
	result, err := page.Eval(js)
	if err != nil {
		return "", err
	}
	return result.Value.Str(), nil
}

// getStatusCodeFromPage attempts to get the actual HTTP status code
func getStatusCodeFromPage(page *rod.Page, log svc1log.Logger) int {
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

// extractNavigationError extracts meaningful error message from navigation errors
func extractNavigationError(err error) string {
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
	case strings.Contains(errStr, "timeout"):
		return "request timeout"
	default:
		return errStr
	}
}

// SendRequest sends a request using the headless browser
func (b *Requester) SendRequest(ctx context.Context, config common.SendHttpRequestConfig) (common.HttpRequestResponse, error) {
	log := svc1log.FromContext(ctx)
	request := config.Request

	// Construct the URL
	constructedURL, err := standardhelpers.ConstructURL(ctx, request)
	if err != nil {
		return common.HttpRequestResponse{Request: request}, fmt.Errorf("URL construction failed: %v", err)
	}
	log.Info("Requesting", svc1log.SafeParam("url", *constructedURL))

	if b.Browser == nil {
		log.Info("Initializing browser")
		// Create a new browser launcher
		launch := launcher.New().Headless(true)
		// Set the verifyTLS flag if defined
		if !config.VerifyTls {
			launch = launch.Set("ignore-certificate-errors")
		}
		if b.PathToBrowser != nil && *b.PathToBrowser != "" {
			launch = launch.Bin(*b.PathToBrowser)
		}

		// Use non-panicking launch
		browserURL, err := launch.Launch()
		if err != nil {
			return common.HttpRequestResponse{Request: request}, fmt.Errorf("browser launch failed: %v", err)
		}

		// Connect to browser
		b.Browser = rod.New().ControlURL(browserURL)
		err = b.Browser.Connect()
		if err != nil {
			return common.HttpRequestResponse{Request: request}, fmt.Errorf("browser connection failed: %v", err)
		}
		log.Info("Connected to browser")
	}

	// Create a context with a timeout
	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	redirectChain := []string{*constructedURL}
	headers := make(map[string][]string)
	var statusCode int
	var once sync.Once
	requestComplete := make(chan struct{})
	redirectError := make(chan error, 1)
	var result common.HttpRequestResponse
	var redirectErr error
	var navigationErr error

	err = rod.Try(func() {
		// Create page with context
		page, err := b.Browser.Page(proto.TargetCreateTarget{})
		if err != nil {
			navigationErr = fmt.Errorf("failed to create page: %v", err)
			return
		}
		page = page.Context(pageCtx)

		// Ensure page is closed on completion
		defer func() {
			if page != nil {
				_ = page.Close()
			}
		}()

		// Setup header interception and navigation tracking
		setupHeaderInterception(page)

		setupNavigationTracking(page, &redirectChain, requestComplete, &once, log, config.MaxRedirects, redirectError)

		// Perform the navigation
		navErr := performNavigation(page, config, constructedURL, request, log)
		if navErr != nil {
			navigationErr = navErr
			log.Error("Navigation failed", svc1log.SafeParam("error", navErr))
			return
		}

		// Wait for navigation to complete or error
		select {
		case err := <-redirectError:
			log.Error("Redirect error occurred", svc1log.SafeParam("error", err))
			redirectErr = err
			return
		case <-requestComplete:
			log.Info("Request complete, redirect chain", svc1log.SafeParam("chain", strings.Join(redirectChain, " -> ")))
		case <-pageCtx.Done():
			navigationErr = fmt.Errorf("request timeout after %d seconds", b.TimeoutSeconds)
			return
		}

		// Get final URL
		finalURL, err := safeEval(page, `() => window.location.href`)
		if err != nil {
			log.Warn("Failed to get final URL", svc1log.SafeParam("error", err))
			finalURL = ""
		}

		if finalURL != "" && !utils.IsStaticAsset(finalURL) {
			// Check if final URL is already in chain
			exists := false
			for _, url := range redirectChain {
				if url == finalURL {
					exists = true
					break
				}
			}
			if !exists {
				redirectChain = append(redirectChain, finalURL)
				log.Info("Adding final URL to chain", svc1log.SafeParam("url", finalURL))
				log.Info("Updated redirect chain", svc1log.SafeParam("chain", strings.Join(redirectChain, " -> ")))
			}
		}

		// Wait for page to stabilize
		err = waitForPageLoad(page, b.MinDOMStabalizeTimeSeconds, log)
		if err != nil {
			log.Warn("Page stabilization warning", svc1log.SafeParam("error", err))
		}

		log.Info("Final URL", svc1log.SafeParam("url", finalURL))

		// Capture status code
		readyState, err := safeEval(page, `() => document.readyState`)
		if err == nil && readyState == "complete" {
			statusCode = 200
		} else {
			// Try to get actual status code
			statusCode = getStatusCodeFromPage(page, log)
			if statusCode == 0 && navigationErr == nil {
				// Default to 200 if page loaded successfully but we can't determine status
				statusCode = 200
			}
		}

		// Get response headers
		headers = getResponseHeaders(page, log)

		var responseBody string
		if statusCode >= 200 && statusCode < 300 {
			// Get the response body
			htmlContent, err := page.HTML()
			if err != nil {
				log.Error("Failed to get HTML content", svc1log.SafeParam("error", err))
				responseBody = ""
			} else {
				responseBody = htmlContent
			}
		}

		// Parse the constructed URL to get the host
		parsedURL, err := url.Parse(*constructedURL)
		if err != nil {
			log.Error("Failed to parse URL", svc1log.SafeParam("error", err))
			return
		}
		originalHost := getHost(parsedURL.Host)

		// Filter the redirect chain
		filteredChain := filterRedirectChain(redirectChain, originalHost)

		// If filtered chain is empty, use the original chain
		if len(filteredChain) == 0 {
			filteredChain = redirectChain
		}

		// Create response using the helper function
		response := requesthelpers.CreateHTTPResponse(
			statusCode,
			filteredChain,
			headers,
			responseBody,
		)

		result = common.HttpRequestResponse{
			Request:  request,
			Response: &response,
		}
	})

	// Handle various error cases
	if navigationErr != nil {
		// Extract specific navigation error details
		errMsg := extractNavigationError(navigationErr)
		log.Error("Navigation error details", svc1log.SafeParam("error", errMsg))

		// Create error response
		response := requesthelpers.CreateHTTPResponse(
			0, // Status code 0 indicates error
			redirectChain,
			headers,
			fmt.Sprintf("Navigation failed: %s", errMsg),
		)
		return common.HttpRequestResponse{
			Request:  request,
			Response: &response,
		}, fmt.Errorf("navigation failed: %s", errMsg)
	}

	if err != nil {
		log.Error("Failed during headless capture", svc1log.SafeParam("url", *constructedURL), svc1log.SafeParam("error", err))

		// Create error response
		response := requesthelpers.CreateHTTPResponse(
			0,
			redirectChain,
			headers,
			fmt.Sprintf("Headless capture error: %v", err),
		)
		return common.HttpRequestResponse{
			Request:  request,
			Response: &response,
		}, fmt.Errorf("headless capture failed: %v", err)
	}

	if redirectErr != nil {
		// Create a response with error status
		response := requesthelpers.CreateHTTPResponse(
			0, // Status code 0 indicates error
			redirectChain,
			headers,
			redirectErr.Error(),
		)
		return common.HttpRequestResponse{
			Request:  request,
			Response: &response,
		}, redirectErr
	}

	return result, nil
}

func (b *Requester) InitializeBrowser() error {
	launch := launcher.New().Headless(true)
	if b.PathToBrowser != nil && *b.PathToBrowser != "" {
		launch = launch.Bin(*b.PathToBrowser)
	}

	// Use non-panicking launch
	browserURL, err := launch.Launch()
	if err != nil {
		return fmt.Errorf("browser launch failed: %v", err)
	}

	// Connect to browser
	b.Browser = rod.New().ControlURL(browserURL)
	err = b.Browser.Connect()
	if err != nil {
		return fmt.Errorf("browser connection failed: %v", err)
	}

	return nil
}
