package headless

import (
	// Standard
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	standardhelpers "github.com/Method-Security/webscan/utils/request/helpers/standard/helpers"

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
			values[i] = fmt.Sprintf("'%s'", val)
		}
		headerStr += fmt.Sprintf("'%s': [%s],", k, strings.Join(values, ","))
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
	return *bodyString
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
		window.responseHeaders = {};
		const originalFetch = window.fetch;
		window.fetch = async function(url, options) {
			const response = await originalFetch(url, options);
			window.responseHeaders = Object.fromEntries(response.headers.entries());
			return response;
		};
	`)
}

// setupNavigationTracking sets up tracking for top-level frame navigations
func setupNavigationTracking(page *rod.Page, redirectChain *[]string, requestComplete chan struct{}, once *sync.Once, log svc1log.Logger) {
	go page.EachEvent(func(e *proto.PageFrameNavigated) {
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
				*redirectChain = append(*redirectChain, e.Frame.URL)
				log.Info("Top-level frame navigated", svc1log.SafeParam("url", e.Frame.URL))
				once.Do(func() { close(requestComplete) })
			}
		}
	})()
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
func performNavigation(page *rod.Page, config common.SendHttpRequestConfig, constructedURL *string, request *common.HttpRequest, log svc1log.Logger) {
	if config.MaxRedirects > 0 {
		log.Info("Following redirect", svc1log.SafeParam("url", *constructedURL))
		page.MustNavigate(*constructedURL)
	} else {
		log.Info("Not following redirects")
		script := fmt.Sprintf(`
			() => {
				fetch("%s", {
					method: "%s",
					headers: %s,
					body: %s,
					credentials: "include",
					redirect: "manual"
				}).catch(e => console.error(e));
			}
		`, *constructedURL, request.Method,
			marshalHeaders(request.Params.Headers),
			marshalBody(request.Params.Body))

		page.MustEval(script)
	}
}

// waitForPageLoad waits for the page to stabilize and load
func waitForPageLoad(page *rod.Page, minDOMStabalizeTimeSeconds int, log svc1log.Logger) {
	log.Info("Waiting for DOM stabilization", svc1log.SafeParam("seconds", strconv.Itoa(minDOMStabalizeTimeSeconds)))
	time.Sleep(time.Duration(minDOMStabalizeTimeSeconds) * time.Second)
	page.MustWaitLoad().MustWaitStable()
}

// getResponseHeaders retrieves the captured response headers
func getResponseHeaders(page *rod.Page, log svc1log.Logger) map[string][]string {
	responseHeaders, err := page.Eval(`() => window.responseHeaders`)
	if err != nil {
		log.Error("Failed to get response headers", svc1log.SafeParam("error", err))
		return nil
	}

	headerMap := make(map[string][]string)
	for k, v := range responseHeaders.Value.Map() {
		headerMap[k] = []string{v.Str()}
	}
	return headerMap
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
		// Set the insecure flag if defined
		if config.Insecure {
			launch = launch.Set("ignore-certificate-errors")
		}
		if b.PathToBrowser != nil && *b.PathToBrowser != "" {
			launch = launch.Bin(*b.PathToBrowser)
		}
		browserURL := launch.MustLaunch()
		b.Browser = rod.New().ControlURL(browserURL).MustConnect()
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
	var result common.HttpRequestResponse

	err = rod.Try(func() {
		page := b.Browser.MustPage().Context(pageCtx)

		// Setup header interception and navigation tracking
		setupHeaderInterception(page)
		setupNavigationTracking(page, &redirectChain, requestComplete, &once, log)

		// Perform the navigation
		performNavigation(page, config, constructedURL, request, log)

		select {
		case <-requestComplete:
			log.Info("Request complete, redirect chain", svc1log.SafeParam("chain", strings.Join(redirectChain, " -> ")))
		case <-pageCtx.Done():
			return
		}

		finalURL := page.MustEval(`() => window.location.href`).Str()
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
		waitForPageLoad(page, b.MinDOMStabalizeTimeSeconds, log)

		log.Info("Final URL", svc1log.SafeParam("url", finalURL))

		// Capture status code
		evalResp, err := page.Eval(`() => document.readyState`)
		statusResp := evalResp.Value.String()
		if err == nil && statusResp == "complete" {
			statusCode = 200
		}

		// Get response headers
		headers = getResponseHeaders(page, log)

		var responseBody string
		if statusCode >= 200 && statusCode < 300 {
			// Get the response body
			htmlContent, err := page.HTML()
			if err != nil {
				log.Error("Failed to get HTML content", svc1log.SafeParam("error", err))
				return
			}
			responseBody = htmlContent
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

	if err != nil {
		log.Error("Failed during headless capture", svc1log.SafeParam("url", *constructedURL), svc1log.SafeParam("error", err))
		return common.HttpRequestResponse{Request: request}, fmt.Errorf("headless capture failed: %v", err)
	}

	return result, nil
}

func (b *Requester) InitializeBrowser() {
	launch := launcher.New().Headless(true)
	if b.PathToBrowser != nil && *b.PathToBrowser != "" {
		launch = launch.Bin(*b.PathToBrowser)
	}
	browserURL := launch.MustLaunch()
	b.Browser = rod.New().ControlURL(browserURL).MustConnect()
}
