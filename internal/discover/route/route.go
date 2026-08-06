package discoverroute

import (
	// Standard
	"context"
	"fmt"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
	utils "github.com/Method-Security/webscan/utils"

	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	headless "github.com/Method-Security/webscan/utils/request/headless"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// Internal
	discoverroutehelpers "github.com/Method-Security/webscan/internal/discover/route/helpers"
	capturerouteextractors "github.com/Method-Security/webscan/internal/discover/route/helpers/extractors"

	// External
	goquery "github.com/PuerkitoBio/goquery"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// resolveEffectiveTarget follows HTTP redirects for target and returns the final URL.
// Falls back to target if the HEAD request fails. Routes the HEAD through
// utils/request so it honors VerifyTls, UserAgent and Timeout from the
// surrounding DiscoverRouteConfig.
//
// TODO(aitf-71-followup): support headless/browserbase modes; today this
// always uses the standard transport regardless of config.RequestMethod.
func resolveEffectiveTarget(ctx context.Context, target string, config discover.DiscoverRouteConfig) string {
	baseURL, path, queryParams, err := requesthelpers.SplitTargetURL(target)
	if err != nil {
		return target
	}

	httpRequest := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodHead,
		Params: &common.HttpRequestParams{
			Query: queryParams,
			// Carry auth headers/cookies so redirect resolution matches the
			// credentialed spider requests (login/session cookies can change
			// where the target redirects).
			Headers: requesthelpers.BuildAuthHeaders(config.Headers, config.Cookies),
		},
	}

	sendConfig := common.SendHttpRequestConfig{
		Request:      &httpRequest,
		MaxRedirects: config.MaxRedirects,
		VerifyTls:    config.VerifyTls,
		Timeout:      config.Timeout,
		// IgnoreCrossDomainRedirects is the transport-layer flag — a strict
		// hostname-string equality check. Leave it false here so this HEAD
		// resolve still follows hostname-changing redirects (e.g. apex → www)
		// and lands on the final effective target host. The route allowlist
		// (IsURLAllowed / IsHostInScope) then scopes discovery to that resolved
		// host and its subdomains at discover time.
		IgnoreCrossDomainRedirects: false,
		UserAgent:                  config.UserAgent,
		RequestMethod:              common.RequestMethodStandard,
	}

	// Add proxy settings from context
	requesthelpers.ApplyProxySettings(ctx, &sendConfig)

	response, err := request.SendRequest(ctx, sendConfig)
	if err != nil || response == nil || response.Response == nil {
		return target
	}
	if chain := response.Response.RedirectChain; len(chain) > 0 {
		return strings.TrimRight(chain[len(chain)-1], "/")
	}
	return target
}

// ExtractRedirectRoutes analyzes redirect chain URLs to extract routes with parameters.
// Scope is anchored on the original target (routeCaptureConfig.Target), not the
// per-page post-redirect host.
func ExtractRedirectRoutes(redirectChain []string, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	for _, redirectURL := range redirectChain {
		// Parse the redirect URL
		parsedURL, err := url.Parse(redirectURL)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to parse redirect URL %s: %s", redirectURL, err))
			continue
		}

		// Only process URLs with query parameters
		if parsedURL.RawQuery == "" {
			continue
		}

		// Static assets are diverted to the StaticAssets output rather than
		// recorded as routes.
		if discoverroutehelpers.CaptureStaticAssetReference(urls, routeCaptureConfig.Target, redirectURL, routeCaptureConfig.IgnoreCrossDomainStaticAssets, routeCaptureConfig.CollectStaticAssets) {
			continue
		}

		// Check if the URL is allowed
		if !discoverroutehelpers.IsURLAllowed(routeCaptureConfig.Target, redirectURL, routeCaptureConfig.IgnoreCrossDomainRoutes, routeCaptureConfig.CollectStaticAssets) {
			continue
		}

		// Extract query parameters
		queryParams := discoverroutehelpers.ParseQueryParams(parsedURL)
		if len(queryParams) == 0 {
			continue
		}

		// Create route without query params in the URL
		urlNoQuery, err := discoverroutehelpers.URLRemoveQueryParams(redirectURL)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to remove query params from %s: %s", redirectURL, err))
			continue
		}

		routeBaseURL, routePath, err := discoverroutehelpers.SplitURLBaseAndPath(urlNoQuery)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to parse clean redirect URL %s: %s", urlNoQuery, err))
			continue
		}

		urls[urlNoQuery] = struct{}{}

		routeVar := &discover.RouteDetails{
			BaseUrl:     routeBaseURL,
			Path:        routePath,
			Method:      common.HttpMethodGet, // Redirects are typically GET
			QueryParams: queryParams,
		}

		routes = append(routes, routeVar)
	}

	return discoverroutehelpers.MergeWebRoutes(routes), discoverroutehelpers.SetToListString(urls), errors
}

// buildAllParameterURLs creates URLs for ALL discovered parameter values (no sampling)
func buildAllParameterURLs(route *discover.RouteDetails) []string {
	var allURLs []string
	if route == nil || route.QueryParams == nil || len(route.QueryParams) == 0 {
		return allURLs
	}

	baseURL := route.BaseUrl + route.Path

	// Build URLs with ALL discovered parameter values - no sampling or limits
	for _, param := range route.QueryParams {
		if param == nil {
			continue
		}
		if param.ExampleValues != nil && len(param.ExampleValues) > 0 {
			// Test EVERY value for this parameter to ensure complete coverage
			for _, value := range param.ExampleValues {
				// For single parameter, create simple query string
				if len(route.QueryParams) == 1 {
					paramURL := fmt.Sprintf("%s?%s=%s", baseURL, param.Name, value)
					allURLs = append(allURLs, paramURL)
				} else {
					// For multiple parameters, we'd need more complex combination logic
					// For now, handle single parameter case which covers most scenarios
					paramURL := fmt.Sprintf("%s?%s=%s", baseURL, param.Name, value)
					allURLs = append(allURLs, paramURL)
				}
			}
		}
	}

	return allURLs
}

func createSendHTTPRequestConfigWithQuery(ctx context.Context, baseURL, path string, queryParams map[string]string, config discover.DiscoverRouteConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params: &common.HttpRequestParams{
			Query:   queryParams,
			Headers: requesthelpers.BuildAuthHeaders(config.Headers, config.Cookies),
		},
	}
	// Capture console logs and page cookies on headless captures to match the
	// page-capture output contract; the standard transport ignores both flags.
	captureBrowserArtifacts := config.RequestMethod == common.RequestMethodHeadless
	sendConfig := common.SendHttpRequestConfig{
		Request:                    &request,
		MaxRedirects:               config.MaxRedirects,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		IgnoreCrossDomainRedirects: config.IgnoreCrossDomainRoutes,
		UserAgent:                  config.UserAgent,
		RequestMethod:              config.RequestMethod,
		HeadlessConfig:             config.HeadlessConfig,
		BrowserbaseConfig:          config.BrowserbaseConfig,
		BrowserbaseSecrets:         browserbaseSecrets,
		Cookies:                    config.Cookies,
		LocalStorage:               config.LocalStorage,
		SessionStorage:             config.SessionStorage,
		CaptureConsoleLogs:         &captureBrowserArtifacts,
		CaptureCookies:             &captureBrowserArtifacts,
	}

	// Add proxy settings from context
	requesthelpers.ApplyProxySettings(ctx, &sendConfig)

	return sendConfig
}

func extractRoutes(ctx context.Context, httpRequestResponse *common.HttpRequestResponse, requestConfig common.SendHttpRequestConfig, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	log := svc1log.FromContext(ctx)
	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	log.Info("Parsing HTML content using goquery")
	htmlContentPtr := requesthelpers.GetResponseBodyStringFromBodyStruct(httpRequestResponse.Response.ResponseBody)
	if htmlContentPtr == nil {
		errors = append(errors, "No response body content available")
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}
	if httpRequestResponse.Response.RedirectChain == nil || len(httpRequestResponse.Response.RedirectChain) == 0 {
		errors = append(errors, "No redirect chain available")
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}
	htmlContent := *htmlContentPtr
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to parse HTML content from %s: %s", httpRequestResponse.Response.RedirectChain[len(httpRequestResponse.Response.RedirectChain)-1], err)
		log.Error(errorMsg)
		errors = append(errors, errorMsg)
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}

	redirectedURL := httpRequestResponse.Response.RedirectChain[len(httpRequestResponse.Response.RedirectChain)-1]
	log.Info("Redirected URL", svc1log.SafeParam("url", redirectedURL))

	// Helper function to process errors with context
	processErrors := func(source string, newErrors []string) {
		for _, err := range newErrors {
			errors = append(errors, fmt.Sprintf("[%s] %s", source, err))
		}
	}

	// Extract routes from form elements
	log.Info("Extracting routes from form elements")
	formRoutes, formUrls, formErrors := capturerouteextractors.ExtractFormRoutes(doc, redirectedURL, routeCaptureConfig)
	routes = append(routes, formRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, formUrls)
	processErrors("Form Elements", formErrors)

	// Extract routes from anchor elements
	log.Info("Extracting routes from anchor elements")
	anchorRoutes, anchorUrls, anchorErrors := capturerouteextractors.ExtractAnchorRoutes(doc, redirectedURL, routeCaptureConfig)
	routes = append(routes, anchorRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, anchorUrls)
	processErrors("Anchor Elements", anchorErrors)

	// Extract routes from link elements
	log.Info("Extracting routes from link elements")
	linkRoutes, linkUrls, linkErrors := capturerouteextractors.ExtractLinkRoutes(doc, redirectedURL, routeCaptureConfig)
	routes = append(routes, linkRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, linkUrls)
	processErrors("Link Elements", linkErrors)

	// Extract routes from script elements
	log.Info("Extracting routes from script elements")
	scriptRoutes, scriptUrls, scriptErrors := capturerouteextractors.ExtractScriptRoutes(ctx, doc, redirectedURL, routeCaptureConfig)
	routes = append(routes, scriptRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, scriptUrls)
	errors = append(errors, scriptErrors...)

	// Extract routes from inline script elements
	log.Info("Extracting routes from inline script elements")
	inlineScriptRoutes, inlineScriptUrls, inlineScriptErrors := capturerouteextractors.ExtractInlineScriptRoutes(ctx, doc, redirectedURL, routeCaptureConfig)
	routes = append(routes, inlineScriptRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, inlineScriptUrls)
	errors = append(errors, inlineScriptErrors...)

	// Extract routes from redirect chain (analyze redirect URLs for parameters)
	log.Info("Extracting routes from redirect chain")
	redirectRoutes, redirectUrls, redirectErrors := ExtractRedirectRoutes(httpRequestResponse.Response.RedirectChain, routeCaptureConfig)
	routes = append(routes, redirectRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, redirectUrls)
	processErrors("Redirect Chain", redirectErrors)

	// Extract routes from network calls
	// Only to be performed if requestMethod is of type Headless or Browserbase
	if requestConfig.RequestMethod == common.RequestMethodHeadless || requestConfig.RequestMethod == common.RequestMethodBrowserbase {
		// Set a timeout for the network route extraction
		networkRouteCtx, networkCancel := context.WithTimeout(ctx, time.Duration(requestConfig.Timeout)*time.Second)
		defer networkCancel()

		log.Info("Extracting routes from inspecting network calls")
		browser := &headless.Requester{
			TimeoutSeconds:             requestConfig.Timeout,
			PathToBrowser:              requestConfig.HeadlessConfig.PathToBrowserShell,
			MinDOMStabalizeTimeSeconds: requestConfig.HeadlessConfig.MinDomStabalizeTime,
		}
		browser.SetProxyConfigFromRequest(requestConfig)
		err := browser.InitializeBrowser(networkRouteCtx)
		if err != nil {
			log.Error("Failed to initialize browser", svc1log.SafeParam("error", err))
			errors = append(errors, err.Error())
			return routes, discoverroutehelpers.SetToListString(urls), errors
		}

		fullRedirectedURL := redirectedURL
		networkRoutes, networkUrls, networkErrors := capturerouteextractors.ExtractNetworkRoutes(networkRouteCtx, browser, fullRedirectedURL, routeCaptureConfig.Target, routeCaptureConfig.IgnoreCrossDomainRoutes, routeCaptureConfig.IgnoreCrossDomainStaticAssets, routeCaptureConfig.CollectStaticAssets, routeCaptureConfig.VerifyTls)
		routes = append(routes, networkRoutes...)
		urls = discoverroutehelpers.AddListToSetString(urls, networkUrls)
		errors = append(errors, networkErrors...)
	}

	// Merge routes to remove duplicates
	mergedRoutes := discoverroutehelpers.MergeWebRoutes(routes) // Duplicate routes are removed
	log.Info("Returning results", svc1log.SafeParam("routes", len(mergedRoutes)))

	// Filter out static assets from all Route + Static Asset URLs
	staticAssets := make(map[string]struct{})
	for url := range urls {
		if routeCaptureConfig.CollectStaticAssets && utils.IsStaticAsset(url) {
			if !routeCaptureConfig.IgnoreCrossDomainStaticAssets || utils.IsHostInScope(routeCaptureConfig.Target, url) {
				staticAssets[url] = struct{}{}
			}
		}
	}
	staticAssetsList := discoverroutehelpers.SetToListString(staticAssets)

	return mergedRoutes, staticAssetsList, errors
}

func getResponseBaseURL(httpRequestResponse *common.HttpRequestResponse, fallbackURL string) string {
	rawURL := fallbackURL
	if httpRequestResponse != nil && httpRequestResponse.Response != nil && len(httpRequestResponse.Response.RedirectChain) > 0 {
		rawURL = httpRequestResponse.Response.RedirectChain[len(httpRequestResponse.Response.RedirectChain)-1]
	}

	baseURL, _, err := discoverroutehelpers.SplitURLBaseAndPath(rawURL)
	if err != nil {
		return ""
	}
	return baseURL
}

func sortRoutes(routes []*discover.RouteDetails) {
	sort.SliceStable(routes, func(i, j int) bool {
		ri := routes[i]
		rj := routes[j]
		hasEvi := ri.Evidence != nil
		hasEvj := rj.Evidence != nil
		if hasEvi != hasEvj {
			return hasEvi
		}
		return ri.BaseUrl+ri.Path < rj.BaseUrl+rj.Path
	})
}

func buildWebApplications(routes []*discover.RouteDetails, staticAssetsByBaseURL map[string][]string) []*discover.WebApplicationDetails {
	webApplicationsByBaseURL := make(map[string]*discover.WebApplicationDetails)
	getWebApplication := func(baseURL string) *discover.WebApplicationDetails {
		if baseURL == "" {
			return nil
		}
		if webApplication, ok := webApplicationsByBaseURL[baseURL]; ok {
			return webApplication
		}
		webApplication := &discover.WebApplicationDetails{BaseUrl: baseURL}
		webApplicationsByBaseURL[baseURL] = webApplication
		return webApplication
	}

	for _, route := range routes {
		if route == nil {
			continue
		}
		webApplication := getWebApplication(route.BaseUrl)
		if webApplication == nil {
			continue
		}
		webApplication.Routes = append(webApplication.Routes, route)
	}

	for baseURL, staticAssets := range staticAssetsByBaseURL {
		webApplication := getWebApplication(baseURL)
		if webApplication == nil {
			continue
		}

		staticAssetDetails := webApplication.StaticAssets
		if staticAssetDetails == nil {
			staticAssetDetails = &discover.StaticAssetDetails{}
		}
		for _, staticAsset := range discoverroutehelpers.MergeStaticAssets(staticAssets) {
			staticAssetBaseURL, _, err := discoverroutehelpers.SplitURLBaseAndPath(staticAsset)
			if err != nil {
				continue
			}
			if staticAssetBaseURL == baseURL {
				staticAssetDetails.Local = append(staticAssetDetails.Local, staticAsset)
			} else {
				staticAssetDetails.Remote = append(staticAssetDetails.Remote, staticAsset)
			}
		}
		if len(staticAssetDetails.Local) > 0 || len(staticAssetDetails.Remote) > 0 {
			webApplication.StaticAssets = staticAssetDetails
		}
	}

	webApplications := make([]*discover.WebApplicationDetails, 0, len(webApplicationsByBaseURL))
	for _, webApplication := range webApplicationsByBaseURL {
		if webApplication.StaticAssets != nil {
			webApplication.StaticAssets.Local = discoverroutehelpers.MergeStaticAssets(webApplication.StaticAssets.Local)
			webApplication.StaticAssets.Remote = discoverroutehelpers.MergeStaticAssets(webApplication.StaticAssets.Remote)
			sort.Strings(webApplication.StaticAssets.Local)
			sort.Strings(webApplication.StaticAssets.Remote)
		}
		webApplications = append(webApplications, webApplication)
	}
	sort.SliceStable(webApplications, func(i, j int) bool {
		return webApplications[i].BaseUrl < webApplications[j].BaseUrl
	})
	return webApplications
}

// PerformRouteCapture performs route discovery and spidering for the given config, returning a DiscoverRouteReport.
func PerformRouteCapture(ctx context.Context, config discover.DiscoverRouteConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) discover.DiscoverRouteReport {
	// Get the logger from the context
	log := svc1log.FromContext(ctx)

	// Initialize Report
	report := discover.DiscoverRouteReport{
		Config: &config,
		Result: &discover.DiscoverRouteResult{
			Target: config.Target,
		},
	}
	errors := []string{}

	// Track visited URLs to avoid cycles
	visitedURLs := make(map[string]struct{})
	urlsToVisit := []string{config.Target}
	currentDepth := 0

	// Keep track of all discovered routes and static assets
	allRoutes := []*discover.RouteDetails{}
	allStaticAssetsByBaseURL := make(map[string][]string)

	// Mutex to protect shared data structures
	var mu sync.Mutex

	// Extract routes from explicit bundle URLs once before spidering (not per page)
	if len(config.BundleUrls) > 0 {
		log.Info("Extracting routes from explicit bundle URLs")
		effectiveBase := resolveEffectiveTarget(ctx, config.Target, config)
		bundleRoutes, _, bundleErrors := capturerouteextractors.ExtractBundleURLRoutes(ctx, config.BundleUrls, effectiveBase, config)
		allRoutes = append(allRoutes, bundleRoutes...)
		errors = append(errors, bundleErrors...)
	}

	// Spider through Route URLs up to the specified depth
	for len(urlsToVisit) > 0 && currentDepth < config.SpiderDepth {
		// Process all URLs at the current depth
		urlsAtCurrentDepth := urlsToVisit
		nextDepthUrls := []string{}
		var nextDepthMu sync.Mutex

		log.Info("Visiting URLs at depth", svc1log.SafeParam("depth", currentDepth))

		// Create a wait group to wait for all goroutines to complete
		var wg sync.WaitGroup
		// Create a channel to collect errors
		errChan := make(chan string, len(urlsAtCurrentDepth))

		// Determine number of concurrent goroutines
		maxGoroutines := runtime.GOMAXPROCS(0) // Default to number of CPUs
		if config.Threads > 0 {
			maxGoroutines = config.Threads
		}

		// Create a semaphore to limit concurrent goroutines
		semaphore := make(chan struct{}, maxGoroutines)

		// Process each URL concurrently
		for _, urlToProcess := range urlsAtCurrentDepth {
			wg.Add(1)

			// Acquire semaphore (blocks if maxGoroutines are running)
			semaphore <- struct{}{}

			go func(targetURL string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore when done

				// Skip if already visited
				mu.Lock()
				if _, visited := visitedURLs[targetURL]; visited {
					mu.Unlock()
					return
				}
				visitedURLs[targetURL] = struct{}{}
				mu.Unlock()

				// Parse the URL to preserve query parameters
				parsedURL, err := url.Parse(targetURL)
				if err != nil {
					errChan <- fmt.Sprintf("error parsing URL %s: %s", targetURL, err)
					return
				}

				// Extract base URL and path
				currentBaseURL, currentPath, err := discoverroutehelpers.SplitURLBaseAndPath(targetURL)
				if err != nil {
					errChan <- fmt.Sprintf("error splitting URL %s: %s", targetURL, err)
					return
				}

				// Separate query parameters
				var queryParams map[string]string
				if parsedURL.RawQuery != "" {
					queryParams = make(map[string]string)
					values, err := url.ParseQuery(parsedURL.RawQuery)
					if err == nil {
						for key, vals := range values {
							if len(vals) > 0 {
								queryParams[key] = vals[0] // Use first value if multiple
							}
						}
					}
				}

				// Send the request
				requestConfig := createSendHTTPRequestConfigWithQuery(ctx, currentBaseURL, currentPath, queryParams, config, browserbaseSecrets)
				request, err := request.SendRequest(ctx, requestConfig)
				if err != nil {
					errChan <- fmt.Sprintf("error performing request to %s: %s", targetURL, err)
					return
				}

				// Apply stealth delay between requests. On ctx cancel, fall
				// through to extraction so we don't discard the response we
				// already paid the request cost for; the URL stays in
				// visitedURLs intentionally (it has been fetched).
				if config.Sleep > 0 {
					delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
					select {
					case <-time.After(delay):
					case <-ctx.Done():
					}
				}

				// Extract the routes and if enabled, static assets
				if request.Response == nil || request.Response.ResponseBody == nil {
					log.Info("No response from", svc1log.SafeParam("url", targetURL))
					errChan <- fmt.Sprintf("no response from %s", targetURL)
					return
				}

				routes, staticAssets, newErrors := extractRoutes(ctx, request, requestConfig, config)
				responseBaseURL := getResponseBaseURL(request, targetURL)

				// Safely append to shared data structures
				mu.Lock()
				allRoutes = append(allRoutes, routes...)
				if responseBaseURL != "" {
					allStaticAssetsByBaseURL[responseBaseURL] = append(allStaticAssetsByBaseURL[responseBaseURL], staticAssets...)
				}
				errors = append(errors, newErrors...)
				mu.Unlock()

				// Collect routes to spider
				for _, route := range routes {
					if route == nil {
						continue
					}
					// Visit the base route (without parameters)
					baseRouteURL := route.BaseUrl + route.Path
					mu.Lock()
					if _, visited := visitedURLs[baseRouteURL]; !visited {
						nextDepthMu.Lock()
						nextDepthUrls = append(nextDepthUrls, baseRouteURL)
						nextDepthMu.Unlock()
					}
					mu.Unlock()

					// Visit routes with ALL their discovered query parameter values (comprehensive testing)
					if route.QueryParams != nil && len(route.QueryParams) > 0 {
						// Build URLs with ALL parameter values - no sampling to ensure complete coverage
						allParameterURLs := buildAllParameterURLs(route)
						mu.Lock()
						for _, paramURL := range allParameterURLs {
							if _, visited := visitedURLs[paramURL]; !visited {
								nextDepthMu.Lock()
								nextDepthUrls = append(nextDepthUrls, paramURL)
								nextDepthMu.Unlock()
							}
						}
						mu.Unlock()
					}
				}
			}(urlToProcess)
		}

		// Wait for all goroutines to complete
		wg.Wait()
		close(errChan)

		// Collect errors from the channel
		for err := range errChan {
			report.Errors = append(report.Errors, err)
		}

		// Move to next depth
		urlsToVisit = nextDepthUrls
		currentDepth++
	}

	mergedRoutes := discoverroutehelpers.MergeWebRoutes(allRoutes)
	// Runs after the crawl so templated paths are never fetched as literal URLs.
	mergedRoutes = discoverroutehelpers.ApplyDeclaredRouteTemplates(mergedRoutes)
	sortRoutes(mergedRoutes)
	report.Result.WebApplications = buildWebApplications(mergedRoutes, allStaticAssetsByBaseURL)
	report.Errors = append(report.Errors, errors...)
	return report
}
