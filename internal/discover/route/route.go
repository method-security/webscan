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
		},
	}

	sendConfig := common.SendHttpRequestConfig{
		Request:      &httpRequest,
		MaxRedirects: config.MaxRedirects,
		VerifyTls:    config.VerifyTls,
		Timeout:      config.Timeout,
		// IgnoreCrossDomainRedirects is the transport-layer flag — a strict
		// hostname-string equality check. The route allowlist (IsURLAllowed /
		// IsSubdomain) handles cross-domain scoping at discover time and is
		// subdomain-aware. Match legacy HEAD-resolve behavior so apex → www
		// and other in-scope hostname-changing redirects still resolve.
		IgnoreCrossDomainRedirects: false,
		UserAgent:                  config.UserAgent,
		RequestMethod:              common.RequestMethodStandard,
	}

	response, err := request.SendRequest(ctx, sendConfig)
	if err != nil || response == nil || response.Response == nil {
		return target
	}
	if chain := response.Response.RedirectChain; len(chain) > 0 {
		return strings.TrimRight(chain[len(chain)-1], "/")
	}
	return target
}

// ExtractRedirectRoutes analyzes redirect chain URLs to extract routes with parameters
func ExtractRedirectRoutes(redirectChain []string, baseURL string, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
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

		// Check if the URL is allowed
		if !discoverroutehelpers.IsURLAllowed(baseURL, redirectURL, routeCaptureConfig.IgnoreCrossDomain, routeCaptureConfig.CollectStaticAssets) {
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

func createSendHTTPRequestConfigWithQuery(baseURL, path string, queryParams map[string]string, config discover.DiscoverRouteConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params: &common.HttpRequestParams{
			Query: queryParams,
		},
	}
	return common.SendHttpRequestConfig{
		Request:                    &request,
		MaxRedirects:               config.MaxRedirects,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		IgnoreCrossDomainRedirects: config.IgnoreCrossDomain,
		UserAgent:                  config.UserAgent,
		RequestMethod:              config.RequestMethod,
		HeadlessConfig:             config.HeadlessConfig,
		BrowserbaseConfig:          config.BrowserbaseConfig,
		BrowserbaseSecrets:         browserbaseSecrets,
	}
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

	// Use the full page URL for resolving relative paths, but keep BaseUrl output origin-only.
	redirectedURLBase, _, err := discoverroutehelpers.SplitURLBaseAndPath(redirectedURL)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to split redirected URL %s: %s", redirectedURL, err)
		log.Error(errorMsg)
		errors = append(errors, errorMsg)
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}

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
	redirectRoutes, redirectUrls, redirectErrors := ExtractRedirectRoutes(httpRequestResponse.Response.RedirectChain, redirectedURLBase, routeCaptureConfig)
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
		err := browser.InitializeBrowser(networkRouteCtx)
		if err != nil {
			log.Error("Failed to initialize browser", svc1log.SafeParam("error", err))
			errors = append(errors, err.Error())
			return routes, discoverroutehelpers.SetToListString(urls), errors
		}

		fullRedirectedURL := redirectedURL
		networkRoutes, networkUrls, networkErrors := capturerouteextractors.ExtractNetworkRoutes(networkRouteCtx, browser, fullRedirectedURL, routeCaptureConfig.IgnoreCrossDomain, routeCaptureConfig.CollectStaticAssets)
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
			if discoverroutehelpers.IsSubdomain(redirectedURLBase, url) || !routeCaptureConfig.IgnoreCrossDomain {
				staticAssets[url] = struct{}{}
			}
		}
	}
	staticAssetsList := discoverroutehelpers.SetToListString(staticAssets)

	return mergedRoutes, staticAssetsList, errors
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
	allStaticAssets := []string{}

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
				requestConfig := createSendHTTPRequestConfigWithQuery(currentBaseURL, currentPath, queryParams, config, browserbaseSecrets)
				request, err := request.SendRequest(ctx, requestConfig)
				if err != nil {
					errChan <- fmt.Sprintf("error performing request to %s: %s", targetURL, err)
					return
				}

				// Apply stealth delay between requests
				if config.Sleep > 0 {
					delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
					time.Sleep(delay)
				}

				// Extract the routes and if enabled, static assets
				if request.Response == nil || request.Response.ResponseBody == nil {
					log.Info("No response from", svc1log.SafeParam("url", targetURL))
					errChan <- fmt.Sprintf("no response from %s", targetURL)
					return
				}

				routes, staticAssets, newErrors := extractRoutes(ctx, request, requestConfig, config)

				// Safely append to shared data structures
				mu.Lock()
				allRoutes = append(allRoutes, routes...)
				allStaticAssets = append(allStaticAssets, staticAssets...)
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

	// Remove duplicate Routes and Static Assets
	report.Result.Routes = discoverroutehelpers.MergeWebRoutes(allRoutes)
	sort.SliceStable(report.Result.Routes, func(i, j int) bool {
		ri := report.Result.Routes[i]
		rj := report.Result.Routes[j]
		// Evidence-tagged routes survive MaxRoutes cap before untagged routes
		hasEvi := ri.Evidence != nil
		hasEvj := rj.Evidence != nil
		if hasEvi != hasEvj {
			return hasEvi // true means ri comes first
		}
		// Same evidence tier: lexical for determinism
		return ri.BaseUrl+ri.Path < rj.BaseUrl+rj.Path
	})
	if config.MaxRoutes != nil && *config.MaxRoutes > 0 && len(report.Result.Routes) > *config.MaxRoutes {
		report.Result.Routes = report.Result.Routes[:*config.MaxRoutes]
	}
	report.Result.StaticAssets = discoverroutehelpers.MergeStaticAssets(allStaticAssets)
	report.Errors = append(report.Errors, errors...)
	return report
}
