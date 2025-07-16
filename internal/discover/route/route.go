package discoverroute

import (
	// Standard
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
	"github.com/Method-Security/webscan/utils"

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

func createSendHTTPRequestConfig(baseURL, path string, config discover.DiscoverRouteConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       config.MaxRedirects,
		VerifyTls:          config.VerifyTls,
		Timeout:            config.Timeout,
		RequestMethod:      config.RequestMethod,
		HeadlessConfig:     config.HeadlessConfig,
		BrowserbaseConfig:  config.BrowserbaseConfig,
		BrowserbaseSecrets: browserbaseSecrets,
	}
}

func extractRoutes(ctx context.Context, httpRequestResponse *common.HttpRequestResponse, requestConfig common.SendHttpRequestConfig, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	log := svc1log.FromContext(ctx)
	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	log.Info("Parsing HTML content using goquery")
	htmlContent := *requesthelpers.GetResponseBodyStringFromBodyStruct(httpRequestResponse.Response.ResponseBody)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to parse HTML content from %s: %s", httpRequestResponse.Response.RedirectChain[len(httpRequestResponse.Response.RedirectChain)-1], err)
		log.Error(errorMsg)
		errors = append(errors, errorMsg)
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}

	redirectedURL := httpRequestResponse.Response.RedirectChain[len(httpRequestResponse.Response.RedirectChain)-1]
	log.Info("Redirected URL", svc1log.SafeParam("url", redirectedURL))
	redirectedURLBase, redirectedURLPath, err := requesthelpers.SplitTargetURL(redirectedURL)
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

	log.Info("Extracting routes from form elements")
	formRoutes, formUrls, formErrors := capturerouteextractors.ExtractFormRoutes(doc, redirectedURLBase, routeCaptureConfig)
	routes = append(routes, formRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, formUrls)
	processErrors("Form Elements", formErrors)

	log.Info("Extracting routes from anchor elements")
	anchorRoutes, anchorUrls, anchorErrors := capturerouteextractors.ExtractAnchorRoutes(doc, redirectedURLBase, routeCaptureConfig)
	routes = append(routes, anchorRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, anchorUrls)
	processErrors("Anchor Elements", anchorErrors)

	log.Info("Extracting routes from link elements")
	linkRoutes, linkUrls, linkErrors := capturerouteextractors.ExtractLinkRoutes(doc, redirectedURLBase, routeCaptureConfig)
	routes = append(routes, linkRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, linkUrls)
	processErrors("Link Elements", linkErrors)

	log.Info("Extracting routes from script elements")
	scriptRoutes, scriptUrls, scriptErrors := capturerouteextractors.ExtractScriptRoutes(ctx, doc, redirectedURLBase, routeCaptureConfig)
	routes = append(routes, scriptRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, scriptUrls)
	errors = append(errors, scriptErrors...)

	log.Info("Extracting routes from inline script elements")
	inlineScriptRoutes, inlineScriptUrls, inlineScriptErrors := capturerouteextractors.ExtractInlineScriptRoutes(ctx, doc, redirectedURLBase, routeCaptureConfig)
	routes = append(routes, inlineScriptRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, inlineScriptUrls)
	errors = append(errors, inlineScriptErrors...)

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

		fullRedirectedURL := fmt.Sprintf("%s%s", redirectedURLBase, redirectedURLPath)
		networkRoutes, networkUrls, networkErrors := capturerouteextractors.ExtractNetworkRoutes(networkRouteCtx, browser, fullRedirectedURL, routeCaptureConfig.NoBaseUrlMatch, routeCaptureConfig.CollectStaticAssets)
		routes = append(routes, networkRoutes...)
		urls = discoverroutehelpers.AddListToSetString(urls, networkUrls)
		errors = append(errors, networkErrors...)
	}

	log.Info("Returning results")

	// Merge routes to remove duplicates
	mergedRoutes := discoverroutehelpers.MergeWebRoutes(routes) // For uniqueness across techniques

	// Filter out static assets from all Route + Static Asset URLs
	staticAssets := make(map[string]struct{})
	for url := range urls {
		if routeCaptureConfig.CollectStaticAssets && utils.IsStaticAsset(url) {
			staticAssets[url] = struct{}{}
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
		for _, currentURL := range urlsAtCurrentDepth {
			wg.Add(1)

			// Acquire semaphore (blocks if maxGoroutines are running)
			semaphore <- struct{}{}

			go func(url string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore when done

				// Skip if already visited
				mu.Lock()
				if _, visited := visitedURLs[url]; visited {
					mu.Unlock()
					return
				}
				visitedURLs[url] = struct{}{}
				mu.Unlock()

				// Split and standardize the current URL
				currentBaseURL, currentPath, err := requesthelpers.SplitTargetURL(url)
				if err != nil {
					errChan <- fmt.Sprintf("error splitting URL %s: %s", url, err)
					return
				}

				// Send the request
				requestConfig := createSendHTTPRequestConfig(currentBaseURL, currentPath, config, browserbaseSecrets)
				request, err := request.SendRequest(ctx, requestConfig)
				if err != nil {
					errChan <- fmt.Sprintf("error performing request to %s: %s", url, err)
					return
				}

				// Extract the routes and if enabled, static assets
				if request.Response == nil || request.Response.ResponseBody == nil {
					log.Info("No response from", svc1log.SafeParam("url", url))
					errChan <- fmt.Sprintf("no response from %s", url)
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
					routeURL := route.BaseUrl + route.Path
					mu.Lock()
					if _, visited := visitedURLs[routeURL]; !visited {
						nextDepthMu.Lock()
						nextDepthUrls = append(nextDepthUrls, routeURL)
						nextDepthMu.Unlock()
					}
					mu.Unlock()
				}
			}(currentURL)
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
	report.Result.StaticAssets = discoverroutehelpers.MergeStaticAssets(allStaticAssets)
	report.Errors = errors
	return report
}
