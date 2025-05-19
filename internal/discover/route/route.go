package discoverroute

import (
	// Standard
	"context"
	"fmt"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discoverroutefern "github.com/Method-Security/webscan/generated/go/discover/route"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	headless "github.com/Method-Security/webscan/utils/request/helpers/headless"

	// Internal
	discoverroutehelpers "github.com/Method-Security/webscan/internal/discover/route/helpers"
	capturerouteextractors "github.com/Method-Security/webscan/internal/discover/route/helpers/extractors"

	// External
	goquery "github.com/PuerkitoBio/goquery"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func createSendHTTPRequestConfig(baseURL, path string, config discoverroutefern.RouteCaptureConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       config.MaxRedirects,
		Insecure:           config.Insecure,
		Timeout:            config.Timeout,
		RequestMethod:      config.RequestMethod,
		HeadlessConfig:     config.HeadlessConfig,
		BrowserbaseConfig:  config.BrowserbaseConfig,
		BrowserbaseSecrets: browserbaseSecrets,
	}
}

func extractRoutes(ctx context.Context, httpRequestResponse *common.HttpRequestResponse, requestConfig common.SendHttpRequestConfig, routeCaptureConfig discoverroutefern.RouteCaptureConfig) ([]*discoverroutefern.RouteDetails, []string, []string) {
	log := svc1log.FromContext(ctx)
	routes := []*discoverroutefern.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	log.Info("Parsing HTML content using goquery")
	htmlContent := *requesthelpers.GetResponseBodyStringFromBodyStruct(httpRequestResponse.Response.ResponseBody)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		log.Error("Failed to parse HTML content", svc1log.SafeParam("error", err))
		errors = append(errors, err.Error())
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}

	log.Info("Extracting routes from form elements")
	formRoutes, formUrls, formErrors := capturerouteextractors.ExtractFormRoutes(doc, httpRequestResponse, routeCaptureConfig)
	routes = append(routes, formRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, formUrls)
	errors = append(errors, formErrors...)

	log.Info("Extracting routes from anchor elements")
	anchorRoutes, anchorUrls, anchorErrors := capturerouteextractors.ExtractAnchorRoutes(doc, httpRequestResponse, routeCaptureConfig)
	routes = append(routes, anchorRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, anchorUrls)
	errors = append(errors, anchorErrors...)

	log.Info("Extracting routes from link elements")
	linkRoutes, linkUrls, linkErrors := capturerouteextractors.ExtractLinkRoutes(doc, httpRequestResponse, routeCaptureConfig)
	routes = append(routes, linkRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, linkUrls)
	errors = append(errors, linkErrors...)

	log.Info("Extracting routes from script elements")
	scriptRoutes, scriptUrls, scriptErrors := capturerouteextractors.ExtractScriptRoutes(doc, httpRequestResponse, routeCaptureConfig)
	routes = append(routes, scriptRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, scriptUrls)
	errors = append(errors, scriptErrors...)

	log.Info("Extracting routes from inline script elements")
	inlineScriptRoutes, inlineScriptUrls, inlineScriptErrors := capturerouteextractors.ExtractInlineScriptRoutes(doc, httpRequestResponse, routeCaptureConfig)
	routes = append(routes, inlineScriptRoutes...)
	urls = discoverroutehelpers.AddListToSetString(urls, inlineScriptUrls)
	errors = append(errors, inlineScriptErrors...)

	// Only to be performed if requestMethod is of type Headless or Browserbase
	if requestConfig.RequestMethod == common.RequestMethodHeadless || requestConfig.RequestMethod == common.RequestMethodBrowserbase {
		log.Info("Extracting routes from inspecting network calls")
		browser := &headless.Requester{
			TimeoutSeconds: requestConfig.Timeout,
		}
		browser.InitializeBrowser()
		networkRoutes, networkUrls, networkErrors := capturerouteextractors.ExtractNetworkRoutes(ctx, browser, httpRequestResponse.Request.BaseUrl, routeCaptureConfig.RequireBaseUrlMatch, !routeCaptureConfig.IgnoreStaticAssets)
		routes = append(routes, networkRoutes...)
		urls = discoverroutehelpers.AddListToSetString(urls, networkUrls)
		errors = append(errors, networkErrors...)
	}

	log.Info("Returning results")
	mergedRoutes := discoverroutehelpers.MergeWebRoutes(routes) // For uniqueness across techniques
	return mergedRoutes, discoverroutehelpers.SetToListString(urls), errors
}

func PerformRouteCapture(ctx context.Context, config discoverroutefern.RouteCaptureConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) discoverroutefern.RouteCaptureReport {
	report := discoverroutefern.RouteCaptureReport{
		Target: config.Target,
		Errors: []string{},
	}

	// Track visited URLs to avoid cycles
	visitedURLs := make(map[string]struct{})
	urlsToVisit := []string{config.Target}
	currentDepth := 0

	// Keep track of all discovered routes and static assets
	allRoutes := []*discoverroutefern.RouteDetails{}
	allStaticAssets := []string{}

	// Spider through URLs up to the specified depth
	for len(urlsToVisit) > 0 && currentDepth <= config.SpiderDepth {
		// Get the next URL to visit
		currentURL := urlsToVisit[0]
		urlsToVisit = urlsToVisit[1:]

		// Skip if already visited
		if _, visited := visitedURLs[currentURL]; visited {
			continue
		}
		visitedURLs[currentURL] = struct{}{}

		// Split and standardize the current URL
		currentBaseURL, currentPath, err := requesthelpers.SplitTargetURL(currentURL)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("error splitting URL %s: %s", currentURL, err))
			continue
		}

		// Send the request
		requestConfig := createSendHTTPRequestConfig(currentBaseURL, currentPath, config, browserbaseSecrets)
		request, err := request.SendRequest(ctx, requestConfig)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("error performing request to %s: %s", currentURL, err))
			continue
		}

		// Extract the routes and urls
		routes, urls, errors := extractRoutes(ctx, request, requestConfig, config)
		report.Errors = append(report.Errors, errors...)

		// Add discovered routes
		allRoutes = append(allRoutes, routes...)

		// Process static assets
		for _, url := range urls {
			if utils.IsStaticAsset(url) {
				allStaticAssets = append(allStaticAssets, url)
			} else if currentDepth < config.SpiderDepth {
				// Add non-static URLs to visit in the next depth level
				urlsToVisit = append(urlsToVisit, url)
			}
		}

		currentDepth++
	}

	// Merge routes to remove duplicates
	report.Routes = discoverroutehelpers.MergeWebRoutes(allRoutes)
	report.StaticAssets = allStaticAssets

	return report
}
