package discoverroute

import (
	// Standard
	"context"
	"net/url"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"
	discoverroutehelpers "github.com/Method-Security/webscan/internal/discover/route/helpers"

	// Utils
	headless "github.com/Method-Security/webscan/utils/request/headless"
	// External
	rod "github.com/go-rod/rod"
	proto "github.com/go-rod/rod/lib/proto"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// ExtractNetworkRoutes uses a headless browser to capture network requests and extract route details from them.
// Returns a slice of RouteDetails, a slice of URLs, and a slice of errors.
func ExtractNetworkRoutes(ctx context.Context, browser *headless.Requester, target string, ignoreCrossDomain bool, captureStaticAssets bool) ([]*discover.RouteDetails, []string, []string) {
	// Get the logger from the context
	log := svc1log.FromContext(ctx)

	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	log.Info("Initiating network events capture with Headless method", svc1log.SafeParam("target", target))
	// Ensure the browser is initialized
	if browser.Browser == nil {
		err := browser.InitializeBrowser(ctx)
		if err != nil {
			log.Error("Failed to initialize browser", svc1log.SafeParam("error", err))
			return routes, discoverroutehelpers.SetToListString(urls), []string{err.Error()}
		}
	}

	var page *rod.Page
	pageErr := rod.Try(func() {
		page = browser.Browser.MustPage(target).Context(ctx)
	})
	if pageErr != nil {
		log.Error("Failed to create page", svc1log.SafeParam("url", target), svc1log.SafeParam("error", pageErr))
		errors = append(errors, pageErr.Error())
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}
	log.Debug("Successfully connected to page for network capture")

	// Enable network event tracking
	networkEventErr := proto.NetworkEnable{}.Call(page)
	if networkEventErr != nil {
		log.Error("Failed to enable network tracking", svc1log.SafeParam("error", networkEventErr))
		errors = append(errors, networkEventErr.Error())
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}

	log.Info("Capturing network events")
	// Capture network requests of type 'fetch' which are typical of API calls
	networkEvents := []*proto.NetworkRequestWillBeSent{}
	waitForNetworkEvents := page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		log.Debug("Captured network event", svc1log.SafeParam("url", e.Request.URL), svc1log.SafeParam("type", e.Type))
		// Only capture fetch requests
		if e.Type == proto.NetworkResourceTypeFetch {
			networkEvents = append(networkEvents, e)
		}
	})

	// Navigate to the page
	err := page.Navigate(target)
	if err != nil {
		log.Error("Failed to navigate to page", svc1log.SafeParam("url", target), svc1log.SafeParam("error", err))
		errors = append(errors, err.Error())
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}
	// Wait for the page to load
	err = page.WaitLoad()
	if err != nil {
		log.Debug("Failed to wait for page load", svc1log.SafeParam("url", target), svc1log.SafeParam("error", err))
		errors = append(errors, err.Error())
		// Reload the page if it can't load, possible redirect
		reloadErr := page.Reload()
		if reloadErr != nil {
			log.Error("Failed to reload page", svc1log.SafeParam("url", target), svc1log.SafeParam("error", reloadErr))
			errors = append(errors, reloadErr.Error())
			return routes, discoverroutehelpers.SetToListString(urls), errors
		}
	}
	// Wait for network events to be captured
	waitForNetworkEvents()

	log.Info("Processing network events")
	// Process network events and populate the WebRoute structure
	for _, event := range networkEvents {
		request := event.Request

		// Filter requests by base domain if required
		reqURL, err := url.Parse(request.URL)
		if err != nil {
			log.Error("Failed to parse URL", svc1log.SafeParam("url", request.URL), svc1log.SafeParam("error", err))
			continue
		}

		if !discoverroutehelpers.IsURLAllowed(target, reqURL.String(), ignoreCrossDomain, captureStaticAssets) {
			log.Debug("Skipping URL", svc1log.SafeParam("url", reqURL.String()), svc1log.SafeParam("target", target))
			continue
		}

		// The route URL should not have query params, those are stored in QueryParams
		urlNoQuery, err := discoverroutehelpers.URLRemoveQueryParams(request.URL)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// Get the origin and path from the full URL
		routeBaseURL, routePath, err := discoverroutehelpers.SplitURLBaseAndPath(urlNoQuery)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// Build WebRoute object
		log.Info("Building WebRoute object", svc1log.SafeParam("url", urlNoQuery), svc1log.SafeParam("path", routePath), svc1log.SafeParam("method", request.Method))
		webRoute := &discover.RouteDetails{
			BaseUrl: routeBaseURL,
			Path:    routePath,
			Method:  common.HttpMethod(request.Method),
		}

		// Capture query parameters
		webRoute.QueryParams = discoverroutehelpers.ParseQueryParams(reqURL)

		// Capture body parameters (if any)
		if request.HasPostData {
			bodyParams, bodyErr := discoverroutehelpers.ParseBodyParams(request.PostData)
			if bodyErr != nil {
				errors = append(errors, bodyErr.Error())
			} else {
				webRoute.BodyParams = bodyParams
			}
		}

		// Add the WebRoute to the list
		routes = append(routes, webRoute)
	}

	return discoverroutehelpers.MergeWebRoutes(routes), discoverroutehelpers.SetToListString(urls), errors
}
