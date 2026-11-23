package discoverroute

import (
	// Standard
	"context"
	stderrors "errors"
	"fmt"
	"net/url"
	"sync"
	"time"

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
// target is the page to navigate to (the per-page post-redirect URL); scopeURL is the
// scope anchor (config.Target) used to keep discovery tight to the original target.
// ignoreCrossDomainRoutes gates the scope of discovered routes; ignoreCrossDomainStaticAssets
// gates the scope of captured static assets — matching the HTML/JS extractors.
// Returns a slice of RouteDetails, a slice of URLs (static assets), and a slice of errors.
func ExtractNetworkRoutes(ctx context.Context, browser *headless.Requester, target string, scopeURL string, ignoreCrossDomainRoutes bool, ignoreCrossDomainStaticAssets bool, captureStaticAssets bool, verifyTLS bool) ([]*discover.RouteDetails, []string, []string) {
	log := svc1log.FromContext(ctx)
	const maxNetworkCaptureAttempts = 3

	var lastRoutes []*discover.RouteDetails
	var lastUrls []string
	var lastErrors []string
	for attempt := 1; attempt <= maxNetworkCaptureAttempts; attempt++ {
		if attempt > 1 {
			if !sleepBeforeNetworkCaptureRetry(ctx, attempt) {
				break
			}
			log.Warn("Retrying transient network route capture failure",
				svc1log.SafeParam("attempt", attempt),
				svc1log.SafeParam("maxAttempts", maxNetworkCaptureAttempts),
				svc1log.SafeParam("target", target))
		}

		routes, urls, errors := extractNetworkRoutesOnce(ctx, browser, target, scopeURL, ignoreCrossDomainRoutes, ignoreCrossDomainStaticAssets, captureStaticAssets, verifyTLS)
		lastRoutes = routes
		lastUrls = urls
		lastErrors = errors
		if len(routes) > 0 || !networkCaptureErrorsAreTransient(errors) || ctx.Err() != nil {
			return routes, urls, errors
		}
		if len(errors) > 0 {
			browser.ResetOwnedBrowser(ctx, errors[0])
		}
	}

	return lastRoutes, lastUrls, lastErrors
}

func extractNetworkRoutesOnce(ctx context.Context, browser *headless.Requester, target string, scopeURL string, ignoreCrossDomainRoutes bool, ignoreCrossDomainStaticAssets bool, captureStaticAssets bool, verifyTLS bool) ([]*discover.RouteDetails, []string, []string) {
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

	if !verifyTLS {
		if err := browser.Browser.IgnoreCertErrors(true); err != nil {
			errMsg := fmt.Sprintf("failed to disable certificate error checking: %s", cleanNetworkCaptureError(err))
			log.Warn("Failed to disable certificate error checking for network capture", svc1log.SafeParam("error", errMsg))
			errors = append(errors, errMsg)
			return routes, discoverroutehelpers.SetToListString(urls), errors
		}
		log.Info("Certificate error checking disabled for network capture")
	}

	page, err := browser.Browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		errMsg := fmt.Sprintf("failed to create page: %s", cleanNetworkCaptureError(err))
		log.Error("Failed to create page", svc1log.SafeParam("url", target), svc1log.SafeParam("error", errMsg))
		errors = append(errors, errMsg)
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}
	createdPage := page
	defer func() {
		if closeErr := createdPage.Close(); closeErr != nil {
			log.Debug("Failed to close network capture page", svc1log.SafeParam("error", cleanNetworkCaptureError(closeErr)))
		}
	}()

	captureCtx, stopNetworkCapture := context.WithCancel(ctx)
	defer stopNetworkCapture()
	page = page.Context(captureCtx)
	log.Debug("Successfully connected to page for network capture")

	// Enable network event tracking
	networkEventErr := proto.NetworkEnable{}.Call(page)
	if networkEventErr != nil {
		errMsg := fmt.Sprintf("failed to enable network tracking: %s", cleanNetworkCaptureError(networkEventErr))
		log.Error("Failed to enable network tracking", svc1log.SafeParam("error", errMsg))
		errors = append(errors, errMsg)
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}

	log.Info("Capturing network events")
	// Capture API-style requests that may only appear during browser execution.
	networkEvents := []*proto.NetworkRequestWillBeSent{}
	var networkEventsMu sync.Mutex
	waitForNetworkEvents := page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		log.Debug("Captured network event", svc1log.SafeParam("url", e.Request.URL), svc1log.SafeParam("type", e.Type))
		if isRouteNetworkResourceType(e.Type) {
			networkEventsMu.Lock()
			networkEvents = append(networkEvents, e)
			networkEventsMu.Unlock()
		}
	})
	networkEventsDone := make(chan struct{})
	go func() {
		waitForNetworkEvents()
		close(networkEventsDone)
	}()

	// Navigate to the page
	err = page.Navigate(target)
	if err != nil {
		errMsg := fmt.Sprintf("failed to navigate to page: %s", cleanNetworkCaptureError(err))
		log.Warn("Failed to navigate to page, processing captured network events", svc1log.SafeParam("url", target), svc1log.SafeParam("error", errMsg))
		errors = append(errors, errMsg)
	} else {
		// Wait for the page to load. If this fails, keep any events already captured.
		err = page.WaitLoad()
		if err != nil {
			errMsg := fmt.Sprintf("failed to wait for page load: %s", cleanNetworkCaptureError(err))
			log.Debug("Failed to wait for page load, processing captured network events", svc1log.SafeParam("url", target), svc1log.SafeParam("error", errMsg))
			errors = append(errors, errMsg)
		}
	}

	waitForNetworkStabilization(ctx, browser.MinDOMStabalizeTimeSeconds)

	// Wait for network events to be captured
	stopNetworkCapture()
	<-networkEventsDone

	log.Info("Processing network events")
	// Process network events and populate the WebRoute structure
	networkEventsMu.Lock()
	capturedNetworkEvents := append([]*proto.NetworkRequestWillBeSent(nil), networkEvents...)
	networkEventsMu.Unlock()
	for _, event := range capturedNetworkEvents {
		request := event.Request

		// Filter requests by base domain if required
		reqURL, err := url.Parse(request.URL)
		if err != nil {
			log.Error("Failed to parse URL", svc1log.SafeParam("url", request.URL), svc1log.SafeParam("error", err))
			continue
		}

		// Static assets are diverted to the StaticAssets output (scoped by the static
		// asset flag) rather than recorded as routes, matching the HTML/JS extractors.
		if discoverroutehelpers.CaptureStaticAssetReference(urls, scopeURL, reqURL.String(), ignoreCrossDomainStaticAssets, captureStaticAssets) {
			continue
		}

		// Route scope check uses the routes flag.
		if !discoverroutehelpers.IsURLAllowed(scopeURL, reqURL.String(), ignoreCrossDomainRoutes, captureStaticAssets) {
			log.Debug("Skipping URL", svc1log.SafeParam("url", reqURL.String()), svc1log.SafeParam("scope", scopeURL))
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

func isRouteNetworkResourceType(resourceType proto.NetworkResourceType) bool {
	return resourceType == proto.NetworkResourceTypeFetch || resourceType == proto.NetworkResourceTypeXHR
}

func waitForNetworkStabilization(ctx context.Context, minDOMStabalizeTimeSeconds int) {
	waitSeconds := minDOMStabalizeTimeSeconds
	if waitSeconds <= 0 {
		waitSeconds = 2
	}

	select {
	case <-time.After(time.Duration(waitSeconds) * time.Second):
	case <-ctx.Done():
	}
}

func sleepBeforeNetworkCaptureRetry(ctx context.Context, attempt int) bool {
	delay := time.Duration(attempt-1) * 250 * time.Millisecond
	select {
	case <-time.After(delay):
		return true
	case <-ctx.Done():
		return false
	}
}

func networkCaptureErrorsAreTransient(errorMessages []string) bool {
	if len(errorMessages) == 0 {
		return false
	}
	for _, msg := range errorMessages {
		if headless.IsTransientHeadlessError(fmt.Errorf("%s", msg)) {
			return true
		}
	}
	return false
}

func cleanNetworkCaptureError(err error) string {
	if err == nil {
		return "unknown error"
	}

	var navErr *rod.NavigationError
	if stderrors.As(err, &navErr) {
		return navErr.Reason
	}

	var tryErr *rod.TryError
	if stderrors.As(err, &tryErr) {
		return fmt.Sprintf("%v", tryErr.Value)
	}

	if stderrors.Is(err, context.DeadlineExceeded) {
		return "network route capture timed out"
	}
	if stderrors.Is(err, context.Canceled) {
		return "network route capture canceled"
	}

	return err.Error()
}
