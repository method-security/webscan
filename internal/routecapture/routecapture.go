package routecapture

import (
	"context"
	"net/http"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go/routecapture"
	"github.com/Method-Security/webscan/internal/browserbase"
	capture "github.com/Method-Security/webscan/internal/capture"
	"github.com/PuerkitoBio/goquery"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func extractRoutes(ctx context.Context, target string, htmlContent string, baseURLsOnly bool, captureStaticAssets bool, timeout int, captureMethod webscan.PageCaptureMethod, browserCapturer *capture.BrowserPageCapturer) ([]*webscan.WebRoute, []string, []string) {
	routes := []*webscan.WebRoute{}
	urls := make(map[string]struct{})
	errors := []string{}

	// Parse the HTML content using goquery
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		errors = append(errors, err.Error())
		return routes, setToListString(urls), errors
	}

	// Initialize an HTTP client for getting javascript content
	httpClient := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Extract routes from form elements
	formRoutes, formUrls, formErrors := extractFormRoutes(doc, target, baseURLsOnly, captureStaticAssets)
	routes = append(routes, formRoutes...)
	urls = addListToSetString(urls, formUrls)
	errors = append(errors, formErrors...)

	// Extract routes from anchor elements
	anchorRoutes, anchorUrls, anchorErrors := extractAnchorRoutes(doc, target, baseURLsOnly, captureStaticAssets)
	routes = append(routes, anchorRoutes...)
	urls = addListToSetString(urls, anchorUrls)
	errors = append(errors, anchorErrors...)

	// Extract routes from link elements
	linkRoutes, linkUrls, linkErrors := extractLinkRoutes(doc, target, baseURLsOnly, captureStaticAssets)
	routes = append(routes, linkRoutes...)
	urls = addListToSetString(urls, linkUrls)
	errors = append(errors, linkErrors...)

	// Extract routes from script elements
	// This fetches script file contents and extracts routes from them
	scriptRoutes, scriptUrls, scriptErrors := extractScriptRoutes(doc, target, baseURLsOnly, captureStaticAssets, httpClient)
	routes = append(routes, scriptRoutes...)
	urls = addListToSetString(urls, scriptUrls)
	errors = append(errors, scriptErrors...)

	// Extract routes from inline script elements
	inlineScriptRoutes, inlineScriptUrls, inlineScriptErrors := extractInlineScriptRoutes(doc, target, baseURLsOnly, captureStaticAssets)
	routes = append(routes, inlineScriptRoutes...)
	urls = addListToSetString(urls, inlineScriptUrls)
	errors = append(errors, inlineScriptErrors...)

	// Extract routes from inspecting network calls
	// Only to be performed if captureMethod is of type Browser or Browserbase
	if captureMethod == webscan.PageCaptureMethodBrowser || captureMethod == webscan.PageCaptureMethodBrowserbase {
		networkRoutes, networkUrls, networkErrors := extractNetworkRoutes(ctx, browserCapturer, target, baseURLsOnly, captureStaticAssets)
		routes = append(routes, networkRoutes...)
		urls = addListToSetString(urls, networkUrls)
		errors = append(errors, networkErrors...)
	}

	// Return results
	mergedRoutes := mergeWebRoutes(routes) // For uniqueness across techniques
	return mergedRoutes, setToListString(urls), errors
}

func PerformRouteCapture(ctx context.Context, target string, captureMethod webscan.PageCaptureMethod, baseURLsOnly bool, captureStaticAssets bool, timeout int, minDOMStabalizeTime int, insecure bool, browserPath *string, browserBaseToken *string, browserBaseProject *string, browserBaseOptions *[]browserbase.Option) webscan.RouteCaptureReport {
	log := svc1log.FromContext(ctx)

	report := webscan.RouteCaptureReport{
		Target: target,
		Errors: []string{},
	}

	// Get the HTML content with specified method
	var htmlContent string
	var routes []*webscan.WebRoute
	var urls []string
	var errors []string
	switch captureMethod {
	case webscan.PageCaptureMethodRequest:
		log.Info("Initiating page capture with request method", svc1log.SafeParam("target", target))
		capturer := capture.NewRequestPageCapturer(insecure, timeout)
		result, err := capturer.Capture(ctx, target, &capture.Options{})
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}
		log.Info("Page capture successful")
		htmlContent = string(result.Content)

		// Extract the routes and urls
		routes, urls, errors = extractRoutes(ctx, target, htmlContent, baseURLsOnly, captureStaticAssets, timeout, webscan.PageCaptureMethodRequest, nil)

		_ = capturer.Close(ctx)

	case webscan.PageCaptureMethodBrowser:
		log.Info("Initiating page capture with browser method", svc1log.SafeParam("target", target))
		capturer := capture.NewBrowserPageCapturer(browserPath, timeout, minDOMStabalizeTime)
		result, err := capturer.Capture(ctx, target, &capture.Options{})
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}

		log.Info("Page capture successful")
		htmlContent = string(result.Content)

		// Extract the routes and urls
		routes, urls, errors = extractRoutes(ctx, target, htmlContent, baseURLsOnly, captureStaticAssets, timeout, webscan.PageCaptureMethodBrowser, capturer)

		_ = capturer.Close(ctx)

	case webscan.PageCaptureMethodBrowserbase:
		log.Info("Initiating page capture with browserbase method", svc1log.SafeParam("target", target))
		client := browserbase.NewBrowserbaseClient(*browserBaseToken, *browserBaseProject, browserbase.NewBrowserbaseOptions(ctx, *browserBaseOptions...))
		capturer := capture.NewBrowserbasePageCapturer(ctx, timeout, minDOMStabalizeTime, client)
		result, err := capturer.Capture(ctx, target, &capture.Options{})
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}
		log.Info("Page capture successful")
		htmlContent = string(result.Content)

		// Extract the routes and urls
		routes, urls, errors = extractRoutes(ctx, target, htmlContent, baseURLsOnly, captureStaticAssets, timeout, webscan.PageCaptureMethodBrowserbase, capturer.Capturer)

		_ = capturer.Close(ctx)

	default:
		report.Errors = append(report.Errors, "Unsupported capture method")
		return report
	}

	// Extract the routes and urls
	report.Routes = routes
	report.Urls = urls
	report.Errors = errors

	return report
}
