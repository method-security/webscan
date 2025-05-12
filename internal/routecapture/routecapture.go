package routecapture

import (
	"context"
	"net/http"
	"strings"
	"time"

	common "github.com/Method-Security/webscan/generated/go/common"
	routecapturefern "github.com/Method-Security/webscan/generated/go/routecapture"
	"github.com/Method-Security/webscan/utils"
	"github.com/Method-Security/webscan/utils/headless"
	"github.com/Method-Security/webscan/utils/headless/browserbase"
	"github.com/PuerkitoBio/goquery"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

var FollowRedirects = true

func extractRoutes(ctx context.Context, target string, htmlContent common.Body, baseURLsOnly bool, captureStaticAssets bool, timeout int, captureMethod common.CaptureMethod, browserCapturer *headless.BrowserPageCapturer) ([]*routecapturefern.WebRoute, []string, []string) {
	log := svc1log.FromContext(ctx)
	routes := []*routecapturefern.WebRoute{}
	urls := make(map[string]struct{})
	errors := []string{}

	log.Info("Parsing HTML content using goquery")
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent.GetText().GetValue()))
	if err != nil {
		log.Error("Failed to parse HTML content", svc1log.SafeParam("error", err))
		errors = append(errors, err.Error())
		return routes, setToListString(urls), errors
	}

	log.Info("Initializing HTTP client")
	httpClient := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	log.Info("Extracting routes from form elements")
	formRoutes, formUrls, formErrors := extractFormRoutes(doc, target, baseURLsOnly, captureStaticAssets)
	routes = append(routes, formRoutes...)
	urls = addListToSetString(urls, formUrls)
	errors = append(errors, formErrors...)

	log.Info("Extracting routes from anchor elements")
	anchorRoutes, anchorUrls, anchorErrors := extractAnchorRoutes(doc, target, baseURLsOnly, captureStaticAssets)
	routes = append(routes, anchorRoutes...)
	urls = addListToSetString(urls, anchorUrls)
	errors = append(errors, anchorErrors...)

	log.Info("Extracting routes from link elements")
	linkRoutes, linkUrls, linkErrors := extractLinkRoutes(doc, target, baseURLsOnly, captureStaticAssets)
	routes = append(routes, linkRoutes...)
	urls = addListToSetString(urls, linkUrls)
	errors = append(errors, linkErrors...)

	log.Info("Extracting routes from script elements")
	scriptRoutes, scriptUrls, scriptErrors := extractScriptRoutes(doc, target, baseURLsOnly, captureStaticAssets, httpClient)
	routes = append(routes, scriptRoutes...)
	urls = addListToSetString(urls, scriptUrls)
	errors = append(errors, scriptErrors...)

	log.Info("Extracting routes from inline script elements")
	inlineScriptRoutes, inlineScriptUrls, inlineScriptErrors := extractInlineScriptRoutes(doc, target, baseURLsOnly, captureStaticAssets)
	routes = append(routes, inlineScriptRoutes...)
	urls = addListToSetString(urls, inlineScriptUrls)
	errors = append(errors, inlineScriptErrors...)

	// Only to be performed if captureMethod is of type Browser or Browserbase
	if captureMethod == common.CaptureMethodBrowser || captureMethod == common.CaptureMethodBrowserbase {
		log.Info("Extracting routes from inspecting network calls")
		networkRoutes, networkUrls, networkErrors := extractNetworkRoutes(ctx, browserCapturer, target, baseURLsOnly, captureStaticAssets)
		routes = append(routes, networkRoutes...)
		urls = addListToSetString(urls, networkUrls)
		errors = append(errors, networkErrors...)
	}

	log.Info("Returning results")
	mergedRoutes := mergeWebRoutes(routes) // For uniqueness across techniques
	return mergedRoutes, setToListString(urls), errors
}

func PerformRouteCapture(ctx context.Context, target string, captureMethod common.CaptureMethod, baseURLsOnly bool, captureStaticAssets bool, timeout int, minDOMStabalizeTime int, insecure bool, browserPath *string, browserBaseToken *string, browserBaseProject *string, browserBaseOptions *[]browserbase.Option) routecapturefern.RouteCaptureReport {
	log := svc1log.FromContext(ctx)

	report := routecapturefern.RouteCaptureReport{
		Target: target,
		Errors: []string{},
	}

	var routes []*routecapturefern.WebRoute
	var urls []string
	var errors []string
	switch captureMethod {
	case common.CaptureMethodRequest:
		baseURL, path, err := utils.SplitTarget(target)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}
		log.Info("Initiating page capture with request method", svc1log.SafeParam("target", target))
		requestInfo := utils.PerformRequestScan(utils.RequestOptions{
			BaseURL:         baseURL,
			Path:            path,
			Method:          common.HttpMethodGet,
			Params:          common.RequestParams{},
			Timeout:         timeout,
			FollowRedirects: FollowRedirects,
			Insecure:        insecure,
		})
		if requestInfo.Errors != nil {
			report.Errors = requestInfo.Errors
			return report
		}
		log.Info("Page capture successful")
		// Extract the routes and urls
		routes, urls, errors = extractRoutes(ctx, target, *requestInfo.ResponseBody, baseURLsOnly, captureStaticAssets, timeout, common.CaptureMethodRequest, nil)

	case common.CaptureMethodBrowser:
		log.Info("Initiating page capture with browser method", svc1log.SafeParam("target", target))
		capturer := headless.NewBrowserPageCapturer(browserPath, timeout, minDOMStabalizeTime)
		result, err := capturer.Capture(ctx, target, &headless.BrowserOptions{FollowRedirects: FollowRedirects})
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}
		log.Info("Page capture successful")

		// Extract the routes and urls
		routes, urls, errors = extractRoutes(ctx, target, *result.ResponseBody, baseURLsOnly, captureStaticAssets, timeout, common.CaptureMethodBrowser, capturer)

		_ = capturer.Close(ctx)

	case common.CaptureMethodBrowserbase:
		log.Info("Initiating page capture with browserbase method", svc1log.SafeParam("target", target))
		client := browserbase.NewBrowserbaseClient(*browserBaseToken, *browserBaseProject, browserbase.NewBrowserbaseOptions(ctx, *browserBaseOptions...))
		capturer := browserbase.NewBrowserbasePageCapturer(ctx, timeout, minDOMStabalizeTime, *client)
		result, err := capturer.Capture(ctx, target, &headless.BrowserOptions{FollowRedirects: FollowRedirects})
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}
		log.Info("Page capture successful")

		// Extract the routes and urls
		routes, urls, errors = extractRoutes(ctx, target, *result.ResponseBody, baseURLsOnly, captureStaticAssets, timeout, common.CaptureMethodBrowserbase, capturer.Capturer)

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
