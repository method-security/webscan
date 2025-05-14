package routecapture

import (
	"context"
	"net/http"
	"strings"
	"time"

	routefern "github.com/Method-Security/webscan/generated/go/capture/route"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	"github.com/PuerkitoBio/goquery"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func createRouteCaptureRequestConfig(baseURL, path string, config routefern.CaptureRouteConfig, browserbaseSecrets *common.BrowserbaseSecrets) common.RequestConfig {
	maxRedirects := config.MaxRedirects
	return common.RequestConfig{
		BaseUrl:            baseURL,
		Path:               path,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		Timeout:            config.Timeout,
		FollowRedirects:    true,
		MaxRedirects:       &maxRedirects,
		Insecure:           config.Insecure,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     config.HeadlessConfig,
		BrowserbaseConfig:  config.BrowserbaseConfig,
		BrowserbaseSecrets: browserbaseSecrets,
	}
}

func extractRoutes(ctx context.Context, target string, htmlContent string, baseURLsOnly bool, captureStaticAssets bool, timeout int, requestMethod common.RequestMethod) ([]*routefern.WebRoute, []string, []string) {
	log := svc1log.FromContext(ctx)
	routes := []*routefern.WebRoute{}
	urls := make(map[string]struct{})
	errors := []string{}

	log.Info("Parsing HTML content using goquery")
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
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

	// Only to be performed if requestMethod is of type Browser or Browserbase
	if requestMethod == common.RequestMethodStandard || requestMethod == common.RequestMethodBrowserbase {
		log.Info("Extracting routes from inspecting network calls")
		networkRoutes, networkUrls, networkErrors := extractNetworkRoutes(ctx, nil, target, baseURLsOnly, captureStaticAssets)
		routes = append(routes, networkRoutes...)
		urls = addListToSetString(urls, networkUrls)
		errors = append(errors, networkErrors...)
	}

	log.Info("Returning results")
	mergedRoutes := mergeWebRoutes(routes) // For uniqueness across techniques
	return mergedRoutes, setToListString(urls), errors
}

func PerformRouteCapture(ctx context.Context, config routefern.CaptureRouteConfig, browserbaseSecrets *common.BrowserbaseSecrets) routefern.CaptureRouteReport {
	report := routefern.CaptureRouteReport{
		Target: config.Target,
		Errors: []string{},
	}

	baseURL, path, err := utils.SplitTarget(config.Target)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}
	requestConfig := createRouteCaptureRequestConfig(baseURL, path, config, browserbaseSecrets)
	request, err := request.SendRequest(ctx, requestConfig)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Extract the routes and urls
	routes, urls, errors := extractRoutes(ctx, config.Target, *request.ResponseBody, config.BaseUrLsOnly, true, config.Timeout, config.RequestMethod)

	// Extract the routes and urls
	report.Routes = routes
	report.Urls = urls
	report.Errors = errors

	return report
}
