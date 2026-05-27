package discoverroute

import (
	// Standard
	"net/url"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Internal
	discoverroutehelpers "github.com/Method-Security/webscan/internal/discover/route/helpers"
	"github.com/Method-Security/webscan/utils"

	// External
	goquery "github.com/PuerkitoBio/goquery"
)

// ExtractFormRoutes extracts WebRoutes from form elements in the HTML document
// It returns a slice of WebRoutes, a slice of URLs and a slice of errors
// ExtractFormRoutes extracts WebRoutes from form elements in the HTML document
// It returns a slice of WebRoutes, a slice of URLs and a slice of errors
// WebRoutes are merged to only return unique routes
func ExtractFormRoutes(doc *goquery.Document, baseURL string, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	doc.Find("form").Each(func(i int, s *goquery.Selection) {

		routeVar := discover.RouteDetails{}

		// Extract action attribute
		action, exists := s.Attr("action")
		if !exists || action == "" {
			action = "" // Default action is current page
		}

		// Resolve the action URL relative to the base URL
		fullURL := discoverroutehelpers.ResolveURL(baseURL, action)

		// Check if the URL is allowed
		if !discoverroutehelpers.IsURLAllowed(baseURL, fullURL, routeCaptureConfig.IgnoreCrossDomain, routeCaptureConfig.CollectStaticAssets) {
			return
		}

		// The route URL should not have query params, those are stored in QueryParams
		urlNoQuery, err := discoverroutehelpers.URLRemoveQueryParams(fullURL)
		if err != nil {
			errors = append(errors, err.Error())
			return
		}
		routeBaseURL, routePath, err := discoverroutehelpers.SplitURLBaseAndPath(urlNoQuery)
		if err != nil {
			errors = append(errors, err.Error())
			return
		}
		routeVar.BaseUrl = routeBaseURL
		routeVar.Path = routePath
		urls[urlNoQuery] = struct{}{}

		// Extract method attribute
		method, exists := s.Attr("method")
		if !exists || method == "" {
			method = "GET"
		} else {
			method = strings.ToUpper(method)
		}
		routeVar.Method = common.HttpMethod(method).Ptr()

		// Collect input names
		var queryParams []*discover.RouteQueryParam
		var bodyParams []*discover.RouteBodyParam
		s.Find("input[name], select[name], textarea[name]").Each(func(_ int, input *goquery.Selection) {
			name, _ := input.Attr("name")
			if name != "" {
				if method == "POST" || method == "PUT" || method == "PATCH" {
					// For POST, PUT, PATCH methods, add to BodyParams
					param := &discover.RouteBodyParam{Name: name}
					bodyParams = append(bodyParams, param)
				} else {
					// For GET and other methods, add to QueryParams
					param := &discover.RouteQueryParam{Name: name}
					queryParams = append(queryParams, param)
				}
			}
		})

		if len(queryParams) > 0 {
			routeVar.QueryParams = queryParams
		}
		if len(bodyParams) > 0 {
			routeVar.BodyParams = bodyParams
		}

		routes = append(routes, &routeVar)
	})

	return discoverroutehelpers.MergeWebRoutes(routes), discoverroutehelpers.SetToListString(urls), errors
}

// ExtractAnchorRoutes extracts WebRoutes from anchor (<a>) elements in the HTML document.
// Returns a slice of RouteDetails, a slice of URLs, and a slice of errors.
func ExtractAnchorRoutes(doc *goquery.Document, baseURL string, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && href != "" {
			fullURL := discoverroutehelpers.ResolveURL(baseURL, href)

			// Parse the full URL to extract query parameters before removing them
			parsedFullURL, err := url.Parse(fullURL)
			if err != nil {
				errors = append(errors, err.Error())
				return
			}

			// Extract query parameters from the original URL
			var queryParams []*discover.RouteQueryParam
			if parsedFullURL.RawQuery != "" {
				queryParams = discoverroutehelpers.ParseQueryParams(parsedFullURL)
			}

			// The route URL should not have query params, those are stored in QueryParams
			urlNoQuery, err := discoverroutehelpers.URLRemoveQueryParams(fullURL)
			if err != nil {
				errors = append(errors, err.Error())
				return
			}

			// Check if the URL is allowed
			if !discoverroutehelpers.IsURLAllowed(baseURL, fullURL, routeCaptureConfig.IgnoreCrossDomain, routeCaptureConfig.CollectStaticAssets) {
				return
			}
			urls[urlNoQuery] = struct{}{}

			// Get the origin and path from the full URL without query params
			routeBaseURL, routePath, err := discoverroutehelpers.SplitURLBaseAndPath(urlNoQuery)
			if err != nil {
				errors = append(errors, err.Error())
				return
			}

			routeVar := &discover.RouteDetails{
				BaseUrl: routeBaseURL,
				Path:    routePath,
				Method:  common.HttpMethodGet.Ptr(), // Anchor links are accessed via GET
			}

			// Add query parameters if any were found
			if len(queryParams) > 0 {
				routeVar.QueryParams = queryParams
			}

			routes = append(routes, routeVar)
		}
	})

	return discoverroutehelpers.MergeWebRoutes(routes), discoverroutehelpers.SetToListString(urls), errors
}

// ExtractLinkRoutes extracts WebRoutes from link (<link>) elements in the HTML document.
// Returns a slice of RouteDetails, a slice of URLs, and a slice of errors.
func ExtractLinkRoutes(doc *goquery.Document, baseURL string, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	doc.Find("link[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && href != "" {
			fullURL := discoverroutehelpers.ResolveURL(baseURL, href)

			// Skip if this is a static asset
			if utils.IsStaticAsset(fullURL) {
				// Only add to URLs if we're not ignoring static assets
				if routeCaptureConfig.CollectStaticAssets {
					urls[fullURL] = struct{}{}
				}
				return
			}

			// The route URL should not have query params, those are stored in QueryParams
			urlNoQuery, err := discoverroutehelpers.URLRemoveQueryParams(fullURL)
			if err != nil {
				errors = append(errors, err.Error())
				return
			}

			// Check if the URL is allowed
			if !discoverroutehelpers.IsURLAllowed(baseURL, fullURL, routeCaptureConfig.IgnoreCrossDomain, routeCaptureConfig.CollectStaticAssets) {
				return
			}

			urls[urlNoQuery] = struct{}{}

			// Get the origin and path from the full URL
			routeBaseURL, routePath, err := discoverroutehelpers.SplitURLBaseAndPath(urlNoQuery)
			if err != nil {
				errors = append(errors, err.Error())
				return
			}

			routeVar := &discover.RouteDetails{
				BaseUrl: routeBaseURL,
				Path:    routePath,
				Method:  common.HttpMethodGet.Ptr(), // Link elements are accessed via GET
			}

			routes = append(routes, routeVar)
		}
	})

	return discoverroutehelpers.MergeWebRoutes(routes), discoverroutehelpers.SetToListString(urls), errors
}
