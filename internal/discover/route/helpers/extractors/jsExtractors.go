package discoverroute

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"
	discoverroutehelpers "github.com/Method-Security/webscan/internal/discover/route/helpers"

	// External
	goquery "github.com/PuerkitoBio/goquery"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	ast "github.com/robertkrimen/otto/ast"
	parser "github.com/robertkrimen/otto/parser"
)

// sourceMap represents the structure of a JavaScript source map.
type sourceMap struct {
	Sources        []string  `json:"sources"`
	SourcesContent []*string `json:"sourcesContent"`
}

// allCapsVarPattern matches ALL_CAPS variable names (at least two chars).
var allCapsVarPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)

// numericSegmentPattern matches purely numeric path segments.
var numericSegmentPattern = regexp.MustCompile(`^\d+$`)

// uuidSegmentPattern matches UUID-like segments (8-4-4-4-12 hex).
var uuidSegmentPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// longHexSegmentPattern matches long hex strings (16+ hex chars) that are not UUIDs.
var longHexSegmentPattern = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)

// normalizePathTemplate replaces dynamic path segments with placeholder tokens.
// - Numeric segments become <id>
// - UUID segments become <uuid>
// - Long hex strings (16+ chars) become <hash>
func normalizePathTemplate(path string) string {
	if path == "" || path == "/" {
		return path
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if uuidSegmentPattern.MatchString(seg) {
			segments[i] = "<uuid>"
		} else if longHexSegmentPattern.MatchString(seg) {
			segments[i] = "<hash>"
		} else if numericSegmentPattern.MatchString(seg) {
			segments[i] = "<id>"
		}
	}
	return strings.Join(segments, "/")
}

// hasTemplateSegments returns true if any segment in the path is dynamic (numeric/uuid/hex).
func hasTemplateSegments(path string) bool {
	if path == "" {
		return false
	}
	for _, seg := range strings.Split(path, "/") {
		if uuidSegmentPattern.MatchString(seg) || longHexSegmentPattern.MatchString(seg) || numericSegmentPattern.MatchString(seg) {
			return true
		}
	}
	return false
}

// Common API call patterns in JavaScript
var apiPatterns = []struct {
	pattern *regexp.Regexp
	method  string
}{
	// fetch() calls
	{regexp.MustCompile(`fetch\(['"]([^'"]+)['"]\)`), "GET"},
	{regexp.MustCompile(`fetch\(['"]([^'"]+)['"],\s*{\s*method:\s*['"]([^'"]+)['"]`), ""}, // Method will be in second capture group

	// axios calls
	{regexp.MustCompile(`axios\.(get|post|put|delete|patch)\(['"]([^'"]+)['"]`), ""},             // Method will be in first capture group
	{regexp.MustCompile(`axios\({\s*method:\s*['"]([^'"]+)['"],\s*url:\s*['"]([^'"]+)['"]`), ""}, // Method and URL in capture groups

	// jQuery ajax calls
	{regexp.MustCompile(`\$\.(get|post|put|delete)\(['"]([^'"]+)['"]`), ""},                                  // Method and URL in capture groups
	{regexp.MustCompile(`\$\.ajax\({\s*(?:method|type):\s*['"]([^'"]+)['"],\s*url:\s*['"]([^'"]+)['"]`), ""}, // Method and URL in capture groups

	// XMLHttpRequest calls (more specific to avoid matching window.open)
	{regexp.MustCompile(`xhr\.open\(['"]([^'"]+)['"],\s*['"]([^'"]+)['"]`), ""},     // Method and URL in capture groups
	{regexp.MustCompile(`request\.open\(['"]([^'"]+)['"],\s*['"]([^'"]+)['"]`), ""}, // Method and URL in capture groups
	{regexp.MustCompile(`xmlhttp\.open\(['"]([^'"]+)['"],\s*['"]([^'"]+)['"]`), ""}, // Method and URL in capture groups

	// Generic URL patterns that might be API endpoints
	{regexp.MustCompile(`['"](/api/[^'"]+)['"]`), "GET"},
	{regexp.MustCompile(`['"](/v\d+/[^'"]+)['"]`), "GET"},
	{regexp.MustCompile(`['"](/graphql[^'"]*)['"]`), "POST"},
	{regexp.MustCompile(`['"](/rest/[^'"]+)['"]`), "GET"},
}

// extractRoutesFromPatterns uses regex patterns to find potential API routes in JavaScript content
func extractRoutesFromPatterns(content string, baseURL string, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	for _, pattern := range apiPatterns {
		matches := pattern.pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			var urlStr string
			var method string

			// Handle different pattern formats
			if len(match) == 2 {
				// Pattern with single capture group (URL)
				urlStr = match[1]
				method = pattern.method
			} else if len(match) == 3 {
				patternStr := pattern.pattern.String()

				// Only the fetch pattern with method options has URL first, method second
				// All other patterns have method first, URL second
				if strings.Contains(patternStr, "fetch") && strings.Contains(patternStr, "method") && strings.Contains(patternStr, `{\s*method`) {
					// fetch('url', { method: 'method' }) - URL first, method second
					urlStr = match[1]
					method = strings.ToUpper(match[2])
				} else {
					// All other patterns: method first, URL second
					// xhr.open('method', 'url'), axios.*, jquery.*, etc.
					method = strings.ToUpper(match[1])
					urlStr = match[2]
				}
			}

			// Skip if no URL found
			if urlStr == "" {
				continue
			}

			// Resolve relative URLs
			fullURL := discoverroutehelpers.ResolveURL(baseURL, urlStr)

			// Check if the URL is allowed
			if !discoverroutehelpers.IsURLAllowed(baseURL, fullURL, routeCaptureConfig.IgnoreCrossDomain, routeCaptureConfig.CollectStaticAssets) {
				continue
			}

			// The route URL should not have query params, those are stored in QueryParams
			urlNoQuery, err := discoverroutehelpers.URLRemoveQueryParams(fullURL)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			routeBaseURL, routePath, err := discoverroutehelpers.SplitURLBaseAndPath(urlNoQuery)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			// If no method was found in the pattern, default to GET
			if method == "" {
				method = "GET"
			}

			route := &discover.RouteDetails{
				BaseUrl: routeBaseURL,
				Path:    routePath,
				Method:  common.HttpMethod(method).Ptr(),
			}

			// Apply path templating if the path has dynamic segments
			if hasTemplateSegments(routePath) {
				tmpl := normalizePathTemplate(routePath)
				route.PathTemplate = &tmpl
			}

			routes = append(routes, route)
			urls[fullURL] = struct{}{}
		}
	}

	return routes, discoverroutehelpers.SetToListString(urls), errors
}

// shouldSkipScriptContent determines if a script should be skipped based on its content
func shouldSkipScriptContent(content string) (bool, string) {
	// Skip empty content
	if len(strings.TrimSpace(content)) == 0 {
		return true, "Empty script content"
	}

	// Skip JSON-LD content
	if strings.Contains(content, `"@context"`) && strings.Contains(content, `"@type"`) {
		// Get a preview of the JSON-LD content
		preview := content
		if len(content) > 200 {
			preview = content[:200] + "..."
		}
		return true, fmt.Sprintf("JSON-LD structured data\nContent preview: %s", preview)
	}

	// Skip minified/compressed JavaScript patterns
	minifiedPatterns := []struct {
		pattern string
		name    string
	}{
		{"window._stq=window._stq||[]", "WordPress"},
		{"window.NREUM||(NREUM={})", "New Relic"},
		{"window.ga=window.ga||function", "Google Analytics"},
		{"window.fbq=window.fbq||function", "Facebook Pixel"},
		{"window.dataLayer=window.dataLayer||[]", "Google Tag Manager"},
	}

	for _, p := range minifiedPatterns {
		if strings.Contains(content, p.pattern) {
			// Get a preview of the script content
			preview := content
			if len(content) > 200 {
				preview = content[:200] + "..."
			}
			return true, fmt.Sprintf("Minified %s script\nContent preview: %s", p.name, preview)
		}
	}

	// Skip if content is too short to be meaningful
	if len(content) < 10 {
		return true, "Script content too short"
	}

	return false, ""
}

// extractScriptContentRoutes takes JavaScript code as a string, parses it using the Otto parser library to find all routes (including POST and GET methods with bodyParams and queryParams), and returns them.
func extractScriptContentRoutes(ctx context.Context, scriptContent string, baseURL string, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	// Check if we should skip this script
	if skip, reason := shouldSkipScriptContent(scriptContent); skip {
		// Log the skip reason as debug information
		svc1log.FromContext(ctx).Debug("Skipping script",
			svc1log.SafeParam("url", baseURL),
			svc1log.SafeParam("reason", reason))
		return routes, discoverroutehelpers.SetToListString(urls), errors
	}

	// First try to parse the JavaScript code into an AST
	program, err := parser.ParseFile(nil, "", scriptContent, parser.IgnoreRegExpErrors)
	if err != nil {
		// If parsing fails, try regex pattern matching
		patternRoutes, patternUrls, patternErrors := extractRoutesFromPatterns(scriptContent, baseURL, routeCaptureConfig)
		routes = append(routes, patternRoutes...)
		for _, u := range patternUrls {
			urls[u] = struct{}{}
		}
		errors = append(errors, patternErrors...)

		// Log the parsing error as debug information
		errorMsg := err.Error()
		lineInfo := ""
		if strings.Contains(errorMsg, "Line") {
			parts := strings.Split(errorMsg, "Line")
			if len(parts) > 1 {
				lineInfo = "Line" + parts[1]
			}
		}

		svc1log.FromContext(ctx).Debug("JavaScript parsing failed, falling back to pattern matching",
			svc1log.SafeParam("url", baseURL),
			svc1log.SafeParam("error", errorMsg),
			svc1log.SafeParam("line", lineInfo))

		return routes, discoverroutehelpers.SetToListString(urls), errors
	}

	// If parsing succeeds, use AST traversal
	v := &visitor{
		routes:              &routes,
		urls:                urls,
		baseURL:             baseURL,
		baseURLsOnly:        routeCaptureConfig.IgnoreCrossDomain,
		captureStaticAssets: routeCaptureConfig.CollectStaticAssets,
		errors:              &errors,
		symbolTable:         make(map[string]string),
	}
	ast.Walk(v, program)

	return discoverroutehelpers.MergeWebRoutes(routes), discoverroutehelpers.SetToListString(urls), errors
}

// visitor struct for AST traversal
type visitor struct {
	routes              *[]*discover.RouteDetails
	urls                map[string]struct{}
	baseURL             string
	baseURLsOnly        bool
	captureStaticAssets bool
	errors              *[]string
	symbolTable         map[string]string
}

// Enter method for the visitor to process each node
func (v *visitor) Enter(n ast.Node) ast.Visitor {
	switch node := n.(type) {
	case *ast.CallExpression:
		v.handleCallExpression(node)
	case *ast.VariableStatement:
		v.handleVariableStatement(node)
	}
	return v
}

// Exit method (required by the ast.Visitor interface)
func (v *visitor) Exit(n ast.Node) {}

// handleVariableStatement processes variable statements to build a symbol table.
// It also emits routes for ALL_CAPS variables that look like API paths (Feature 2 + 3).
func (v *visitor) handleVariableStatement(node *ast.VariableStatement) {
	for _, expr := range node.List {
		varExpr, ok := expr.(*ast.VariableExpression)
		if !ok || varExpr.Initializer == nil {
			continue
		}
		varName := varExpr.Name

		strVal := v.resolveExpressionToString(varExpr.Initializer)
		if strVal == "" {
			continue
		}

		// Store in symbol table
		v.symbolTable[varName] = strVal

		// Feature 3: ALL_CAPS variable with API path value
		if allCapsVarPattern.MatchString(varName) && strings.HasPrefix(strVal, "/") {
			// Resolve and emit a route
			fullURL := discoverroutehelpers.ResolveURL(v.baseURL, strVal)
			if discoverroutehelpers.IsURLAllowed(v.baseURL, fullURL, v.baseURLsOnly, v.captureStaticAssets) {
				urlNoQuery, err := discoverroutehelpers.URLRemoveQueryParams(fullURL)
				if err == nil {
					routeBaseURL, routePath, err := discoverroutehelpers.SplitURLBaseAndPath(urlNoQuery)
					if err == nil {
						evidence := "CONST:" + varName
						tmpl := normalizePathTemplate(routePath)
						route := &discover.RouteDetails{
							BaseUrl:      routeBaseURL,
							Path:         routePath,
							Method:       common.HttpMethodGet.Ptr(),
							Evidence:     &evidence,
							PathTemplate: &tmpl,
						}
						*v.routes = append(*v.routes, route)
						v.urls[fullURL] = struct{}{}
					}
				}
			}
		}
	}
}

// resolveExpressionToString attempts to evaluate an AST expression to a string value.
// Handles string literals, identifiers (via symbolTable), and binary "+" concatenations.
func (v *visitor) resolveExpressionToString(expr ast.Expression) string {
	switch e := expr.(type) {
	case *ast.StringLiteral:
		return e.Value
	case *ast.Identifier:
		if val, ok := v.symbolTable[e.Name]; ok {
			return val
		}
	case *ast.BinaryExpression:
		if e.Operator.String() == "+" {
			left := v.resolveExpressionToString(e.Left)
			right := v.resolveExpressionToString(e.Right)
			if left != "" && right != "" {
				return left + right
			}
		}
	}
	return ""
}

// handleCallExpression processes function calls like fetch(), $.ajax(), XMLHttpRequest, etc.
func (v *visitor) handleCallExpression(node *ast.CallExpression) {
	switch callee := node.Callee.(type) {
	case *ast.Identifier:
		// Handle fetch()
		if callee.Name == "fetch" {
			v.processFetchCall(node)
		}
	}
	// In the future need to be able to handle other types of calls
}

// processFetchCall handles fetch() calls
func (v *visitor) processFetchCall(node *ast.CallExpression) {
	if len(node.ArgumentList) == 0 {
		return
	}

	// First argument is the URL — resolve via symbol table if needed
	urlStr := v.resolveExpressionToString(node.ArgumentList[0])
	if urlStr == "" {
		return
	}

	fullURL := discoverroutehelpers.ResolveURL(v.baseURL, urlStr)

	// Check if the URL is allowed
	// Only consider URLs that are part of the base URL if specified
	if !discoverroutehelpers.IsURLAllowed(v.baseURL, fullURL, v.baseURLsOnly, v.captureStaticAssets) {
		return
	}

	method := "GET" // Default method
	var bodyParams []*discover.RouteBodyParam
	var queryParams []*discover.RouteQueryParam

	// Second argument may be options object
	if len(node.ArgumentList) > 1 {
		if objLit, ok := node.ArgumentList[1].(*ast.ObjectLiteral); ok {
			for _, prop := range objLit.Value {
				switch prop.Key {
				case "method":
					if value, ok := prop.Value.(*ast.StringLiteral); ok {
						method = strings.ToUpper(value.Value)
					}
				case "body":
					// Placeholder for body parameters
					bodyParams = append(bodyParams, &discover.RouteBodyParam{Name: "body"})
				}
			}
		}
	}

	v.addRoute(fullURL, method, bodyParams, queryParams)
}

// addRoute adds a route to the list
func (v *visitor) addRoute(urlStr, method string, bodyParams []*discover.RouteBodyParam, queryParams []*discover.RouteQueryParam) {
	// The route URL should not have query params, those are stored in QueryParams
	urlNoQuery, err := discoverroutehelpers.URLRemoveQueryParams(urlStr)
	if err != nil {
		*v.errors = append(*v.errors, err.Error())
		return
	}

	routeBaseURL, routePath, err := discoverroutehelpers.SplitURLBaseAndPath(urlNoQuery)
	if err != nil {
		*v.errors = append(*v.errors, err.Error())
		return
	}

	route := &discover.RouteDetails{
		BaseUrl:     routeBaseURL,
		Path:        routePath,
		Method:      common.HttpMethod(method).Ptr(),
		BodyParams:  bodyParams,
		QueryParams: queryParams,
	}

	// Apply path templating if the path has dynamic segments
	if hasTemplateSegments(routePath) {
		tmpl := normalizePathTemplate(routePath)
		route.PathTemplate = &tmpl
	}

	*v.routes = append(*v.routes, route)
	v.urls[urlStr] = struct{}{}
}

// fetchSourceMapRoutes fetches a source map from the given URL, parses it, and extracts routes
// from each sourcesContent entry. Routes are tagged with evidence = "sourcemap:<source_name>".
func fetchSourceMapRoutes(ctx context.Context, sourceMapURL string, baseURL string, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	routes := []*discover.RouteDetails{}
	urls := []string{}
	errors := []string{}

	resp, err := http.Get(sourceMapURL) //nolint:noctx
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to fetch source map %s: %s", sourceMapURL, err))
		return routes, urls, errors
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			errors = append(errors, cerr.Error())
		}
	}()

	if resp.StatusCode != http.StatusOK {
		errors = append(errors, fmt.Sprintf("Failed to fetch source map %s: %s", sourceMapURL, resp.Status))
		return routes, urls, errors
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to read source map body %s: %s", sourceMapURL, err))
		return routes, urls, errors
	}

	var sm sourceMap
	if err := json.Unmarshal(bodyBytes, &sm); err != nil {
		errors = append(errors, fmt.Sprintf("Failed to parse source map %s: %s", sourceMapURL, err))
		return routes, urls, errors
	}

	for i, contentPtr := range sm.SourcesContent {
		if contentPtr == nil || *contentPtr == "" {
			continue
		}
		content := *contentPtr

		// Determine evidence tag from the parallel sources[] entry
		sourceName := ""
		if i < len(sm.Sources) {
			sourceName = sm.Sources[i]
		}

		contentRoutes, contentUrls, contentErrors := extractScriptContentRoutes(ctx, content, baseURL, routeCaptureConfig)
		// Tag each extracted route with source map evidence
		for _, route := range contentRoutes {
			if sourceName != "" {
				evidence := "sourcemap:" + sourceName
				route.Evidence = &evidence
			}
			// Apply path templating
			if route.PathTemplate == nil && hasTemplateSegments(route.Path) {
				tmpl := normalizePathTemplate(route.Path)
				route.PathTemplate = &tmpl
			}
		}
		routes = append(routes, contentRoutes...)
		urls = append(urls, contentUrls...)
		errors = append(errors, contentErrors...)
	}

	return routes, urls, errors
}

// shouldFetchSourceMaps returns true when source map fetching is enabled (default: true).
func shouldFetchSourceMaps(routeCaptureConfig discover.DiscoverRouteConfig) bool {
	if routeCaptureConfig.FetchSourceMaps == nil {
		return true
	}
	return *routeCaptureConfig.FetchSourceMaps
}

// ExtractScriptRoutes finds script elements with a src attribute, fetches the JavaScript data, parses it, and extracts routes.
// Returns a slice of RouteDetails, a slice of URLs, and a slice of errors.
func ExtractScriptRoutes(ctx context.Context, doc *goquery.Document, baseURL string, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	bundleCount := 0

	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		// Honor MaxBundles limit
		if routeCaptureConfig.MaxBundles != nil && *routeCaptureConfig.MaxBundles > 0 && bundleCount >= *routeCaptureConfig.MaxBundles {
			return
		}

		src, exists := s.Attr("src")
		if exists && src != "" {
			// Only process JavaScript files
			if !strings.HasSuffix(src, ".js") {
				return
			}

			// If onlybaseURLs is set, only request script src that are relative
			if routeCaptureConfig.IgnoreCrossDomain && discoverroutehelpers.IsAbsoluteURL(src) {
				return
			}

			fullURL := discoverroutehelpers.ResolveURL(baseURL, src)

			// Check if the URL is allowed
			if !discoverroutehelpers.IsURLAllowed(baseURL, fullURL, routeCaptureConfig.IgnoreCrossDomain, routeCaptureConfig.CollectStaticAssets) {
				return
			}

			// Fetch the JavaScript content
			resp, err := http.Get(fullURL) //nolint:noctx
			if err != nil {
				errors = append(errors, err.Error())
				return
			}
			defer func() {
				if cerr := resp.Body.Close(); cerr != nil {
					err = cerr
				}
			}()
			if err != nil {
				errors = append(errors, err.Error())
				return
			}

			if resp.StatusCode != http.StatusOK {
				errors = append(errors, fmt.Sprintf("Failed to get %s: %s", fullURL, resp.Status))
				return
			}

			bundleCount++
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				errors = append(errors, err.Error())
				return
			}
			scriptContent := string(bodyBytes)

			// Extract routes from the JavaScript content
			contentRoutes, contentUrls, contentErrors := extractScriptContentRoutes(ctx, scriptContent, baseURL, routeCaptureConfig)
			routes = append(routes, contentRoutes...)
			for _, u := range contentUrls {
				urls[u] = struct{}{}
			}
			errors = append(errors, contentErrors...)

			// Feature 1: Source map ingestion
			if shouldFetchSourceMaps(routeCaptureConfig) {
				// Check response headers for a source map URL
				sourceMapURL := resp.Header.Get("SourceMap")
				if sourceMapURL == "" {
					sourceMapURL = resp.Header.Get("X-SourceMap")
				}
				// Fallback: try <bundle_url>.map
				if sourceMapURL == "" {
					mapBase := strings.SplitN(fullURL, "?", 2)[0]
					mapBase = strings.SplitN(mapBase, "#", 2)[0]
					sourceMapURL = mapBase + ".map"
				} else {
					// Resolve relative source map URLs against the bundle URL
					sourceMapURL = discoverroutehelpers.ResolveURL(fullURL, sourceMapURL)
				}

				smRoutes, smURLs, smErrors := fetchSourceMapRoutes(ctx, sourceMapURL, baseURL, routeCaptureConfig)
				routes = append(routes, smRoutes...)
				for _, u := range smURLs {
					urls[u] = struct{}{}
				}
				errors = append(errors, smErrors...)
			}
		}
	})

	return discoverroutehelpers.MergeWebRoutes(routes), discoverroutehelpers.SetToListString(urls), errors
}

// ExtractBundleURLRoutes processes a list of explicit JS bundle URLs and extracts routes from each.
// Returns a slice of RouteDetails, a slice of URLs, and a slice of errors.
func ExtractBundleURLRoutes(ctx context.Context, bundleURLs []string, baseURL string, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	for i, bundleURL := range bundleURLs {
		// Honor MaxBundles limit
		if routeCaptureConfig.MaxBundles != nil && *routeCaptureConfig.MaxBundles > 0 && i >= *routeCaptureConfig.MaxBundles {
			break
		}

		// Resolve relative bundle URLs
		fullURL := discoverroutehelpers.ResolveURL(baseURL, bundleURL)

		// Fetch the JS bundle
		resp, err := http.Get(fullURL) //nolint:noctx
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to fetch bundle %s: %s", fullURL, err))
			continue
		}

		if resp.StatusCode != http.StatusOK {
			if cerr := resp.Body.Close(); cerr != nil {
				errors = append(errors, cerr.Error())
			}
			errors = append(errors, fmt.Sprintf("Failed to fetch bundle %s: %s", fullURL, resp.Status))
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to read bundle %s: %s", fullURL, err))
			continue
		}
		scriptContent := string(bodyBytes)

		contentRoutes, contentUrls, contentErrors := extractScriptContentRoutes(ctx, scriptContent, baseURL, routeCaptureConfig)
		routes = append(routes, contentRoutes...)
		for _, u := range contentUrls {
			urls[u] = struct{}{}
		}
		errors = append(errors, contentErrors...)

		// Feature 1: Source map ingestion for explicit bundles
		if shouldFetchSourceMaps(routeCaptureConfig) {
			sourceMapURL := resp.Header.Get("SourceMap")
			if sourceMapURL == "" {
				sourceMapURL = resp.Header.Get("X-SourceMap")
			}
			if sourceMapURL == "" {
				mapBase := strings.SplitN(fullURL, "?", 2)[0]
				mapBase = strings.SplitN(mapBase, "#", 2)[0]
				sourceMapURL = mapBase + ".map"
			} else {
				sourceMapURL = discoverroutehelpers.ResolveURL(fullURL, sourceMapURL)
			}

			smRoutes, smURLs, smErrors := fetchSourceMapRoutes(ctx, sourceMapURL, baseURL, routeCaptureConfig)
			routes = append(routes, smRoutes...)
			for _, u := range smURLs {
				urls[u] = struct{}{}
			}
			errors = append(errors, smErrors...)
		}
	}

	return discoverroutehelpers.MergeWebRoutes(routes), discoverroutehelpers.SetToListString(urls), errors
}

// ExtractInlineScriptRoutes finds inline JavaScript code within script tags, parses it, and extracts routes.
// Returns a slice of RouteDetails, a slice of URLs, and a slice of errors.
func ExtractInlineScriptRoutes(ctx context.Context, doc *goquery.Document, url string, routeCaptureConfig discover.DiscoverRouteConfig) ([]*discover.RouteDetails, []string, []string) {
	routes := []*discover.RouteDetails{}
	urls := make(map[string]struct{})
	errors := []string{}

	doc.Find("script:not([src])").Each(func(i int, s *goquery.Selection) {
		scriptContent := s.Text()
		contentRoutes, contentUrls, contentErrors := extractScriptContentRoutes(ctx, scriptContent, url, routeCaptureConfig)
		routes = append(routes, contentRoutes...)
		for _, u := range contentUrls {
			urls[u] = struct{}{}
		}
		errors = append(errors, contentErrors...)
	})

	return discoverroutehelpers.MergeWebRoutes(routes), discoverroutehelpers.SetToListString(urls), errors
}
