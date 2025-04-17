package routecapture

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	common "github.com/Method-Security/webscan/generated/go/common"
	routecapturefern "github.com/Method-Security/webscan/generated/go/routecapture"
	"github.com/PuerkitoBio/goquery"
	"github.com/robertkrimen/otto/ast"
	"github.com/robertkrimen/otto/parser"
)

// extractScriptContentRoutes takes JavaScript code as a string, parses it using the Otto parser library to find all routes (including POST and GET methods with bodyParams and queryParams), and returns them.
func extractScriptContentRoutes(scriptContent string, baseURL string, baseURLsOnly bool, captureStaticAssets bool) ([]*routecapturefern.WebRoute, []string, []string) {
	routes := []*routecapturefern.WebRoute{}
	urls := make(map[string]struct{})
	errors := []string{}

	// Parse the JavaScript code into an AST
	// TODO - this parsing method seems to not work well with js files on the internet - minified, obfuscated, etc.
	program, err := parser.ParseFile(nil, "", scriptContent, parser.IgnoreRegExpErrors)
	if err != nil {
		errors = append(errors, err.Error())
		return routes, setToListString(urls), errors
	}

	// Traverse the AST to find relevant nodes
	ast.Walk(&visitor{routes: &routes, urls: urls, baseURL: baseURL, baseURLsOnly: baseURLsOnly, captureStaticAssets: captureStaticAssets, errors: &errors}, program)

	return mergeWebRoutes(routes), setToListString(urls), errors
}

// visitor struct for AST traversal
type visitor struct {
	routes              *[]*routecapturefern.WebRoute
	urls                map[string]struct{}
	baseURL             string
	baseURLsOnly        bool
	captureStaticAssets bool
	errors              *[]string
}

// Enter method for the visitor to process each node
func (v *visitor) Enter(n ast.Node) ast.Visitor {
	switch node := n.(type) {
	case *ast.CallExpression:
		v.handleCallExpression(node)
	}
	return v
}

// Exit method (required by the ast.Visitor interface)
func (v *visitor) Exit(n ast.Node) {}

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

	// First argument is the URL
	urlArg, ok := node.ArgumentList[0].(*ast.StringLiteral)
	if !ok {
		return
	}
	urlStr := urlArg.Value

	// Check if the URL is allowed
	// Only consider URLs that are part of the base URL if specified
	if !isURLAllowed(v.baseURL, urlStr, v.baseURLsOnly, v.baseURLsOnly) {
		return
	}

	method := "GET" // Default method
	var bodyParams []*routecapturefern.BodyParams
	var queryParams []*routecapturefern.QueryParams

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
					bodyParams = append(bodyParams, &routecapturefern.BodyParams{Name: "body"})
				}
			}
		}
	}

	v.addRoute(urlStr, method, bodyParams, queryParams)
}

// addRoute adds a route to the list
func (v *visitor) addRoute(urlStr, method string, bodyParams []*routecapturefern.BodyParams, queryParams []*routecapturefern.QueryParams) {
	// The route URL should not have query params, those are stored in QueryParams
	urlNoQuery, err := urlRemoveQueryParams(urlStr)
	if err != nil {
		*v.errors = append(*v.errors, err.Error())
		return
	}

	parsedURL, err := url.Parse(urlNoQuery)
	if err != nil {
		*v.errors = append(*v.errors, err.Error())
		return
	}

	route := &routecapturefern.WebRoute{
		Url:         urlNoQuery,
		Path:        &parsedURL.Path,
		Method:      common.HttpMethod(method).Ptr(),
		BodyParams:  bodyParams,
		QueryParams: queryParams,
	}

	*v.routes = append(*v.routes, route)
	v.urls[urlStr] = struct{}{}
}

// extractScriptRoutes finds script elements with a src attribute, fetches the JavaScript data, converts it to a string, then calls extractScriptContentRoutes and returns the results. If onlybaseURLs is set, only request script src that are relative.
func extractScriptRoutes(doc *goquery.Document, baseURL string, baseURLsOnly bool, captureStaticAssets bool, httpClient *http.Client) ([]*routecapturefern.WebRoute, []string, []string) {
	routes := []*routecapturefern.WebRoute{}
	urls := make(map[string]struct{})
	errors := []string{}

	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists && src != "" {
			// Only process JavaScript files
			if !strings.HasSuffix(src, ".js") {
				return
			}

			// If onlybaseURLs is set, only request script src that are relative
			if baseURLsOnly && isAbsoluteURL(src) {
				return
			}

			fullURL := resolveURL(baseURL, src)

			// Check if the URL is allowed
			if !isURLAllowed(baseURL, fullURL, baseURLsOnly, captureStaticAssets) {
				return
			}

			// Fetch the JavaScript content
			resp, err := httpClient.Get(fullURL)
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

			if resp.StatusCode != 200 {
				errors = append(errors, fmt.Sprintf("Failed to get %s: %s", fullURL, resp.Status))
				return
			}
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				errors = append(errors, err.Error())
				return
			}
			scriptContent := string(bodyBytes)

			// Extract routes from the JavaScript content
			contentRoutes, contentUrls, contentErrors := extractScriptContentRoutes(scriptContent, baseURL, baseURLsOnly, captureStaticAssets)
			routes = append(routes, contentRoutes...)
			for _, u := range contentUrls {
				urls[u] = struct{}{}
			}
			errors = append(errors, contentErrors...)
		}
	})

	return mergeWebRoutes(routes), setToListString(urls), errors
}

// extractInlineScriptRoutes finds inline JavaScript code within script tags, and for each, passes the string contents to extractScriptContentRoutes and returns the results.
func extractInlineScriptRoutes(doc *goquery.Document, baseURL string, baseURLsOnly bool, captureStaticAssets bool) ([]*routecapturefern.WebRoute, []string, []string) {
	routes := []*routecapturefern.WebRoute{}
	urls := make(map[string]struct{})
	errors := []string{}

	doc.Find("script:not([src])").Each(func(i int, s *goquery.Selection) {
		scriptContent := s.Text()
		contentRoutes, contentUrls, contentErrors := extractScriptContentRoutes(scriptContent, baseURL, baseURLsOnly, captureStaticAssets)
		routes = append(routes, contentRoutes...)
		for _, u := range contentUrls {
			urls[u] = struct{}{}
		}
		errors = append(errors, contentErrors...)
	})

	return mergeWebRoutes(routes), setToListString(urls), errors
}
