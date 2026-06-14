package apiapplication

import (
	// Standard
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumerateapiapplicationfern "github.com/Method-Security/webscan/generated/go/enumerate/apiapplication"

	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	libopenapi "github.com/pb33f/libopenapi"
	base "github.com/pb33f/libopenapi/datamodel/high/base"
	v2 "github.com/pb33f/libopenapi/datamodel/high/v2"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
	orderedmap "github.com/pb33f/libopenapi/orderedmap"
	yaml "gopkg.in/yaml.v3"
)

// detectOpenAPISpec tries to parse the response body as both JSON and YAML
// Returns the document type map and true if it's a valid OpenAPI/Swagger spec
func detectOpenAPISpec(responseBody string) (map[string]interface{}, bool) {
	var docType map[string]interface{}

	// Try JSON first
	if err := json.Unmarshal([]byte(responseBody), &docType); err == nil {
		// Check if it's a valid OpenAPI/Swagger spec
		if _, ok := docType["swagger"]; ok || docType["openapi"] != nil {
			return docType, true
		}
	}

	// Try YAML if JSON fails or isn't a valid spec
	docType = make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(responseBody), &docType); err == nil {
		// Check if it's a valid OpenAPI/Swagger spec
		if _, ok := docType["swagger"]; ok || docType["openapi"] != nil {
			return docType, true
		}
	}

	return nil, false
}

// isSwaggerUIPage checks if the HTML content indicates a Swagger UI page
func isSwaggerUIPage(htmlContent string) bool {
	content := strings.ToLower(htmlContent)
	return strings.Contains(content, "swagger-ui") ||
		strings.Contains(content, "swagger ui") ||
		strings.Contains(content, "swaggerui")
}

// Base spec paths without extensions - extensions will be added dynamically
var baseSpecPaths = []string{
	"/swagger",
	"/openapi",
	"/api-docs",
	"/v3/api-docs",
	"/api/swagger",
	"/api/openapi",
	"/api/v3/api-docs",
	"/api/v1/swagger",
	"/api/v1/openapi",
	"/api/v2/swagger",
	"/api/v2/openapi",
	"/swagger/v1",
	"/swagger/v2",
	"/v1/swagger",
	"/v1/openapi",
	"/v2/swagger",
	"/v2/openapi",
	"/docs/swagger",
	"/docs/openapi",
}

// Spec file extensions to try (in order of preference)
var specExtensions = []string{"", ".json", ".yaml", ".yml"}

// generateSpecPaths creates all possible spec paths by combining base paths with extensions
func generateSpecPaths() []string {
	var paths []string

	// Generate paths with each extension for each base path
	for _, extension := range specExtensions {
		for _, basePath := range baseSpecPaths {
			if extension == "" {
				// Extensionless path
				paths = append(paths, basePath)
			} else {
				// Path with extension
				paths = append(paths, basePath+extension)
			}
		}
	}

	return paths
}

func createSendHTTPRequestConfig(baseURL, path string, timeout int, userAgent common.UserAgentPreset, requestMethod common.RequestMethod, headlessConfig *common.HeadlessRequestConfig, headers map[string][]string) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{Headers: headers},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       1,
		VerifyTls:          false,
		Timeout:            timeout,
		UserAgent:          userAgent,
		RequestMethod:      requestMethod,
		HeadlessConfig:     headlessConfig,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

// extractSpecURLFromRenderedContent looks for spec URLs in the rendered HTML content
func extractSpecURLFromRenderedContent(htmlContent, baseURL string) []string {
	var specURLs []string

	// Use regex to find anchor tags with href attributes that point to spec files
	// Pattern matches: <a ...href="/path/to/spec.json"...> or similar
	anchorRegex := regexp.MustCompile(`<a[^>]+href\s*=\s*["']([^"']*\.(?:json|yaml|yml))[^"']*["'][^>]*>`)
	matches := anchorRegex.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			url := match[1]

			// Check if it looks like a spec URL
			if isLikelySpecURL(url) {
				// Convert relative URLs to absolute
				if strings.HasPrefix(url, "/") {
					url = baseURL + url
				} else if !strings.HasPrefix(url, "http") {
					url = baseURL + "/" + url
				}
				specURLs = append(specURLs, url)
			}
		}
	}

	// Also look for URLs in the span content (like <span class="url"> /static/openapi.yaml</span>)
	// Updated regex to capture both extensioned and extensionless spec URLs
	spanRegex := regexp.MustCompile(`<span[^>]*class\s*=\s*["']url["'][^>]*>\s*([^<]*(?:\.(?:json|yaml|yml)|(?:swagger|openapi|api-docs|spec|schema|docs|api)[^<]*?))[^<]*</span>`)
	spanMatches := spanRegex.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range spanMatches {
		if len(match) > 1 {
			url := strings.TrimSpace(match[1])

			// Check if it looks like a spec URL
			if isLikelySpecURL(url) {
				// Convert relative URLs to absolute
				if strings.HasPrefix(url, "/") {
					url = baseURL + url
				} else if !strings.HasPrefix(url, "http") {
					url = baseURL + "/" + url
				}
				specURLs = append(specURLs, url)
			}
		}
	}

	return specURLs
}

// isLikelySpecURL checks if a URL is likely to be a spec URL
func isLikelySpecURL(url string) bool {
	url = strings.ToLower(url)

	// Check for spec file extensions
	hasSpecExtension := strings.HasSuffix(url, ".json") ||
		strings.HasSuffix(url, ".yaml") ||
		strings.HasSuffix(url, ".yml")

	// Check for spec-related keywords
	specKeywords := []string{
		"swagger", "openapi", "api-docs", "spec", "schema",
		"docs", "api", "v1", "v2", "v3",
	}

	hasSpecKeyword := false
	for _, keyword := range specKeywords {
		if strings.Contains(url, keyword) {
			hasSpecKeyword = true
			break
		}
	}

	// URL is likely a spec if it has both extension and keywords, or just keywords (for extensionless endpoints)
	return hasSpecExtension && hasSpecKeyword || hasSpecKeyword
}

// findOpenAPISpec attempts to locate a valid OpenAPI/Swagger specification
// First checks if target is a Swagger UI page, then uses headless if needed,
// otherwise falls back to trying common endpoint paths.
func findOpenAPISpec(ctx context.Context, target string, timeout int, headlessPath string, userAgent common.UserAgentPreset, headers map[string][]string, candidatePaths []string) (string, []byte, map[string]interface{}, error) {
	baseURL, parsedTargetPath, _, err := requesthelpers.SplitTargetURL(target)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to split target URL: %w", err)
	}

	// Caller-supplied candidate paths are probed before the built-in spec paths.
	specPaths := append(append([]string{}, candidatePaths...), generateSpecPaths()...)

	if dl, ok := ctx.Deadline(); ok {
		timeout = int(time.Until(dl).Seconds())
	}

	// STEP 1: Make a standard request to check if target is a Swagger UI page
	requestConfig := createSendHTTPRequestConfig(baseURL, parsedTargetPath, timeout, userAgent, common.RequestMethodStandard, nil, headers)
	response, err := request.SendRequest(ctx, requestConfig)

	if err == nil && response.Response != nil && response.Response.StatusCode != nil &&
		*response.Response.StatusCode == 200 && response.Response.ResponseBody != nil {

		responseBody := requesthelpers.GetResponseBodyStringFromBodyStruct(response.Response.ResponseBody)
		if responseBody != nil {
			// Check if this is a Swagger UI page
			if isSwaggerUIPage(*responseBody) {
				// STEP 2: Use headless to render the page and extract the spec URL
				headlessConfig := &common.HeadlessRequestConfig{
					PathToBrowserShell:  &headlessPath, // Use default
					MinDomStabalizeTime: 5,
				}

				headlessRequestConfig := createSendHTTPRequestConfig(baseURL, parsedTargetPath, timeout, userAgent, common.RequestMethodHeadless, headlessConfig, headers)
				headlessResponse, err := request.SendRequest(ctx, headlessRequestConfig)

				if err == nil && headlessResponse.Response != nil && headlessResponse.Response.StatusCode != nil &&
					*headlessResponse.Response.StatusCode == 200 && headlessResponse.Response.ResponseBody != nil {

					headlessBody := requesthelpers.GetResponseBodyStringFromBodyStruct(headlessResponse.Response.ResponseBody)
					if headlessBody != nil {
						// Extract spec URLs from the rendered content
						specURLs := extractSpecURLFromRenderedContent(*headlessBody, baseURL)

						// Try each extracted spec URL
						for _, specURL := range specURLs {
							// Parse the spec URL to get the path
							parsedURL, err := url.Parse(specURL)
							if err != nil {
								continue
							}

							specPath := parsedURL.Path
							if parsedURL.RawQuery != "" {
								specPath += "?" + parsedURL.RawQuery
							}

							// Make request to the extracted spec URL
							specRequestConfig := createSendHTTPRequestConfig(baseURL, specPath, timeout, userAgent, common.RequestMethodStandard, nil, headers)
							specResponse, err := request.SendRequest(ctx, specRequestConfig)
							if err != nil {
								continue
							}

							if specResponse.Response == nil || specResponse.Response.StatusCode == nil ||
								*specResponse.Response.StatusCode != 200 || specResponse.Response.ResponseBody == nil {
								continue
							}

							specBody := requesthelpers.GetResponseBodyStringFromBodyStruct(specResponse.Response.ResponseBody)
							if specBody == nil {
								continue
							}

							docType, isValidSpec := detectOpenAPISpec(*specBody)
							if isValidSpec {
								bodyBytes := []byte(*specBody)
								return specURL, bodyBytes, docType, nil
							}
						}

						// If no extracted URLs worked, try common paths as fallback
						for _, path := range specPaths {
							specRequestConfig := createSendHTTPRequestConfig(baseURL, path, timeout, userAgent, common.RequestMethodStandard, nil, headers)
							specResponse, err := request.SendRequest(ctx, specRequestConfig)
							if err != nil {
								continue
							}

							if specResponse.Response == nil || specResponse.Response.StatusCode == nil ||
								*specResponse.Response.StatusCode != 200 || specResponse.Response.ResponseBody == nil {
								continue
							}

							specBody := requesthelpers.GetResponseBodyStringFromBodyStruct(specResponse.Response.ResponseBody)
							if specBody == nil {
								continue
							}

							docType, isValidSpec := detectOpenAPISpec(*specBody)
							if isValidSpec {
								swaggerURL := baseURL + path
								bodyBytes := []byte(*specBody)
								return swaggerURL, bodyBytes, docType, nil
							}
						}
					}
				}
			}
		}
	}

	// STEP 3: Fall back to trying common spec paths directly
	for _, path := range specPaths {
		if dl, ok := ctx.Deadline(); ok {
			timeout = int(time.Until(dl).Seconds())
		}

		// Create a request config for the Swagger/OpenAPI spec and send the request
		requestConfig := createSendHTTPRequestConfig(baseURL, fmt.Sprintf("%s%s", parsedTargetPath, path), timeout, userAgent, common.RequestMethodStandard, nil, headers)
		request, err := request.SendRequest(ctx, requestConfig)
		if err != nil {
			continue // Try next path on request failure
		}

		// Check if the request was successful
		if request.Response == nil || request.Response.StatusCode == nil || *request.Response.StatusCode != 200 || request.Response.ResponseBody == nil {
			continue
		}

		// Check if the response body contains a valid OpenAPI/Swagger spec
		responseBody := requesthelpers.GetResponseBodyStringFromBodyStruct(request.Response.ResponseBody)
		if responseBody == nil {
			continue
		}

		docType, isValidSpec := detectOpenAPISpec(*responseBody)
		if isValidSpec {
			swaggerURL := target + path // full URL for the report
			bodyBytes := []byte(*responseBody)
			return swaggerURL, bodyBytes, docType, nil
		}
	}

	return "", nil, nil, fmt.Errorf("no valid Swagger/OpenAPI spec found")
}

// processOpenAPIDocument dispatches document parsing to the appropriate version handler.
// It is shared by the normal probe path and the specUrl early-exit path.
func processOpenAPIDocument(document libopenapi.Document, docType map[string]interface{}, report *enumerateapiapplicationfern.EnumerateSwaggerReport, target string) {
	if version, ok := docType["swagger"]; ok {
		versionStr := fmt.Sprintf("%v", version)
		if strings.HasPrefix(versionStr, "2") {
			report.Result.Version = &versionStr
			if err := handleSwaggerV2(document, report, target); err != nil {
				report.Errors = append(report.Errors, err.Error())
			}
		} else {
			report.Errors = append(report.Errors, fmt.Sprintf("unsupported Swagger version: %s", versionStr))
		}
	} else if version, ok := docType["openapi"]; ok {
		versionStr := fmt.Sprintf("%v", version)
		if strings.HasPrefix(versionStr, "3") {
			report.Result.Version = &versionStr
			if err := handleOpenAPIV3(document, report, target); err != nil {
				report.Errors = append(report.Errors, err.Error())
			}
		} else {
			report.Errors = append(report.Errors, fmt.Sprintf("unsupported OpenAPI version: %s", versionStr))
		}
	} else {
		report.Errors = append(report.Errors, "unsupported OpenAPI version")
	}
}

// PerformAppEnumerateSwagger performs a Swagger scan against a target URL and returns the report.
func PerformAppEnumerateSwagger(ctx context.Context, config enumerateapiapplicationfern.EnumerateSwaggerConfig, headlessPath string) enumerateapiapplicationfern.EnumerateSwaggerReport {
	result := enumerateapiapplicationfern.EnumerateSwaggerResult{}
	report := enumerateapiapplicationfern.EnumerateSwaggerReport{Config: &config, Result: &result}

	// Normalize target URL
	target := strings.TrimSuffix(config.Target, "/")

	// Merge caller-supplied headers/cookies for authenticated spec fetches
	headers := requesthelpers.BuildAuthHeaders(config.Headers, config.Cookies)

	// Early-exit path: caller already knows the spec URL — fetch it directly, skip all probing.
	if config.SpecUrl != nil && *config.SpecUrl != "" {
		baseURL, specPath, queryParams, err := requesthelpers.SplitTargetURL(*config.SpecUrl)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("invalid specUrl: %v", err))
			return report
		}
		requestConfig := createSendHTTPRequestConfig(baseURL, specPath, config.Timeout, config.UserAgent, common.RequestMethodStandard, nil, headers)
		// Preserve query parameters from specUrl (e.g., ?format=openapi) — SplitTargetURL strips them.
		if len(queryParams) > 0 {
			if requestConfig.Request.Params == nil {
				requestConfig.Request.Params = &common.HttpRequestParams{}
			}
			requestConfig.Request.Params.Query = queryParams
		}
		response, err := request.SendRequest(ctx, requestConfig)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("failed to fetch specUrl: %v", err))
			return report
		}
		if response.Response == nil || response.Response.StatusCode == nil || *response.Response.StatusCode != 200 || response.Response.ResponseBody == nil {
			status := 0
			if response.Response != nil && response.Response.StatusCode != nil {
				status = *response.Response.StatusCode
			}
			report.Errors = append(report.Errors, fmt.Sprintf("specUrl returned non-200 status: %d", status))
			return report
		}
		responseBody := requesthelpers.GetResponseBodyStringFromBodyStruct(response.Response.ResponseBody)
		if responseBody == nil {
			report.Errors = append(report.Errors, "specUrl returned empty body")
			return report
		}
		docType, isValidSpec := detectOpenAPISpec(*responseBody)
		if !isValidSpec {
			report.Errors = append(report.Errors, "specUrl response is not a valid OpenAPI/Swagger spec")
			return report
		}
		swaggerURL := *config.SpecUrl
		bodyBytes := []byte(*responseBody)
		result.SchemaUrl = &swaggerURL
		result.Raw = base64.StdEncoding.EncodeToString(bodyBytes)
		document, err := libopenapi.NewDocument(bodyBytes)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Error creating new document: %v", err))
			return report
		}
		processOpenAPIDocument(document, docType, &report, target)
		return report
	}

	// Try to find a valid Swagger/OpenAPI spec
	swaggerURL, bodyBytes, docType, err := findOpenAPISpec(ctx, target, config.Timeout, headlessPath, config.UserAgent, headers, config.CandidatePaths)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	result.SchemaUrl = &swaggerURL

	// Encode the raw body in base64 and add to the report
	result.Raw = base64.StdEncoding.EncodeToString(bodyBytes)

	// Create a new document from specification bytes
	document, err := libopenapi.NewDocument(bodyBytes)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Error creating new document: %v", err))
		return report
	}

	processOpenAPIDocument(document, docType, &report, target)

	return report
}

func handleSwaggerV2(document libopenapi.Document, report *enumerateapiapplicationfern.EnumerateSwaggerReport, target string) error {
	report.Result.ApiType = enumerateapiapplicationfern.ApiTypeSwaggerV2
	var errors []error
	var v2Model *libopenapi.DocumentModel[v2.Swagger]

	v2Model, errors = document.BuildV2Model()
	if len(errors) > 0 {
		for i := range errors {
			errMsg := fmt.Sprintf("error: %v", errors[i])
			report.Errors = append(report.Errors, errMsg)
		}
		return fmt.Errorf("cannot create v2 model from document: %d errors reported", len(errors))
	}

	model := v2Model.Model

	// Construct the base endpoint URL from the host and basePath fields
	var baseEndpointURL string
	if model.Host != "" {
		// Use the scheme from the original target
		parsedURL, err := url.Parse(target)
		if err != nil {
			errMsg := fmt.Sprintf("failed to parse target URL: %v", err)
			report.Errors = append(report.Errors, errMsg)
			return fmt.Errorf("failed to parse target URL: %v", err)
		}
		scheme := parsedURL.Scheme
		if scheme == "" {
			scheme = "https" // Default to HTTPS if no scheme
		}
		basePath := model.BasePath
		if basePath == "" {
			basePath = ""
		}
		// Wrap IPv6 addresses in brackets for valid URL construction
		host := model.Host
		if hostOnly, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			// host:port form — check if host part is IPv6
			if net.ParseIP(hostOnly) != nil && strings.Contains(hostOnly, ":") {
				host = fmt.Sprintf("[%s]:%s", hostOnly, host[strings.LastIndex(host, ":")+1:])
			}
		} else if net.ParseIP(host) != nil && strings.Contains(host, ":") {
			// bare IPv6 address without port
			host = fmt.Sprintf("[%s]", host)
		}
		baseEndpointURL = fmt.Sprintf("%s://%s%s", scheme, host, basePath)
	} else {
		// No host specified, use the target's base URL
		parsedURL, err := url.Parse(target)
		if err != nil {
			errMsg := fmt.Sprintf("failed to parse target URL: %v", err)
			report.Errors = append(report.Errors, errMsg)
			return fmt.Errorf("failed to parse target URL: %v", err)
		}
		baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		if model.BasePath != "" {
			baseEndpointURL = baseURL + model.BasePath
		} else {
			baseEndpointURL = baseURL
		}
	}
	report.Result.BaseEndpointUrl = baseEndpointURL

	// Extract security definitions
	securityDefinitions := make(map[string]*v2.SecurityScheme)
	if model.SecurityDefinitions != nil {
		for pair := model.SecurityDefinitions.Definitions.Oldest(); pair != nil; pair = pair.Next() {
			securityDefinitions[pair.Key] = pair.Value
		}
	}

	// Add security schemes to the report
	report.Result.SecuritySchemes = convertSecurityDefinitionsV2(securityDefinitions)

	// Add app-level security requirements to the report
	securityRequirements := convertSecurityRequirementsV2(model.Security)
	if securityRequirements != nil {
		report.Result.Security = []*enumerateapiapplicationfern.SecurityRequirement{securityRequirements}
	}

	// Iterate over paths and methods to populate the report
	if model.Paths == nil || model.Paths.PathItems == nil {
		return nil
	}
	for pair := model.Paths.PathItems.Oldest(); pair != nil; pair = pair.Next() {
		path := pair.Key
		pathItem := pair.Value
		for opPair := pathItem.GetOperations().Oldest(); opPair != nil; opPair = opPair.Next() {
			method := opPair.Key
			operation := opPair.Value

			var responseProperties map[string][]string
			if strings.ToUpper(method) == "GET" {
				var err error
				responseProperties, err = extractResponsePropertiesV2(operation)
				if err != nil {
					responseProperties = nil
				}
			}

			requestSchema := extractRequestSchemaV2(operation, document, report)

			securityRequirements := convertSecurityRequirementsV2(operation.Security)
			route := enumerateapiapplicationfern.ApiApplicationRouteDetails{
				Path:               path,
				Method:             method,
				QueryParams:        getQueryParamsV2(operation.Parameters),
				Security:           securityRequirements,
				Type:               enumerateapiapplicationfern.ApiTypeSwaggerV2,
				Description:        operation.Description,
				RequestSchema:      requestSchema,
				ResponseProperties: responseProperties,
			}

			report.Result.Routes = append(report.Result.Routes, &route)
		}
	}

	return nil
}

func handleOpenAPIV3(document libopenapi.Document, report *enumerateapiapplicationfern.EnumerateSwaggerReport, target string) error {
	report.Result.ApiType = enumerateapiapplicationfern.ApiTypeSwaggerV3
	var errors []error
	var v3Model *libopenapi.DocumentModel[v3.Document]

	v3Model, errors = document.BuildV3Model()
	if len(errors) > 0 {
		for i := range errors {
			errMsg := fmt.Sprintf("error: %v", errors[i])
			report.Errors = append(report.Errors, errMsg)
		}
		return fmt.Errorf("cannot create v3 model from document: %d errors reported", len(errors))
	}

	model := v3Model.Model

	// Construct the base endpoint URL from the servers array
	serverURL := ""
	if len(model.Servers) > 0 {
		serverURL = model.Servers[0].URL
	}

	var baseEndpointURL string
	if serverURL != "" {
		// Check if the server URL is absolute or relative
		if strings.HasPrefix(serverURL, "http://") || strings.HasPrefix(serverURL, "https://") {
			// Server URL is absolute, use it directly
			baseEndpointURL = strings.TrimSuffix(serverURL, "/")
		} else {
			// Server URL is relative, append to the base URL from target
			parsedURL, err := url.Parse(target)
			if err != nil {
				errMsg := fmt.Sprintf("failed to parse target URL: %v", err)
				report.Errors = append(report.Errors, errMsg)
				return fmt.Errorf("failed to parse target URL: %v", err)
			}
			baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
			baseURL = strings.TrimSuffix(baseURL, "/")
			serverURL = strings.TrimPrefix(serverURL, "/")
			if serverURL != "" {
				baseEndpointURL = baseURL + "/" + serverURL
			} else {
				baseEndpointURL = baseURL
			}
		}
	} else {
		// No server URL specified, use the target's base URL
		parsedURL, err := url.Parse(target)
		if err != nil {
			errMsg := fmt.Sprintf("failed to parse target URL: %v", err)
			report.Errors = append(report.Errors, errMsg)
			return fmt.Errorf("failed to parse target URL: %v", err)
		}
		baseEndpointURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	}

	report.Result.BaseEndpointUrl = baseEndpointURL

	// Extract security definitions
	securityDefinitions := make(map[string]*v3.SecurityScheme)
	if model.Components != nil && model.Components.SecuritySchemes != nil {
		for pair := model.Components.SecuritySchemes.Oldest(); pair != nil; pair = pair.Next() {
			securityDefinitions[pair.Key] = pair.Value
		}
	}

	// Add security schemes to the report
	report.Result.SecuritySchemes = convertSecurityDefinitionsV3(securityDefinitions)

	// Add app-level security requirements to the report
	securityRequirements := convertSecurityRequirementsV3(model.Security)
	if securityRequirements != nil {
		report.Result.Security = []*enumerateapiapplicationfern.SecurityRequirement{securityRequirements}
	}

	// Iterate over paths and methods to populate the report
	if model.Paths == nil || model.Paths.PathItems == nil {
		return nil
	}
	for pair := model.Paths.PathItems.Oldest(); pair != nil; pair = pair.Next() {
		path := pair.Key
		pathItem := pair.Value
		for opPair := pathItem.GetOperations().Oldest(); opPair != nil; opPair = opPair.Next() {
			method := opPair.Key
			operation := opPair.Value

			var responseProperties map[string][]string
			if strings.ToUpper(method) == "GET" {
				var err error
				responseProperties, err = extractResponsePropertiesV3(operation)
				if err != nil {
					responseProperties = nil
				}
			}

			requestSchema := extractRequestSchemaV3(operation, document, report)

			securityRequirements := convertSecurityRequirementsV3(operation.Security)
			route := enumerateapiapplicationfern.ApiApplicationRouteDetails{
				Path:               path,
				Method:             method,
				QueryParams:        getQueryParamsV3(operation.Parameters),
				Security:           securityRequirements,
				Type:               enumerateapiapplicationfern.ApiTypeSwaggerV3,
				Description:        operation.Description,
				RequestSchema:      requestSchema,
				ResponseProperties: responseProperties,
			}

			report.Result.Routes = append(report.Result.Routes, &route)
		}
	}

	return nil
}

// Helper function to get the first layer of schema properties recursively
func getSchemaPropertiesRecursive(schema *base.Schema) []string {
	var properties []string
	if schema.Properties != nil {
		for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
			propName := pair.Key
			properties = append(properties, propName)
			// Recursively get properties of nested schemas
			nestedSchema := pair.Value.Schema()
			if nestedSchema != nil {
				nestedProperties := getSchemaPropertiesRecursive(nestedSchema)
				properties = append(properties, nestedProperties...)
			}
		}
	}
	return properties
}

// getQueryParamsV2 extracts query parameters from the operation parameters for Swagger (OpenAPI 2.0)
func getQueryParamsV2(params []*v2.Parameter) []string {
	var queryParams []string
	for _, param := range params {
		if param.In == "query" {
			queryParams = append(queryParams, param.Name)
		}
	}
	return queryParams
}

// getQueryParamsV3 extracts query parameters from the operation parameters for OpenAPI 3.0+
func getQueryParamsV3(params []*v3.Parameter) []string {
	var queryParams []string
	for _, param := range params {
		if param.In == "query" {
			queryParams = append(queryParams, param.Name)
		}
	}
	return queryParams
}

func convertSecurityDefinitionsV2(securityDefinitions map[string]*v2.SecurityScheme) map[string]*enumerateapiapplicationfern.SecurityScheme {
	schemes := make(map[string]*enumerateapiapplicationfern.SecurityScheme)
	for name, scheme := range securityDefinitions {
		if scheme == nil {
			continue
		}
		webscanScheme := &enumerateapiapplicationfern.SecurityScheme{
			Type:        enumerateapiapplicationfern.SecuritySchemeType(scheme.Type),
			Description: &scheme.Description,
			Name:        &name,
		}

		switch scheme.Type {
		case "apiKey":
			webscanScheme.In = &scheme.In
		case "oauth2":
			webscanScheme.Flow = &scheme.Flow
			webscanScheme.AuthorizationUrl = &scheme.AuthorizationUrl
			webscanScheme.TokenUrl = &scheme.TokenUrl
			webscanScheme.Scopes = convertV2ScopesToMap(scheme.Scopes)
		}

		if webscanScheme.Type != "" {
			schemes[name] = webscanScheme
		}

		switch scheme.Type {
		case "apiKey":
			webscanScheme.In = &scheme.In
		case "oauth2":
			webscanScheme.Flow = &scheme.Flow
			webscanScheme.AuthorizationUrl = &scheme.AuthorizationUrl
			webscanScheme.TokenUrl = &scheme.TokenUrl
			webscanScheme.Scopes = convertV2ScopesToMap(scheme.Scopes)
		}

		schemes[name] = webscanScheme
	}
	return schemes
}

func convertV2ScopesToMap(scopes *v2.Scopes) map[string]string {
	if scopes == nil {
		return nil
	}
	result := make(map[string]string)
	for pair := scopes.Values.Oldest(); pair != nil; pair = pair.Next() {
		result[pair.Key] = pair.Value
	}
	return result
}

func convertSecurityDefinitionsV3(securityDefinitions map[string]*v3.SecurityScheme) map[string]*enumerateapiapplicationfern.SecurityScheme {
	schemes := make(map[string]*enumerateapiapplicationfern.SecurityScheme)
	for name, scheme := range securityDefinitions {
		if scheme == nil {
			continue
		}
		webscanScheme := &enumerateapiapplicationfern.SecurityScheme{
			Type:        enumerateapiapplicationfern.SecuritySchemeType(scheme.Type),
			Description: &scheme.Description,
			Name:        &name,
		}

		switch scheme.Type {
		case "apiKey":
			webscanScheme.In = &scheme.In
		case "http":
			webscanScheme.Scheme = &scheme.Scheme
			webscanScheme.BearerFormat = &scheme.BearerFormat
		case "oauth2":
			webscanScheme.OAuthFlow = convertOAuthFlowV3(scheme.Flows)
		case "openIdConnect":
			webscanScheme.OpenIdConnectUrl = &scheme.OpenIdConnectUrl
		}

		if webscanScheme.Type != "" {
			schemes[name] = webscanScheme
		}
	}
	return schemes
}

func convertOAuthFlowV3(flows *v3.OAuthFlows) *enumerateapiapplicationfern.OauthFlow {
	if flows == nil {
		return nil
	}
	return &enumerateapiapplicationfern.OauthFlow{
		Implicit:          convertOAuthFlowDetailsV3(flows.Implicit),
		Password:          convertOAuthFlowDetailsV3(flows.Password),
		ClientCredentials: convertOAuthFlowDetailsV3(flows.ClientCredentials),
		AuthorizationCode: convertOAuthFlowDetailsV3(flows.AuthorizationCode),
	}
}

func convertOAuthFlowDetailsV3(flow *v3.OAuthFlow) *enumerateapiapplicationfern.OauthFlowDetails {
	if flow == nil {
		return nil
	}
	return &enumerateapiapplicationfern.OauthFlowDetails{
		AuthorizationUrl: &flow.AuthorizationUrl,
		TokenUrl:         &flow.TokenUrl,
		RefreshUrl:       &flow.RefreshUrl,
		Scopes:           convertOrderedMapToMap(flow.Scopes),
	}
}

func convertOrderedMapToMap(orderedMap *orderedmap.Map[string, string]) map[string]string {
	if orderedMap == nil {
		return nil
	}
	result := make(map[string]string)
	for pair := orderedMap.Oldest(); pair != nil; pair = pair.Next() {
		result[pair.Key] = pair.Value
	}
	return result
}

func convertSecurityRequirementsV2(security []*base.SecurityRequirement) *enumerateapiapplicationfern.SecurityRequirement {
	if len(security) == 0 {
		return nil
	}
	req := &enumerateapiapplicationfern.SecurityRequirement{
		Schemes: make(map[string][]string),
	}
	for _, secReq := range security {
		for pair := secReq.Requirements.Oldest(); pair != nil; pair = pair.Next() {
			req.Schemes[pair.Key] = pair.Value
		}
	}
	if len(req.Schemes) == 0 {
		return nil
	}
	return req
}

func convertSecurityRequirementsV3(security []*base.SecurityRequirement) *enumerateapiapplicationfern.SecurityRequirement {
	if len(security) == 0 {
		return nil
	}
	req := &enumerateapiapplicationfern.SecurityRequirement{
		Schemes: make(map[string][]string),
	}
	for _, secReq := range security {
		for pair := secReq.Requirements.Oldest(); pair != nil; pair = pair.Next() {
			req.Schemes[pair.Key] = pair.Value
		}
	}
	if len(req.Schemes) == 0 {
		return nil
	}
	return req
}

func extractResponsePropertiesV2(operation *v2.Operation) (map[string][]string, error) {
	responseProperties := make(map[string][]string)
	if operation.Responses != nil && operation.Responses.Codes != nil {
		for respPair := operation.Responses.Codes.Oldest(); respPair != nil; respPair = respPair.Next() {
			statusCode := respPair.Key
			response := respPair.Value

			if response.Schema != nil {
				schema := response.Schema.Schema()
				if schema != nil {
					properties := getSchemaPropertiesRecursive(schema)
					if len(properties) > 0 {
						responseProperties[statusCode] = properties
					}
				}
			}
		}
	}
	if len(responseProperties) == 0 {
		return nil, fmt.Errorf("no response properties found")
	}
	return responseProperties, nil
}

func extractResponsePropertiesV3(operation *v3.Operation) (map[string][]string, error) {
	responseProperties := make(map[string][]string)
	if operation.Responses != nil && operation.Responses.Codes != nil {
		for respPair := operation.Responses.Codes.Oldest(); respPair != nil; respPair = respPair.Next() {
			statusCode := respPair.Key
			response := respPair.Value

			if response.Content != nil {
				for contentPair := response.Content.Oldest(); contentPair != nil; contentPair = contentPair.Next() {
					mediaTypeObject := contentPair.Value
					if mediaTypeObject.Schema != nil {
						schema := mediaTypeObject.Schema.Schema()
						if schema != nil {
							properties := getSchemaPropertiesRecursive(schema)
							if len(properties) > 0 {
								responseProperties[statusCode] = properties
							}
						}
					}
				}
			}
		}
	}
	if len(responseProperties) == 0 {
		return nil, fmt.Errorf("no response properties found")
	}
	return responseProperties, nil
}

func convertSchemaToRequestSchema(s *base.Schema, seenSchemas map[*base.Schema]bool, report *enumerateapiapplicationfern.EnumerateSwaggerReport) *enumerateapiapplicationfern.RequestSchema {
	if s == nil {
		report.Errors = append(report.Errors, "Encountered nil schema")
		return nil
	}

	// Check for circular references
	if seenSchemas[s] {
		report.Errors = append(report.Errors, "Circular reference detected in schema")
		return &enumerateapiapplicationfern.RequestSchema{
			Type:        []string{"circular_reference"},
			Description: strPtr("Circular reference detected"),
		}
	}
	seenSchemas[s] = true

	rs := &enumerateapiapplicationfern.RequestSchema{
		Type:        s.Type,
		Required:    s.Required,
		Description: strPtr(s.Description),
		Format:      strPtr(s.Format),
	}

	if s.Default != nil {
		defaultStr := fmt.Sprintf("%v", s.Default)
		rs.Default = &defaultStr
	}

	if s.Example != nil {
		rs.Example = s.Example
	}

	convertEnumValues(s, rs, report)

	if s.MultipleOf != nil {
		rs.MultipleOf = s.MultipleOf
	}

	if s.Maximum != nil {
		rs.Maximum = s.Maximum
	}

	if s.ExclusiveMaximum != nil {
		if s.ExclusiveMaximum.IsA() {
			boolVal := s.ExclusiveMaximum.A
			rs.ExclusiveMaximum = &boolVal
		} else if s.ExclusiveMaximum.IsB() {
			boolVal := s.ExclusiveMaximum.B > 0
			rs.ExclusiveMaximum = &boolVal
		}
	}

	if s.Minimum != nil {
		rs.Minimum = s.Minimum
	}

	if s.ExclusiveMinimum != nil {
		if s.ExclusiveMinimum.IsA() {
			boolVal := s.ExclusiveMinimum.A
			rs.ExclusiveMinimum = &boolVal
		} else if s.ExclusiveMinimum.IsB() {
			boolVal := s.ExclusiveMinimum.B > 0
			rs.ExclusiveMinimum = &boolVal
		}
	}

	if s.MaxLength != nil {
		intVal := int(*s.MaxLength)
		rs.MaxLength = &intVal
	}

	if s.MinLength != nil {
		intVal := int(*s.MinLength)
		rs.MinLength = &intVal
	}

	if s.Pattern != "" {
		rs.Pattern = &s.Pattern
	}

	if s.MaxItems != nil {
		intVal := int(*s.MaxItems)
		rs.MaxItems = &intVal
	}

	if s.MinItems != nil {
		intVal := int(*s.MinItems)
		rs.MinItems = &intVal
	}

	if s.UniqueItems != nil {
		rs.UniqueItems = s.UniqueItems
	}

	if s.MaxProperties != nil {
		intVal := int(*s.MaxProperties)
		rs.MaxProperties = &intVal
	}

	if s.MinProperties != nil {
		intVal := int(*s.MinProperties)
		rs.MinProperties = &intVal
	}

	if s.Properties != nil {
		rs.Properties = make([]*enumerateapiapplicationfern.SchemaProperty, 0)
		for pair := s.Properties.Oldest(); pair != nil; pair = pair.Next() {
			propName := pair.Key
			propSchema := pair.Value.Schema()
			if propSchema != nil {
				required := contains(s.Required, propName)
				prop := &enumerateapiapplicationfern.SchemaProperty{
					Name:        propName,
					Type:        propSchema.Type,
					Format:      strPtr(propSchema.Format),
					Description: strPtr(propSchema.Description),
					Required:    &required,
				}
				if propSchema.Items != nil && propSchema.Items.A != nil {
					prop.Items = convertSchemaToRequestSchema(propSchema.Items.A.Schema(), seenSchemas, report)
				}
				if propSchema.Properties != nil {
					nestedSchema := convertSchemaToRequestSchema(propSchema, seenSchemas, report)
					prop.Properties = nestedSchema.Properties
				}
				rs.Properties = append(rs.Properties, prop)
			} else {
				report.Errors = append(report.Errors, fmt.Sprintf("Nil property schema for property: %s", propName))
			}
		}
	}

	if s.Items != nil && s.Items.A != nil {
		rs.Items = convertSchemaToRequestSchema(s.Items.A.Schema(), seenSchemas, report)
	}

	if s.AdditionalProperties != nil && s.AdditionalProperties.A != nil {
		rs.AdditionalProperties = convertSchemaToRequestSchema(s.AdditionalProperties.A.Schema(), seenSchemas, report)
	}

	if len(s.AllOf) > 0 {
		rs.AllOf = make([]*enumerateapiapplicationfern.RequestSchema, len(s.AllOf))
		for i, schema := range s.AllOf {
			rs.AllOf[i] = convertSchemaToRequestSchema(schema.Schema(), seenSchemas, report)
		}
	}

	if len(s.OneOf) > 0 {
		rs.OneOf = make([]*enumerateapiapplicationfern.RequestSchema, len(s.OneOf))
		for i, schema := range s.OneOf {
			rs.OneOf[i] = convertSchemaToRequestSchema(schema.Schema(), seenSchemas, report)
		}
	}

	if len(s.AnyOf) > 0 {
		rs.AnyOf = make([]*enumerateapiapplicationfern.RequestSchema, len(s.AnyOf))
		for i, schema := range s.AnyOf {
			rs.AnyOf[i] = convertSchemaToRequestSchema(schema.Schema(), seenSchemas, report)
		}
	}

	if s.Not != nil {
		rs.Not = convertSchemaToRequestSchema(s.Not.Schema(), seenSchemas, report)
	}

	delete(seenSchemas, s)
	return rs
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func extractRequestSchemaV2(operation *v2.Operation, doc libopenapi.Document, report *enumerateapiapplicationfern.EnumerateSwaggerReport) *enumerateapiapplicationfern.RequestSchema {
	if operation.Parameters == nil {
		// No parameters is normal for some operations, don't log as error
		return nil
	}

	for _, param := range operation.Parameters {
		if param.In == "body" && param.Schema != nil {
			if s := param.Schema.Schema(); s != nil {
				return convertSchemaToRequestSchema(s, make(map[*base.Schema]bool), report)
			}
		}
	}
	// No body parameter is normal for GET, DELETE, etc. operations, don't log as error
	return nil
}

func extractRequestSchemaV3(operation *v3.Operation, doc libopenapi.Document, report *enumerateapiapplicationfern.EnumerateSwaggerReport) *enumerateapiapplicationfern.RequestSchema {
	if operation.RequestBody == nil || operation.RequestBody.Content == nil {
		// No request body is normal for GET, DELETE, etc. operations, don't log as error
		return nil
	}

	for pair := operation.RequestBody.Content.Oldest(); pair != nil; pair = pair.Next() {
		mediaType := pair.Value
		if mediaType.Schema != nil {
			if s := mediaType.Schema.Schema(); s != nil {
				return convertSchemaToRequestSchema(s, make(map[*base.Schema]bool), report)
			}
		}
	}
	// No schema in request body content might be normal, don't log as error
	return nil
}

func convertEnumValues(s *base.Schema, rs *enumerateapiapplicationfern.RequestSchema, report *enumerateapiapplicationfern.EnumerateSwaggerReport) {
	if len(s.Enum) > 0 {
		rs.Enum = make([]interface{}, len(s.Enum))
		for i, v := range s.Enum {
			rs.Enum[i] = convertEnumValue(v, report)
		}
	}
}

func convertEnumValue(v *yaml.Node, report *enumerateapiapplicationfern.EnumerateSwaggerReport) interface{} {
	switch v.Kind {
	case yaml.ScalarNode:
		switch v.Tag {
		case "!!str":
			return v.Value
		case "!!int":
			val, err := strconv.ParseInt(v.Value, 10, 64)
			if err == nil {
				return val
			}
			report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse int enum value: %s", err))
		case "!!float":
			val, err := strconv.ParseFloat(v.Value, 64)
			if err == nil {
				return val
			}
			report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse float enum value: %s", err))
		case "!!bool":
			val, err := strconv.ParseBool(v.Value)
			if err == nil {
				return val
			}
			report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse bool enum value: %s", err))
		}
	case yaml.SequenceNode, yaml.MappingNode:
		// For complex types, we return them as is
		return v
	}
	return v.Value // fallback to string
}
