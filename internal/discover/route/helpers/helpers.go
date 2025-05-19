package discoverroute

import (
	// Standard
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discoverroutefern "github.com/Method-Security/webscan/generated/go/discover/route"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
)

// SetToListString converts a set of strings to a list of strings.
func SetToListString(set map[string]struct{}) []string {
	list := make([]string, 0, len(set))
	for key := range set {
		list = append(list, key)
	}
	return list
}

// AddListToSetString adds elements from a list of strings to a set of strings.
func AddListToSetString(set map[string]struct{}, list []string) map[string]struct{} {
	for _, item := range list {
		set[item] = struct{}{}
	}
	return set
}

// MergeWebRoutes merges WebRoutes, retaining only unique routes
// unique routes are defined by the combination of method and URL
func MergeWebRoutes(routes []*discoverroutefern.RouteDetails) []*discoverroutefern.RouteDetails {
	routeMap := make(map[string]*discoverroutefern.RouteDetails)

	for _, route := range routes {
		// Create a unique key based on method and URL
		method := string(common.HttpMethodGet)
		if route.Method != nil {
			method = string(*route.Method)
		}
		key := fmt.Sprintf("%s:%s%s", method, route.BaseUrl, route.Path)

		if existingRoute, exists := routeMap[key]; exists {
			// Merge QueryParams
			existingRoute.QueryParams = MergeQueryParams(existingRoute.QueryParams, route.QueryParams)
			// Merge BodyParams
			existingRoute.BodyParams = MergeBodyParams(existingRoute.BodyParams, route.BodyParams)
		} else {
			// Add new route to the map
			// Create a copy to avoid modifying the original
			newRoute := route
			routeMap[key] = newRoute
		}
	}

	// Convert map back to slice
	var mergedRoutes []*discoverroutefern.RouteDetails
	for _, route := range routeMap {
		mergedRoutes = append(mergedRoutes, route)
	}

	return mergedRoutes
}

// MergeQueryParams Helper function to merge QueryParams only retaining those that are unique
// When the same param name is encountered, the example values are merged
func MergeQueryParams(params1 []*discoverroutefern.RouteQueryParams, params2 []*discoverroutefern.RouteQueryParams) []*discoverroutefern.RouteQueryParams {
	// If either is nil return the other
	if params1 == nil && params2 == nil {
		return nil
	} else if params1 == nil {
		return params2
	} else if params2 == nil {
		return params1
	}

	// Merge
	paramMap := make(map[string]*discoverroutefern.RouteQueryParams)
	for _, param := range params1 {
		paramMap[param.Name] = param
	}
	for _, param := range params2 {
		if _, exists := paramMap[param.Name]; exists {
			existingParam := paramMap[param.Name]
			if existingParam.ExampleValues != nil && param.ExampleValues != nil {
				existingParam.ExampleValues = append(existingParam.ExampleValues, param.ExampleValues...)
			} else if param.ExampleValues != nil {
				existingParam.ExampleValues = param.ExampleValues
			} // else existingParam.ExampleValues is already set
			paramMap[param.Name] = existingParam
		}
	}

	// Convert map back to slice
	var mergedParams []*discoverroutefern.RouteQueryParams
	for _, param := range paramMap {
		mergedParams = append(mergedParams, param)
	}
	return mergedParams
}

// MergeBodyParams helper function to merge BodyParams only retaining those that are unique
// When the same param name is encountered, the example values are merged
func MergeBodyParams(params1 []*discoverroutefern.RouteBodyParams, params2 []*discoverroutefern.RouteBodyParams) []*discoverroutefern.RouteBodyParams {
	// If either is nil return the other
	if params1 == nil && params2 == nil {
		return nil
	} else if params1 == nil {
		return params2
	} else if params2 == nil {
		return params1
	}

	// Merge
	paramMap := make(map[string]*discoverroutefern.RouteBodyParams)
	for _, param := range params1 {
		paramMap[param.Name] = param
	}
	for _, param := range params2 {
		if _, exists := paramMap[param.Name]; exists {
			existingParam := paramMap[param.Name]
			if existingParam.ExampleValues != nil && param.ExampleValues != nil {
				existingParam.ExampleValues = append(existingParam.ExampleValues, param.ExampleValues...)
			} else if param.ExampleValues != nil {
				existingParam.ExampleValues = param.ExampleValues
			}
			paramMap[param.Name] = existingParam
		}
	}

	// Convert map back to slice
	var mergedParams []*discoverroutefern.RouteBodyParams
	for _, param := range paramMap {
		mergedParams = append(mergedParams, param)
	}
	return mergedParams
}

// ParseQueryParams helper function to parse query parameters from the URL
func ParseQueryParams(reqURL *url.URL) []*discoverroutefern.RouteQueryParams {
	var queryParams []*discoverroutefern.RouteQueryParams
	for key, values := range reqURL.Query() {
		queryParams = append(queryParams, &discoverroutefern.RouteQueryParams{
			Name:          key,
			ExampleValues: values,
		})
	}
	return queryParams
}

// ParseBodyParams helper function to parse body parameters
func ParseBodyParams(postData string) ([]*discoverroutefern.RouteBodyParams, error) {
	var bodyParams []*discoverroutefern.RouteBodyParams

	// For simplicity, assume the body is JSON or form-urlencoded
	if strings.HasPrefix(postData, "{") {
		// Try to parse JSON
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(postData), &jsonData); err == nil {
			for key, value := range jsonData {
				// Stringify the value to ensure it's a string
				valueStr, err := json.Marshal(value)
				if err == nil {
					bodyParams = append(bodyParams, &discoverroutefern.RouteBodyParams{
						Name:          key,
						ExampleValues: []string{string(valueStr)}, // Store as a string
					})
				} else {
					return bodyParams, fmt.Errorf("failed to stringify json value: %v", err)
				}
			}
		} else {
			return bodyParams, fmt.Errorf("failed to parse json: %v", err)
		}
	} else {
		// Parse form-urlencoded data
		formData, err := url.ParseQuery(postData)
		if err == nil {
			for key, values := range formData {
				bodyParams = append(bodyParams, &discoverroutefern.RouteBodyParams{
					Name:          key,
					ExampleValues: values,
				})
			}
		} else {
			return bodyParams, fmt.Errorf("failed to parse form-urlencoded data: %v", err)
		}
	}

	return bodyParams, nil
}

// ResolveURL helper function to resolve relative URLs
func ResolveURL(base, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	// Return with trailing slash removed
	return strings.TrimRight(baseURL.ResolveReference(refURL).String(), "/")
}

// URLRemoveQueryParams helper function to remove query parameters from a URL
func URLRemoveQueryParams(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	parsedURL.RawQuery = ""
	return parsedURL.String(), nil
}

// IsURLAllowed helper function to check if a URL is allowed based on baseUrlsOnly and base domain and captureStaticAssets
// This only checks the first subdomain only of the baseURL as a condition for match
// Web routes often get redirected to www.* or other subdomains, so we only check the base domain
// baseURL should be the original URL sent to the CLI, targetURL is the URL discovered that needs checking
func IsURLAllowed(baseURL string, targetURL string, requireBaseURLMatch bool, ignoreStaticAssets bool) bool {
	// First check to see if the targetURL is a static asset type
	if !ignoreStaticAssets {
		if utils.IsStaticAsset(targetURL) {
			return false
		}
	}

	if !requireBaseURLMatch {
		return true
	}

	baseDomain := ExtractDomain(baseURL, 2)
	targetDomain := ExtractDomain(targetURL, 0)

	// Check if targetDomain is the same as baseDomain or a subdomain
	return IsSubdomain(baseDomain, targetDomain)
}

// ExtractDomain helper function to extract the domain from a URL with an optional maxDomainLevel parameter
// maxDomainLevel specifies the number of domain levels to include in the extracted domain
// e.g. maxDomainLevel=2 would extract "example.com" from "www.sub.example.com"
// maxDomainLevel=0 would extract the full domain
func ExtractDomain(rawURL string, maxDomainLevel int) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	domain := u.Hostname()

	if maxDomainLevel > 0 {
		parts := strings.Split(domain, ".")
		if len(parts) > maxDomainLevel {
			domain = strings.Join(parts[len(parts)-maxDomainLevel:], ".")
		}
	}

	return domain
}

// IsSubdomain helper function to check if sub is a subdomain of base
func IsSubdomain(base string, sub string) bool {
	if base == "" || sub == "" {
		return false
	}
	return sub == base || strings.HasSuffix(sub, "."+base)
}

// IsAbsoluteURL helper function to check if a URL is absolute
func IsAbsoluteURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "//")
}
