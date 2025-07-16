package discoverroute

import (
	// Standard
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"

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

// MergeStaticAssets merges static asset URLs, retaining only unique static assets.
func MergeStaticAssets(staticAssets []string) []string {
	staticAssetMap := make(map[string]struct{})

	for _, staticAsset := range staticAssets {
		if utils.IsStaticAsset(staticAsset) {
			staticAssetMap[staticAsset] = struct{}{}
		}
	}

	return SetToListString(staticAssetMap)
}

// MergeWebRoutes merges WebRoutes, retaining only unique routes (by method and URL).
func MergeWebRoutes(routes []*discover.RouteDetails) []*discover.RouteDetails {
	routeMap := make(map[string]*discover.RouteDetails)

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
	var mergedRoutes []*discover.RouteDetails
	for _, route := range routeMap {
		mergedRoutes = append(mergedRoutes, route)
	}

	return mergedRoutes
}

// MergeQueryParams merges two slices of RouteQueryParam, retaining unique params and merging example values.
func MergeQueryParams(params1 []*discover.RouteQueryParam, params2 []*discover.RouteQueryParam) []*discover.RouteQueryParam {
	// If either is nil return the other
	if params1 == nil && params2 == nil {
		return nil
	} else if params1 == nil {
		return params2
	} else if params2 == nil {
		return params1
	}

	// Merge
	paramMap := make(map[string]*discover.RouteQueryParam)
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
	var mergedParams []*discover.RouteQueryParam
	for _, param := range paramMap {
		mergedParams = append(mergedParams, param)
	}
	return mergedParams
}

// MergeBodyParams merges two slices of RouteBodyParam, retaining unique params and merging example values.
func MergeBodyParams(params1 []*discover.RouteBodyParam, params2 []*discover.RouteBodyParam) []*discover.RouteBodyParam {
	// If either is nil return the other
	if params1 == nil && params2 == nil {
		return nil
	} else if params1 == nil {
		return params2
	} else if params2 == nil {
		return params1
	}

	// Merge
	paramMap := make(map[string]*discover.RouteBodyParam)
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
	var mergedParams []*discover.RouteBodyParam
	for _, param := range paramMap {
		mergedParams = append(mergedParams, param)
	}
	return mergedParams
}

// ParseQueryParams parses query parameters from a URL into RouteQueryParam structs.
func ParseQueryParams(reqURL *url.URL) []*discover.RouteQueryParam {
	var queryParams []*discover.RouteQueryParam
	for key, values := range reqURL.Query() {
		queryParams = append(queryParams, &discover.RouteQueryParam{
			Name:          key,
			ExampleValues: values,
		})
	}
	return queryParams
}

// ParseBodyParams parses body parameters from a JSON or form-urlencoded string into RouteBodyParam structs.
func ParseBodyParams(postData string) ([]*discover.RouteBodyParam, error) {
	var bodyParams []*discover.RouteBodyParam

	// For simplicity, assume the body is JSON or form-urlencoded
	if strings.HasPrefix(postData, "{") {
		// Try to parse JSON
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(postData), &jsonData); err == nil {
			for key, value := range jsonData {
				// Stringify the value to ensure it's a string
				valueStr, err := json.Marshal(value)
				if err == nil {
					bodyParams = append(bodyParams, &discover.RouteBodyParam{
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
				bodyParams = append(bodyParams, &discover.RouteBodyParam{
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

// ResolveURL resolves a reference URL relative to a base URL.
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

// URLRemoveQueryParams removes query parameters from a URL string.
func URLRemoveQueryParams(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	parsedURL.RawQuery = ""
	return parsedURL.String(), nil
}

// IsURLAllowed checks if a target URL is allowed based on base URL, static asset rules, and domain matching.
func IsURLAllowed(baseURL string, targetURL string, noBaseURLMatch bool, collectStaticAssets bool) bool {
	// First check to see if the targetURL is a static asset type
	if collectStaticAssets {
		if utils.IsStaticAsset(targetURL) {
			return true // Allow static assets when ignoreStaticAssets is false
		}
	}

	if noBaseURLMatch {
		return true
	}

	baseDomain := ExtractDomain(baseURL, 2)
	targetDomain := ExtractDomain(targetURL, 0)

	// Check if targetDomain is the same as baseDomain or a subdomain
	return IsSubdomain(baseDomain, targetDomain)
}

// ExtractDomain extracts the domain from a URL up to a specified domain level.
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

// IsSubdomain checks if 'sub' is a subdomain of 'base'.
func IsSubdomain(base string, sub string) bool {
	if base == "" || sub == "" {
		return false
	}
	return sub == base || strings.HasSuffix(sub, "."+base)
}

// IsAbsoluteURL returns true if the given URL is absolute.
func IsAbsoluteURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "//")
}
