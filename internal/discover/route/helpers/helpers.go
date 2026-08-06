package discoverroute

import (
	// Standard
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
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
		method := route.Method
		if method == "" {
			method = common.HttpMethodGet
		}

		// Normalize path: treat empty path "" and root path "/" as equivalent
		// Follow existing codebase convention: root paths should be empty strings
		normalizedPath := route.Path
		if normalizedPath == "/" {
			normalizedPath = ""
		}

		key := fmt.Sprintf("%s:%s%s", method, route.BaseUrl, normalizedPath)

		if existingRoute, exists := routeMap[key]; exists {
			// Merge QueryParams
			existingRoute.QueryParams = MergeQueryParams(existingRoute.QueryParams, route.QueryParams)
			// Merge BodyParams
			existingRoute.BodyParams = MergeBodyParams(existingRoute.BodyParams, route.BodyParams)
			// Merge PathParams
			existingRoute.PathParams = MergePathParams(existingRoute.PathParams, route.PathParams)
			// Prefer evidence-tagged fields (sourcemap/CONST beats untagged first-seen)
			if existingRoute.Evidence == nil && route.Evidence != nil {
				existingRoute.Evidence = route.Evidence
			}
			if existingRoute.PathTemplate == nil && route.PathTemplate != nil {
				existingRoute.PathTemplate = route.PathTemplate
			}
		} else {
			// Add new route to the map
			// Create a copy to avoid modifying the original
			newRoute := *route
			// Normalize the path in the route object itself for consistent output
			newRoute.Path = normalizedPath
			routeMap[key] = &newRoute
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
		if existingParam, exists := paramMap[param.Name]; exists {
			if existingParam.ExampleValues != nil && param.ExampleValues != nil {
				// Use a set to deduplicate example values
				valueSet := make(map[string]struct{})
				for _, val := range existingParam.ExampleValues {
					valueSet[val] = struct{}{}
				}
				for _, val := range param.ExampleValues {
					valueSet[val] = struct{}{}
				}
				// Convert back to slice
				deduplicatedValues := make([]string, 0, len(valueSet))
				for val := range valueSet {
					deduplicatedValues = append(deduplicatedValues, val)
				}
				existingParam.ExampleValues = deduplicatedValues
			} else if param.ExampleValues != nil {
				existingParam.ExampleValues = param.ExampleValues
			} // else existingParam.ExampleValues is already set
			paramMap[param.Name] = existingParam
		} else {
			paramMap[param.Name] = param
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
		if existingParam, exists := paramMap[param.Name]; exists {
			if existingParam.ExampleValues != nil && param.ExampleValues != nil {
				// Use a set to deduplicate example values
				valueSet := make(map[string]struct{})
				for _, val := range existingParam.ExampleValues {
					valueSet[val] = struct{}{}
				}
				for _, val := range param.ExampleValues {
					valueSet[val] = struct{}{}
				}
				// Convert back to slice
				deduplicatedValues := make([]string, 0, len(valueSet))
				for val := range valueSet {
					deduplicatedValues = append(deduplicatedValues, val)
				}
				existingParam.ExampleValues = deduplicatedValues
			} else if param.ExampleValues != nil {
				existingParam.ExampleValues = param.ExampleValues
			}
			paramMap[param.Name] = existingParam
		} else {
			paramMap[param.Name] = param
		}
	}

	// Convert map back to slice
	var mergedParams []*discover.RouteBodyParam
	for _, param := range paramMap {
		mergedParams = append(mergedParams, param)
	}
	return mergedParams
}

// MergePathParams merges two slices of RoutePathParam, retaining unique params and merging example values.
func MergePathParams(params1 []*discover.RoutePathParam, params2 []*discover.RoutePathParam) []*discover.RoutePathParam {
	// If either is nil return the other
	if params1 == nil && params2 == nil {
		return nil
	} else if params1 == nil {
		return params2
	} else if params2 == nil {
		return params1
	}

	// Merge
	paramMap := make(map[string]*discover.RoutePathParam)
	order := make([]string, 0, len(params1)+len(params2))
	for _, param := range params1 {
		if _, exists := paramMap[param.Name]; !exists {
			order = append(order, param.Name)
		}
		paramMap[param.Name] = param
	}
	for _, param := range params2 {
		existingParam, exists := paramMap[param.Name]
		if !exists {
			paramMap[param.Name] = param
			order = append(order, param.Name)
			continue
		}
		if existingParam.ExampleValues != nil && param.ExampleValues != nil {
			// Use a set to deduplicate example values
			valueSet := make(map[string]struct{})
			for _, val := range existingParam.ExampleValues {
				valueSet[val] = struct{}{}
			}
			deduplicatedValues := existingParam.ExampleValues
			for _, val := range param.ExampleValues {
				if _, seen := valueSet[val]; seen {
					continue
				}
				valueSet[val] = struct{}{}
				deduplicatedValues = append(deduplicatedValues, val)
			}
			existingParam.ExampleValues = deduplicatedValues
		} else if param.ExampleValues != nil {
			existingParam.ExampleValues = param.ExampleValues
		} // else existingParam.ExampleValues is already set
		paramMap[param.Name] = existingParam
	}

	// Path parameters are positional, so preserve insertion order rather than ranging the map.
	mergedParams := make([]*discover.RoutePathParam, 0, len(order))
	for _, name := range order {
		mergedParams = append(mergedParams, paramMap[name])
	}
	return mergedParams
}

// ParseQueryParams parses query parameters from a URL into RouteQueryParam structs.
func ParseQueryParams(reqURL *url.URL) []*discover.RouteQueryParam {
	var queryParams []*discover.RouteQueryParam
	for key, values := range reqURL.Query() {
		if key == "" {
			continue
		}

		// Set Max Size and Length of Examples
		// Max Value Length is 256 characters
		// Max Example Values is 5 values
		// Empty values carry no example information, so omit them rather than
		// recording an empty string.
		filteredValues := make([]string, 0, len(values))
		for _, value := range values {
			if value == "" {
				continue
			}
			if len(value) <= 256 {
				filteredValues = append(filteredValues, value)
			}
		}
		if len(filteredValues) > 5 {
			filteredValues = filteredValues[:5]
		}

		queryParams = append(queryParams, &discover.RouteQueryParam{
			Name:          key,
			ExampleValues: filteredValues,
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
				if key == "" {
					continue
				}
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
				if key == "" {
					continue
				}
				// Empty values carry no example information, so omit them rather
				// than recording an empty string.
				filteredValues := make([]string, 0, len(values))
				for _, value := range values {
					if value == "" {
						continue
					}
					filteredValues = append(filteredValues, value)
				}
				bodyParams = append(bodyParams, &discover.RouteBodyParam{
					Name:          key,
					ExampleValues: filteredValues,
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

// SplitURLBaseAndPath returns the URL origin and escaped path as separate route fields.
func SplitURLBaseAndPath(rawURL string) (string, string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}

	baseURL := ""
	if parsedURL.Scheme != "" && parsedURL.Host != "" {
		baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	} else if parsedURL.Host != "" {
		baseURL = "//" + parsedURL.Host
	}

	return strings.TrimRight(baseURL, "/"), parsedURL.EscapedPath(), nil
}

// IsURLAllowed checks if a target URL is allowed based on the scope anchor, host
// matching, and static-asset policy. When captureStaticAssets is false, static
// asset URLs (e.g. PDFs, images, archives, and JS bundles) are rejected so they
// are not recorded as routes or queued for spidering. When ignoreCrossDomain is
// true, scope is anchored on the full host of scopeURL — which callers set to the
// original discovery target (config.Target), NOT the per-page post-redirect host —
// so scope stays tight to the target the user requested: the target host and its
// subdomains (children) are in scope, while the apex domain and sibling subdomains
// (e.g. careers.example.com when the target is www.example.com) are treated as out
// of scope. JS bundle fetching for route discovery is gated separately by
// MaxBundles in the bundle extractors and intentionally bypasses this allowlist;
// endpoints discovered inside a bundle are still filtered through IsURLAllowed
// against the target host.
func IsURLAllowed(scopeURL string, targetURL string, ignoreCrossDomain bool, captureStaticAssets bool) bool {
	if !captureStaticAssets && utils.IsStaticAsset(targetURL) {
		return false
	}
	if ignoreCrossDomain {
		return utils.IsHostInScope(scopeURL, targetURL)
	}
	return true
}

// CaptureStaticAssetReference centralizes the static-asset-vs-route decision so
// every route extractor behaves identically. It reports whether fullURL refers to
// a static asset (e.g. a PDF, image, or archive), in which case the caller must
// NOT record it as a route. When it is a static asset and static-asset collection
// is enabled (and the asset is in scope), the asset is added to the urls set so it
// surfaces in the StaticAssets output instead. A non-asset URL returns false and
// is left for the caller to handle as a normal route. scopeURL is the scope anchor
// (config.Target) used for the in-scope check.
func CaptureStaticAssetReference(urls map[string]struct{}, scopeURL string, fullURL string, ignoreCrossDomain bool, captureStaticAssets bool) bool {
	if !utils.IsStaticAsset(fullURL) {
		return false
	}
	if IsURLAllowed(scopeURL, fullURL, ignoreCrossDomain, captureStaticAssets) {
		urls[fullURL] = struct{}{}
	}
	return true
}

// ExtractDomain extracts the domain from a URL up to a specified domain level.
func ExtractDomain(rawURL string, maxDomainLevel int) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	domain := u.Hostname()

	// IPv6 addresses use colons, not dots — return as-is without domain level splitting
	if net.ParseIP(domain) != nil {
		return domain
	}

	if maxDomainLevel > 0 {
		parts := strings.Split(domain, ".")
		if len(parts) > maxDomainLevel {
			domain = strings.Join(parts[len(parts)-maxDomainLevel:], ".")
		}
	}

	return domain
}

// IsSubdomain checks if 'sub' is a subdomain of 'base'.
func IsSubdomain(baseURL string, targetURL string) bool {
	baseDomain := ExtractDomain(baseURL, 2)
	targetDomain := ExtractDomain(targetURL, 0)

	if baseDomain == "" || targetDomain == "" {
		return false
	}

	// For IP addresses (IPv4 or IPv6), require an exact match — IPs don't have subdomains
	if net.ParseIP(baseDomain) != nil || net.ParseIP(targetDomain) != nil {
		return baseDomain == targetDomain
	}

	return targetDomain == baseDomain || strings.HasSuffix(targetDomain, "."+baseDomain)
}

// IsAbsoluteURL returns true if the given URL is absolute.
func IsAbsoluteURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "//")
}

const (
	// pathParamMinCardinality is how many distinct values a path segment must take across sibling
	// routes before it is treated as an identifier rather than a literal.
	pathParamMinCardinality = 3
	// maxCollapsePasses bounds the sibling-collapse loop so a pathological route set can't spin.
	maxCollapsePasses = 8
)

// numericSegmentPattern matches purely numeric path segments.
var numericSegmentPattern = regexp.MustCompile(`^\d+$`)

// uuidSegmentPattern matches UUID-like segments (8-4-4-4-12 hex).
var uuidSegmentPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// longHexSegmentPattern matches long hex strings (16+ hex chars) that are not UUIDs.
var longHexSegmentPattern = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)

// versionSegmentPattern matches API version segments. These are literals, but a cardinality count
// over /v1, /v2, /v3 would otherwise mistake them for an identifier.
var versionSegmentPattern = regexp.MustCompile(`^[vV]\d+$`)

// templatedSegmentPattern matches a segment that is already a `{name}` placeholder.
var templatedSegmentPattern = regexp.MustCompile(`^\{[^{}]+\}$`)

// wordSegmentPattern matches segments usable as the stem of a derived parameter name.
var wordSegmentPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

// IsIdentifierSegment reports whether a segment looks like an identifier on shape alone.
func IsIdentifierSegment(segment string) bool {
	if versionSegmentPattern.MatchString(segment) {
		return false
	}
	return numericSegmentPattern.MatchString(segment) ||
		uuidSegmentPattern.MatchString(segment) ||
		longHexSegmentPattern.MatchString(segment)
}

// isCollapseCandidate reports whether a segment may be considered for cardinality-based collapsing.
// Version segments are literals, dotted segments are usually filenames, and already-templated
// segments are done.
func isCollapseCandidate(segment string) bool {
	if segment == "" || strings.Contains(segment, ".") {
		return false
	}
	return !versionSegmentPattern.MatchString(segment) && !templatedSegmentPattern.MatchString(segment)
}

// singularize strips a naive English plural suffix so `/documents/1042` yields `documentId`.
func singularize(word string) string {
	switch {
	case strings.HasSuffix(word, "ies") && len(word) > 3:
		return word[:len(word)-3] + "y"
	case strings.HasSuffix(word, "sses"), strings.HasSuffix(word, "shes"), strings.HasSuffix(word, "ches"):
		return word[:len(word)-2]
	case strings.HasSuffix(word, "ss"):
		return word
	case strings.HasSuffix(word, "s") && len(word) > 1:
		return word[:len(word)-1]
	}
	return word
}

// pathParamNameFor derives a parameter name for the segment at index i, preferring the preceding
// segment as a stem. Names must be unique within a route because the ontology keys a
// WebEndpointParameter on (parameter_name, parameter_location).
func pathParamNameFor(segments []string, i int, taken map[string]struct{}) string {
	name := fmt.Sprintf("param%d", i+1)
	if i > 0 && wordSegmentPattern.MatchString(segments[i-1]) {
		name = singularize(segments[i-1]) + "Id"
	}
	candidate := name
	for suffix := 2; ; suffix++ {
		if _, exists := taken[candidate]; !exists {
			return candidate
		}
		candidate = fmt.Sprintf("%s%d", name, suffix)
	}
}

// existingPathParamNames collects the parameter names already recorded on a route.
func existingPathParamNames(route *discover.RouteDetails) map[string]struct{} {
	names := make(map[string]struct{}, len(route.PathParams))
	for _, param := range route.PathParams {
		names[param.Name] = struct{}{}
	}
	return names
}

// applyPathTemplate rewrites the segments at the given indices to `{name}` placeholders, recording
// each replaced literal as an example value. The concrete path is recoverable from those examples.
func applyPathTemplate(route *discover.RouteDetails, indices map[int]struct{}) bool {
	if len(indices) == 0 {
		return false
	}
	original := strings.Split(route.Path, "/")
	templated := append([]string(nil), original...)
	taken := existingPathParamNames(route)
	var params []*discover.RoutePathParam

	for i := range original {
		if _, ok := indices[i]; !ok {
			continue
		}
		name := pathParamNameFor(original, i, taken)
		taken[name] = struct{}{}
		params = append(params, &discover.RoutePathParam{Name: name, ExampleValues: []string{original[i]}})
		templated[i] = "{" + name + "}"
	}
	if len(params) == 0 {
		return false
	}

	template := strings.Join(templated, "/")
	route.Path = template
	route.PathTemplate = &template
	route.PathParams = MergePathParams(route.PathParams, params)
	return true
}

// collapseKey identifies a set of sibling routes that differ only at segment position pos.
type collapseKey struct {
	method  string
	baseURL string
	masked  string
	pos     int
}

// maskSegment renders a path with the segment at index i replaced by a wildcard, so routes that
// differ only at that position share a key.
func maskSegment(segments []string, i int) string {
	masked := append([]string(nil), segments...)
	masked[i] = "\x00"
	return strings.Join(masked, "/")
}

// collapseSiblingRoutes templates any segment position that takes at least pathParamMinCardinality
// distinct values across otherwise-identical sibling routes. This is the only signal that catches
// non-numeric identifiers such as slugs, which shape matching cannot see.
func collapseSiblingRoutes(routes []*discover.RouteDetails) ([]*discover.RouteDetails, bool) {
	observed := map[collapseKey]map[string]struct{}{}
	for _, route := range routes {
		segments := strings.Split(route.Path, "/")
		for i, segment := range segments {
			if !isCollapseCandidate(segment) {
				continue
			}
			key := collapseKey{string(route.Method), route.BaseUrl, maskSegment(segments, i), i}
			if observed[key] == nil {
				observed[key] = map[string]struct{}{}
			}
			observed[key][segment] = struct{}{}
		}
	}

	targets := map[collapseKey]struct{}{}
	for key, distinct := range observed {
		if len(distinct) >= pathParamMinCardinality {
			targets[key] = struct{}{}
		}
	}
	if len(targets) == 0 {
		return routes, false
	}

	changed := false
	for _, route := range routes {
		// Key off the original segments; templating earlier positions would change later masks.
		segments := strings.Split(route.Path, "/")
		indices := map[int]struct{}{}
		for i, segment := range segments {
			if !isCollapseCandidate(segment) {
				continue
			}
			key := collapseKey{string(route.Method), route.BaseUrl, maskSegment(segments, i), i}
			if _, ok := targets[key]; ok {
				indices[i] = struct{}{}
			}
		}
		if applyPathTemplate(route, indices) {
			changed = true
		}
	}
	if !changed {
		return routes, false
	}
	return MergeWebRoutes(routes), true
}

// CollapseTemplatedRoutes folds routes that differ only by an identifier segment into a single
// templated route carrying PathParams, so `/documents/1042` and `/documents/3517` become
// `/documents/{documentId}` with both values retained as examples.
//
// Run this once over the full route set. It is deliberately not part of MergeWebRoutes, which the
// extractors call on partial corpora where a premature collapse could not be re-merged.
func CollapseTemplatedRoutes(routes []*discover.RouteDetails) []*discover.RouteDetails {
	// Shape evidence is per-route and needs no corpus.
	changed := false
	for _, route := range routes {
		segments := strings.Split(route.Path, "/")
		indices := map[int]struct{}{}
		for i, segment := range segments {
			if IsIdentifierSegment(segment) {
				indices[i] = struct{}{}
			}
		}
		if applyPathTemplate(route, indices) {
			changed = true
		}
	}
	if changed {
		routes = MergeWebRoutes(routes)
	}

	// Cardinality evidence needs the whole corpus, and collapsing one position can expose another.
	for pass := 0; pass < maxCollapsePasses; pass++ {
		next, collapsed := collapseSiblingRoutes(routes)
		routes = next
		if !collapsed {
			break
		}
	}
	return routes
}
