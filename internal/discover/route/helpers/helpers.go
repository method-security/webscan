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

// DeclaredRouteEvidence tags routes that came from an application's own route table rather than
// from an observed request, so precedence between a declared literal and a declared template can be
// resolved the way a router would resolve it.
const DeclaredRouteEvidence = "route-table"

// declaredParamPattern matches a parameter placeholder in a client-side route declaration.
// Covers the three conventions that appear in shipped bundles: `:id` (React Router, Vue Router,
// Angular, Express), `[id]` and `[...slug]` (Next.js file-based routing), and `{id}` (already
// normalized, and the form ConstructURL substitutes).
var declaredParamPattern = regexp.MustCompile(`^(?::([A-Za-z_][A-Za-z0-9_]*)\??|\[\.{0,3}([A-Za-z_][A-Za-z0-9_.]*)\]|\{([A-Za-z_][A-Za-z0-9_]*)\})$`)

// DeclaredParamName returns the parameter name a route-declaration segment names, and whether the
// segment is a placeholder at all. The name is authoritative — it comes from the application's own
// route table rather than being synthesized from surrounding path text.
func DeclaredParamName(segment string) (string, bool) {
	match := declaredParamPattern.FindStringSubmatch(segment)
	if match == nil {
		return "", false
	}
	for _, group := range match[1:] {
		if group != "" {
			return strings.TrimPrefix(group, "..."), true
		}
	}
	return "", false
}

// NormalizeDeclaredTemplate rewrites a declared route template into the `{name}` form that
// ConstructURL substitutes, and returns the parameters it declares. Returns ok=false when the path
// declares no parameters, so callers can leave ordinary routes untouched.
func NormalizeDeclaredTemplate(path string) (string, []*discover.RoutePathParam, bool) {
	segments := strings.Split(path, "/")
	params := make([]*discover.RoutePathParam, 0, len(segments))
	seen := map[string]struct{}{}

	for i, segment := range segments {
		name, isParam := DeclaredParamName(segment)
		if !isParam {
			continue
		}
		segments[i] = "{" + name + "}"
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		params = append(params, &discover.RoutePathParam{Name: name})
	}

	if len(params) == 0 {
		return path, nil, false
	}
	return strings.Join(segments, "/"), params, true
}

// templateMatchesLiteral reports whether a literal path is an instance of a normalized template,
// and returns the value each placeholder took. Matching is exact on segment count and on every
// non-placeholder segment, so this is a decision about the declared route rather than a guess.
func templateMatchesLiteral(template string, literal string) (map[string]string, bool) {
	templateSegments := strings.Split(template, "/")
	literalSegments := strings.Split(literal, "/")
	if len(templateSegments) != len(literalSegments) {
		return nil, false
	}

	values := map[string]string{}
	for i, templateSegment := range templateSegments {
		name, isParam := DeclaredParamName(templateSegment)
		if !isParam {
			if templateSegment != literalSegments[i] {
				return nil, false
			}
			continue
		}
		if literalSegments[i] == "" {
			return nil, false
		}
		values[name] = literalSegments[i]
	}
	return values, true
}

// ApplyDeclaredRouteTemplates folds observed literal routes into the templates the application
// declares, so `/documents/1042` becomes an example of a declared `/documents/{id}` rather than a
// separate endpoint. Nothing is inferred: a literal is only folded when the application's own route
// table says that template exists, and an exact literal declaration always wins over a template.
func ApplyDeclaredRouteTemplates(routes []*discover.RouteDetails) []*discover.RouteDetails {
	type templateRoute struct {
		route    *discover.RouteDetails
		template string
	}

	var templates []templateRoute
	declaredLiterals := map[string]struct{}{}
	for _, route := range routes {
		if len(route.PathParams) > 0 && route.PathTemplate != nil {
			templates = append(templates, templateRoute{route: route, template: *route.PathTemplate})
			continue
		}
		// Only a literal the route table itself declares outranks a matching template. An observed
		// crawl hit carries no such claim and is free to fold.
		if route.Evidence != nil && *route.Evidence == DeclaredRouteEvidence {
			declaredLiterals[routeKey(route.Method, route.BaseUrl, route.Path)] = struct{}{}
		}
	}
	if len(templates) == 0 {
		return routes
	}

	folded := make([]*discover.RouteDetails, 0, len(routes))
	for _, route := range routes {
		if len(route.PathParams) > 0 && route.PathTemplate != nil {
			folded = append(folded, route)
			continue
		}

		matched := false
		for _, candidate := range templates {
			if candidate.route.Method != route.Method || candidate.route.BaseUrl != route.BaseUrl {
				continue
			}
			values, ok := templateMatchesLiteral(candidate.template, route.Path)
			if !ok {
				continue
			}
			// Router semantics: an explicitly declared literal beats a template that also matches.
			if _, isDeclared := declaredLiterals[routeKey(route.Method, route.BaseUrl, route.Path)]; isDeclared {
				continue
			}
			for _, param := range candidate.route.PathParams {
				if value, exists := values[param.Name]; exists {
					param.ExampleValues = appendUniqueValue(param.ExampleValues, value)
				}
			}
			candidate.route.QueryParams = MergeQueryParams(candidate.route.QueryParams, route.QueryParams)
			candidate.route.BodyParams = MergeBodyParams(candidate.route.BodyParams, route.BodyParams)
			matched = true
			break
		}
		if !matched {
			folded = append(folded, route)
		}
	}

	return MergeWebRoutes(folded)
}

// routeKey builds the identity a route is deduplicated on.
func routeKey(method common.HttpMethod, baseURL string, path string) string {
	return fmt.Sprintf("%s:%s%s", method, baseURL, path)
}

// appendUniqueValue appends a value if it is not already present.
func appendUniqueValue(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
