package discoverroute

import (
	// Standard
	"fmt"
	"regexp"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
)

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

// IsTemplatedPath reports whether a path carries an unresolved `{name}` placeholder, and is
// therefore a route declaration rather than a URL that can be requested.
func IsTemplatedPath(path string) bool {
	return strings.Contains(path, "{") && strings.Contains(path, "}")
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
