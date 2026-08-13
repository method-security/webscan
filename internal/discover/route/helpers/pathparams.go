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
// Angular, Express), `[id]` (Next.js file-based routing), and `{id}` (already normalized, and the
// form ConstructURL substitutes).
//
// Next.js rest parameters (`[...slug]`) are deliberately excluded. A catch-all matches one or more
// segments, which a single placeholder cannot express: a root-level `/{slug}` would swallow every
// unrelated top-level page while never folding the multi-segment paths the route actually serves.
var declaredParamPattern = regexp.MustCompile(`^(?::([A-Za-z_][A-Za-z0-9_]*)\??|\[([A-Za-z_][A-Za-z0-9_.]*)\]|\{([A-Za-z_][A-Za-z0-9_]*)\})$`)

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
	// A template with no literal segment discriminates on nothing but segment count, so `/{slug}`
	// swallows every top-level page and `/{locale}/{page}` every two-segment one. Sibling literals
	// from the same route table are not recorded, so nothing can outrank it the way a declared
	// literal would. One literal segment is enough to anchor it: `/{locale}/products/{id}` only
	// ever matches paths with `products` in that position.
	if !hasLiteralSegment(segments) {
		return path, nil, false
	}
	return strings.Join(segments, "/"), params, true
}

// hasLiteralSegment reports whether any non-empty segment is a fixed string rather than a
// placeholder.
func hasLiteralSegment(segments []string) bool {
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		if !strings.HasPrefix(segment, "{") {
			return true
		}
	}
	return false
}

// declaredParamSyntaxPattern matches a segment that looks like a route parameter in any convention,
// including forms that do not yield a usable template such as a catch-all.
var declaredParamSyntaxPattern = regexp.MustCompile(`(?:^|/)(?::[^/]+|\[[^/]*\]|\{[^/]*\})(?:/|$)`)

// HasDeclaredParamSyntax reports whether a path contains route-parameter syntax at all, regardless
// of whether NormalizeDeclaredTemplate can turn it into a usable template. A path that looks
// parameterized is never a fetchable literal, so callers must not fall back to emitting it as one.
func HasDeclaredParamSyntax(path string) bool {
	return declaredParamSyntaxPattern.MatchString(path)
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
		if !matchTemplateSegment(templateSegment, literalSegments[i], values) {
			return nil, false
		}
	}
	return values, true
}

// embeddedPlaceholderPattern matches a `{name}` placeholder anywhere within a segment.
var embeddedPlaceholderPattern = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// matchTemplateSegment matches one template segment against a literal segment, recording any
// placeholder values it captures.
//
// A placeholder need not span the whole segment: interpolated templates such as
// `order_{orderId}.pdf` embed one, and ConstructURL substitutes those the same way, so folding has
// to understand them or the observed values are never captured.
func matchTemplateSegment(templateSegment string, literalSegment string, values map[string]string) bool {
	if name, isParam := DeclaredParamName(templateSegment); isParam {
		if literalSegment == "" {
			return false
		}
		values[name] = literalSegment
		return true
	}

	locations := embeddedPlaceholderPattern.FindAllStringSubmatchIndex(templateSegment, -1)
	if len(locations) == 0 {
		return templateSegment == literalSegment
	}

	var names []string
	var pattern strings.Builder
	pattern.WriteString("^")
	previous := 0
	for _, location := range locations {
		pattern.WriteString(regexp.QuoteMeta(templateSegment[previous:location[0]]))
		pattern.WriteString("(.+?)")
		names = append(names, templateSegment[location[2]:location[3]])
		previous = location[1]
	}
	pattern.WriteString(regexp.QuoteMeta(templateSegment[previous:]))
	pattern.WriteString("$")

	matcher, err := regexp.Compile(pattern.String())
	if err != nil {
		return false
	}
	match := matcher.FindStringSubmatch(literalSegment)
	if match == nil {
		return false
	}
	for i, name := range names {
		values[name] = match[i+1]
	}
	return true
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
			if candidate.route.Method != route.Method ||
				NormalizeBaseURLForIdentity(candidate.route.BaseUrl) != NormalizeBaseURLForIdentity(route.BaseUrl) {
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

// routeKey builds the identity a route is deduplicated on. The origin is normalized so an explicit
// default port or differing case does not split one application in two, matching MergeWebRoutes.
func routeKey(method common.HttpMethod, baseURL string, path string) string {
	return fmt.Sprintf("%s:%s%s", method, NormalizeBaseURLForIdentity(baseURL), path)
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

// InterpolatedRouteEvidence tags routes recovered from an interpolated URL in a bundle. The
// interpolation proves a parameter exists at that position, but unlike a route table it does not
// reliably name it — bundles are minified and the expression is often a single letter.
const InterpolatedRouteEvidence = "interpolated"

// identifierExpressionPattern matches an interpolation body that is a plain identifier or property
// access, e.g. `orderId` or `this.orderId`, as opposed to a call or arithmetic expression.
var identifierExpressionPattern = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$`)

// trailingWordPattern captures the last alphabetic word in a fragment of literal path text.
var trailingWordPattern = regexp.MustCompile(`([A-Za-z][A-Za-z0-9]*)[^A-Za-z0-9]*$`)

// singularize strips a naive English plural suffix so `basket` and `products` both read naturally
// with an `Id` suffix.
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

// trailingWord returns the last alphabetic word in a fragment, or "" when there is none.
func trailingWord(fragment string) string {
	match := trailingWordPattern.FindStringSubmatch(fragment)
	if match == nil {
		return ""
	}
	return match[1]
}

// InterpolatedParamName picks the most defensible name for a parameter recovered from an
// interpolated URL, preferring evidence in this order: the interpolated expression itself, the
// literal text preceding it inside the same segment, then the preceding path segment.
//
// Unlike a declared route this name is derived rather than authoritative. The interpolation is what
// proves the parameter exists; only the label is a best effort.
func InterpolatedParamName(expression string, segmentPrefix string, previousSegment string) string {
	if identifierExpressionPattern.MatchString(expression) {
		parts := strings.Split(expression, ".")
		last := parts[len(parts)-1]
		// Minified bundles collapse locals to one or two characters, which carry no meaning.
		if len(last) >= 3 && !strings.EqualFold(last, "this") {
			return last
		}
	}
	if word := trailingWord(segmentPrefix); word != "" {
		return singularize(word) + "Id"
	}
	if word := trailingWord(previousSegment); word != "" {
		return singularize(word) + "Id"
	}
	return "param"
}

// UniqueParamName returns name, or the first numbered variant not already taken. Path parameter
// names must be unique within a route because the ontology keys a WebEndpointParameter on
// (parameter_name, parameter_location).
func UniqueParamName(name string, taken map[string]struct{}) string {
	candidate := name
	for suffix := 2; ; suffix++ {
		if _, exists := taken[candidate]; !exists {
			return candidate
		}
		candidate = fmt.Sprintf("%s%d", name, suffix)
	}
}
